//! Rendering. Pure read of App state; no mutation, no I/O.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};
/// Display width in terminal cells (CJK-safe via per-char widths).
fn dw(s: &str) -> usize {
    s.chars()
        .map(|c| unicode_width::UnicodeWidthChar::width(c).unwrap_or(0))
        .sum()
}

/// Hard-split one word into pieces no wider than `width` (only used for
/// words longer than the line; normal text wraps between words instead).
fn chunk_word(word: &str, width: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut cur = String::new();
    let mut w = 0usize;
    for ch in word.chars() {
        let cw = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
        if w + cw > width && !cur.is_empty() {
            chunks.push(std::mem::take(&mut cur));
            w = 0;
        }
        cur.push(ch);
        w += cw;
    }
    if !cur.is_empty() {
        chunks.push(cur);
    }
    chunks
}

/// Word-wrap `s` into lines of at most `width` display cells. Wraps on
/// whitespace (never mid-word unless a single word cannot fit), honors
/// embedded newlines, and keeps blank paragraphs as blank lines. ratatui's
/// own Wrap breaks per character, which is exactly what made model reasons
/// read like they were being sliced by the modal border.
fn wrap_words(s: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut out: Vec<String> = Vec::new();
    for para in s.split('\n') {
        let mut cur = String::new();
        let mut curw = 0usize;
        for word in para.split_whitespace() {
            for chunk in chunk_word(word, width) {
                let cw = dw(&chunk);
                if curw == 0 {
                    cur = chunk;
                    curw = cw;
                } else if curw + 1 + cw <= width {
                    cur.push(' ');
                    cur.push_str(&chunk);
                    curw += 1 + cw;
                } else {
                    out.push(std::mem::take(&mut cur));
                    cur = chunk;
                    curw = cw;
                }
            }
        }
        out.push(cur);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

use crate::app::{
    fmt_bytes, fmt_countdown, fmt_ttl_mins, fmt_ttl_secs, parse_ttl_override, App, Modal, COLS,
};
use crate::conn::ConnStatus;

pub fn draw(f: &mut Frame, app: &App, st: ConnStatus) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(f.area());

    draw_header(f, app, st, rows[0]);
    draw_table(f, app, st, rows[1]);
    draw_keybar(f, app, rows[2]);

    match &app.modal {
        Modal::Pending(i) => draw_pending_modal(f, app, *i),
        Modal::Detail(id) => draw_detail_modal(f, app, *id),
        Modal::History => draw_history_modal(f, app),
        Modal::Net => draw_net_modal(f, app),
        Modal::ConfirmStop => draw_stop_modal(f, app),
        Modal::ConnLost => draw_conn_modal(f, st),
        Modal::None => {}
    }
}

fn muted(dim: bool) -> Style {
    if dim {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default()
    }
}

/// Two header lines: identity/counts/connection state (the subscribe ack
/// carries the daemon version, rendered so TUI/daemon skew is visible), and
/// the sort indicator, column legend, and any flash message.
fn draw_header(f: &mut Frame, app: &App, st: ConnStatus, a: Rect) {
    let host = hostname();
    let conn = if !st.up {
        Span::styled(" ○reconnecting", Style::default().fg(Color::Red))
    } else if !st.synced {
        Span::styled(" ●syncing…", Style::default().fg(Color::Yellow))
    } else {
        Span::styled(" ●conn", Style::default().fg(Color::Green))
    };
    let net = primary_ip();
    let mut l1_parts = vec![
        Span::styled(
            format!(" tethysd @ {host} ─ {net} ─ "),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{} live", app.live.len()),
            Style::default().fg(if app.live.is_empty() {
                Color::DarkGray
            } else {
                Color::Cyan
            }),
        ),
        Span::raw(" ─ "),
        Span::styled(
            format!("{} pending", app.pending.len()),
            Style::default().fg(if app.pending.is_empty() {
                Color::DarkGray
            } else {
                Color::Yellow
            }),
        ),
        conn,
    ];
    if let Some(v) = &app.daemon_version {
        l1_parts.push(Span::styled(format!(" tethys v{v}"), muted(true)));
    }
    let l1 = Line::from(l1_parts);

    let sort_span = Span::styled(
        format!(
            " sort: {}{}  ",
            app.sort.header(),
            if app.sort_asc { " ▲" } else { " ▼" }
        ),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    let legend = COLS
        .iter()
        .enumerate()
        .map(|(i, c)| format!("{}:{}", i + 1, c.header()))
        .collect::<Vec<_>>()
        .join(" ");
    let mut l2_parts = vec![sort_span, Span::styled(format!("{legend}  "), muted(true))];
    if let Some((msg, _)) = &app.flash {
        l2_parts.push(Span::styled(
            format!("⚠ {msg}"),
            Style::default().fg(Color::LightYellow),
        ));
    }
    let header = Paragraph::new(vec![l1, Line::from(l2_parts)])
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, a);
}

// ---------------------------------------------------------------- table
//
// Hand-rolled instead of ratatui::Table so a row can span the full width on
// its second line. Table clamps every cell to its column, which makes true
// two-line rows impossible at narrow widths.
//
// Width policy (columns: 8 fixed facts + elastic `reason`). Fixed columns
// never clip on a single line; `reason` absorbs every pixel of shrinkage:
//   1. roomy:   fixed cols at natural width (widest value/header); once
//      reason has a comfortable slice, surplus grows the inter-column gap
//      toward GAP_MAX ("ample padding" on big screens), then keeps feeding
//      reason.
//   2. tight:   reason gets the remainder and ellipsizes; facts complete.
//   3. cramped: remainder < REASON_MIN, so rows go two lines tall. Line 1 =
//      fixed cols at natural width, packed greedily (rightmost drop first);
//      line 2 = `↳ <reason>` across the full inner width.

const GAP_MIN: u16 = 1;
const GAP_MAX: u16 = 4;
/// Smallest slice worth giving reason on a single line; below this, wrap.
const REASON_MIN: u16 = 8;
/// Extra cells inserted after the ttl column only (see mk/gap_for).
const TTL_GAP_EXTRA: u16 = 2;
const HEADERS: [&str; 8] = [
    "id",
    "tool",
    "dst",
    "ports",
    "proto",
    "ttl",
    "left",
    "\u{2195}B",
];

fn truncate(s: &str, w: usize) -> String {
    if dw(s) <= w {
        return s.to_string();
    }
    if w == 0 {
        return String::new();
    }
    if w == 1 {
        return "…".into();
    }
    let mut out = String::new();
    let mut width = 0;
    for ch in s.chars() {
        let cw = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
        if width + cw > w - 1 {
            break;
        }
        out.push(ch);
        width += cw;
    }
    out.push('…');
    out
}

/// Pad/truncate `s` to exactly display-width `w`, left-aligned.
fn fit(s: &str, w: usize) -> String {
    let t = truncate(s, w);
    let pad = w.saturating_sub(dw(&t));
    format!("{t}{}", " ".repeat(pad))
}

/// First resolved address, plus a count of the rest.
/// First resolved address plus a count of the rest; "…" until the first
/// poll lands.
fn fmt_dst(row: &crate::app::LiveRow) -> String {
    let Some(first) = row.dst.first() else {
        return "…".into(); // not polled yet
    };
    match row.dst.len() {
        1 => first.clone(),
        n => format!("{first} +{}", n - 1),
    }
}

struct RowCells {
    vals: [String; 8], // id, tool, dst, ports, proto, ttl, left, traffic
    reason: String,
    /// leading status dot: Some(color) once remaining-TTL is known (None
    /// until the first traffic poll lands, leaving a blank cell with the
    /// column still aligned)
    dot: Option<Color>,
}

/// Remaining-vs-total TTL as a traffic-light dot.
/// green > 50% · yellow >= 25% · orange < 25%.
/// Remaining-vs-total TTL as a traffic-light dot.
/// green > 50% · yellow >= 25% · orange < 25% (ratatui has no plain orange;
/// LightRed reads as it).
fn ttl_dot(left: Option<u64>, ttl_secs: u64) -> Option<Color> {
    let left = left?;
    if ttl_secs == 0 {
        return None;
    }
    let frac = left as f64 / ttl_secs as f64;
    Some(if frac > 0.5 {
        Color::Green
    } else if frac >= 0.25 {
        Color::Yellow
    } else {
        Color::LightRed
    })
}

fn cells_for(r: &crate::app::LiveRow) -> RowCells {
    let up = r.bytes_up.unwrap_or(0);
    let down = r.bytes_down.unwrap_or(0);
    let traffic = format!(
        "{}{}",
        if up > 0 {
            format!("↑{}", fmt_bytes(up))
        } else {
            String::new()
        },
        if down > 0 {
            format!("↓{}", fmt_bytes(down))
        } else if up == 0 {
            "·".into()
        } else {
            String::new()
        }
    );
    RowCells {
        dot: ttl_dot(r.left, r.ttl_secs),
        vals: [
            r.id.to_string(),
            r.tool.clone(),
            fmt_dst(r),
            r.ports.clone(),
            r.proto.clone(),
            fmt_ttl_mins(r.ttl_secs),
            fmt_countdown(r.left),
            traffic,
        ],
        reason: r.reason.clone(),
    }
}

/// Fixed-column widths = max(content, header) across visible rows, capped so
/// one pathological value can't starve `reason`; overflow ellipsizes.
/// Column 0 gets +2 cells reserved for the row's status dot (see mk).
fn natural_widths(rows: &[RowCells]) -> [u16; 8] {
    let mut w = HEADERS.map(|h| dw(h) as u16);
    for c in rows {
        for (i, v) in c.vals.iter().enumerate() {
            w[i] = w[i].max(dw(v) as u16);
        }
    }
    w[0] += 2;
    for i in 0..8 {
        w[i] = w[i].clamp(dw(HEADERS[i]) as u16 + if i == 0 { 2 } else { 0 }, 39);
    }
    w
}

/// Two-line plan: pack fixed columns at natural width left-to-right; the
/// rightmost ones that don't fit are dropped entirely (bytes first, then
/// left, ttl…). Returns (widths, count kept).
fn pack_line1(rows: &[RowCells], w: u16) -> ([u16; 8], usize) {
    let nat = natural_widths(rows);
    let mut fw = [0u16; 8];
    let mut used = 0u16;
    let mut kept = 0;
    for i in 0..8 {
        let extra = if i == 5 { TTL_GAP_EXTRA } else { 0 };
        let need = if kept == 0 {
            nat[i] + extra
        } else {
            nat[i] + GAP_MIN + extra
        };
        if used + need > w {
            break;
        }
        fw[i] = nat[i];
        used += need;
        kept += 1;
    }
    (fw, kept)
}

/// Draw the live table under the width policy above. While the socket is
/// down the table is stale: rows are real but frozen, rendered dim. Gaps
/// widen only while every visible reason still fits whole; a reason that
/// would clip pulls gaps back to GAP_MIN before it loses a character. The
/// window scrolls to keep the selected row visible.
fn draw_table(f: &mut Frame, app: &App, st: ConnStatus, a: Rect) {
    let dim = !st.up;
    let title = if dim {
        " LIVE (stale, no daemon) "
    } else {
        " LIVE "
    };
    let inner = Block::default().borders(Borders::ALL).title(title).inner(a);
    f.render_widget(Block::default().borders(Borders::ALL).title(title), a);
    if inner.width < 8 || inner.height == 0 {
        return;
    }

    let rows: Vec<RowCells> = app.sorted_live().iter().map(|r| cells_for(r)).collect();
    let sel_row = app.sel.min(app.live.len().saturating_sub(1));

    let mut fw = natural_widths(&rows);
    let fixed_nat: u16 = fw.iter().sum();
    let need_reason = rows
        .iter()
        .map(|c| dw(&c.reason) as u16)
        .max()
        .unwrap_or(6)
        .max(6);
    let surplus = inner
        .width
        .saturating_sub(fixed_nat + need_reason + GAP_MIN * 8 + TTL_GAP_EXTRA);
    let gap = (GAP_MIN + surplus / 8).clamp(GAP_MIN, GAP_MAX);
    let reason_w = inner
        .width
        .saturating_sub(fixed_nat + gap * 8 + TTL_GAP_EXTRA);

    let wrap = reason_w < REASON_MIN;
    let mut kept = 8usize;
    if wrap {
        let (fw3, kept3) = pack_line1(&rows, inner.width);
        fw = fw3;
        kept = kept3;
    }

    let line_h = if wrap { 2 } else { 1 };
    let body_h = inner.height.saturating_sub(1);
    let visible = (body_h / line_h).max(1) as usize;
    let start = sel_row.saturating_sub(visible.saturating_sub(1));

    let gap_base = gap_used(inner, gap, wrap);
    // One uniform inter-column gap everywhere except after `ttl` (col 5):
    // its digits and the countdown read as one number when crowded, so ttl
    // gets two extra cells of separation.
    let gap_for = |i: usize| {
        let extra = if i == 5 { TTL_GAP_EXTRA } else { 0 };
        " ".repeat((gap_base + extra) as usize)
    };
    const DOT_W: usize = 2;
    let mk = |vals: &mut Vec<Span<'_>>, v: &[String; 8], style: Style, dot: Option<Color>| {
        for (i, s) in v.iter().take(kept).enumerate() {
            if i == 0 {
                vals.push(match dot {
                    Some(c) => Span::styled(" ●".to_string(), Style::default().fg(c)),
                    None => Span::styled("  ".to_string(), style),
                });
                vals.push(Span::styled(
                    format!(
                        "{}{}",
                        fit(s, fw[i].saturating_sub(DOT_W as u16) as usize),
                        gap_for(i)
                    ),
                    style,
                ));
                continue;
            }
            vals.push(Span::styled(
                format!("{}{}", fit(s, fw[i] as usize), gap_for(i)),
                style,
            ));
        }
    };

    let mut hdr: Vec<Span> = Vec::with_capacity(9);
    mk(
        &mut hdr,
        &HEADERS.map(|h| h.to_string()).clone(),
        muted(dim),
        None,
    );
    if !wrap {
        hdr.push(Span::styled(
            truncate("reason", reason_w as usize),
            muted(dim),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(hdr)), inner);

    let body = Rect {
        y: inner.y + 1,
        height: body_h,
        ..inner
    };
    let mut lines: Vec<Line> = Vec::with_capacity(visible * line_h as usize);
    for (i, c) in rows.iter().skip(start).take(visible).enumerate() {
        let base = muted(dim);
        // Selection highlight is bg-only, deliberately NOT REVERSED: the
        // TTL dot sets an explicit fg and the line sets an explicit bg, so
        // a terminal-level fg/bg swap would render the dot as a gray glyph
        // on a green box (text cells hide the swap by keeping default fg).
        // Zebra striping: every other row gets a DarkGray bg so long
        // rows can be tracked across wide terminals. Selection is Gray
        // (one step lighter) with black text so it stays distinct from
        // the stripes; when the socket is down (dim) stripes are skipped
        // because muted text would vanish into them.
        let style = if start + i == sel_row && !dim {
            base.bg(Color::Gray).fg(Color::Black)
        } else if (start + i) % 2 == 1 && !dim {
            base.bg(Color::DarkGray)
        } else {
            base
        };
        let mut spans: Vec<Span> = Vec::with_capacity(10);
        mk(&mut spans, &c.vals, Style::default(), c.dot);
        if !wrap {
            spans.push(Span::raw(truncate(&c.reason, reason_w as usize)));
        }
        lines.push(Line::from(spans).style(style));
        if wrap {
            let cont = format!("  ↳ {}", c.reason);
            lines.push(Line::from(Span::raw(truncate(&cont, inner.width as usize))).style(style));
        }
    }
    f.render_widget(Paragraph::new(lines), body);

    let hidden = rows.len().saturating_sub(start + visible);
    if hidden > 0 && body_h > 1 {
        let note = format!(" {} more ", hidden);
        let nx = inner.x + inner.width.saturating_sub(note.len() as u16);
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(note.clone(), muted(true)))),
            Rect {
                x: nx,
                width: note.len() as u16,
                height: 1,
                ..inner
            },
        );
    }
}

/// Gap used between columns; the two-line plan is always GAP_MIN.
fn gap_used(_inner: Rect, gap: u16, wrap: bool) -> u16 {
    if wrap {
        GAP_MIN
    } else {
        gap
    }
}

fn draw_keybar(f: &mut Frame, app: &App, a: Rect) {
    let keys = match &app.modal {
        Modal::None => {
            "j/k select · Enter detail · e revoke · d history · n interfaces · R reload allow · ! stop all · q quit"
        }
        Modal::Pending(_) => {
            if app.deny_note.is_some() {
                "type deny note · Enter send · Esc deny-empty"
            } else {
                "a approve · d deny+note · t edit ttl (30s/45m/2h) · n next pending · Esc dismiss (stays queued)"
            }
        }
        Modal::Detail(_) => "e revoke · Esc back",
        Modal::History => "j/k select · r re-load · Esc back",
        Modal::Net => "Esc back",
        Modal::ConfirmStop => "type `stop` + Enter to confirm · any other key cancels",
        Modal::ConnLost => "retrying automatically · Esc to view stale state",
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(format!(" {keys}"), muted(true)))),
        a,
    );
}

// ------------------------------------------------------------------ modals

fn centered(a: Rect, w_pct: u16, h_pct: u16) -> Rect {
    let v = Layout::vertical([Constraint::Percentage(h_pct)])
        .flex(ratatui::layout::Flex::Center)
        .split(a);
    let h = Layout::horizontal([Constraint::Percentage(w_pct)])
        .flex(ratatui::layout::Flex::Center)
        .split(v[0]);
    h[0]
}

/// Pending request modal. The title carries a countdown to daemon
/// auto-deny (approver_timeout_secs from the subscribe ack): the bar fills
/// as the deadline approaches while the number shows time remaining.
/// Every grant fact gets its own line; the reason word-wraps (never
/// mid-word) with continuation lines indented under its label, and the
/// modal grows to fit rather than clipping it.
fn draw_pending_modal(f: &mut Frame, app: &App, idx: usize) {
    let ids = app.pending_ids();
    let Some(id) = ids.get(idx).copied() else {
        return;
    };
    let Some(p) = app.pending.get(&id) else {
        return;
    };
    let mut area = centered(f.area(), 70, 60);
    f.render_widget(Clear, area);

    let label = |s: &str| Span::styled(format!("{s:<14}"), muted(true));
    let wrap_w = (area.width as usize).saturating_sub(2 + 14).max(20);

    let waiting = app.now.saturating_sub(p.created_at);
    let mut title = format!(
        " REQUEST {id} · {} · waiting {}:{:02} ",
        p.tool,
        waiting / 60,
        waiting % 60
    );
    if let Some(to) = app.timeout_secs {
        let left = to.saturating_sub(waiting);
        let filled = (waiting.min(to) as usize * 20 / to.max(1) as usize).min(20);
        title.push_str(&format!(
            "· auto-deny in {:>3}s [{}{}] ",
            left,
            "█".repeat(filled),
            "░".repeat(20 - filled)
        ));
    }

    // One labeled block per fact; values longer than the line wrap under
    // their label instead of colliding with the next field or the border.
    let field_styled = |name: &str, val: &str, st: Style| -> Vec<Line> {
        let ws = wrap_words(val, wrap_w);
        ws.iter()
            .enumerate()
            .map(|(i, l)| {
                Line::from(vec![
                    if i == 0 {
                        label(name)
                    } else {
                        Span::styled(" ".repeat(14), muted(true))
                    },
                    Span::styled(l.clone(), st),
                ])
            })
            .collect()
    };

    let field = |name: &str, val: &str| field_styled(name, val, Style::default());

    let mut body: Vec<Line> = Vec::new();
    // The dst (hostname or IP the agent supplied) is THE decision — bold
    // green so the eye lands on it first even mid-queue.
    body.extend(field_styled(
        "requested",
        &p.target,
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
    ));
    body.extend(field("ports", &p.ports));
    body.extend(field("ttl requested", &p.ttl_requested));
    body.push(Line::from(""));
    body.extend(field("reason", &p.reason));

    let mut action_spans = vec![
        Span::styled(
            " [a]pprove",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("   [d]eny+note", Style::default().fg(Color::Red)),
        Span::styled("   [t]tl→__ (s|m|h)", Style::default().fg(Color::Cyan)),
    ];
    if let Some(t) = &app.ttl_edit {
        // Show the canonical form the daemon will get; unparseable text is
        // flagged right where it was typed, not just on approve.
        let t = t.trim();
        if t.is_empty() {
            action_spans.push(Span::styled("  ttl→(enter to clear)", muted(true)));
        } else {
            match parse_ttl_override(t) {
                Some(secs) => action_spans.push(Span::styled(
                    format!("  ttl→{}", fmt_ttl_secs(secs)),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                None => action_spans.push(Span::styled(
                    format!("  ttl→{t}? (digits + s/m/h)"),
                    Style::default().fg(Color::LightRed),
                )),
            }
        }
    }
    if ids.len() > 1 {
        action_spans.push(Span::styled(
            format!("   [n]ext {}/{}", idx + 1, ids.len()),
            muted(false),
        ));
    }
    action_spans.push(Span::styled("   [Esc]close", muted(true)));

    body.push(Line::from(""));
    if let Some(note) = &app.deny_note {
        body.push(Line::from(vec![
            Span::styled("note          ", Style::default().fg(Color::Red)),
            Span::raw(format!("{note}▏")),
        ]));
    }
    body.push(Line::from(action_spans));

    // Grow (never shrink below the default slice) so the wrapped reason and
    // the action row both fit; capped by the screen.
    let need = (body.len() + 2).min((f.area().height as usize).saturating_sub(1)) as u16;
    if need > area.height {
        area = Rect {
            y: f.area().y + f.area().height.saturating_sub(need) / 2,
            height: need,
            ..area
        };
        f.render_widget(Clear, area);
    }

    let block = Paragraph::new(body).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    f.render_widget(block, area);
}

/// Grant detail modal. Wrapping is on so a long installed-address list
/// cannot clip the "⚠ IP addresses resolved from hostname" annotation.
fn draw_detail_modal(f: &mut Frame, app: &App, id: i64) {
    let Some(r) = app.live.get(&id) else { return };
    let area = centered(f.area(), 80, 55);
    f.render_widget(Clear, area);
    let differs = r.dst.iter().any(|d| !r.target.ends_with(d.as_str()));
    let mut lines = vec![
        Line::from(vec![
            Span::styled(" requested   ", muted(true)),
            // same orientation cue as the pending modal: dst is bold green
            Span::styled(
                r.target.clone(),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(" installed   ", muted(true)),
            Span::raw(r.dst.join(", ")),
            if differs {
                Span::styled(
                    "   ⚠️ IP addresses resolved from hostname",
                    Style::default().fg(Color::Yellow),
                )
            } else {
                Span::raw("")
            },
        ]),
        Line::from(vec![
            Span::styled(" ports/proto ", muted(true)),
            Span::raw(format!(
                "{}  {}   ttl granted {}",
                r.ports,
                r.proto,
                fmt_ttl_secs(r.ttl_secs)
            )),
        ]),
        Line::from(vec![
            Span::styled(" reason      ", muted(true)),
            Span::raw(r.reason.clone()),
        ]),
        Line::from(vec![
            Span::styled(" traffic     ", muted(true)),
            Span::raw(format!(
                "↑ {} B   ↓ {} B   left {}",
                fmt_bytes(r.bytes_up.unwrap_or(0)),
                fmt_bytes(r.bytes_down.unwrap_or(0)),
                fmt_countdown(r.left)
            )),
        ]),
    ];
    lines.push(Line::from(""));
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" GRANT {id} · {} ", r.tool))
                .title_bottom(" e revoke · Esc back "),
        ),
        area,
    );
}

fn draw_history_modal(f: &mut Frame, app: &App) {
    let area = centered(f.area(), 90, 80);
    f.render_widget(Clear, area);
    if let Some(e) = &app.history_err {
        f.render_widget(
            Paragraph::new(format!("history failed: {e}"))
                .block(Block::default().borders(Borders::ALL).title(" HISTORY ")),
            area,
        );
        return;
    }
    let items: Vec<ListItem> = app
        .history
        .iter()
        .enumerate()
        .map(|(i, g)| {
            use tethys_core::wire::GrantState;
            let state = g.state.as_str();
            let color = match g.state {
                GrantState::Denied => Color::Red,
                GrantState::Revoked => Color::LightMagenta,
                GrantState::Expired => Color::DarkGray,
                _ => Color::Green,
            };
            // dst + ports on every row (the wire row carries them); denied
            // rows additionally trail their code and note.
            let dst = format!(
                "{} {}",
                g.target,
                crate::app::port_text(g.port_from, g.port_to)
            );
            let extra = match g.state {
                GrantState::Denied => format!(
                    "{}  {} {}",
                    dst,
                    g.deny_code.as_ref().map(|c| c.as_str()).unwrap_or_default(),
                    g.note.clone().unwrap_or_default()
                ),
                _ => dst,
            };
            let line = Line::from(vec![
                Span::styled(format!("{:>4} ", g.id), muted(true)),
                Span::styled(format!("{state:<8}"), Style::default().fg(color)),
                Span::raw(extra),
            ]);
            // Same rule as the live table: selection is a bg patch, not
            // REVERSED — the state span's explicit fg would swap with the
            // default bg and paint a colored box around grayed-out text.
            ListItem::new(line).style(if i == app.hist_sel {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            })
        })
        .collect();
    f.render_widget(
        List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" HISTORY · {} decided rows ", app.history.len()))
                .title_bottom(" j/k select · Esc back "),
        ),
        area,
    );
}

fn draw_net_modal(f: &mut Frame, app: &App) {
    let area = centered(f.area(), 60, 50);
    f.render_widget(Clear, area);
    let items: Vec<ListItem> = app
        .net
        .iter()
        .flat_map(|i| {
            let mut spans = vec![Span::styled(
                format!("{:<12}", i.name),
                Style::default().add_modifier(Modifier::BOLD),
            )];
            if i.default {
                spans.push(Span::styled("(default) ", Style::default().fg(Color::Cyan)));
            }
            if i.addrs.is_empty() {
                spans.push(Span::styled("no addresses", muted(true)));
            }
            let mut lines = vec![Line::from(spans)];
            for (k, a) in i.addrs.iter().enumerate() {
                let pad = if k + 1 == i.addrs.len() {
                    "  └ "
                } else {
                    "  ├ "
                };
                lines.push(Line::from(vec![
                    Span::styled(pad, muted(true)),
                    Span::raw(a.clone()),
                ]));
            }
            lines
        })
        .map(ListItem::new)
        .collect();
    let body = if app.net.is_empty() {
        List::new(vec![ListItem::new("  no non-loopback interfaces found")])
    } else {
        List::new(items)
    };
    f.render_widget(
        body.block(
            Block::default()
                .borders(Borders::ALL)
                .title(" NETWORK INTERFACES ")
                .title_bottom(" Esc back "),
        ),
        area,
    );
}

fn draw_stop_modal(f: &mut Frame, app: &App) {
    let area = centered(f.area(), 50, 30);
    f.render_widget(Clear, area);
    let body = vec![
        Line::from(""),
        Line::from(" Remove ALL live grants (baseline rules untouched)."),
        Line::from(vec![
            Span::raw(" type "),
            Span::styled("stop", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!(" to confirm: {}▏", app.stop_typed)),
        ]),
    ];
    f.render_widget(
        Paragraph::new(body).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" STOP.GRANTS ")
                .border_style(Style::default().fg(Color::Red)),
        ),
        area,
    );
}

fn draw_conn_modal(f: &mut Frame, st: ConnStatus) {
    let area = centered(f.area(), 60, 30);
    f.render_widget(Clear, area);
    let body = vec![
        Line::from(""),
        Line::from(Span::styled(
            " ⚠ lost connection to the tethysd daemon.",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(" Check its status (systemctl status tethysd)."),
        Line::from(Span::styled(
            format!(
                " retrying in background… {}",
                if st.up { "socket up" } else { "socket down" }
            ),
            muted(true),
        )),
    ];
    f.render_widget(
        Paragraph::new(body).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" DISCONNECTED ")
                .border_style(Style::default().fg(Color::Red)),
        ),
        area,
    );
}

/// ASYNCBLOCK-002: header identity facts are read once and cached, because
/// the render path must not touch /proc every 500 ms tick/keypress/event.
fn hostname() -> &'static str {
    static HOST: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HOST.get_or_init(|| {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "?".into())
    })
}

/// The header shows the host address an operator is talking to: the
/// default-route interface's address (not its subnet), preferring its
/// global IPv4, falling back to any address on it, then to just the name.
/// Cached like hostname(); a mid-session interface change is cosmetic
/// here.
fn primary_ip() -> &'static str {
    static NET: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    NET.get_or_init(compute_primary_ip)
}

fn compute_primary_ip() -> String {
    let Some(iface) = default_iface() else {
        return "-".into();
    };
    let ifaddrs = match if_addrs::get_if_addrs() {
        Ok(v) => v,
        Err(_) => return iface,
    };
    let mut fallback: Option<String> = None;
    for a in &ifaddrs {
        if a.name != iface {
            continue;
        }
        match a.ip() {
            std::net::IpAddr::V4(v4) => {
                if !v4.is_loopback() && !v4.is_link_local() {
                    return v4.to_string();
                }
                fallback.get_or_insert_with(|| v4.to_string());
            }
            v6 => {
                fallback.get_or_insert_with(|| v6.to_string());
            }
        }
    }
    fallback.unwrap_or(iface)
}

/// Interface carrying the default route, from /proc/net/route (hex LE).
/// Columns: Iface Dst GW Flags RefCnt Use Metric Mask ...; the default
/// route is the row whose Dst is all zeros. Shared by the header and the
/// net modal's "(default)" marker.
pub fn default_iface() -> Option<String> {
    let rt = std::fs::read_to_string("/proc/net/route").ok()?;
    rt.lines()
        .skip(1)
        .map(|l| l.split_whitespace().collect::<Vec<_>>())
        .find(|c| c.len() >= 8 && c[1] == "00000000")
        .map(|c| c[0].to_string())
}

/// All non-loopback interfaces with their addresses, snapshot on open.
pub fn collect_ifaces() -> Vec<crate::app::NetIface> {
    let def = default_iface();
    let mut order: Vec<String> = Vec::new();
    let mut addrs: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    if let Ok(list) = if_addrs::get_if_addrs() {
        for a in list {
            if a.is_loopback() || a.name == "lo" {
                continue;
            }
            let (ip, bits) = match &a.addr {
                if_addrs::IfAddr::V4(v4) => (std::net::IpAddr::V4(v4.ip), v4.prefixlen),
                if_addrs::IfAddr::V6(v6) => (std::net::IpAddr::V6(v6.ip), v6.prefixlen),
            };
            if !addrs.contains_key(&a.name) {
                order.push(a.name.clone());
            }
            addrs.entry(a.name.clone()).or_default().push(if bits > 0 {
                format!("{ip}/{bits}")
            } else {
                ip.to_string()
            });
        }
    }
    order
        .into_iter()
        .map(|name| crate::app::NetIface {
            default: def.as_deref() == Some(name.as_str()),
            addrs: addrs.remove(&name).unwrap_or_default(),
            name,
        })
        .collect()
}

// ------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{App, LiveRow};
    use ratatui::{backend::TestBackend, Terminal};

    fn row(id: i64, tool: &str, dst: &[&str], reason: &str) -> LiveRow {
        LiveRow {
            id,
            target: "host:mcp.jina.ai".into(),
            dst: dst.iter().map(|s| s.to_string()).collect(),
            ports: "443".into(),
            proto: "tcp".into(),
            ttl_secs: 3600,
            reason: reason.into(),
            tool: tool.into(),
            left: Some(61),
            bytes_up: Some(1234),
            bytes_down: Some(98765),
        }
    }

    fn sample_app() -> App {
        let mut app = App::new();
        app.live.insert(
            1,
            row(
                1,
                "hermes-agent",
                &["104.26.10.242", "104.26.11.242", "172.67.70.54"],
                "restore jina MCP web tools (search/read) for agent session",
            ),
        );
        app.live.insert(
            2,
            row(2, "curl", &["93.184.216.34"], "fetch payload for analysis"),
        );
        app.now = 1;
        app
    }

    /// Render the whole UI at w×h and return the drawn frame lines.
    fn render(w: u16, h: u16) -> Vec<String> {
        let app = sample_app();
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        let st = ConnStatus {
            up: true,
            synced: true,
        };
        terminal.draw(|f| draw(f, &app, st)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .chunks(w as usize)
            .map(|row| row.iter().map(|c| c.symbol()).collect::<String>())
            .collect()
    }

    // At wide sizes every fact renders intact (full first IP, +N for the
    // rest, no mid-address comma clip) and the reason shows whole.
    #[test]
    fn wide_frame_has_no_clipped_facts_and_roomy_reason() {
        let lines = render(140, 14);
        let body = lines.join("\n");
        assert!(
            body.contains("104.26.10.242 +2"),
            "dst summary missing:\n{body}"
        );
        assert!(body.contains("93.184.216.34"));
        assert!(body.contains("restore jina MCP web tools (search/read) for agent session"));
    }

    // At medium width the fixed facts stay complete and the reason
    // ellipsizes rather than wrapping to a second line.
    #[test]
    fn medium_yields_reason_first() {
        let lines = render(90, 14);
        let body = lines.join("\n");
        assert!(body.contains("104.26.10.242 +2"));
        assert!(body.contains("93.184.216.34"));
        assert!(body.contains("hermes-agent"));
        let rline = lines.iter().find(|l| l.contains("restore")).unwrap();
        assert!(rline.contains('…'), "reason should ellipsize:\n{rline}");
    }

    // At tiny width rows go two lines tall: fixed columns stay readable and
    // the reason appears as a full-width continuation line.
    #[test]
    fn tiny_wraps_rows_to_two_lines() {
        let lines = render(40, 14);
        let body = lines.join("\n");
        assert!(
            body.contains("93.184.216.34"),
            "facts must stay complete:\n{body}"
        );
        assert!(
            body.contains("↳ fetch payload for analysis"),
            "missing wrap line:\n{body}"
        );
        assert!(body.contains("↳ restore jina MCP web tools"));
    }

    // The resolved-IPs annotation must wrap into view at narrow widths, not
    // clip away behind a long installed-address list.
    #[test]
    fn detail_modal_annotation_survives_narrow_width() {
        let mut app = sample_app();
        app.modal = Modal::Detail(1);
        app.live
            .get_mut(&1)
            .unwrap()
            .dst
            .push("2606:4700:20::681a:af2".into());
        let mut terminal = Terminal::new(TestBackend::new(56, 16)).unwrap();
        let st = ConnStatus {
            up: true,
            synced: true,
        };
        terminal.draw(|f| draw(f, &app, st)).unwrap();
        let body: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(
            body.contains("IP addresses resolved from hostname"),
            "annotation must wrap, not clip:\n{body}"
        );
    }

    // The row TTL dot must carry its color as the glyph foreground, and the
    // selected-row highlight must NOT use REVERSED: the dot span sets an
    // explicit fg while the selection line sets an explicit bg, so a
    // terminal-level fg/bg swap would show a gray dot on a green box. The
    // buffer records patched styles, so asserting "no REVERSED on selected
    // cells" catches the regression even though the swap itself happens in
    // the terminal.
    #[test]
    fn ttl_dot_is_foreground_colored_including_selected_row() {
        use ratatui::style::{Color, Modifier};
        let mut app = sample_app();
        // sort desc by left => row 2 (left=61, LightRed) is selected first
        app.sort_asc = false;
        let mut terminal = Terminal::new(TestBackend::new(140, 14)).unwrap();
        let st = ConnStatus {
            up: true,
            synced: true,
        };
        terminal.draw(|f| draw(f, &app, st)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let dots: Vec<_> = buf
            .content()
            .iter()
            // both rows have left=61 of ttl 3600 (<25%) => LightRed; the
            // header's ●conn dot is Green, so color filters it out
            .filter(|c| c.symbol() == "●" && c.style().fg == Some(Color::LightRed))
            .collect();
        assert_eq!(dots.len(), 2, "both live rows carry a status dot");
        for d in &dots {
            assert!(
                matches!(d.style().fg, Some(Color::Green) | Some(Color::LightRed)),
                "dot glyph must be colorized via fg, got {:?}",
                d.style()
            );
            assert!(
                !d.style().add_modifier.contains(Modifier::REVERSED),
                "selected-row highlight must not REVERSE (would gray the dot), got {:?}",
                d.style()
            );
        }
        // selected row's dot: still a green-family glyph fg, not greyed out
        assert_eq!(dots[0].style().fg, Some(Color::LightRed));
    }

    // Render across a grid of extreme terminal sizes without panicking.
    #[test]
    fn never_panics_at_degenerate_sizes() {
        for w in [8u16, 12, 20, 33, 47, 63, 100, 220] {
            for h in [5u16, 7, 9, 13, 30] {
                let _ = render(w, h);
            }
        }
    }

    #[test]
    fn wrap_words_breaks_at_spaces_never_mid_word() {
        let l = wrap_words("restore jina MCP web tools for the agent session", 20);
        assert!(l.iter().all(|s| dw(s) <= 20));
        assert!(l.join(" ").contains("MCP web tools"));
        // a single over-long word hard-splits instead of overflowing
        let l = wrap_words("aaaaaaaaaaaaaaaaaaaa b", 10);
        assert_eq!(dw(&l[0]), 10);
        // embedded newlines survive
        assert_eq!(
            wrap_words("a\nb", 40),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    // Live table cosmetics: alternating row backgrounds for scanability,
    // no yellow near-expiry text recolor (it fought the TTL dots), and the
    // ttl column spelled in whole minutes like the countdown beside it.
    #[test]
    fn rows_zebra_stripe_and_ttl_reads_minutes() {
        use ratatui::style::Color;
        let mut app = sample_app();
        for id in 3..=6i64 {
            app.live.insert(id, row(id, "curl", &["1.2.3.4"], "r"));
        }
        // put a row inside the old <=60s warn window; sorted asc by `left`
        // it lands first, so row 5 is exactly the row the old code painted
        // yellow.
        app.live.get_mut(&1).unwrap().left = Some(30);
        let mut terminal = Terminal::new(TestBackend::new(140, 14)).unwrap();
        let st = ConnStatus {
            up: true,
            synced: true,
        };
        terminal.draw(|f| draw(f, &app, st)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let w = 140usize;
        let cell = |x: usize, y: usize| &buf.content()[y * w + x];
        // rows start at frame row 5 (header block 3 + table border + header line)
        let bg_of = |row_y: usize| cell(60, row_y).style().bg;
        // row 5 is under the cursor (selection bg); stripes start below it
        let clear = |y: usize| matches!(bg_of(y), None | Some(Color::Reset));
        assert_eq!(bg_of(5), Some(Color::Gray), "selected row highlight");
        assert_eq!(bg_of(6), Some(Color::DarkGray), "second row stripes");
        assert!(clear(7), "third row clear again");
        assert_eq!(bg_of(8), Some(Color::DarkGray), "fourth row stripes");
        // ttl for the 3600s rows reads in minutes next to the M:SS countdown
        let line: String = (0..w).map(|x| cell(x, 6).symbol()).collect();
        assert!(
            line.contains("60m"),
            "ttl column should read minutes: {line}"
        );
        // no yellow fg text on near-expiry rows anymore (left=30 was inside
        // the old <=60s warn window; only the dots may be colored)
        for y in 5..8 {
            for x in 0..w {
                assert_ne!(
                    cell(x, y).style().fg,
                    Some(Color::Yellow),
                    "row text must not recolor"
                );
            }
        }
    }

    // History rows must carry the port spec next to the dst, for both
    // approved and denied states (the deny case trails code + note).
    #[test]
    fn history_rows_show_ports_with_dst() {
        use tethys_core::wire::{GrantRow, GrantState};
        let mut app = sample_app();
        let base = GrantRow {
            id: 9,
            idem_key: None,
            target: "host:api.jina.ai".into(),
            dst_json: "[\"ip:104.26.10.242\"]".into(),
            port_from: 443,
            port_to: 443,
            proto: tethys_core::types::Proto::Tcp,
            reason: "r".into(),
            tool: "curl".into(),
            ttl_secs: 600,
            granted_ttl_secs: Some(600),
            state: GrantState::Expired,
            created_at: 0,
            expires_at: None,
            deny_code: None,
            note: None,
        };
        app.history = vec![
            base.clone(),
            GrantRow {
                id: 10,
                target: "ip:192.168.10.2".into(),
                dst_json: "[]".into(),
                port_from: 22,
                port_to: 22,
                state: GrantState::Denied,
                deny_code: Some(tethys_core::wire::DenyCode::ApproverTimeout),
                note: Some("nope".into()),
                ..base.clone()
            },
        ];
        app.modal = Modal::History;
        let mut terminal = Terminal::new(TestBackend::new(100, 14)).unwrap();
        let st = ConnStatus {
            up: true,
            synced: true,
        };
        terminal.draw(|f| draw(f, &app, st)).unwrap();
        let body: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(
            body.contains("host:api.jina.ai 443"),
            "expired row must show dst + port:\n{body}"
        );
        assert!(
            body.contains("ip:192.168.10.2 22"),
            "denied row must show dst + port:\n{body}"
        );
    }

    #[test]
    fn ttl_override_units() {
        use crate::app::parse_ttl_override as p;
        assert_eq!(p("30"), Some(30)); // bare digits = seconds (default)
        assert_eq!(p("30s"), Some(30));
        assert_eq!(p("45m"), Some(2700));
        assert_eq!(p("2h"), Some(7200));
        assert_eq!(p("999999999999999999999h"), None); // overflow rejected
        assert_eq!(p(""), None);
        assert_eq!(p("s"), None);
        assert_eq!(p("0"), None);
        assert_eq!(p("5x"), None);
        assert_eq!(p("5m3"), None);
    }

    // The pending modal must give each grant fact its own line and wrap the
    // reason at word boundaries inside the frame — no mid-word slice at the
    // right border, no fields colliding on one line.
    #[test]
    fn pending_modal_separates_fields_and_wraps_reason() {
        use crate::app::PendingRow;
        let mut app = sample_app();
        app.pending.insert(
            7,
            PendingRow {
                target: "host:api.example.com".into(),
                ports: "443/tcp".into(),
                reason: "need this long-lived outbound access so the retrieval worker can refresh embeddings for the knowledge base index overnight".into(),
                tool: "hermes-agent".into(),
                ttl_requested: "15m".into(),
                created_at: 0,
            },
        );
        app.modal = Modal::Pending(0);
        let mut terminal = Terminal::new(TestBackend::new(72, 24)).unwrap();
        let st = ConnStatus {
            up: true,
            synced: true,
        };
        terminal.draw(|f| draw(f, &app, st)).unwrap();
        let lines: Vec<String> = terminal
            .backend()
            .buffer()
            .content()
            .chunks(72)
            .map(|r| r.iter().map(|c| c.symbol()).collect::<String>())
            .collect();
        let body = lines.join("\n");
        // The modal is drawn over the live table, so inspect the text
        // inside its left border: every cell segment after a │.
        let segs: Vec<&str> = lines.iter().flat_map(|l| l.split('│')).collect();
        // each label starts its own line
        for lbl in ["requested", "ports", "ttl requested", "reason"] {
            assert!(
                segs.iter().any(|s| s.starts_with(lbl)),
                "{lbl} should start a line:\n{body}"
            );
        }
        // ports and ttl requested no longer share a line
        assert!(
            !segs
                .iter()
                .any(|s| s.contains("ports") && s.contains("ttl requested")),
            "fields must not collide:\n{body}"
        );
        // the dst is the orientation cue: bold green text (the target has
        // three 'a's; no other modal field carries them in green)
        let dst_green = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .filter(|c| {
                c.symbol() == "a"
                    && c.style().fg == Some(Color::Green)
                    && c.style().add_modifier.contains(Modifier::BOLD)
            })
            .count();
        assert!(dst_green >= 3, "dst must render bold green");
        // the reason wrapped at spaces inside the frame: continuation lines
        // are indented under the label, and the tail is visible whole.
        let ridx = lines
            .iter()
            .position(|l| l.split('│').any(|s| s.starts_with("reason")))
            .unwrap();
        assert!(lines[ridx].contains("long-lived"));
        let cont = lines[ridx + 1]
            .split('│')
            .find(|s| s.starts_with(" ") && s.trim_start().starts_with("access"))
            .unwrap_or("");
        assert!(
            cont.trim_start().starts_with("access"),
            "reason continuation must be indented under the label, got {cont:?}:\n{body}"
        );
        // no word sliced at the border, nothing clipped: reassembling the
        // modal's reason block from the buffer must reproduce it exactly.
        let mut got = String::new();
        for l in &lines[ridx..] {
            let inside = l.split('│').nth(2).unwrap_or("").trim();
            if inside.is_empty() {
                break;
            }
            let val = inside.strip_prefix("reason").unwrap_or(inside).trim();
            got.push_str(val);
            got.push(' ');
        }
        assert_eq!(
            got.trim(),
            "need this long-lived outbound access so the retrieval worker \
             can refresh embeddings for the knowledge base index overnight"
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
            "reason must render whole, word-wrapped:\n{body}"
        );
    }
}
