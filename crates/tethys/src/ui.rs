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

use crate::app::{fmt_bytes, fmt_countdown, fmt_ttl_secs, App, Modal, COLS};
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
    warn: Style,
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
    let warn = match r.left {
        Some(s) if s <= 60 => Style::default().fg(Color::Yellow),
        _ => Style::default(),
    };
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
            fmt_ttl_secs(r.ttl_secs),
            fmt_countdown(r.left),
            traffic,
        ],
        reason: r.reason.clone(),
        warn,
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
        let need = if kept == 0 { nat[i] } else { nat[i] + GAP_MIN };
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
        .saturating_sub(fixed_nat + need_reason + GAP_MIN * 8);
    let gap = (GAP_MIN + surplus / 8).clamp(GAP_MIN, GAP_MAX);
    let reason_w = inner.width.saturating_sub(fixed_nat + gap * 8);

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

    let gap_s = " ".repeat(gap_used(inner, gap, wrap) as usize);
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
                        gap_s.as_str()
                    ),
                    style,
                ));
                continue;
            }
            vals.push(Span::styled(
                format!("{}{}", fit(s, fw[i] as usize), gap_s.as_str()),
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
        let base = c.warn.patch(muted(dim));
        // Selection highlight is bg-only, deliberately NOT REVERSED: the
        // TTL dot sets an explicit fg and the line sets an explicit bg, so
        // a terminal-level fg/bg swap would render the dot as a gray glyph
        // on a green box (text cells hide the swap by keeping default fg).
        let style = if start + i == sel_row && !dim {
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
                "a approve · d deny+note · t edit ttl · n next pending · Esc dismiss (stays queued)"
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
fn draw_pending_modal(f: &mut Frame, app: &App, idx: usize) {
    let ids = app.pending_ids();
    let Some(id) = ids.get(idx).copied() else {
        return;
    };
    let Some(p) = app.pending.get(&id) else {
        return;
    };
    let area = centered(f.area(), 70, 60);
    f.render_widget(Clear, area);

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

    let lines = vec![
        Line::from(vec![
            Span::styled(" requested  ", muted(true)),
            Span::raw(&p.target),
        ]),
        Line::from(vec![
            Span::styled(" ports       ", muted(true)),
            Span::raw(p.ports.clone()),
            Span::styled("     ttl req ", muted(true)),
            Span::raw(p.ttl_requested.clone()),
        ]),
    ];
    let reason = Paragraph::new(p.reason.clone()).wrap(Wrap { trim: false });
    let ra = Rect {
        x: area.x + 2,
        y: area.y + 4,
        width: area.width.saturating_sub(4),
        height: 3,
    };
    f.render_widget(reason, ra);

    let mut action_spans = vec![
        Span::styled(
            " [a]pprove",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("   [d]eny+note", Style::default().fg(Color::Red)),
        Span::styled("   [t]tl→__", Style::default().fg(Color::Cyan)),
    ];
    if let Some(t) = &app.ttl_edit {
        action_spans.push(Span::raw(format!("  ttl={t}")));
    }
    if ids.len() > 1 {
        action_spans.push(Span::styled(
            format!("   [n]ext {}/{}", idx + 1, ids.len()),
            muted(false),
        ));
    }
    action_spans.push(Span::styled("   [Esc]close", muted(true)));

    let mut body: Vec<Line> = lines;
    body.push(Line::from(""));
    body.push(Line::from("")); // room for wrapped reason above
    if let Some(note) = &app.deny_note {
        body.push(Line::from(vec![
            Span::styled(" note  ", Style::default().fg(Color::Red)),
            Span::raw(format!("{note}▏")),
        ]));
    }
    body.push(Line::from(action_spans));
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
            Span::raw(r.target.clone()),
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
            let extra = match g.state {
                GrantState::Denied => format!(
                    "{} {}",
                    g.deny_code.as_ref().map(|c| c.as_str()).unwrap_or_default(),
                    g.note.clone().unwrap_or_default()
                ),
                _ => g.target.clone(),
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
}
