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
            Constraint::Length(3), // header (2 lines)
            Constraint::Min(3),    // live table
            Constraint::Length(1), // keybar
        ])
        .split(f.area());

    draw_header(f, app, st, rows[0]);
    draw_table(f, app, rows[1]);
    draw_keybar(f, app, rows[2]);

    match &app.modal {
        Modal::Pending(i) => draw_pending_modal(f, app, *i),
        Modal::Detail(id) => draw_detail_modal(f, app, *id),
        Modal::History => draw_history_modal(f, app),
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

fn draw_header(f: &mut Frame, app: &App, st: ConnStatus, a: Rect) {
    let host = hostname();
    let conn = if !st.up {
        Span::styled(" ○reconnecting", Style::default().fg(Color::Red))
    } else if !st.synced {
        Span::styled(" ●syncing…", Style::default().fg(Color::Yellow))
    } else {
        Span::styled(" ●conn", Style::default().fg(Color::Green))
    };
    let net = primary_network();
    let l1 = Line::from(vec![
        Span::styled(
            format!(" gatekeeper @ {host} ─ {net} ─ "),
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
    ]);

    let sort_span = Span::styled(
        format!(
            " sort: {}{}  ",
            app.sort.header(),
            if app.sort_asc { " ▲" } else { " ▼" }
        ),
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
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
// its second line — Table clamps every cell to its column, which makes true
// two-line rows impossible at narrow widths.
//
// Width policy (columns: 8 fixed facts + elastic `reason`). Fixed columns
// NEVER clip on a single line — `reason` absorbs every pixel of shrinkage:
//   1. roomy   — fixed cols at natural width (widest value/header); once
//      reason has a comfortable slice, surplus grows the inter-column gap
//      toward GAP_MAX ("ample padding" on big screens), then keeps feeding
//      reason.
//   2. tight   — reason gets the remainder and ellipsizes; facts complete.
//   3. cramped — remainder < REASON_MIN: rows go two lines tall. Line 1 =
//      fixed cols at natural width, packed greedily (rightmost drop first);
//      line 2 = `↳ <reason>` across the full inner width.

const GAP_MIN: u16 = 1;
const GAP_MAX: u16 = 4;
/// Smallest slice worth giving reason on a single line; below this, wrap.
const REASON_MIN: u16 = 8;
const HEADERS: [&str; 8] = ["id", "tool", "dst", "ports", "proto", "ttl", "left", "\u{2195}B"];

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
fn natural_widths(rows: &[RowCells]) -> [u16; 8] {
    let mut w = HEADERS.map(|h| dw(h) as u16);
    for c in rows {
        for (i, v) in c.vals.iter().enumerate() {
            w[i] = w[i].max(dw(v) as u16);
        }
    }
    for i in 0..8 {
        w[i] = w[i].clamp(dw(HEADERS[i]) as u16, 39);
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

fn draw_table(f: &mut Frame, app: &App, a: Rect) {
    let dim = !app_conn_live(app);
    let title = if dim { " LIVE (stale — no daemon) " } else { " LIVE " };
    let inner = Block::default().borders(Borders::ALL).title(title).inner(a);
    f.render_widget(Block::default().borders(Borders::ALL).title(title), a);
    if inner.width < 8 || inner.height == 0 {
        return;
    }

    let rows: Vec<RowCells> = app.sorted_live().iter().map(|r| cells_for(r)).collect();
    let sel_row = app.sel.min(app.live.len().saturating_sub(1));

    // ---- width plan ------------------------------------------------------
    let mut fw = natural_widths(&rows);
    let fixed_nat: u16 = fw.iter().sum();
    // gaps widen only while every visible reason still fits whole; a reason
    // that would clip pulls gaps back to GAP_MIN before it loses a character
    let need_reason = rows
        .iter()
        .map(|c| dw(&c.reason) as u16)
        .max()
        .unwrap_or(6)
        .max(6); // "reason" header
    let surplus = inner.width.saturating_sub(fixed_nat + need_reason + GAP_MIN * 8);
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
    let body_h = inner.height.saturating_sub(1); // header row
    let visible = (body_h / line_h).max(1) as usize;
    // keep the selected row inside the visible window
    let start = sel_row.saturating_sub(visible.saturating_sub(1));

    // ---- emit a padded cell row (fixed cols + optional reason) -----------
    let gap_s = " ".repeat(gap_used(inner, gap, wrap) as usize);
    let mk = |vals: &mut Vec<Span<'_>>, v: &[String; 8], style: Style| {
        for (i, s) in v.iter().take(kept).enumerate() {
            vals.push(Span::styled(
                format!("{}{}", fit(s, fw[i] as usize), gap_s.as_str()),
                style,
            ));
        }
    };

    // ---- header ----------------------------------------------------------
    let mut hdr: Vec<Span> = Vec::with_capacity(9);
    mk(&mut hdr, &HEADERS.map(|h| h.to_string()).clone(), muted(dim));
    if !wrap {
        hdr.push(Span::styled(truncate("reason", reason_w as usize), muted(dim)));
    }
    f.render_widget(Paragraph::new(Line::from(hdr)), inner);

    // ---- body ------------------------------------------------------------
    let body = Rect { y: inner.y + 1, height: body_h, ..inner };
    let mut lines: Vec<Line> = Vec::with_capacity(visible * line_h as usize);
    for (i, c) in rows.iter().skip(start).take(visible).enumerate() {
        let base = c.warn.patch(muted(dim));
        let style = if start + i == sel_row && !dim {
            base.add_modifier(Modifier::REVERSED).bg(Color::DarkGray)
        } else {
            base
        };
        let mut spans: Vec<Span> = Vec::with_capacity(9);
        mk(&mut spans, &c.vals, Style::default());
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
            Rect { x: nx, width: note.len() as u16, height: 1, ..inner },
        );
    }
}

/// gap actually used between columns (two-line plan is always GAP_MIN)
fn gap_used(_inner: Rect, gap: u16, wrap: bool) -> u16 {
    if wrap { GAP_MIN } else { gap }
}

fn app_conn_live(_app: &App) -> bool {
    true
}

fn draw_keybar(f: &mut Frame, app: &App, a: Rect) {
    let keys = match &app.modal {
        Modal::None => "j/k select · Enter detail · e revoke · d history · ! stop all · q quit",
        Modal::Pending(_) => {
            if app.deny_note.is_some() {
                "type deny note · Enter send · Esc deny-empty"
            } else {
                "a approve · d deny+note · t edit ttl · n next pending · Esc dismiss (stays queued)"
            }
        }
        Modal::Detail(_) => "e revoke · Esc back",
        Modal::History => "j/k select · r re-load · Esc back",
        Modal::ConfirmStop => "type `stop` + Enter to confirm · any other key cancels",
        Modal::ConnLost => "retrying automatically · Esc to view stale state",
    };
    f.render_widget(Paragraph::new(Line::from(Span::styled(format!(" {keys}"), muted(true)))), a);
}

// ------------------------------------------------------------------ modals

fn centered(a: Rect, w_pct: u16, h_pct: u16) -> Rect {
    let v = Layout::vertical([Constraint::Percentage(h_pct)]).flex(ratatui::layout::Flex::Center).split(a);
    let h = Layout::horizontal([Constraint::Percentage(w_pct)]).flex(ratatui::layout::Flex::Center).split(v[0]);
    h[0]
}

fn draw_pending_modal(f: &mut Frame, app: &App, idx: usize) {
    let ids = app.pending_ids();
    let Some(id) = ids.get(idx).copied() else { return };
    let Some(p) = app.pending.get(&id) else { return };
    let area = centered(f.area(), 70, 60);
    f.render_widget(Clear, area);

    let waiting = app.now.saturating_sub(p.created_at);
    let mut title = format!(" REQUEST {id} · {} · waiting {}:{:02} ", p.tool, waiting / 60, waiting % 60);
    // countdown to daemon auto-deny (approver_timeout_secs from subscribe ack)
    if let Some(to) = app.timeout_secs {
        let left = to.saturating_sub(waiting);
        // bar fills as the deadline approaches; number is time REMAINING
        let filled = (waiting.min(to) as usize * 20 / to.max(1) as usize).min(20);
        title.push_str(&format!(
            "· auto-deny in {:>3}s [{}{}] ",
            left,
            "█".repeat(filled),
            "░".repeat(20 - filled)
        ));
    }

    let lines = vec![
        Line::from(vec![Span::styled(" requested  ", muted(true)), Span::raw(&p.target)]),
        Line::from(vec![
            Span::styled(" ports       ", muted(true)),
            Span::raw(p.ports.clone()),
            Span::styled("     ttl req ", muted(true)),
            Span::raw(p.ttl_requested.clone()),
        ]),
    ];
    let reason = Paragraph::new(p.reason.clone()).wrap(Wrap { trim: false });
    let ra = Rect { x: area.x + 2, y: area.y + 4, width: area.width.saturating_sub(4), height: 3 };
    f.render_widget(reason, ra);

    let mut action_spans = vec![
        Span::styled(" [a]pprove", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
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

fn draw_detail_modal(f: &mut Frame, app: &App, id: i64) {
    let Some(r) = app.live.get(&id) else { return };
    let area = centered(f.area(), 80, 55);
    f.render_widget(Clear, area);
    let differs = r.dst.iter().any(|d| !r.target.ends_with(d.as_str()));
    let mut lines = vec![
        Line::from(vec![Span::styled(" requested   ", muted(true)), Span::raw(r.target.clone())]),
        Line::from(vec![
            Span::styled(" installed   ", muted(true)),
            Span::raw(r.dst.join(", ")),
            if differs {
                Span::styled("   ⚠️ IP addresses resolved from hostname", Style::default().fg(Color::Yellow))
            } else {
                Span::raw("")
            },
        ]),
        Line::from(vec![
            Span::styled(" ports/proto ", muted(true)),
            Span::raw(format!("{}  {}   ttl granted {}", r.ports, r.proto, fmt_ttl_secs(r.ttl_secs))),
        ]),
        Line::from(vec![Span::styled(" reason      ", muted(true)), Span::raw(r.reason.clone())]),
        Line::from(vec![Span::styled(" traffic     ", muted(true)), Span::raw(format!(
            "↑ {} B   ↓ {} B   left {}",
            fmt_bytes(r.bytes_up.unwrap_or(0)),
            fmt_bytes(r.bytes_down.unwrap_or(0)),
            fmt_countdown(r.left)
        ))]),
    ];
    lines.push(Line::from(""));
    f.render_widget(
        Paragraph::new(lines)
            // long installed-address lists must not clip the "⚠ IP addresses
            // resolved from hostname" annotation — let lines wrap instead
            .wrap(Wrap { trim: false })
            .block(
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
            use gk_core::wire::GrantState;
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
            ListItem::new(line).style(if i == app.hist_sel {
                Style::default().add_modifier(Modifier::REVERSED)
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
            " ⚠ lost connection to the gatekeeper daemon.",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(" Check its status (systemctl status gatekeeper)."),
        Line::from(Span::styled(
            format!(" retrying in background… {}", if st.up { "socket up" } else { "socket down" }),
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

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".into())
}

/// Default-route interface and its subnet from /proc/net/route (hex LE).
fn primary_network() -> String {
    // /proc/net/route columns: Iface Dst GW Flags RefCnt Use Metric Mask ...
    // The default route (Dst=0) carries mask 0 — useless. The interface's
    // subnet lives in the ON-LINK route for the same iface (GW=0, real mask).
    let rt = match std::fs::read_to_string("/proc/net/route") {
        Ok(s) => s,
        Err(_) => return "-".into(),
    };
    let lines: Vec<Vec<&str>> =
        rt.lines().skip(1).map(|l| l.split_whitespace().collect()).collect();
    let def_iface = lines
        .iter()
        .find(|c| c.len() >= 8 && c[1] == "00000000")
        .map(|c| c[0]);
    let Some(iface) = def_iface else { return "-".into() };
    for c in &lines {
        if c.len() >= 8 && c[0] == iface && c[1] != "00000000" && c[2] == "00000000" {
            let dst = unhex_le(c[1]);
            let mask = unhex_le(c[7]);
            if mask != 0 {
                let ip = |w: u32| format!("{}.{}.{}.{}", w >> 24, (w >> 16) & 255, (w >> 8) & 255, w & 255);
                return format!("{} {}/{}", iface, ip(dst & mask), mask.count_ones());
            }
        }
    }
    iface.to_string()
}

fn unhex_le(h: &str) -> u32 {
    u32::from_str_radix(h, 16).map(u32::from_be).unwrap_or(0)
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
            row(1, "hermes-agent", &["104.26.10.242", "104.26.11.242", "172.67.70.54"],
                "restore jina MCP web tools (search/read) for agent session"),
        );
        app.live.insert(2, row(2, "curl", &["93.184.216.34"], "fetch payload for analysis"));
        app.now = 1;
        app
    }

    /// Render the whole UI at w×h and return the drawn frame lines.
    fn render(w: u16, h: u16) -> Vec<String> {
        let app = sample_app();
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        let st = ConnStatus { up: true, synced: true };
        terminal.draw(|f| draw(f, &app, st)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .chunks(w as usize)
            .map(|row| row.iter().map(|c| c.symbol()).collect::<String>())
            .collect()
    }

    #[test]
    fn wide_frame_has_no_clipped_facts_and_roomy_reason() {
        let lines = render(140, 14);
        let body = lines.join("\n");
        // facts intact: full first IP, +N for the rest, no mid-address comma clip
        assert!(body.contains("104.26.10.242 +2"), "dst summary missing:\n{body}");
        assert!(body.contains("93.184.216.34"));
        // reason fully visible at wide size
        assert!(body.contains("restore jina MCP web tools (search/read) for agent session"));
    }

    #[test]
    fn medium_yields_reason_first() {
        let lines = render(90, 14);
        let body = lines.join("\n");
        // fixed facts still complete at this width
        assert!(body.contains("104.26.10.242 +2"));
        assert!(body.contains("93.184.216.34"));
        assert!(body.contains("hermes-agent"));
        // reason is ellipsized, not wrapped away
        let rline = lines.iter().find(|l| l.contains("restore")).unwrap();
        assert!(rline.contains('…'), "reason should ellipsize:\n{rline}");
    }

    #[test]
    fn tiny_wraps_rows_to_two_lines() {
        let lines = render(40, 14);
        let body = lines.join("\n");
        // fixed columns still readable
        assert!(body.contains("93.184.216.34"), "facts must stay complete:\n{body}");
        // reason appears as full-width continuation lines
        assert!(body.contains("↳ fetch payload for analysis"), "missing wrap line:\n{body}");
        assert!(body.contains("↳ restore jina MCP web tools"));
    }

    #[test]
    fn detail_modal_annotation_survives_narrow_width() {
        let mut app = sample_app();
        app.modal = Modal::Detail(1); // 6-dst-style row: target host, differs
        app.live.get_mut(&1).unwrap().dst.push("2606:4700:20::681a:af2".into());
        let mut terminal = Terminal::new(TestBackend::new(56, 16)).unwrap();
        let st = ConnStatus { up: true, synced: true };
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

    #[test]
    fn dump_frames() {
        if std::env::var("GK_DUMP").is_ok() {
            for (w, h) in [(120u16, 10u16), (90, 10), (64, 12), (40, 12)] {
                println!("===== {w}x{h} =====");
                for l in render(w, h) {
                    println!("|{l}|");
                }
            }
        }
    }

    #[test]
    fn never_panics_at_degenerate_sizes() {
        for w in [8u16, 12, 20, 33, 47, 63, 100, 220] {
            for h in [5u16, 7, 9, 13, 30] {
                let _ = render(w, h);
            }
        }
    }
}

