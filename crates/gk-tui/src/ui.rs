//! Rendering. Pure read of App state; no mutation, no I/O.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};

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

fn draw_table(f: &mut Frame, app: &App, a: Rect) {
    let dim = !app_conn_live(app);
    let widths = [
        Constraint::Length(4),  // id
        Constraint::Length(8),  // tool
        Constraint::Length(17), // dst
        Constraint::Length(10), // ports
        Constraint::Length(5),  // proto
        Constraint::Length(5),  // ttl
        Constraint::Length(6),  // left
        Constraint::Length(9),  // bytes
        Constraint::Min(8),     // reason — yields first, benefits last
    ];
    let header = Row::new(COLS.iter().map(|c| Cell::from(c.header()))).style(muted(dim));

    let rows: Vec<Row> = app
        .sorted_live()
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            let left = fmt_countdown(r.left);
            // urgency tint as the countdown runs out (kernel truth)
            let warn = match r.left {
                Some(s) if s <= 60 => Style::default().fg(Color::Yellow),
                _ => Style::default(),
            };
            let up = r.bytes_up.unwrap_or(0);
            let down = r.bytes_down.unwrap_or(0);
            let traffic = format!(
                "{}{}",
                if up > 0 { format!("↑{}", fmt_bytes(up)) } else { String::new() },
                if down > 0 {
                    format!("↓{}", fmt_bytes(down))
                } else if up == 0 {
                    "·".into()
                } else {
                    String::new()
                }
            );
            let dst = r.dst.join(",");
            let differs = !r.dst.is_empty()
                && !r.target.starts_with("ip:")
                && !r.target.starts_with("net:")
                || (r.dst.len() > 1);
            let dst_cell = if differs && r.target.contains(':') {
                format!("{dst} ≠")
            } else {
                dst
            };
            Row::new(vec![
                Cell::from(r.id.to_string()),
                Cell::from(r.tool.clone()),
                Cell::from(dst_cell),
                Cell::from(r.ports.clone()),
                Cell::from(r.proto.clone()),
                Cell::from(fmt_ttl_secs(r.ttl_secs)),
                Cell::from(left),
                Cell::from(traffic),
                Cell::from(r.reason.clone()),
            ])
            .style(if i == app.sel && !dim {
                warn.patch(muted(dim)).add_modifier(Modifier::BOLD)
            } else {
                warn.patch(muted(dim))
            })
        })
        .collect();

    let mut ts = TableState::default().with_selected(if app.live.is_empty() {
        None
    } else {
        Some(app.sel.min(app.live.len().saturating_sub(1)))
    });
    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::REVERSED),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(if dim { " LIVE (stale — no daemon) " } else { " LIVE " }),
        );
    f.render_stateful_widget(table, a, &mut ts);
}

fn app_conn_live(_app: &App) -> bool {
    true // placeholder; staleness handled via ConnStatus at draw entry
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
                Span::styled("   ≠ resolved at approval time", Style::default().fg(Color::Yellow))
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
        Paragraph::new(lines).block(
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
            let state = g["state"].as_str().unwrap_or("?");
            let color = match state {
                "denied" => Color::Red,
                "revoked" => Color::LightMagenta,
                "expired" => Color::DarkGray,
                _ => Color::Green,
            };
            let id = g["id"].as_i64().unwrap_or(0);
            let extra = match state {
                "denied" => format!(
                    "{} {}",
                    g["deny_code"].as_str().unwrap_or(""),
                    g["note"].as_str().unwrap_or("")
                ),
                _ => g["target"].as_str().unwrap_or("").to_string(),
            };
            let line = Line::from(vec![
                Span::styled(format!("{id:>4} "), muted(true)),
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

/// Best-effort "primary network": default-route interface + its subnet from
/// /proc/net/route (destination/mask, hex LE). Never claims more than it read.
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

