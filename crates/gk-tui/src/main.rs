//! gk-tui: the human approver's control plane. ratatui frontend over the
//! admin socket; all daemon interaction via conn.rs, all state in app.rs.

mod app;
mod conn;
mod ui;

use std::io;
use std::path::PathBuf;

use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use tokio::sync::mpsc;

use app::{App, Modal, COLS};

#[derive(Parser)]
#[command(name = "gk-tui", about = "gatekeeper approver TUI")]
struct Args {
    #[arg(long, default_value = "/run/gatekeeper/admin.sock")]
    socket: PathBuf,
}

type Tx = mpsc::UnboundedSender<conn::Cmd>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    // Keyboard only: mouse capture would steal terminal text selection.
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let res = run(&mut terminal, args.socket).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    res
}

async fn run(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    socket: PathBuf,
) -> anyhow::Result<()> {
    let (mut cmd_tx, mut ev_rx, mut status_rx) = conn::spawn(socket);
    let mut app = App::new();
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(500));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // event::read() blocks; shuttle keys on a thread so the select loop stays live.
    let (key_tx, mut key_rx) = mpsc::unbounded_channel::<Event>();
    std::thread::spawn(move || {
        while let Ok(ev) = event::read() {
            if key_tx.send(ev).is_err() {
                break; // UI gone
            }
        }
    });

    // the conn-lost modal opens once per outage, not on every failed poll
    let mut lost_modal_shown = false;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                app.now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if let Some((_, at)) = &app.flash {
                    if at.elapsed().as_secs() > 6 {
                        app.flash = None;
                    }
                }
                let st = *status_rx.borrow_and_update();
                if !st.up && !lost_modal_shown {
                    app.modal = Modal::ConnLost;
                    lost_modal_shown = true;
                }
                if st.up && matches!(app.modal, Modal::ConnLost) {
                    app.modal = Modal::None;
                    lost_modal_shown = false;
                }
                if !st.up {
                    lost_modal_shown = true;
                }
                terminal.draw(|f| ui::draw(f, &app, st))?;
            }
            ev = ev_rx.recv() => {
                match ev {
                    Some(v) => {
                        let mut out = Vec::new();
                        app.on_line(&v, &mut out);
                        if !flush(&mut cmd_tx, out) { break; }
                        let st = *status_rx.borrow();
                        terminal.draw(|f| ui::draw(f, &app, st))?;
                    }
                    None => break, // conn task ended
                }
            }
            Some(ev) = key_rx.recv() => {
                if let Event::Key(k) = ev {
                    if k.kind == KeyEventKind::Press {
                        let mut out = Vec::new();
                        let quit = handle_key(&mut app, k, &mut out);
                        if !flush(&mut cmd_tx, out) || quit {
                            break;
                        }
                        let st = *status_rx.borrow();
                        terminal.draw(|f| ui::draw(f, &app, st))?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Push queued commands to the conn task; false when the task is gone.
fn flush(tx: &mut Tx, cmds: Vec<conn::Cmd>) -> bool {
    for c in cmds {
        if tx.send(c).is_err() {
            return false;
        }
    }
    true
}

/// Returns true to exit.
fn handle_key(app: &mut App, k: event::KeyEvent, out: &mut Vec<conn::Cmd>) -> bool {
    if k.modifiers.contains(KeyModifiers::CONTROL) && matches!(k.code, KeyCode::Char('c')) {
        return true;
    }
    match &app.modal {
        Modal::None => key_table(app, k, out),
        Modal::Pending(_) => key_pending(app, k, out),
        Modal::Detail(_) => key_detail(app, k, out),
        Modal::History => {
            key_history(app, k, out);
            false
        }
        Modal::ConfirmStop => {
            key_stop(app, k, out);
            false
        }
        Modal::ConnLost => {
            if matches!(k.code, KeyCode::Esc) {
                app.modal = Modal::None; // view stale table meanwhile
            }
            false
        }
    }
}

fn key_table(app: &mut App, k: event::KeyEvent, out: &mut Vec<conn::Cmd>) -> bool {
    match k.code {
        KeyCode::Char('q') => return true,
        KeyCode::Char('j') | KeyCode::Down => {
            app.sel = (app.sel + 1).min(app.live.len().saturating_sub(1));
        }
        KeyCode::Char('k') | KeyCode::Up => app.sel = app.sel.saturating_sub(1),
        KeyCode::Enter => {
            if let Some(id) = app.focused_live() {
                app.modal = Modal::Detail(id);
            }
        }
        KeyCode::Char('e') => app.revoke_focused(out),
        KeyCode::Char('d') => app.open_history(out),
        KeyCode::Char('!') => {
            app.stop_typed.clear();
            app.modal = Modal::ConfirmStop;
        }
        KeyCode::Char('P') => {
            if !app.pending.is_empty() {
                app.modal = Modal::Pending(0);
                app.deny_note = None;
                app.ttl_edit = None;
            }
        }
        // sort: number key picks column; pressing it again flips asc/desc
        KeyCode::Char(c) if ('1'..='9').contains(&c) => {
            let col = COLS[c as usize - '1' as usize];
            if app.sort == col {
                app.sort_asc = !app.sort_asc;
            } else {
                app.sort = col;
                app.sort_asc = true;
            }
        }
        KeyCode::Left => cycle_sort(app, true),
        KeyCode::Right => cycle_sort(app, false),
        _ => {}
    }
    false
}

fn cycle_sort(app: &mut App, back: bool) {
    let i = COLS.iter().position(|c| *c == app.sort).unwrap_or(0);
    app.sort = if back {
        COLS[(i + COLS.len() - 1) % COLS.len()]
    } else {
        COLS[(i + 1) % COLS.len()]
    };
}

fn key_pending(app: &mut App, k: event::KeyEvent, out: &mut Vec<conn::Cmd>) -> bool {
    // inline deny-note editor owns all typing while open
    if app.deny_note.is_some() {
        match k.code {
            KeyCode::Esc => app.deny_selected(None, out), // Esc denies with empty note
            KeyCode::Enter => {
                let note = std::mem::take(&mut app.deny_note);
                app.deny_selected(note, out);
            }
            KeyCode::Backspace => {
                if let Some(n) = &mut app.deny_note {
                    n.pop();
                }
            }
            KeyCode::Char(c) => {
                if let Some(n) = &mut app.deny_note {
                    n.push(c);
                }
            }
            _ => {}
        }
        return false;
    }

    match k.code {
        KeyCode::Esc => app.modal = Modal::None, // dismiss; request stays queued
        KeyCode::Char('a') => app.approve_selected(out),
        KeyCode::Char('d') => app.deny_note = Some(String::new()),
        KeyCode::Char('t') => {
            app.ttl_edit = match &app.ttl_edit {
                Some(_) => None,
                None => Some(String::new()),
            };
        }
        KeyCode::Char('n') | KeyCode::Tab => {
            let n = app.pending_ids().len().max(1);
            if let Modal::Pending(i) = &app.modal {
                app.modal = Modal::Pending((i + 1) % n);
            }
            app.deny_note = None;
            app.ttl_edit = None;
        }
        // ttl edit: seconds, digits only (grammar mirrors approve RPC param)
        KeyCode::Char(c) if app.ttl_edit.is_some() && c.is_ascii_digit() => {
            if let Some(t) = &mut app.ttl_edit {
                t.push(c);
            }
        }
        KeyCode::Backspace => {
            if let Some(t) = &mut app.ttl_edit {
                t.pop();
            }
        }
        _ => {}
    }
    false
}

fn key_detail(app: &mut App, k: event::KeyEvent, out: &mut Vec<conn::Cmd>) -> bool {
    match k.code {
        KeyCode::Esc => app.modal = Modal::None,
        KeyCode::Char('e') => {
            // revoke THIS detail row, wherever the table cursor sits
            if let Modal::Detail(id) = app.modal {
                out.push(conn::cmd(
                    "a-revoke",
                    gk_core::protocol::method::REVOKE,
                    Some(serde_json::json!({"grant_id": id.to_string()})),
                ));
                app.modal = Modal::None;
            }
        }
        _ => {}
    }
    false
}

fn key_history(app: &mut App, k: event::KeyEvent, out: &mut Vec<conn::Cmd>) {
    match k.code {
        KeyCode::Esc => app.modal = Modal::None,
        KeyCode::Char('j') | KeyCode::Down => {
            app.hist_sel = (app.hist_sel + 1).min(app.history.len().saturating_sub(1));
        }
        KeyCode::Char('k') | KeyCode::Up => app.hist_sel = app.hist_sel.saturating_sub(1),
        KeyCode::Char('r') => {
            out.push(conn::cmd(
                "c-hist",
                gk_core::protocol::method::LIST_HISTORY,
                Some(serde_json::json!({"limit": 100})),
            ));
        }
        _ => {}
    }
}

fn key_stop(app: &mut App, k: event::KeyEvent, out: &mut Vec<conn::Cmd>) {
    match k.code {
        KeyCode::Esc => app.modal = Modal::None,
        KeyCode::Enter => {
            if app.stop_typed == "stop" {
                app.stop_confirmed(out);
            } else {
                app.modal = Modal::None; // Enter on wrong text cancels
            }
        }
        KeyCode::Backspace => {
            app.stop_typed.pop();
        }
        KeyCode::Char(c) => {
            app.stop_typed.push(c);
            if !"stop".starts_with(&app.stop_typed) {
                app.modal = Modal::None; // mistyped -> cancel
            }
        }
        _ => {}
    }
}
