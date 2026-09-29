//! Application state. ui.rs reads this; it does not render.

use std::collections::BTreeMap;

use serde_json::Value;

use tethys_core::protocol::{
    method, EvDecided, EvError, EvExpired, EvRequestNew, EvStopped, EvTraffic, SubscribeAck,
};
use tethys_core::types::PortSpec;
use tethys_core::wire::{GrantRow, PendingRowWire};

use crate::conn::{cmd, Cmd};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Col {
    Id,
    Tool,
    Dst,
    Ports,
    Proto,
    Ttl,
    Left,
    Bytes,
    Reason,
}
pub const COLS: [Col; 9] = [
    Col::Id,
    Col::Tool,
    Col::Dst,
    Col::Ports,
    Col::Proto,
    Col::Ttl,
    Col::Left,
    Col::Bytes,
    Col::Reason,
];

impl Col {
    pub fn header(self) -> &'static str {
        match self {
            Col::Id => "id",
            Col::Tool => "tool",
            Col::Dst => "dst",
            Col::Ports => "ports",
            Col::Proto => "proto",
            Col::Ttl => "ttl",
            Col::Left => "left",
            Col::Bytes => "\u{2195}B",
            Col::Reason => "reason",
        }
    }
}

/// One row of the live table: ledger facts merged with kernel-truth stats.
#[derive(Clone, Debug)]
pub struct LiveRow {
    pub id: i64,
    pub target: String,   // requested (canonical)
    pub dst: Vec<String>, // installed (post-resolution)
    pub ports: String,
    pub proto: String,
    pub ttl_secs: u64,
    pub reason: String,
    pub tool: String,
    /// Kernel truth (traffic.stat); None until the first poll covers this grant.
    pub left: Option<u64>,
    pub bytes_up: Option<u64>,
    pub bytes_down: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct PendingRow {
    pub target: String,
    pub ports: String,
    pub reason: String,
    pub tool: String,
    pub ttl_requested: String,
    pub created_at: u64,
}

#[derive(PartialEq)]
pub enum Modal {
    None,
    /// pending-approval queue; index into `pending_ids()`
    Pending(usize),
    /// row detail for a live grant
    Detail(i64),
    /// decided history (lazy-loaded)
    History,
    /// host network interfaces (snapshot taken when opened)
    Net,
    /// stop-all: must type the word "stop"
    ConfirmStop,
    /// socket lost; retrying in background
    ConnLost,
}

/// One row of the network modal: interface + its addresses.
pub struct NetIface {
    pub name: String,
    pub addrs: Vec<String>, // "ip/prefix" per address
    pub default: bool,      // carries the default route
}

pub struct App {
    pub live: BTreeMap<i64, LiveRow>,
    pub net: Vec<NetIface>,
    pub pending: BTreeMap<i64, PendingRow>,
    pub history: Vec<GrantRow>,
    pub history_err: Option<String>,

    pub modal: Modal,
    pub sel: usize, // table cursor
    pub hist_sel: usize,
    pub sort: Col,
    pub sort_asc: bool,

    // inline editors (modal)
    pub deny_note: Option<String>, // Some(_) => note input open
    pub ttl_edit: Option<String>,
    pub stop_typed: String,

    pub now: u64,
    pub timeout_secs: Option<u64>, // from subscribe ack
    pub daemon_version: Option<String>,
    pub flash: Option<(String, std::time::Instant)>, // transient status line
}

impl App {
    pub fn new() -> Self {
        Self {
            live: BTreeMap::new(),
            net: Vec::new(),
            pending: BTreeMap::new(),
            history: Vec::new(),
            history_err: None,
            modal: Modal::None,
            sel: 0,
            hist_sel: 0,
            sort: Col::Left,
            sort_asc: true,
            deny_note: None,
            ttl_edit: None,
            stop_typed: String::new(),
            now: 0,
            timeout_secs: None,
            daemon_version: None,
            flash: None,
        }
    }

    pub fn sorted_live(&self) -> Vec<&LiveRow> {
        let mut v: Vec<&LiveRow> = self.live.values().collect();
        let key = |r: &LiveRow| match self.sort {
            Col::Id => r.id as i128,
            Col::Left => r.left.unwrap_or(u64::MAX) as i128,
            Col::Bytes => (r.bytes_up.unwrap_or(0) + r.bytes_down.unwrap_or(0)) as i128,
            Col::Ttl => r.ttl_secs as i128,
            _ => 0,
        };
        let text = |r: &LiveRow| match self.sort {
            Col::Tool => r.tool.clone(),
            Col::Dst => r.dst.join(","),
            Col::Ports => r.ports.clone(),
            Col::Proto => r.proto.clone(),
            Col::Reason => r.reason.clone(),
            _ => String::new(),
        };
        v.sort_by(|a, b| {
            let (ka, kb) = (key(a), key(b));
            if ka != kb || matches!(self.sort, Col::Id | Col::Left | Col::Bytes | Col::Ttl) {
                if self.sort_asc {
                    ka.cmp(&kb)
                } else {
                    kb.cmp(&ka)
                }
            } else {
                let (ta, tb) = (text(a), text(b));
                if self.sort_asc {
                    ta.cmp(&tb)
                } else {
                    tb.cmp(&ta)
                }
            }
        });
        v
    }

    pub fn clamp_sel(&mut self) {
        let n = self.live.len();
        self.sel = self.sel.min(n.saturating_sub(1));
    }

    /// True if row id is under the table cursor (for modal focus sync).
    pub fn focused_live(&self) -> Option<i64> {
        self.sorted_live().get(self.sel).map(|r| r.id)
    }

    /// Oldest first: the blocked model at the head of the queue.
    pub fn pending_ids(&self) -> Vec<i64> {
        let mut ids: Vec<i64> = self.pending.keys().copied().collect();
        ids.sort();
        ids
    }

    fn set_flash(&mut self, msg: impl Into<String>) {
        self.flash = Some((msg.into(), std::time::Instant::now()));
    }

    // ------------------------------------------------------------- inbound

    /// Fold one inbound JSON line (event or response) into state; returns
    /// follow-up commands to send.
    pub fn on_line(&mut self, v: &Value, out: &mut Vec<Cmd>) {
        match v.get("method").and_then(|m| m.as_str()) {
            Some(m) => self.on_event(m, v.get("params").cloned().unwrap_or(Value::Null), out),
            None => self.on_response(v, out),
        }
    }

    /// Fold one daemon event into state. Each event deserializes once into
    /// its typed payload; anything that fails to parse is a contract
    /// violation and gets flashed, not silently half-applied. grant.decided
    /// is a tagged enum: each decision names its own grant, so there is no
    /// state string to compare and no nullable soup; the affected row is
    /// dropped from both tables and fresh snapshots are requested. A new
    /// request opens the pending modal unless some other modal is already
    /// open; traffic.stat only patches kernel-truth columns on rows that
    /// already exist.
    fn on_event(&mut self, m: &str, p: Value, out: &mut Vec<Cmd>) {
        let bad = |e: serde_json::Error| format!("daemon sent bad {m} payload: {e}");
        match m {
            method::EV_REQUEST_NEW => match serde_json::from_value::<EvRequestNew>(p) {
                Ok(ev) => {
                    let Ok(id) = ev.grant_id.parse::<i64>() else {
                        return;
                    };
                    self.pending.entry(id).or_insert_with(|| PendingRow {
                        target: ev.target,
                        ports: fmt_ports(&ev.dst_port, ev.proto),
                        reason: ev.reason,
                        tool: ev.tool,
                        ttl_requested: ev.ttl_requested,
                        created_at: ev.created_at,
                    });
                    if matches!(self.modal, Modal::None | Modal::Detail(_) | Modal::History) {
                        self.modal = Modal::Pending(0);
                        self.deny_note = None;
                        self.ttl_edit = None;
                    }
                }
                Err(e) => self.set_flash(bad(e)),
            },
            method::EV_DECIDED => match serde_json::from_value::<EvDecided>(p) {
                Ok(ev) => {
                    let gid = match &ev {
                        EvDecided::Approved { grant_id, .. }
                        | EvDecided::Denied { grant_id, .. }
                        | EvDecided::Revoked { grant_id } => grant_id.parse::<i64>().ok(),
                    };
                    if let Some(gid) = gid {
                        self.pending.remove(&gid);
                        self.live.remove(&gid);
                        out.push(cmd("c-live", method::LIST_GRANTS, None));
                        out.push(cmd("c-pend", method::LIST_PENDING, None));
                        if self.modal == Modal::Pending(0) && self.pending.is_empty() {
                            self.modal = Modal::None;
                        }
                    }
                }
                Err(e) => self.set_flash(bad(e)),
            },
            method::EV_STOPPED => match serde_json::from_value::<EvStopped>(p) {
                Ok(ev) => {
                    self.live.clear();
                    self.pending.clear();
                    self.modal = Modal::None;
                    self.set_flash(format!("stop.grants: {} grants removed", ev.grants_removed));
                }
                Err(e) => self.set_flash(bad(e)),
            },
            method::EV_EXPIRED => match serde_json::from_value::<EvExpired>(p) {
                Ok(ev) => {
                    if let Ok(gid) = ev.grant_id.parse::<i64>() {
                        self.live.remove(&gid);
                    }
                }
                Err(e) => self.set_flash(bad(e)),
            },
            method::EV_TRAFFIC => match serde_json::from_value::<EvTraffic>(p) {
                Ok(ev) => {
                    for g in ev.grants {
                        let Ok(id) = g.grant_id.parse::<i64>() else {
                            continue;
                        };
                        if let Some(row) = self.live.get_mut(&id) {
                            row.left = Some(g.seconds_remaining);
                            row.bytes_up = Some(g.bytes_sent);
                            row.bytes_down = Some(g.bytes_received);
                        }
                    }
                }
                Err(e) => self.set_flash(bad(e)),
            },
            method::EV_ERROR => match serde_json::from_value::<EvError>(p) {
                Ok(ev) => self.set_flash(format!("daemon: {}", ev.message)),
                Err(e) => self.set_flash(bad(e)),
            },
            _ => {}
        }
    }

    /// Fold one response into state, dispatched on the response id. Each
    /// reply deserializes through its typed payload; errors flash rather
    /// than silently leaving stale state rendered as fresh. The c-live
    /// snapshot preserves kernel stats already held for an id (they arrive
    /// separately via traffic.stat), and c-pend keeps only rows with a live
    /// decision channel; the rest are not actionable. When a resync lands
    /// an empty pending queue, a stale modal closes; a non-empty queue while
    /// no modal is open opens one.
    fn on_response(&mut self, v: &Value, _out: &mut Vec<Cmd>) {
        let err_msg = |d: &Value| {
            d["error"]["message"]
                .as_str()
                .unwrap_or("daemon error")
                .to_string()
        };
        match v.get("id").and_then(|i| i.as_str()).unwrap_or("") {
            "c-sub" => match serde_json::from_value::<SubscribeAck>(v["result"].clone()) {
                Ok(ack) => {
                    self.timeout_secs = Some(ack.approver_timeout_secs);
                    self.daemon_version = Some(ack.version);
                }
                Err(e) => self.set_flash(format!("bad subscribe ack: {e}")),
            },
            "c-live" => {
                if v.get("error").is_some() {
                    return;
                }
                match serde_json::from_value::<Vec<GrantRow>>(v["result"].clone()) {
                    Ok(rows) => {
                        let mut fresh = BTreeMap::new();
                        for row in rows.iter().filter_map(live_from_row) {
                            fresh.insert(
                                row.id,
                                match self.live.get(&row.id) {
                                    Some(old) => LiveRow {
                                        left: old.left,
                                        bytes_up: old.bytes_up,
                                        bytes_down: old.bytes_down,
                                        ..row.clone()
                                    },
                                    None => row,
                                },
                            );
                        }
                        self.live = fresh;
                        self.clamp_sel();
                    }
                    Err(e) => self.set_flash(format!("bad list.grants payload: {e}")),
                }
            }
            "c-pend" => {
                if v.get("error").is_some() {
                    return;
                }
                match serde_json::from_value::<Vec<PendingRowWire>>(v["result"].clone()) {
                    Ok(rows) => {
                        let mut fresh = BTreeMap::new();
                        for pr in rows {
                            if !pr.waiting {
                                continue;
                            }
                            fresh.insert(
                                pr.row.id,
                                PendingRow {
                                    target: pr.row.target,
                                    ports: fmt_ports(
                                        &PortSpec {
                                            from: pr.row.port_from,
                                            to: pr.row.port_to,
                                        },
                                        pr.row.proto,
                                    ),
                                    reason: pr.row.reason,
                                    tool: pr.row.tool,
                                    ttl_requested: fmt_ttl_secs(pr.row.ttl_secs),
                                    created_at: pr.row.created_at,
                                },
                            );
                        }
                        self.pending = fresh;
                        if matches!(self.modal, Modal::Pending(_)) && self.pending.is_empty() {
                            self.modal = Modal::None;
                        }
                        if matches!(self.modal, Modal::None) && !self.pending.is_empty() {
                            self.modal = Modal::Pending(0);
                        }
                    }
                    Err(e) => self.set_flash(format!("bad list.pending payload: {e}")),
                }
            }
            "c-hist" => match serde_json::from_value::<Vec<GrantRow>>(v["result"].clone()) {
                Ok(rows) if v.get("error").is_none() => {
                    self.history = rows;
                    self.history_err = None;
                }
                _ => {
                    self.history_err = Some(err_msg(v));
                }
            },
            "a-reload" => match v.get("error") {
                Some(e) => self.set_flash(format!(
                    "reload failed: {}",
                    e["message"].as_str().unwrap_or("?")
                )),
                None => {
                    let n = v["result"]["reloaded"].as_u64().unwrap_or(0);
                    self.set_flash(format!("allow list reloaded ({n} entries)"));
                }
            },
            "a-approve" | "a-deny" | "a-revoke" | "a-stop" => {
                if let Some(e) = v.get("error") {
                    self.set_flash(format!("daemon: {}", e["message"].as_str().unwrap_or("?")));
                }
            }
            _ => {}
        }
    }

    // -------------------------------------------------------------- actions

    pub fn approve_selected(&mut self, out: &mut Vec<Cmd>) {
        let Some(id) = self.modal_pending_id() else {
            return;
        };
        let mut params = serde_json::json!({"grant_id": id.to_string()});
        if let Some(raw) = self.ttl_edit.as_deref() {
            let raw = raw.trim();
            if !raw.is_empty() {
                // A malformed override must NOT silently approve at the
                // requested ttl — that grants time the operator meant to
                // change. Flash and keep the modal open instead.
                match parse_ttl_override(raw) {
                    Some(secs) => params["ttl_secs"] = serde_json::json!(secs),
                    None => {
                        self.set_flash(format!(
                            "bad ttl `{raw}` — type seconds, or end with m/h (e.g. 30s, 45m, 2h)"
                        ));
                        return;
                    }
                }
            }
        }
        out.push(cmd("a-approve", method::APPROVE, Some(params)));
        self.after_decision(out);
    }

    pub fn deny_selected(&mut self, note: Option<String>, out: &mut Vec<Cmd>) {
        if let Some(id) = self.modal_pending_id() {
            out.push(cmd(
                "a-deny",
                method::DENY,
                Some(serde_json::json!({"grant_id": id.to_string(), "note": note.unwrap_or_default()})),
            ));
            self.after_decision(out);
        }
    }

    /// Optimistic local removal of the decided row; EV_DECIDED plus the
    /// snapshot resync confirm it. Clears any open editor and lands on the
    /// next queued request, or closes the modal when the queue drains.
    fn after_decision(&mut self, _out: &mut Vec<Cmd>) {
        if let Some(id) = self.modal_pending_id() {
            self.pending.remove(&id);
        }
        self.deny_note = None;
        self.ttl_edit = None;
        self.stop_typed.clear();
        let ids = self.pending_ids();
        self.modal = match ids.first() {
            Some(_) => Modal::Pending(0),
            None => Modal::None,
        };
    }

    pub fn modal_pending_id(&self) -> Option<i64> {
        match &self.modal {
            Modal::Pending(i) => self.pending_ids().get(*i).copied(),
            _ => None,
        }
    }

    pub fn revoke_focused(&mut self, out: &mut Vec<Cmd>) {
        if let Some(id) = self.focused_live() {
            out.push(cmd(
                "a-revoke",
                method::REVOKE,
                Some(serde_json::json!({"grant_id": id.to_string()})),
            ));
            self.modal = Modal::None;
        }
    }

    pub fn open_history(&mut self, out: &mut Vec<Cmd>) {
        self.modal = Modal::History;
        self.hist_sel = 0;
        out.push(cmd(
            "c-hist",
            method::LIST_HISTORY,
            Some(serde_json::json!({"limit": 100})),
        ));
    }

    pub fn stop_confirmed(&mut self, out: &mut Vec<Cmd>) {
        out.push(cmd("a-stop", method::STOP_GRANTS, None));
        self.modal = Modal::None;
        self.stop_typed.clear();
    }
}

// ------------------------------------------------------------------ format

pub fn port_text(from: u16, to: u16) -> String {
    if from == 0 && to == 0 {
        "*".into()
    } else if from == to {
        from.to_string()
    } else {
        format!("{from}-{to}")
    }
}

fn fmt_ports(spec: &PortSpec, proto: tethys_core::types::Proto) -> String {
    if spec.from == 0 && spec.to == 0 {
        format!("* /{proto}")
    } else {
        format!("{}/{}", port_text(spec.from, spec.to), proto)
    }
}

/// One canonical spelling, owned by tethys-core: the daemon renders ttl text
/// from the same function, so nothing drifts between what is approved and
/// what is shown.
pub use tethys_core::types::fmt_ttl_secs;

/// Operator TTL override typed into the pending modal: digits with an
/// optional unit suffix — `30`/`30s` seconds (default), `45m` minutes, `2h`
/// hours. None on anything else; overflow is rejected, not wrapped.
pub fn parse_ttl_override(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult): (&str, u64) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        _ => (s, 1),
    };
    if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = num.parse().ok()?;
    n.checked_mul(mult).filter(|secs| *secs > 0)
}

/// Table ttl column: always whole minutes (rounded up), so it reads in
/// the same unit as the M:SS countdown beside it. The canonical
/// fmt_ttl_secs stays for modals/history where 15m/2h spellings are fine.
pub fn fmt_ttl_mins(s: u64) -> String {
    format!("{}m", s.div_ceil(60))
}

pub fn fmt_countdown(s: Option<u64>) -> String {
    match s {
        None => "…".into(),
        Some(x) => format!("{}:{:02}m", x / 60, x % 60),
    }
}

pub fn fmt_bytes(b: u64) -> String {
    if b >= 1_000_000_000 {
        format!("{:.1}G", b as f64 / 1e9)
    } else if b >= 1_000_000 {
        format!("{:.1}M", b as f64 / 1e6)
    } else if b >= 1_000 {
        format!("{}k", b / 1_000)
    } else {
        format!("{b}")
    }
}

/// The wire row minus kernel stats (those arrive via traffic.stat).
fn live_from_row(g: &GrantRow) -> Option<LiveRow> {
    let dst: Vec<String> = serde_json::from_str(&g.dst_json).unwrap_or_default();
    Some(LiveRow {
        id: g.id,
        target: g.target.clone(),
        dst,
        ports: port_text(g.port_from, g.port_to),
        proto: g.proto.to_string(),
        ttl_secs: g.granted_ttl_secs.unwrap_or(g.ttl_secs),
        reason: g.reason.clone(),
        tool: g.tool.clone(),
        left: None,
        bytes_up: None,
        bytes_down: None,
    })
}
