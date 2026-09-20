//! Application state + reducer (events in, frame-worthy state out). Kept
//! render-free; ui.rs only ever reads this.

use std::collections::BTreeMap;

use serde_json::Value;

use gk_core::protocol::method;

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
    // kernel truth (traffic.stat); None until first poll covers this grant
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
    /// stop-all: must type the word "stop"
    ConfirmStop,
    /// socket lost; retrying in background
    ConnLost,
}

pub struct App {
    pub live: BTreeMap<i64, LiveRow>,
    pub pending: BTreeMap<i64, PendingRow>,
    pub history: Vec<Value>,
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

    pub fn pending_ids(&self) -> Vec<i64> {
        // oldest first: the blocked model at the head of the queue
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

    fn on_event(&mut self, m: &str, p: Value, out: &mut Vec<Cmd>) {
        match m {
            method::EV_REQUEST_NEW => {
                let id = p["grant_id"].as_str().and_then(|s| s.parse().ok());
                if let Some(id) = id {
                    if !self.pending.contains_key(&id) {
                        self.pending.insert(
                            id,
                            PendingRow {
                                target: p["target"].as_str().unwrap_or("?").into(),
                                ports: fmt_ports(&p["dst_port"], &p["proto"]),
                                reason: p["reason"].as_str().unwrap_or("").into(),
                                tool: p["tool"].as_str().unwrap_or("").into(),
                                ttl_requested: p["ttl_requested"].as_str().unwrap_or("").into(),
                                created_at: p["created_at"].as_u64().unwrap_or(self.now),
                            },
                        );
                    }
                    // auto-open immediately (design decision) unless a modal
                    // the user is mid-edit in owns the screen
                    if matches!(self.modal, Modal::None | Modal::Detail(_)) {
                        self.modal = Modal::Pending(0);
                        self.deny_note = None;
                        self.ttl_edit = None;
                    }
                }
            }
            method::EV_DECIDED => {
                if let Some(gid) = p["grant_id"].as_str().and_then(|s| s.parse::<i64>().ok()) {
                    self.pending.remove(&gid);
                    self.live.remove(&gid);
                    // authoritative refresh of both tables (requests arrive at human speed)
                    out.push(cmd("c-live", method::LIST_GRANTS, None));
                    out.push(cmd("c-pend", method::LIST_PENDING, None));
                    if self.modal == Modal::Pending(0) && self.pending.is_empty() {
                        self.modal = Modal::None;
                    }
                }
                // stop.grants broadcast: no grant_id
                if p["state"].as_str() == Some("all_stopped") {
                    self.live.clear();
                    self.pending.clear();
                    self.modal = Modal::None;
                    let n = p["grants_removed"].as_u64().unwrap_or(0);
                    self.set_flash(format!("stop.grants: {n} grants removed"));
                }
            }
            method::EV_EXPIRED => {
                if let Some(gid) = p["grant_id"].as_str().and_then(|s| s.parse::<i64>().ok()) {
                    self.live.remove(&gid);
                }
            }
            method::EV_TRAFFIC => {
                for g in p["grants"].as_array().into_iter().flatten() {
                    let Some(id) = g["grant_id"].as_str().and_then(|s| s.parse::<i64>().ok())
                    else {
                        continue;
                    };
                    if let Some(row) = self.live.get_mut(&id) {
                        row.left = g["seconds_remaining"].as_u64();
                        row.bytes_up = g["bytes_sent"].as_u64();
                        row.bytes_down = g["bytes_received"].as_u64();
                    }
                }
            }
            method::EV_ERROR => {
                self.set_flash(format!("daemon: {}", p["message"].as_str().unwrap_or("?")));
            }
            _ => {}
        }
    }

    fn on_response(&mut self, v: &Value, _out: &mut Vec<Cmd>) {
        match v.get("id").and_then(|i| i.as_str()).unwrap_or("") {
            "c-sub" => {
                let r = &v["result"];
                self.timeout_secs = r["approver_timeout_secs"].as_u64();
                self.daemon_version = r["version"].as_str().map(String::from);
            }
            "c-live" => {
                if v.get("error").is_some() {
                    return;
                }
                let mut fresh = BTreeMap::new();
                for g in v["result"].as_array().into_iter().flatten() {
                    if let Some(row) = live_from_row(g) {
                        // preserve kernel stats we already have for this id
                        fresh.insert(
                            row.id,
                            match self.live.get(&row.id) {
                                Some(old) => LiveRow {
                                    left: old.left,
                                    bytes_up: old.bytes_up,
                                    bytes_down: old.bytes_down,
                                    ..row
                                },
                                None => row,
                            },
                        );
                    }
                }
                self.live = fresh;
                self.clamp_sel();
            }
            "c-pend" => {
                if v.get("error").is_some() {
                    return;
                }
                let mut fresh = BTreeMap::new();
                for g in v["result"].as_array().into_iter().flatten() {
                    // only rows with a live decision channel are actionable
                    if g["waiting"].as_bool() != Some(true) {
                        continue;
                    }
                    let id = match g["id"].as_i64() {
                        Some(i) => i,
                        None => continue,
                    };
                    fresh.insert(
                        id,
                        PendingRow {
                            target: g["target"].as_str().unwrap_or("?").into(),
                            ports: fmt_ports_flat(&g["port_from"], &g["port_to"], &g["proto"]),
                            reason: g["reason"].as_str().unwrap_or("").into(),
                            tool: g["tool"].as_str().unwrap_or("").into(),
                            ttl_requested: fmt_ttl_secs(g["ttl_secs"].as_u64().unwrap_or(0)),
                            created_at: g["created_at"].as_u64().unwrap_or(self.now),
                        },
                    );
                }
                self.pending = fresh;
                // resync landing while the queue is empty should close a stale modal
                if matches!(self.modal, Modal::Pending(_)) && self.pending.is_empty() {
                    self.modal = Modal::None;
                }
                // TUI cold-started onto a blocked model: the snapshot IS the
                // queue — surface it like a fresh arrival would.
                if matches!(self.modal, Modal::None) && !self.pending.is_empty() {
                    self.modal = Modal::Pending(0);
                }
            }
            "c-hist" => {
                match v.get("result").and_then(|r| r.as_array()) {
                    Some(rows) => {
                        self.history = rows.clone();
                        self.history_err = None;
                    }
                    None => {
                        self.history_err = Some(
                            v["error"]["message"].as_str().unwrap_or("history failed").to_string(),
                        );
                    }
                }
            }
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
        if let Some(id) = self.modal_pending_id() {
            let mut params = serde_json::json!({"grant_id": id.to_string()});
            if let Some(t) = self.ttl_edit.as_deref().and_then(|s| s.parse::<u64>().ok()) {
                params["ttl_secs"] = serde_json::json!(t);
            }
            out.push(cmd("a-approve", method::APPROVE, Some(params)));
            self.after_decision(out);
        }
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

    fn after_decision(&mut self, _out: &mut Vec<Cmd>) {
        // optimistic local removal; EV_DECIDED + snapshot resync confirm it.
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
        out.push(cmd("c-hist", method::LIST_HISTORY, Some(serde_json::json!({"limit": 100}))));
    }

    pub fn stop_confirmed(&mut self, out: &mut Vec<Cmd>) {
        out.push(cmd("a-stop", method::STOP_GRANTS, None));
        self.modal = Modal::None;
        self.stop_typed.clear();
    }
}

// ------------------------------------------------------------------ format

fn fmt_ports(spec: &Value, proto: &Value) -> String {
    let p = proto.as_str().unwrap_or("tcp");
    if let (Some(f), Some(t)) = (spec["from"].as_u64(), spec["to"].as_u64()) {
        if f == 0 && t == 0 {
            format!("* /{p}")
        } else if f == t {
            format!("{f}/{p}")
        } else {
            format!("{f}-{t}/{p}")
        }
    } else {
        format!("?/{p}")
    }
}

/// list.pending rows carry flat port_from/port_to instead of a dst_port object.
fn fmt_ports_flat(from: &Value, to: &Value, proto: &Value) -> String {
    let p = proto.as_str().unwrap_or("tcp");
    match (from.as_u64(), to.as_u64()) {
        (Some(f), Some(t)) if f == 0 && t == 0 => format!("* /{p}"),
        (Some(f), Some(t)) if f == t => format!("{f}/{p}"),
        (Some(f), Some(t)) => format!("{f}-{t}/{p}"),
        _ => format!("?/{p}"),
    }
}

pub fn fmt_ttl_secs(s: u64) -> String {
    if s == 0 {
        return "-".into();
    }
    if s % 3600 == 0 {
        format!("{}h", s / 3600)
    } else if s % 60 == 0 {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

pub fn fmt_countdown(s: Option<u64>) -> String {
    match s {
        None => "…".into(),
        Some(x) => format!("{}:{:02}", x / 60, x % 60),
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

/// list.grants row -> table row. dst_json is a JSON-array string in ledger
/// rows (traffic.stat sends a real array; both shapes are accepted here).
fn live_from_row(g: &Value) -> Option<LiveRow> {
    let id = g["id"].as_i64()?;
    let dst: Vec<String> = match &g["dst_json"] {
        Value::String(s) => serde_json::from_str(s).unwrap_or_default(),
        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        _ => Vec::new(),
    };
    let from = g["port_from"].as_u64()? as u16;
    let to = g["port_to"].as_u64()? as u16;
    let proto = g["proto"].as_str().unwrap_or("tcp").to_string();
    Some(LiveRow {
        id,
        target: g["target"].as_str().unwrap_or("?").into(),
        dst,
        ports: if from == 0 && to == 0 {
            "*".into()
        } else if from == to {
            from.to_string()
        } else {
            format!("{from}-{to}")
        },
        proto,
        ttl_secs: g["granted_ttl_secs"]
            .as_u64()
            .or_else(|| g["ttl_secs"].as_u64())
            .unwrap_or(0),
        reason: g["reason"].as_str().unwrap_or("").into(),
        tool: g["tool"].as_str().unwrap_or("").into(),
        left: None,
        bytes_up: None,
        bytes_down: None,
    })
}
