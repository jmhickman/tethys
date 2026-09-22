//! nftables JSON batch construction and execution.
//!
//! nft 1.1.6 encoding: CIDR elements must be `{"prefix":{...}}` objects (an
//! "a.b.c.d/nn" string is parsed as a hostname), per-element TTL lives in
//! `{"elem":{"val":...,"expires":N}}`, and batches apply atomically.

use std::net::IpAddr;
use std::process::Stdio;
use std::time::Duration;

use ipnet::IpNet;
use serde_json::{json, Value};
use thiserror::Error;
use tokio::process::Command;

use crate::types::{PortSpec, Proto};

pub const TABLE: &str = "gatekeeper";
pub const SET_V4: &str = "grants_v4";
pub const SET_V6: &str = "grants_v6";
/// Operator allow-list tuples (`allow` in config). Flush+reinstall from
/// config; live in the baseline carve sets so stop.grants does not touch them.
pub const SET_CARVE_V4: &str = "carve_v4";
pub const SET_CARVE_V6: &str = "carve_v6";
/// Accounting chains (empty in the static baseline; contents owned here).
/// Rules carry counters only — no verdict — so they cannot bypass egress.
pub const CHAIN_ACCT_OUT: &str = "acct_out";
pub const CHAIN_ACCT_IN: &str = "acct_in";
/// Enforcement scope chain (empty in the baseline; flush-and-rebuild like
/// acct). The egress chain `jump`s here before drop. A hooked base chain
/// cannot pre-exempt packets from a lower-priority base chain (independent
/// netfilter callbacks; only `drop` short-circuits). Policed uids `return`
/// (caller drop continues); everyone else `accept`s.
pub const CHAIN_SCOPE: &str = "scope";
/// Counter for unpoliced (exempt) egress.
pub const COUNTER_EXEMPT: &str = "gk_exempt";
/// Long default so per-element `expires` is the only thing that reaps grants.
const SET_DEFAULT_TIMEOUT_SECS: u64 = 24 * 3600;

/// Per-grant accounting object names. These outlive the grant's set element:
/// counters are swept only when the ledger row leaves the approved state.
pub fn counter_out(gid: i64) -> String {
    format!("gk_g{gid}_out")
}
pub fn counter_in(gid: i64) -> String {
    format!("gk_g{gid}_in")
}
/// Per-grant match set for one direction+family: gk_m7_out_v4 etc.
pub fn acct_set(gid: i64, dir: Dir, v6: bool) -> String {
    format!("gk_m{gid}_{}{}", dir.slug(), if v6 { "_v6" } else { "" })
}

#[derive(Debug, Error)]
pub enum NftError {
    #[error("nft spawn failed (path /usr/sbin/nft): {0}")]
    Spawn(std::io::Error),
    #[error("nft stdin write failed (batch may NOT be applied): {0}")]
    Io(#[from] std::io::Error),
    #[error("nft timed out after {0:?} — prior kernel state retained")]
    Timeout(Duration),
    #[error("nft exited with {}: {}", code.map(|c| c.to_string()).unwrap_or("signal".into()), stderr.trim())]
    Failed { code: Option<i32>, stderr: String },
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// One grant element: destination key + proto + normalized port range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantElem {
    pub dst: ElemDst,
    pub proto: Proto,
    pub port: PortSpec,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ElemDst {
    Ip(IpAddr),
    Net(IpNet),
}

impl ElemDst {
    pub fn is_v6(&self) -> bool {
        match self {
            ElemDst::Ip(ip) => ip.is_ipv6(),
            ElemDst::Net(n) => n.network().is_ipv6(),
        }
    }
    /// Canonical string form (matches LiveElement.dst and dst_json storage).
    pub fn canonical(&self) -> String {
        match self {
            ElemDst::Ip(ip) => ip.to_string(),
            ElemDst::Net(n) => n.to_string(),
        }
    }
    pub fn from_canonical(s: &str) -> Option<Self> {
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Some(ElemDst::Ip(ip));
        }
        s.parse::<IpNet>().ok().map(ElemDst::Net)
    }
}

/// Accounting direction. Out = packets to a granted tuple; In = established
/// replies whose source is the granted tuple (`ct original` concats don't
/// parse on this nft build).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    Out,
    In,
}

impl Dir {
    pub fn slug(self) -> &'static str {
        match self {
            Dir::Out => "out",
            Dir::In => "in",
        }
    }
    pub fn counter(self, gid: i64) -> String {
        match self {
            Dir::Out => counter_out(gid),
            Dir::In => counter_in(gid),
        }
    }
}

impl GrantElem {
    pub fn set_name(&self) -> &'static str {
        match &self.dst {
            ElemDst::Ip(IpAddr::V4(_)) | ElemDst::Net(IpNet::V4(_)) => SET_V4,
            _ => SET_V6,
        }
    }

    /// Carve-set counterpart (operator allow list): same key grammar, but the
    /// carve sets carry no timeout flag, so elements persist until reinstalled.
    pub fn carve_set_name(&self) -> &'static str {
        match &self.dst {
            ElemDst::Ip(IpAddr::V4(_)) | ElemDst::Net(IpNet::V4(_)) => SET_CARVE_V4,
            _ => SET_CARVE_V6,
        }
    }

    fn concat(&self) -> Value {
        let dst = match &self.dst {
            ElemDst::Ip(ip) => json!(ip.to_string()),
            // Slash strings are parsed as hostnames; use prefix objects.
            ElemDst::Net(n) => {
                json!({"prefix": {"addr": n.network().to_string(), "len": n.prefix_len()}})
            }
        };
        let (f, t) = self.port.nft_range();
        let port = if f == t {
            json!(f)
        } else {
            json!({"range": [f, t]})
        };
        json!({"concat": [dst, self.proto.nft_key(), port]})
    }
}

/// JSON command array for `nft --json -f -`. `table` is per deployment
/// (`nft_table`, default "gatekeeper"); tests use a private table.
#[derive(Clone, Debug)]
pub struct Batch {
    pub table: String,
    cmds: Vec<Value>,
}

impl Default for Batch {
    fn default() -> Self {
        Self {
            table: TABLE.into(),
            cmds: Vec::new(),
        }
    }
}

impl Batch {
    /// Batch against the default table ([`TABLE`]).
    pub fn new() -> Self {
        Self::default()
    }

    /// Batch against a named table (config `nft_table`; tests use a private
    /// table so they never touch production kernel state).
    pub fn with_table(table: &str) -> Self {
        Self {
            table: table.into(),
            cmds: Vec::new(),
        }
    }

    /// Ensure our table exists (idempotent — nft treats add-existing as OK).
    pub fn ensure_table(&mut self) {
        self.cmds
            .push(json!({"add":{"table":{"family":"inet","name":&self.table}}}));
    }

    fn push_grant_set(&mut self, name: &str, proto_field: &str) {
        let addr_field = "daddr";
        self.cmds.push(json!({"add":{"set":{
            "family":"inet","table":&self.table,"name":name,
            "type":{"typeof":{"concat":[
                {"payload":{"protocol":proto_field,"field":addr_field}},
                {"meta":{"key":"l4proto"}},
                {"payload":{"protocol":"th","field":"dport"}}
            ]}},
            "flags":["interval","timeout"],
            "timeout":SET_DEFAULT_TIMEOUT_SECS
        }}}));
    }

    /// Idempotent add of table, grant sets, acct chains, scope, exempt counter.
    pub fn ensure_base(&mut self) {
        self.ensure_table();
        self.push_grant_set(SET_V4, "ip");
        self.push_grant_set(SET_V6, "ip6");
        // Also declared by the static baseline; ensure here so dev runs work without it.
        for (chain, hook) in [(CHAIN_ACCT_OUT, "output"), (CHAIN_ACCT_IN, "input")] {
            self.cmds.push(json!({"add":{"chain":{
                "family":"inet","table":&self.table,"name":chain,
                "hook":hook,"type":"filter","prio":-10,"policy":"accept"
            }}}));
        }
        // Unhooked add is idempotent on this nft build.
        self.cmds.push(json!({"add":{"chain":{
            "family":"inet","table":&self.table,"name":CHAIN_SCOPE
        }}}));
        self.add_counter(COUNTER_EXEMPT);
    }

    /// Rebuild scope: policed uids `return` (egress drop continues); others
    /// are counted and accepted. Empty list = host-wide (every packet faces
    /// the caller's verdict) — used when `agent_user` cannot be resolved.
    pub fn rebuild_scope(&mut self, policed_uids: &[u32]) {
        self.cmds.push(json!({"flush":{"chain":{
            "family":"inet","table":&self.table,"name":CHAIN_SCOPE
        }}}));
        if policed_uids.is_empty() {
            return;
        }
        for uid in policed_uids {
            self.cmds.push(json!({"add":{"rule":{
                "family":"inet","table":&self.table,"chain":CHAIN_SCOPE,
                "expr":[
                    {"match":{"op":"==",
                              "left":{"meta":{"key":"skuid"}},
                              "right":uid}},
                    {"return":null}
                ]
            }}}));
        }
        self.cmds.push(json!({"add":{"rule":{
            "family":"inet","table":&self.table,"chain":CHAIN_SCOPE,
            "expr":[{"counter":COUNTER_EXEMPT},{"accept":null}]
        }}}));
    }

    /// Add a grant element with kernel TTL and `gk:g<gid>` comment.
    /// Comment persists in the live dump; concat deletes still match.
    pub fn add_grant(&mut self, e: &GrantElem, ttl: Duration, gid: i64) {
        self.cmds.push(json!({"add":{"element":{
            "family":"inet","table":&self.table,"name":e.set_name(),
            "elem":[{"elem":{"val": e.concat(), "expires": ttl.as_secs(),
                              "comment": format!("gk:g{gid}")}}]
        }}}));
    }

    pub fn delete_grant(&mut self, e: &GrantElem) {
        self.delete_in(e, e.set_name())
    }

    /// Allow-list element: same key as a grant, no timeout/comment.
    /// Callers must `flush_carves()` first — deleting a missing element
    /// aborts the whole nft batch.
    pub fn add_carve(&mut self, e: &GrantElem) {
        self.cmds.push(json!({"add":{"element":{
            "family":"inet","table":&self.table,"name":e.carve_set_name(),
            "elem":[e.concat()]
        }}}));
    }

    /// Flush both carve sets before reinstalling from config.
    pub fn flush_carves(&mut self) {
        for name in [SET_CARVE_V4, SET_CARVE_V6] {
            self.cmds.push(json!({"flush":{"set":{
                "family":"inet","table":&self.table,"name":name
            }}}));
        }
    }

    /// Ensure carve sets exist (baseline also declares them).
    pub fn ensure_carve_sets(&mut self) {
        for (name, proto_field) in [(SET_CARVE_V4, "ip"), (SET_CARVE_V6, "ip6")] {
            self.cmds.push(json!({"add":{"set":{
                "family":"inet","table":&self.table,"name":name,
                "type":{"typeof":{"concat":[
                    {"payload":{"protocol":proto_field,"field":"daddr"}},
                    {"meta":{"key":"l4proto"}},
                    {"payload":{"protocol":"th","field":"dport"}}
                ]}},
                "flags":["interval"]
            }}}));
        }
    }

    fn delete_in(&mut self, e: &GrantElem, set: &str) {
        self.cmds.push(json!({"delete": {"element": {
            "family": "inet", "table": &self.table, "name": set,
            "elem": [e.concat()]
        }}}));
    }

    /// Delete a whole counter object (revoke cleanup).
    pub fn delete_counter(&mut self, name: &str) {
        self.cmds.push(json!({"delete":{"counter":{
            "family":"inet","table":&self.table,"name":name
        }}}));
    }

    // Accounting: named counter, no verdict. Chains are flush + re-add.

    pub fn flush_chain(&mut self, chain: &str) {
        self.cmds.push(json!({"flush":{"chain":{
            "family":"inet","table":&self.table,"name":chain
        }}}));
    }

    pub fn add_counter(&mut self, name: &str) {
        self.cmds.push(json!({"add":{"counter":{
            "family":"inet","table":&self.table,"name":name
        }}}));
    }

    /// Per-grant match set. Address/port fields flip per direction (replies
    /// carry the granted host as source).
    pub fn add_acct_set(&mut self, gid: i64, dir: Dir, v6: bool) {
        let af = if v6 { "ip6" } else { "ip" };
        let (addr_field, port_field) = match dir {
            Dir::Out => ("daddr", "dport"),
            Dir::In => ("saddr", "sport"),
        };
        self.cmds.push(json!({"add":{"set":{
            "family":"inet","table":&self.table,"name":acct_set(gid, dir, v6),
            "type":{"typeof":{"concat":[
                {"payload":{"protocol":af,"field":addr_field}},
                {"meta":{"key":"l4proto"}},
                {"payload":{"protocol":"th","field":port_field}}
            ]}},
            "flags":["interval"]
        }}}));
    }

    /// One element tuple (dst, proto, port) into a per-grant match set.
    pub fn add_acct_elem(&mut self, gid: i64, dir: Dir, e: &GrantElem) {
        let name = acct_set(gid, dir, e.dst.is_v6());
        self.cmds.push(json!({"add":{"element":{
            "family":"inet","table":&self.table,"name":name,
            "elem":[e.concat()]
        }}}));
    }

    /// Count-only rule: match @set . proto variant . counter, no verdict.
    pub fn add_acct_rule(&mut self, gid: i64, dir: Dir, proto: Proto, v6: bool) {
        let (chain, addr_field, port_field, af) = match dir {
            Dir::Out => (
                CHAIN_ACCT_OUT,
                "daddr",
                "dport",
                if v6 { "ip6" } else { "ip" },
            ),
            // replies: granted host is the source of ingress packets
            Dir::In => (
                CHAIN_ACCT_IN,
                "saddr",
                "sport",
                if v6 { "ip6" } else { "ip" },
            ),
        };
        let counter = dir.counter(gid);
        self.cmds.push(json!({"add":{"rule":{
            "family":"inet","table":&self.table,"chain":chain,
            "comment":format!("gk:g{gid}:{}", dir.slug()),
            "expr":[
                {"match":{"op":"==","left":{"concat":[
                    {"payload":{"protocol":af,"field":addr_field}},
                    {"meta":{"key":"l4proto"}},
                    {"payload":{"protocol":proto.nft_key(),"field":port_field}}
                ]},"right":format!("@{}", acct_set(gid, dir, v6))}},
                {"counter":counter}
            ]
        }}}));
    }

    pub fn delete_set(&mut self, name: &str) {
        self.cmds.push(json!({"delete":{"set":{
            "family":"inet","table":&self.table,"name":name
        }}}));
    }

    pub fn is_empty(&self) -> bool {
        self.cmds.is_empty()
    }

    pub fn to_json(&self) -> String {
        json!({"nftables": &self.cmds}).to_string()
    }
}

/// State of one live grant element as read from the kernel.
#[derive(Clone, Debug)]
pub struct LiveElement {
    pub set: String,
    pub dst: String, // canonical "1.2.3.4" / "10.0.0.0/8"
    pub proto: Proto,
    pub port_from: u16,
    pub port_to: u16,
    pub expires_secs: f64,
    /// Attribution from add_grant (`gk:g<gid>`), if present. Not a security check.
    pub comment: Option<String>,
}

#[derive(Debug)]
pub struct PollState {
    pub elements: Vec<LiveElement>,
    /// named counters keyed by object name (gX_out / gX_in).
    pub counters: std::collections::HashMap<String, (u64, u64)>,
}

/// `nft` CLI backend: argv-pinned, env-cleared, JSON on stdin.
pub struct NftCli {
    pub bin: std::path::PathBuf,
    pub timeout: Duration,
}

impl Default for NftCli {
    fn default() -> Self {
        Self {
            bin: "/usr/sbin/nft".into(),
            timeout: Duration::from_secs(5),
        }
    }
}

impl NftCli {
    /// Apply a JSON batch atomically (nft processes a batch as one transact).
    pub async fn apply(&self, batch: &Batch) -> Result<(), NftError> {
        if batch.is_empty() {
            return Ok(());
        }
        let payload = batch.to_json();
        run_nft_json(&self.bin, &payload, self.timeout).await?;
        Ok(())
    }

    /// `nft --json -f` expects a JSON batch, not CLI text. Wraps `list <what>`.
    pub async fn list_json(
        &self,
        what: &str,
        arg: Option<serde_json::Value>,
    ) -> Result<Value, NftError> {
        let mut cmd = serde_json::Map::new();
        match arg {
            Some(a) => cmd.insert(what.to_string(), a),
            None => cmd.insert(what.to_string(), serde_json::json!({})),
        };
        let batch = json!({"nftables": [{"list": Value::Object(cmd)}]});
        let out = run_nft_json(&self.bin, &batch.to_string(), self.timeout).await?;
        Ok(serde_json::from_str(&out)?)
    }

    pub async fn poll_live(&self, table: &str) -> Result<PollState, NftError> {
        let t = self
            .list_json("table", Some(json!({"family": "inet", "name": table})))
            .await?;
        let c = self.list_json("counters", None).await?;
        Ok(parse_poll(&t, &c, table))
    }
}

async fn run_nft_json(
    bin: &std::path::Path,
    payload: &str,
    timeout: Duration,
) -> Result<String, NftError> {
    let mut cmd = Command::new(bin);
    cmd.env_clear();
    // nft 1.1.6: --json must precede -f.
    cmd.args(["--json", "-f", "-"]);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(NftError::Spawn)?;
    {
        use tokio::io::AsyncWriteExt;
        // A failed write means nft never saw the batch: surface it instead of
        // letting the child fail/hang on an empty stdin (apply miss).
        let mut si = child
            .stdin
            .take()
            .ok_or_else(|| NftError::Io(std::io::Error::other("stdin pipe unavailable")))?;
        si.write_all(payload.as_bytes())
            .await
            .map_err(NftError::Io)?;
        si.flush().await.map_err(NftError::Io)?;
        drop(si);
    }
    // take handles so the timeout path can still kill the child by &mut
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let read_out = async move {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        if let Some(mut s) = stdout {
            s.read_to_end(&mut buf).await.ok();
        }
        buf
    };
    let read_err = async move {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        if let Some(mut s) = stderr {
            s.read_to_end(&mut buf).await.ok();
        }
        buf
    };
    let status = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(s) => s.map_err(NftError::Spawn)?,
        Err(_) => {
            let _ = child.start_kill();
            // Reap the readers too: kill closes the pipes so they should EOF
            // promptly, but never leave them detached on our own timeout.
            let _ = tokio::time::timeout(timeout, async {
                let _ = read_out.await;
                let _ = read_err.await;
            })
            .await;
            return Err(NftError::Timeout(timeout));
        }
    };
    let stdout = read_out.await;
    let stderr = read_err.await;
    if !status.success() {
        return Err(NftError::Failed {
            code: status.code(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

/// Parse `nft --json list table` + `list counters` output into PollState.
pub fn parse_poll(doc: &Value, counters: &Value, tname: &str) -> PollState {
    let mut elements = Vec::new();
    if let Some(arr) = doc.get("nftables").and_then(|v| v.as_array()) {
        for item in arr {
            let Some(set) = item.get("set") else { continue };
            let name = set
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if name != SET_V4 && name != SET_V6 {
                continue;
            }
            let Some(elems) = set.get("elem").and_then(|v| v.as_array()) else {
                continue;
            };
            for el in elems {
                // live shape: {"elem":{"val":{"concat":[...]},"expires":f}}
                let wrapper = el.get("elem");
                let val = wrapper.and_then(|e| e.get("val")).or(el.get("val"));
                let Some(val) = val else { continue };
                // expires is a sibling of val (on the elem wrapper); tolerate both
                let expires = wrapper
                    .and_then(|w| w.get("expires"))
                    .or_else(|| val.get("expires"))
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                let comment = wrapper
                    .and_then(|w| w.get("comment"))
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let Some(concat) = val.get("concat").and_then(|v| v.as_array()) else {
                    continue;
                };
                if concat.len() != 3 {
                    continue;
                }
                let dst = match &concat[0] {
                    Value::String(s) => s.clone(),
                    v if v.get("prefix").is_some() => {
                        let a = v["prefix"]["addr"].as_str().unwrap_or("?");
                        let l = v["prefix"]["len"].as_u64().unwrap_or(0);
                        format!("{a}/{l}")
                    }
                    _ => continue,
                };
                let proto = match concat[1].as_str() {
                    Some("tcp") => Proto::Tcp,
                    Some("udp") => Proto::Udp,
                    // kernel echoes proto numerically in some contexts
                    Some(_) | None => {
                        if concat[1].as_u64() == Some(6) {
                            Proto::Tcp
                        } else {
                            Proto::Udp
                        }
                    }
                };
                let (pf, pt) = match &concat[2] {
                    Value::Number(n) => {
                        let p = n.as_u64().unwrap_or(0) as u16;
                        (p, p)
                    }
                    v if v.get("range").is_some() => {
                        let r = v["range"].as_array().unwrap();
                        (
                            r[0].as_u64().unwrap_or(0) as u16,
                            r[1].as_u64().unwrap_or(0) as u16,
                        )
                    }
                    _ => continue,
                };
                elements.push(LiveElement {
                    set: name.clone(),
                    dst,
                    proto,
                    port_from: pf,
                    port_to: pt,
                    expires_secs: expires,
                    comment,
                });
            }
        }
    }

    let mut cmap = std::collections::HashMap::new();
    if let Some(arr) = counters.get("nftables").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(c) = item.get("counter") {
                let name = c
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if name.is_empty() || c.get("table").and_then(|v| v.as_str()) != Some(tname) {
                    continue;
                }
                cmap.insert(
                    name,
                    (
                        c.get("packets").and_then(|v| v.as_u64()).unwrap_or(0),
                        c.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0),
                    ),
                );
            }
        }
    }
    PollState {
        elements,
        counters: cmap,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_never_emits_slash_string() {
        let e = GrantElem {
            dst: ElemDst::Net("10.0.0.0/8".parse::<IpNet>().unwrap()),
            proto: Proto::Tcp,
            port: PortSpec { from: 80, to: 443 },
        };
        let v = e.concat();
        let s = v.to_string();
        assert!(!s.contains("10.0.0.0/8"), "slash string would trigger DNS");
        assert!(s.contains("\"prefix\""));
        assert_eq!(e.set_name(), SET_V4);
    }

    #[test]
    fn wildcard_ports_and_v6_set_choice() {
        let e = GrantElem {
            dst: ElemDst::Ip(ip("fe80::1")),
            proto: Proto::Udp,
            port: PortSpec { from: 0, to: 0 },
        };
        assert_eq!(e.set_name(), SET_V6);
        let s = e.concat().to_string();
        assert!(s.contains("\"range\":[0,65535]"));
    }

    #[test]
    fn grant_add_uses_elem_wrapper() {
        let mut b = Batch::new();
        b.add_grant(
            &GrantElem {
                dst: ElemDst::Ip(ip("203.0.113.7")),
                proto: Proto::Tcp,
                port: PortSpec { from: 22, to: 22 },
            },
            Duration::from_secs(600),
            7,
        );
        let j: serde_json::Value = serde_json::from_str(&b.to_json()).unwrap();
        // serde_json sorts keys; check structure, not substrings
        let cmds = j["nftables"].as_array().unwrap();
        assert_eq!(cmds[0]["add"]["element"]["name"], "grants_v4");
        let e0 = &cmds[0]["add"]["element"]["elem"][0];
        assert_eq!(e0["elem"]["expires"], 600);
        assert_eq!(e0["elem"]["val"]["concat"][0], "203.0.113.7");
        assert_eq!(e0["elem"]["comment"], "gk:g7");
    }

    #[test]
    fn carve_batch_shape() {
        let mut b = Batch::new();
        b.ensure_carve_sets();
        b.flush_carves();
        b.add_carve(&GrantElem {
            dst: ElemDst::Ip("203.0.113.7".parse().unwrap()),
            proto: Proto::Tcp,
            port: PortSpec { from: 443, to: 443 },
        });
        let cmds = serde_json::from_str::<Value>(&b.to_json()).unwrap()["nftables"]
            .as_array()
            .unwrap()
            .clone();
        // carve sets have no timeout flag
        let s0 = &cmds[0]["add"]["set"];
        assert_eq!(s0["name"], "carve_v4");
        assert_eq!(s0["flags"], json!(["interval"]));
        // [0,1]=sets, [2,3]=flushes, [4]=elem
        assert!(cmds[2]["flush"]["set"]["name"].as_str() == Some("carve_v4"));
        let e = &cmds[4]["add"]["element"];
        assert_eq!(e["name"], "carve_v4");
        // plain concat, no expires/comment wrapper
        assert_eq!(e["elem"][0]["concat"][1], json!("tcp"));
        assert!(e["elem"][0]["concat"].is_array());
    }

    #[test]
    fn scope_rules_encode_policed_return_then_exempt_accept() {
        let mut b = Batch::new();
        b.rebuild_scope(&[990]);
        let cmds = &b.cmds;
        assert_eq!(
            cmds[0]["flush"]["chain"]["name"],
            serde_json::json!(CHAIN_SCOPE)
        );
        let policed = &cmds[1]["add"]["rule"];
        assert_eq!(policed["chain"], serde_json::json!(CHAIN_SCOPE));
        let exprs = policed["expr"].as_array().unwrap();
        assert_eq!(
            exprs[0]["match"]["left"],
            serde_json::json!({"meta":{"key":"skuid"}})
        );
        assert_eq!(exprs[0]["match"]["op"], serde_json::json!("=="));
        assert_eq!(exprs[0]["match"]["right"], serde_json::json!(990));
        assert!(exprs[1].get("return").is_some(), "policed uids must RETURN");
        let exempt = &cmds[2]["add"]["rule"];
        let exprs = exempt["expr"].as_array().unwrap();
        assert_eq!(exprs[0]["counter"], serde_json::json!(COUNTER_EXEMPT));
        assert!(exprs[1].get("accept").is_some(), "everyone else ACCEPTs");
    }

    #[test]
    fn scope_empty_list_means_no_exempt_rule() {
        let mut b = Batch::new();
        b.rebuild_scope(&[]);
        // flush only: no accept rule, all packets fall through to drop
        assert_eq!(b.cmds.len(), 1);
        assert!(b.cmds[0].get("flush").is_some());
    }

    /// Every command must target the batch's table. A missed substitution
    /// deletes from the wrong table (ENOENT) and used to break revoke/stop
    /// under a non-default nft_table.
    #[test]
    fn every_command_targets_the_batches_table() {
        let mut b = Batch::with_table("gk_alt");
        b.ensure_base();
        b.rebuild_scope(&[990]);
        let e = GrantElem {
            dst: ElemDst::Ip(ip("203.0.113.7")),
            proto: Proto::Tcp,
            port: PortSpec { from: 443, to: 443 },
        };
        b.add_grant(&e, Duration::from_secs(60), 7);
        b.delete_grant(&e);
        b.ensure_carve_sets();
        b.add_carve(&e);
        b.flush_carves();
        b.add_acct_set(7, Dir::Out, false);
        b.add_acct_elem(7, Dir::Out, &e);
        b.add_acct_rule(7, Dir::Out, Proto::Tcp, false);
        b.flush_chain(CHAIN_ACCT_OUT);
        b.add_counter("g7_out");
        b.delete_counter("g7_out");
        b.delete_set("gk_m7_out");

        fn walk(v: &Value, hits: &mut Vec<(String, Value)>) {
            match v {
                Value::Object(m) => {
                    for (k, x) in m {
                        if k == "table" {
                            // two shapes: `"table": "name"` inside element/
                            // rule ops, or `"table": {"family":..,"name":..}`
                            match x {
                                Value::String(_) => hits.push((k.clone(), x.clone())),
                                Value::Object(_) => {
                                    hits.push((k.clone(), serde_json::json!(x["name"])));
                                    walk(x, hits);
                                }
                                _ => {}
                            }
                        } else {
                            walk(x, hits);
                        }
                    }
                }
                Value::Array(a) => a.iter().for_each(|x| walk(x, hits)),
                _ => {}
            }
        }
        let mut hits = Vec::new();
        for cmd in &b.cmds {
            walk(cmd, &mut hits);
            for (k, v) in &hits {
                assert_eq!(
                    v,
                    &serde_json::json!("gk_alt"),
                    "command with {k} hit wrong table: {cmd}"
                );
            }
        }
        assert!(!hits.is_empty(), "batch emitted no table references at all");
    }

    #[test]
    fn acct_rule_is_counter_only_with_correct_fields() {
        let mut b = Batch::new();
        b.flush_chain(CHAIN_ACCT_OUT);
        b.add_counter(&counter_out(7));
        b.add_acct_set(7, Dir::Out, false);
        b.add_acct_elem(
            7,
            Dir::In,
            &GrantElem {
                dst: ElemDst::Net("10.0.0.0/8".parse().unwrap()),
                proto: Proto::Tcp,
                port: PortSpec { from: 443, to: 443 },
            },
        );
        b.add_acct_rule(7, Dir::In, Proto::Udp, true);
        let j: serde_json::Value = serde_json::from_str(&b.to_json()).unwrap();
        let cmds = j["nftables"].as_array().unwrap();

        assert_eq!(cmds[0]["flush"]["chain"]["name"], CHAIN_ACCT_OUT);
        // In-direction + v6: rule must match ip6 saddr . l4proto . udp sport,
        // count into gk_g7_in, and carry NO verdict expr.
        let r = &cmds[4]["add"]["rule"];
        assert_eq!(r["chain"], CHAIN_ACCT_IN);
        assert_eq!(r["comment"], "gk:g7:in");
        let exprs = r["expr"].as_array().unwrap();
        assert_eq!(exprs.len(), 2, "match + counter only — never a verdict");
        assert_eq!(exprs[1]["counter"], "gk_g7_in");
        let lc = exprs[0]["match"]["left"]["concat"].as_array().unwrap();
        assert_eq!(lc[0]["payload"]["protocol"], "ip6");
        assert_eq!(lc[0]["payload"]["field"], "saddr");
        assert_eq!(lc[2]["payload"]["protocol"], "udp");
        assert_eq!(lc[2]["payload"]["field"], "sport");
        assert!(exprs[0]["match"]["right"]
            .as_str()
            .unwrap()
            .starts_with("@gk_m7_in"));
        // out-direction set uses daddr/dport keys (cmds[2]); the in-direction
        // element (cmds[3]) lands in gk_m7_in with the safe prefix encoding.
        let s_out = &cmds[2]["add"]["set"];
        assert_eq!(s_out["name"], "gk_m7_out");
        assert_eq!(
            s_out["type"]["typeof"]["concat"][0]["payload"]["field"],
            "daddr"
        );
        assert_eq!(
            s_out["type"]["typeof"]["concat"][2]["payload"]["field"],
            "dport"
        );
        let e = &cmds[3]["add"]["element"];
        assert_eq!(e["name"], "gk_m7_in");
        assert!(e["elem"][0]["concat"][0].get("prefix").is_some());
    }

    #[test]
    fn elemdst_canonical_roundtrip() {
        for s in ["10.9.9.9", "fe80::1", "172.16.0.0/12", "2001:db8::/32"] {
            let e = ElemDst::from_canonical(s).expect(s);
            assert_eq!(e.canonical(), s);
        }
        assert!(ElemDst::from_canonical("evil\"hostname").is_none());
        assert!(ElemDst::Ip("::2".parse().unwrap()).is_v6());
    }

    #[test]
    fn parses_live_element_shapes() {
        let table = json!({"nftables":[
            {"set":{"name":SET_V4,"family":"inet","table":TABLE,
                "elem":[{"elem":{"val":{"concat":["1.2.3.4","tcp",53]},"expires":41.9}},
                        {"elem":{"val":{"concat":[{"prefix":{"addr":"10.0.0.0","len":8}},"udp",
                            {"range":[8000,8100]}]},"expires":12.0,"comment":"gk:g7"}}]}}
        ]});
        let counters = json!({"nftables":[
            {"counter":{"name":"g7_out","table":TABLE,"packets":3,"bytes":120}},
            {"counter":{"name":"other","table":"elsewhere","packets":9,"bytes":9}}
        ]});
        let st = parse_poll(&table, &counters, TABLE);
        assert_eq!(st.elements.len(), 2);
        assert!((st.elements[0].expires_secs - 41.9).abs() < 0.01);
        assert_eq!(st.elements[1].dst, "10.0.0.0/8");
        assert_eq!(
            (st.elements[1].port_from, st.elements[1].port_to),
            (8000, 8100)
        );
        assert_eq!(st.elements[0].comment, None);
        assert_eq!(st.elements[1].comment.as_deref(), Some("gk:g7"));
        assert_eq!(st.counters.get("g7_out"), Some(&(3u64, 120u64)));
        assert!(!st.counters.contains_key("other"));
    }
}
