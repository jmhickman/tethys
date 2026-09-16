//! nftables batch construction + execution.
//!
//! Every encoding here was empirically verified on nft 1.1.6 against this
//! kernel — see tool-planning/01-nftables-probe.md ("JSON API input encodings").
//! Notably: CIDR elements MUST be `{"prefix":{...}}` objects (a "a.b.c.d/nn"
//! string is parsed as a hostname → DNS lookup), per-element TTL goes in the
//! `{"elem":{"val":...,"expires":N}}` wrapper, and batches apply atomically.

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
/// Accounting chains (declared empty by the static baseline, contents owned by
/// gatekeeper). Rules here carry COUNTERS ONLY — never a verdict — so they can
/// never bypass egress enforcement even if they drift or outlive a grant.
pub const CHAIN_ACCT_OUT: &str = "acct_out";
pub const CHAIN_ACCT_IN: &str = "acct_in";
/// Long default so per-element `expires` is the only thing that reaps grants.
const SET_DEFAULT_TIMEOUT_SECS: u64 = 24 * 3600;

/// Per-grant accounting object names (survive element expiry by design, R4).
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

/// Accounting direction. Out = packets we send to a granted tuple;
/// In = established replies whose SOURCE is the granted tuple (probe-verified
/// reply-tuple trick — `ct original` concats don't parse on this nft build).
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

    /// concat value components — the verified-safe encoding.
    fn concat(&self) -> Value {
        let dst = match &self.dst {
            ElemDst::Ip(ip) => json!(ip.to_string()),
            // NEVER a "ip/len" string: nft parses it as a hostname.
            ElemDst::Net(n) => json!({"prefix": {"addr": n.network().to_string(), "len": n.prefix_len()}}),
        };
        let (f, t) = self.port.nft_range();
        let port = if f == t {
            json!(f)
        } else {
            json!({"range": [f, t]})
        };
        json!({"concat": [dst, self.proto.nft_key(), port]})
    }

    fn delete_cmd(&self) -> Value {
        json!({"delete": {"element": {
            "family": "inet", "table": TABLE, "name": self.set_name(),
            "elem": [self.concat()]
        }}})
    }
}

/// Builder for the JSON command array shipped to `nft --json -f -`.
#[derive(Default, Clone, Debug)]
pub struct Batch(Vec<Value>);

impl Batch {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ensure our table exists (idempotent — nft treats add-existing as OK).
    pub fn ensure_table(&mut self) {
        self.0
            .push(json!({"add":{"table":{"family":"inet","name":TABLE}}}));
    }

    fn push_grant_set(&mut self, name: &str, proto_field: &str) {
        let addr_field = if proto_field == "ip" { "daddr" } else { "daddr" };
        self.0.push(json!({"add":{"set":{
            "family":"inet","table":TABLE,"name":name,
            "type":{"typeof":{"concat":[
                {"payload":{"protocol":proto_field,"field":addr_field}},
                {"meta":{"key":"l4proto"}},
                {"payload":{"protocol":"th","field":"dport"}}
            ]}},
            "flags":["interval","timeout"],
            "timeout":SET_DEFAULT_TIMEOUT_SECS
        }}}));
    }

    /// Base objects owned by the gatekeeper (decision: gatekeeper owns its own
    /// table, separate from any static drop-in table). Idempotent adds.
    pub fn ensure_base(&mut self) {
        self.ensure_table();
        self.push_grant_set(SET_V4, "ip");
        self.push_grant_set(SET_V6, "ip6");
        // Accounting chains: declared by the static baseline too (reload is
        // idempotent), but ensured here so dev runs without the drop-in work.
        for (chain, hook) in [(CHAIN_ACCT_OUT, "output"), (CHAIN_ACCT_IN, "input")] {
            self.0.push(json!({"add":{"chain":{
                "family":"inet","table":TABLE,"name":chain,
                "hook":hook,"type":"filter","prio":-10,"policy":"accept"
            }}}));
        }
    }

    /// Install one grant element with a per-element kernel TTL.
    pub fn add_grant(&mut self, e: &GrantElem, ttl: Duration) {
        self.0.push(json!({"add":{"element":{
            "family":"inet","table":TABLE,"name":e.set_name(),
            "elem":[{"elem":{"val": e.concat(), "expires": ttl.as_secs()}}]
        }}}));
    }

    pub fn delete_grant(&mut self, e: &GrantElem) {
        self.0.push(e.delete_cmd());
    }

    /// Delete a whole counter object (revoke cleanup).
    pub fn delete_counter(&mut self, name: &str) {
        self.0.push(json!({"delete":{"counter":{
            "family":"inet","table":TABLE,"name":name
        }}}));
    }

    // ------------------------------------------------ accounting (R4)
    // Rules in acct chains carry a named counter and NOTHING ELSE — no
    // verdict, so they cannot grant reachability even if stale. Chains are
    // rebuilt wholesale (flush + re-add from ledger): idempotent, handle-free.

    pub fn flush_chain(&mut self, chain: &str) {
        self.0.push(json!({"flush":{"chain":{
            "family":"inet","table":TABLE,"name":chain
        }}}));
    }

    pub fn add_counter(&mut self, name: &str) {
        self.0.push(json!({"add":{"counter":{
            "family":"inet","table":TABLE,"name":name
        }}}));
    }

    /// Per-grant match set; key order mirrors the enforcement sets but the
    /// address/port fields flip per direction (reply packets carry the granted
    /// host as *source*, probe-verified reply-tuple trick).
    pub fn add_acct_set(&mut self, gid: i64, dir: Dir, v6: bool) {
        let af = if v6 { "ip6" } else { "ip" };
        let (addr_field, port_field) = match dir {
            Dir::Out => ("daddr", "dport"),
            Dir::In => ("saddr", "sport"),
        };
        self.0.push(json!({"add":{"set":{
            "family":"inet","table":TABLE,"name":acct_set(gid, dir, v6),
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
        self.0.push(json!({"add":{"element":{
            "family":"inet","table":TABLE,"name":name,
            "elem":[e.concat()]
        }}}));
    }

    /// Count-only rule: match @set . proto variant . counter, no verdict.
    pub fn add_acct_rule(&mut self, gid: i64, dir: Dir, proto: Proto, v6: bool) {
        let (chain, addr_field, port_field, af) = match dir {
            Dir::Out => (CHAIN_ACCT_OUT, "daddr", "dport", if v6 { "ip6" } else { "ip" }),
            // replies: granted host is the SOURCE of ingress packets
            Dir::In => (CHAIN_ACCT_IN, "saddr", "sport", if v6 { "ip6" } else { "ip" }),
        };
        let counter = dir.counter(gid);
        self.0.push(json!({"add":{"rule":{
            "family":"inet","table":TABLE,"chain":chain,
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
        self.0.push(json!({"delete":{"set":{
            "family":"inet","table":TABLE,"name":name
        }}}));
    }

    /// Full table wipe (test/recovery only — real enforcement relies on the
    /// static base table + element expiry; see design doc).
    pub fn wipe_table(&mut self) {
        self.0.push(json!({"delete":{"table":{"family":"inet","name":TABLE}}}));
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn to_json(&self) -> String {
        json!({"nftables": &self.0}).to_string()
    }
}

/// State of one live grant element as read from the kernel.
#[derive(Clone, Debug)]
pub struct LiveElement {
    pub set: String,
    pub dst: String,     // canonical "1.2.3.4" / "10.0.0.0/8"
    pub proto: Proto,
    pub port_from: u16,
    pub port_to: u16,
    pub expires_secs: f64,
}

#[derive(Debug)]
pub struct PollState {
    pub elements: Vec<LiveElement>,
    /// named counters keyed by object name (gX_out / gX_in).
    pub counters: std::collections::HashMap<String, (u64, u64)>,
}

/// Execution backend (generic dispatch — no dyn needed; AFIT via edition 2021).
/// Kept as a trait so the netlink path stays possible later.
pub trait NftBackend {
    fn apply<'a>(
        &'a self,
        batch: &'a Batch,
    ) -> impl std::future::Future<Output = Result<(), NftError>> + Send;
}

/// The `nft` CLI backend — argv-pinned, env-cleared, JSON over stdin only
/// (hardening rules from 01-nft-access-surface.md §6).
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

impl NftBackend for NftCli {
    async fn apply(&self, batch: &Batch) -> Result<(), NftError> {
        if batch.is_empty() {
            return Ok(());
        }
        let payload = batch.to_json();
        run_nft_json(&self.bin, &payload, self.timeout).await?;
        Ok(())
    }
}

impl NftCli {
    /// JSON-mode list runs MUST be JSON command batches (`--json` makes -f expect
    /// JSON, not CLI text). Wraps a `list <what>` op into the batch envelope.
    pub async fn list_json(&self, what: &str, arg: Option<serde_json::Value>) -> Result<Value, NftError> {
        let mut cmd = serde_json::Map::new();
        match arg {
            Some(a) => cmd.insert(what.to_string(), a),
            None => cmd.insert(what.to_string(), serde_json::json!({})),
        };
        let batch = json!({"nftables": [{"list": Value::Object(cmd)}]});
        let out = run_nft_json(&self.bin, &batch.to_string(), self.timeout).await?;
        Ok(serde_json::from_str(&out)?)
    }

    pub async fn poll_live(&self) -> Result<PollState, NftError> {
        let t = self
            .list_json("table", Some(json!({"family": "inet", "name": TABLE})))
            .await?;
        let c = self.list_json("counters", None).await?;
        Ok(parse_poll(&t, &c))
    }
}

async fn run_nft_json(
    bin: &std::path::Path,
    payload: &str,
    timeout: Duration,
) -> Result<String, NftError> {
    let mut cmd = Command::new(bin);
    cmd.env_clear();
    // --json MUST precede -f on nft 1.1.6 (verified).
    cmd.args(["--json", "-f", "-"]);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(NftError::Spawn)?;
    {
        use tokio::io::AsyncWriteExt;
        let mut si = child.stdin.take().unwrap();
        si.write_all(payload.as_bytes()).await.ok();
        si.flush().await.ok();
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
pub fn parse_poll(table: &Value, counters: &Value) -> PollState {
    let mut elements = Vec::new();
    if let Some(arr) = table.get("nftables").and_then(|v| v.as_array()) {
        for item in arr {
            let Some(set) = item.get("set") else { continue };
            let name = set.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if name != SET_V4 && name != SET_V6 {
                continue;
            }
            let Some(elems) = set.get("elem").and_then(|v| v.as_array()) else {
                continue;
            };
            for el in elems {
                // live shape: {"elem":{"val":{"concat":[...]},"expires":f}}
                let wrapper = el.get("elem");
                let val = wrapper
                    .and_then(|e| e.get("val"))
                    .or(el.get("val"));
                let Some(val) = val else { continue };
                // expires is a sibling of val (on the elem wrapper); tolerate both
                let expires = wrapper
                    .and_then(|w| w.get("expires"))
                    .or_else(|| val.get("expires"))
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
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
                });
            }
        }
    }

    let mut cmap = std::collections::HashMap::new();
    if let Some(arr) = counters.get("nftables").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(c) = item.get("counter") {
                let name = c.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if name.is_empty() || c.get("table").and_then(|v| v.as_str()) != Some(TABLE) {
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
        assert!(!s.contains("10.0.0.0/8"), "slash string would trigger DNS!");
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
        );
        let j: serde_json::Value = serde_json::from_str(&b.to_json()).unwrap();
        // structural check (serde_json sorts keys, so no substring assumptions):
        let cmds = j["nftables"].as_array().unwrap();
        assert_eq!(cmds[0]["add"]["element"]["name"], "grants_v4");
        let e0 = &cmds[0]["add"]["element"]["elem"][0];
        assert_eq!(e0["elem"]["expires"], 600);
        assert_eq!(e0["elem"]["val"]["concat"][0], "203.0.113.7");
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
        assert_eq!(s_out["type"]["typeof"]["concat"][0]["payload"]["field"], "daddr");
        assert_eq!(s_out["type"]["typeof"]["concat"][2]["payload"]["field"], "dport");
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
                            {"range":[8000,8100]}]},"expires":12.0}}]}}
        ]});
        let counters = json!({"nftables":[
            {"counter":{"name":"g7_out","table":TABLE,"packets":3,"bytes":120}},
            {"counter":{"name":"other","table":"elsewhere","packets":9,"bytes":9}}
        ]});
        let st = parse_poll(&table, &counters);
        assert_eq!(st.elements.len(), 2);
        assert!((st.elements[0].expires_secs - 41.9).abs() < 0.01);
        assert_eq!(st.elements[1].dst, "10.0.0.0/8");
        assert_eq!((st.elements[1].port_from, st.elements[1].port_to), (8000, 8100));
        assert_eq!(st.counters.get("g7_out"), Some(&(3u64, 120u64)));
        assert!(!st.counters.contains_key("other"));
    }
}
