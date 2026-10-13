//! nftables JSON batch construction and execution.
//!
//! nft 1.1.6 encoding: CIDR elements must be `{"prefix":{...}}` objects (an
//! "a.b.c.d/nn" string is parsed as a hostname), per-element TTL lives in
//! `{"elem":{"val":...,"expires":N}}`, and batches apply atomically.
//!
//! Enforcement runs inside the agent's dedicated network namespace: every
//! batch goes through [`ExecTarget`], which either `setns`s into a cached,
//! inode-revalidated netns fd ([`Netns`]) or runs on the host stack (routed
//! mode's delegated-port DNAT chain). No call site spawns `nft` ad hoc.

use std::net::IpAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use ipnet::IpNet;
use serde_json::{json, Value};
use thiserror::Error;
use tokio::process::Command;

use crate::types::{Direction, PortSpec, Proto};

pub const TABLE: &str = "tethys";
/// Egress grant sets: key is `ip daddr . meta l4proto . th dport`.
pub const SET_V4: &str = "grants_v4";
pub const SET_V6: &str = "grants_v6";
/// Ingress counterpart sets. Same element grammar with the address slot
/// flipped to `saddr`: an ingress grant matches source . proto . LOCAL port
/// (th dport on inbound packets is the local listener's port). The element
/// JSON is identical for both families; only the set typing differs.
pub const SET_IGRANT_V4: &str = "igrants_v4";
pub const SET_IGRANT_V6: &str = "igrants_v6";
/// Operator allow-list tuples (`allow`/`allow_in` in config). Flush+reinstall
/// from config; live in the carve sets so stop.grants does not touch them.
pub const SET_CARVE_V4: &str = "carve_v4";
pub const SET_CARVE_V6: &str = "carve_v6";
/// Ingress operator allow list (`allow_in`): saddr-keyed like the igrants.
pub const SET_CARVE_IN_V4: &str = "carve_in_v4";
pub const SET_CARVE_IN_V6: &str = "carve_in_v6";
/// Base chains with policy drop, built here (the static baseline.nft is
/// retired — the Rust builder is the single source of enforcement truth).
/// Inside the netns everything belongs to the policed account by
/// construction, so these carry no uid expressions: pure header filtering.
pub const CHAIN_EGRESS: &str = "egress";
pub const CHAIN_INGRESS: &str = "ingress";
/// Accounting chains (contents owned here). Rules carry counters and no
/// verdict, so they cannot bypass enforcement.
pub const CHAIN_ACCT_OUT: &str = "acct_out";
pub const CHAIN_ACCT_IN: &str = "acct_in";
/// Drop counters (rate-limited log + drop at the end of each base chain).
pub const COUNTER_DROPS: &str = "tethys_drops";
pub const COUNTER_DROPS_IN: &str = "tethys_drops_in";
pub const LOG_PREFIX_EGRESS: &str = "TETHYS-DROP: ";
pub const LOG_PREFIX_INGRESS: &str = "TETHYS-DROP-IN: ";
/// Long default so per-element `expires` is the only thing that reaps grants.
const SET_DEFAULT_TIMEOUT_SECS: u64 = 24 * 3600;
/// Drop-log rate cap (packets/sec) shared by both base chains, mirroring
/// `limit rate 20/second` in the retired static baseline.
const DROP_LOG_RATE: u32 = 20;

/// Per-grant accounting object names. These outlive the grant's set element:
/// counters are swept only when the ledger row leaves the approved state.
pub fn counter_out(gid: i64) -> String {
    format!("tethys_g{gid}_out")
}
pub fn counter_in(gid: i64) -> String {
    format!("tethys_g{gid}_in")
}
/// Per-grant match set for one direction+family: tethys_m7_out_v4 etc.
pub fn acct_set(gid: i64, dir: Dir, v6: bool) -> String {
    format!(
        "tethys_m{gid}_{}{}",
        dir.slug(),
        if v6 { "_v6" } else { "" }
    )
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
    #[error("cannot open netns {path}: {src}")]
    NetnsOpen { path: String, src: std::io::Error },
    #[error(
        "netns path {path} no longer exists (cached fd survives) — namespace was deleted; \
         re-provision before applying batches"
    )]
    NetnsGone { path: String },
    #[error(
        "netns at {path} changed inode since it was opened ({cached_ino} -> {found_ino}) — \
         namespace was recreated; reopen required, refusing to act on a foreign stack"
    )]
    NetnsReplaced {
        path: String,
        cached_ino: u64,
        found_ino: u64,
    },
}

/// The agent account's network namespace, opened once and cached. Every
/// namespaced batch revalidates the path against the cached fd's inode
/// before spawning, so a deleted or recreated netns fails loudly instead of
/// silently applying to whatever stack now owns that path (including the
/// host one). Cheap: two stat calls per batch.
#[derive(Debug)]
pub struct Netns {
    path: PathBuf,
    file: std::fs::File,
    ino: u64,
}

impl Netns {
    /// Open `/run/netns/<name>` (any readable nsfs file) and pin its inode.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, NftError> {
        let path = path.as_ref().to_path_buf();
        let file = std::fs::File::open(&path).map_err(|src| NftError::NetnsOpen {
            path: path.display().to_string(),
            src,
        })?;
        let ino = Self::ino_of(&file)?;
        Ok(Self { path, file, ino })
    }

    fn ino_of(f: &std::fs::File) -> Result<u64, NftError> {
        f.metadata().map(|m| m.ino()).map_err(NftError::Io)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Raw fd to `setns` into from a child (see [`setns_pre_exec`]).
    pub fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    /// Fail-closed check that the cached fd still refers to the namespace at
    /// `path`: the path must exist and its inode must match. Called by every
    /// namespaced batch before the spawn.
    pub fn revalidate(&self) -> Result<(), NftError> {
        let found = std::fs::metadata(&self.path).map_err(|_| NftError::NetnsGone {
            path: self.path.display().to_string(),
        })?;
        if found.ino() != self.ino {
            return Err(NftError::NetnsReplaced {
                path: self.path.display().to_string(),
                cached_ino: self.ino,
                found_ino: found.ino(),
            });
        }
        Ok(())
    }
}

/// Where `nft` subprocesses run. `Host` is for the host-stack projection
/// (routed mode's delegated-port DNAT chain); `Netns` applies inside the
/// agent namespace through [`setns_pre_exec`].
#[derive(Clone, Debug, Default)]
pub enum ExecTarget {
    /// Batches run on the host stack (dev default + routed-mode projection).
    #[default]
    Host,
    /// Batches `setns` into the agent namespace first.
    Netns(Arc<Netns>),
}

/// `pre_exec` hook that moves the child into `fd`'s network namespace before
/// exec. Works with both std and tokio `Command`. The fd is inherited across
/// the fork, so its CLOEXEC flag (std sets it) is cleared in the child first;
/// clearing happens post-fork, so the parent's flag is untouched.
pub fn setns_pre_exec(fd: RawFd) -> impl FnMut() -> std::io::Result<()> + Send + Sync + 'static {
    move || {
        // SAFETY: post-fork/pre-exec child context. `fcntl` and `setns` are
        // plain syscalls (no allocator, no locks); the fd is a long-lived
        // parent-owned handle to an nsfs file. Audit note for the
        // workspace unsafe_code="deny" policy.
        #[allow(unsafe_code)]
        let rc = unsafe {
            libc::fcntl(fd, libc::F_SETFD, 0);
            libc::setns(fd, libc::CLONE_NEWNET)
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
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
    pub fn set_name(&self, dir: Direction) -> &'static str {
        match (&self.dst, dir) {
            (ElemDst::Ip(IpAddr::V4(_)) | ElemDst::Net(IpNet::V4(_)), Direction::Egress) => SET_V4,
            (ElemDst::Ip(IpAddr::V6(_)) | ElemDst::Net(IpNet::V6(_)), Direction::Egress) => SET_V6,
            (ElemDst::Ip(IpAddr::V4(_)) | ElemDst::Net(IpNet::V4(_)), Direction::Ingress) => {
                SET_IGRANT_V4
            }
            (ElemDst::Ip(IpAddr::V6(_)) | ElemDst::Net(IpNet::V6(_)), Direction::Ingress) => {
                SET_IGRANT_V6
            }
        }
    }

    /// Carve-set counterpart (operator allow list): same key grammar, but the
    /// carve sets carry no timeout flag, so elements persist until reinstalled.
    pub fn carve_set_name(&self, dir: Direction) -> &'static str {
        match (&self.dst, dir) {
            (ElemDst::Ip(IpAddr::V4(_)) | ElemDst::Net(IpNet::V4(_)), Direction::Egress) => {
                SET_CARVE_V4
            }
            (ElemDst::Ip(IpAddr::V6(_)) | ElemDst::Net(IpNet::V6(_)), Direction::Egress) => {
                SET_CARVE_V6
            }
            (ElemDst::Ip(IpAddr::V4(_)) | ElemDst::Net(IpNet::V4(_)), Direction::Ingress) => {
                SET_CARVE_IN_V4
            }
            (ElemDst::Ip(IpAddr::V6(_)) | ElemDst::Net(IpNet::V6(_)), Direction::Ingress) => {
                SET_CARVE_IN_V6
            }
        }
    }

    /// Build the `[dst, proto, port]` concat key. CIDR destinations use
    /// `prefix` objects because nft parses a slash string as a hostname.
    fn concat(&self) -> Value {
        let dst = match &self.dst {
            ElemDst::Ip(ip) => json!(ip.to_string()),
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
/// (`nft_table`, default "tethys"); tests use a private table.
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

    /// Ensure our table exists (idempotent: nft treats add-existing as OK).
    pub fn ensure_table(&mut self) {
        self.cmds
            .push(json!({"add":{"table":{"family":"inet","name":&self.table}}}));
    }

    fn push_grant_set(&mut self, name: &str, proto_field: &str, addr_field: &str) {
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

    /// One rule in a base chain: `exprs` is the full expression list.
    fn push_rule(&mut self, chain: &str, exprs: Vec<Value>) {
        self.cmds.push(json!({"add":{"rule":{
            "family":"inet","table":&self.table,"chain":chain,"expr":exprs
        }}}));
    }

    /// Counted, rate-limit-logged verdict rule closing a base chain.
    fn push_drop_rule(&mut self, chain: &str, counter: &str, prefix: &str) {
        self.push_rule(
            chain,
            vec![
                json!({"counter": counter}),
                json!({"limit":{"rate": DROP_LOG_RATE, "unit":"second"}}),
                json!({"log":{"prefix": prefix}}),
                json!({"drop":null}),
            ],
        );
    }

    /// Idempotent build of the full netns table: table, grant sets (egress
    /// daddr-keyed, ingress saddr-keyed), carve sets, drop counters, acct
    /// chains, and both hooked base chains with their complete rule bodies.
    /// The static baseline.nft is retired; this builder is the single source
    /// of enforcement truth, and there are no uid expressions anywhere —
    /// inside the namespace every packet belongs to the policed account by
    /// construction (INGRESS-REVIEW.md: `meta skuid` cannot name a listener
    /// at input anyway). Idempotent via flush-and-rebuild of the base chain
    /// rule bodies inside the same atomic batch.
    pub fn ensure_base(&mut self) {
        self.ensure_table();
        self.push_grant_set(SET_V4, "ip", "daddr");
        self.push_grant_set(SET_V6, "ip6", "daddr");
        self.push_grant_set(SET_IGRANT_V4, "ip", "saddr");
        self.push_grant_set(SET_IGRANT_V6, "ip6", "saddr");
        self.ensure_carve_sets();
        self.add_counter(COUNTER_DROPS);
        self.add_counter(COUNTER_DROPS_IN);
        for (chain, hook) in [(CHAIN_ACCT_OUT, "output"), (CHAIN_ACCT_IN, "input")] {
            self.cmds.push(json!({"add":{"chain":{
                "family":"inet","table":&self.table,"name":chain,
                "hook":hook,"type":"filter","prio":-10,"policy":"accept"
            }}}));
        }
        for (chain, hook) in [(CHAIN_EGRESS, "output"), (CHAIN_INGRESS, "input")] {
            self.cmds.push(json!({"add":{"chain":{
                "family":"inet","table":&self.table,"name":chain,
                "hook":hook,"type":"filter","prio":0,"policy":"drop"
            }}}));
        }
        self.flush_chain(CHAIN_EGRESS);
        self.flush_chain(CHAIN_INGRESS);

        // Egress: loopback and replies pass; DHCP/DNS/ICMP always resolve
        // (resolution is never blocked); carve then grant lookups; else drop.
        self.push_rule(
            CHAIN_EGRESS,
            vec![
                json!({"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"lo"}}),
                json!({"accept":null}),
            ],
        );
        self.push_ct_established_accept(CHAIN_EGRESS);
        for proto in ["icmp", "icmpv6"] {
            self.push_rule(
                CHAIN_EGRESS,
                vec![
                    json!({"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":proto}}),
                    json!({"accept":null}),
                ],
            );
        }
        // DHCP (v4 client/server, v6) — before proto-port lookups so it is
        // never hostage to a grant.
        self.push_rule(
            CHAIN_EGRESS,
            vec![
                json!({"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"udp"}}),
                json!({"match":{"op":"in","left":{"payload":{"protocol":"th","field":"dport"}},
                                 "right":[67, 68, 546, 547]}}),
                json!({"accept":null}),
            ],
        );
        for proto in ["udp", "tcp"] {
            self.push_rule(
                CHAIN_EGRESS,
                vec![
                    json!({"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":proto}}),
                    json!({"match":{"op":"==","left":{"payload":{"protocol":"th","field":"dport"}},
                                     "right":53}}),
                    json!({"accept":null}),
                ],
            );
        }
        self.push_set_lookups(
            CHAIN_EGRESS,
            "daddr",
            [SET_CARVE_V4, SET_CARVE_V6, SET_V4, SET_V6],
        );
        self.push_drop_rule(CHAIN_EGRESS, COUNTER_DROPS, LOG_PREFIX_EGRESS);

        // Ingress: loopback and replies pass; ICMP/ICMPv6 must pass or NDP
        // and PMTU break the namespace outright (INGRESS-REVIEW.md: omitting
        // these is how a fix becomes an outage). Everything else is gated by
        // carve_in/igrant lookups on saddr . l4proto . local dport.
        self.push_rule(
            CHAIN_INGRESS,
            vec![
                json!({"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lo"}}),
                json!({"accept":null}),
            ],
        );
        self.push_ct_established_accept(CHAIN_INGRESS);
        for proto in ["icmp", "icmpv6"] {
            self.push_rule(
                CHAIN_INGRESS,
                vec![
                    json!({"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":proto}}),
                    json!({"accept":null}),
                ],
            );
        }
        self.push_set_lookups(
            CHAIN_INGRESS,
            "saddr",
            [
                SET_CARVE_IN_V4,
                SET_CARVE_IN_V6,
                SET_IGRANT_V4,
                SET_IGRANT_V6,
            ],
        );
        self.push_drop_rule(CHAIN_INGRESS, COUNTER_DROPS_IN, LOG_PREFIX_INGRESS);
    }

    /// `ct state established,related accept` — replies are never re-gated.
    /// (Live-flow kill on revoke/expiry is step 4; until a flow dies, its
    /// packets ride this rule.)
    fn push_ct_established_accept(&mut self, chain: &str) {
        self.push_rule(
            chain,
            vec![
                json!({"match":{"op":"in","left":{"ct":{"key":"state"}},
                                 "right":[{"established":null},{"related":null}]}}),
                json!({"accept":null}),
            ],
        );
    }

    /// `ip saddr|daddr . meta l4proto . <proto> dport @set accept` — the
    /// production-proven concat-match shape (same grammar as add_acct_rule).
    /// One tcp + one udp rule per set; family from the set name suffix.
    fn push_set_lookups(
        &mut self,
        chain: &str,
        addr_field: &str,
        sets: impl IntoIterator<Item = &'static str>,
    ) {
        for set in sets {
            let af = if set.ends_with("_v6") { "ip6" } else { "ip" };
            for proto in [Proto::Tcp, Proto::Udp] {
                self.push_rule(
                    chain,
                    vec![
                        json!({"match":{"op":"==","left":{"concat":[
                            {"payload":{"protocol":af,"field":addr_field}},
                            {"meta":{"key":"l4proto"}},
                            {"payload":{"protocol":proto.nft_key(),"field":"dport"}}
                        ]},"right":format!("@{set}")}}),
                        json!({"accept":null}),
                    ],
                );
            }
        }
    }

    /// Add a grant element with kernel TTL and `tethys:g<gid>` comment.
    /// Comment persists in the live dump; concat deletes still match.
    /// `dir` picks the egress (daddr-keyed) or ingress (saddr-keyed) family:
    /// the element JSON is identical for both — th dport on inbound packets
    /// IS the local port, exactly what an ingress grant constrains. Only the
    /// set typing (which header field `addr` reads) differs.
    pub fn add_grant(&mut self, e: &GrantElem, ttl: Duration, gid: i64, dir: Direction) {
        self.cmds.push(json!({"add":{"element":{
            "family":"inet","table":&self.table,"name":e.set_name(dir),
            "elem":[{"elem":{"val": e.concat(), "expires": ttl.as_secs(),
                              "comment": format!("tethys:g{gid}")}}]
        }}}));
    }

    pub fn delete_grant(&mut self, e: &GrantElem, dir: Direction) {
        self.delete_in(e, e.set_name(dir))
    }

    /// Allow-list element: same key as a grant, no timeout/comment.
    /// Callers must `flush_carves()` first, because deleting a missing element
    /// aborts the whole nft batch.
    pub fn add_carve(&mut self, e: &GrantElem, dir: Direction) {
        self.cmds.push(json!({"add":{"element":{
            "family":"inet","table":&self.table,"name":e.carve_set_name(dir),
            "elem":[e.concat()]
        }}}));
    }

    /// Flush all four carve sets (egress + ingress) before reinstalling from
    /// config.
    pub fn flush_carves(&mut self) {
        for name in [SET_CARVE_V4, SET_CARVE_V6, SET_CARVE_IN_V4, SET_CARVE_IN_V6] {
            self.cmds.push(json!({"flush":{"set":{
                "family":"inet","table":&self.table,"name":name
            }}}));
        }
    }

    /// Add a port (or range) element to an `inet_service` interval set —
    /// routed mode's host-stack delegated-port sets. `nft_range` maps the
    /// all-ports wildcard to the full space.
    pub fn add_port(&mut self, set: &str, port: &PortSpec) {
        let (lo, hi) = port.nft_range();
        let elem = if lo == hi {
            lo.to_string()
        } else {
            format!("{lo}-{hi}")
        };
        self.cmds.push(json!({"add":{"element":{
            "family":"inet","table":&self.table,"name":set,"elem":[elem]
        }}}));
    }

    /// Delete a port element (not idempotent: deleting a missing element
    /// aborts the batch, so callers diff against `NftCli::set_ports`).
    pub fn delete_port(&mut self, set: &str, port: &PortSpec) {
        let (lo, hi) = port.nft_range();
        let elem = if lo == hi {
            lo.to_string()
        } else {
            format!("{lo}-{hi}")
        };
        self.cmds.push(json!({"delete":{"element":{
            "family":"inet","table":&self.table,"name":set,"elem":[elem]
        }}}));
    }

    /// Ensure carve sets exist. Ingress carves are saddr-keyed like the
    /// igrant sets.
    pub fn ensure_carve_sets(&mut self) {
        for (name, proto_field, addr_field) in [
            (SET_CARVE_V4, "ip", "daddr"),
            (SET_CARVE_V6, "ip6", "daddr"),
            (SET_CARVE_IN_V4, "ip", "saddr"),
            (SET_CARVE_IN_V6, "ip6", "saddr"),
        ] {
            self.cmds.push(json!({"add":{"set":{
                "family":"inet","table":&self.table,"name":name,
                "type":{"typeof":{"concat":[
                    {"payload":{"protocol":proto_field,"field":addr_field}},
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
    /// Chains are rebuilt by flush + re-add. For the in direction the granted
    /// host is the source of ingress packets, so address/port fields flip.
    pub fn add_acct_rule(&mut self, gid: i64, dir: Dir, proto: Proto, v6: bool) {
        let (chain, addr_field, port_field, af) = match dir {
            Dir::Out => (
                CHAIN_ACCT_OUT,
                "daddr",
                "dport",
                if v6 { "ip6" } else { "ip" },
            ),
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
            "comment":format!("tethys:g{gid}:{}", dir.slug()),
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

    /// Escape hatch for objects outside this builder's vocabulary (the
    /// host-stack forward/masquerade/DNAT projection built by provisioning).
    /// One raw JSON command, still applied through the same executor.
    pub fn push_cmd(&mut self, cmd: Value) {
        self.cmds.push(cmd);
    }

    pub fn to_json(&self) -> String {
        json!({"nftables": &self.cmds}).to_string()
    }
}

/// State of one live grant element as read from the kernel.
#[derive(Clone, Debug)]
pub struct LiveElement {
    pub set: String,
    /// Which grant family this element came from (derived from the set name:
    /// `grants_*` => Egress, `igrants_*` => Ingress).
    pub dir: Direction,
    pub dst: String, // canonical "1.2.3.4" / "10.0.0.0/8"
    pub proto: Proto,
    pub port_from: u16,
    pub port_to: u16,
    pub expires_secs: f64,
    /// Attribution from add_grant (`tethys:g<gid>`), if present. Not a security check.
    pub comment: Option<String>,
}

#[derive(Debug)]
pub struct PollState {
    pub elements: Vec<LiveElement>,
    /// named counters keyed by object name (gX_out / gX_in).
    pub counters: std::collections::HashMap<String, (u64, u64)>,
}

/// Whether the live ruleset actually references each grant set family. A set
/// can exist with zero referencing rules (daemon upgraded onto an older
/// ruleset, half-provisioned table), which is exactly the INGRESS-REVIEW.md
/// Medium failure mode: elements installed, verdicts APPROVED, nothing
/// filtered. Each family counts as active only when a live rule in the
/// target table looks it up; dual-stack is mandatory, so v4 and v6 must both
/// be referenced for a direction to report active.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EnforcementStatus {
    pub grants_v4: bool,
    pub grants_v6: bool,
    pub igrants_v4: bool,
    pub igrants_v6: bool,
}

impl EnforcementStatus {
    pub fn egress_active(&self) -> bool {
        self.grants_v4 && self.grants_v6
    }
    pub fn ingress_active(&self) -> bool {
        self.igrants_v4 && self.igrants_v6
    }
    /// Both directions fully wired; the daemon's "enforcement boundary
    /// active" condition (step 3 refuses installs when this is false).
    pub fn active(&self) -> bool {
        self.egress_active() && self.ingress_active()
    }
}

fn set_family_of(name: &str) -> Option<fn(&mut EnforcementStatus) -> &mut bool> {
    match name {
        SET_V4 => Some(|s| &mut s.grants_v4),
        SET_V6 => Some(|s| &mut s.grants_v6),
        SET_IGRANT_V4 => Some(|s| &mut s.igrants_v4),
        SET_IGRANT_V6 => Some(|s| &mut s.igrants_v6),
        _ => None,
    }
}

/// Scan `nft --json list ruleset` output for live rules in table `tname`
/// that look up each grant set (`"right": "@grants_v4"` style matches).
/// Pure JSON — no netlink, unit-testable. Element-only presence does NOT
/// count: only rule references mean the traffic path consults the set.
pub fn parse_enforcement(doc: &Value, tname: &str) -> EnforcementStatus {
    let mut st = EnforcementStatus::default();
    let Some(arr) = doc.get("nftables").and_then(|v| v.as_array()) else {
        return st;
    };
    for item in arr {
        // `list ruleset` nests rules as {"rule":{...}}; also tolerate the
        // full-dump shape where table is a sibling object.
        let Some(rule) = item.get("rule") else {
            continue;
        };
        if rule.get("table").and_then(|v| v.as_str()) != Some(tname) {
            continue;
        }
        let Some(exprs) = rule.get("expr").and_then(|v| v.as_array()) else {
            continue;
        };
        for expr in exprs {
            // A set reference is a string match RHS like "@grants_v4". Only
            // the RHS can name a set, so scan exactly that slot.
            let Some(right) = expr.get("match").and_then(|m| m.get("right")) else {
                continue;
            };
            let Some(name) = right.as_str().and_then(|s| s.strip_prefix('@')) else {
                continue;
            };
            if let Some(field) = set_family_of(name) {
                *field(&mut st) = true;
            }
        }
    }
    st
}

/// Extract the live port intervals of one `inet_service` set from
/// `nft --json list set` output: plain numbers become (p,p), two-element
/// arrays are intervals. Well-known-service annotations (`service` keys)
/// ride along with numeric `val`s, so only numbers are read; anything else
/// (strings, odd shapes) is skipped — this parser must never be fatal.
pub fn parse_set_ports(doc: &Value, tname: &str, sname: &str) -> Vec<(u16, u16)> {
    let mut out = Vec::new();
    let Some(arr) = doc.get("nftables").and_then(|v| v.as_array()) else {
        return out;
    };
    for item in arr {
        let Some(set) = item.get("set") else { continue };
        if set.get("name").and_then(|v| v.as_str()) != Some(sname)
            || set.get("table").and_then(|v| v.as_str()) != Some(tname)
        {
            continue;
        }
        let Some(elems) = set.get("elem").and_then(|v| v.as_array()) else {
            continue;
        };
        for el in elems {
            // Accept both the direct {"val":N} shape and an {"elem":{...}}
            // wrapper; some nft versions nest element metadata one level in.
            let val = el
                .get("val")
                .or_else(|| el.get("elem").and_then(|e| e.get("val")));
            let Some(val) = val else { continue };
            if let Some(p) = val.as_u64() {
                if p <= 65535 {
                    out.push((p as u16, p as u16));
                }
            } else if let Some(pair) = val.as_array() {
                if pair.len() == 2 {
                    if let (Some(lo), Some(hi)) = (pair[0].as_u64(), pair[1].as_u64()) {
                        if lo <= 65535 && hi <= 65535 {
                            out.push((lo as u16, hi as u16));
                        }
                    }
                }
            }
        }
    }
    out
}

/// `nft` CLI backend: argv-pinned, env-cleared, JSON on stdin. Every spawn
/// funnels through [`NftCli::run_json`] so the [`ExecTarget`] (host stack or
/// setns into the agent netns) is applied uniformly — no call site spawns
/// nft ad hoc.
pub struct NftCli {
    pub bin: std::path::PathBuf,
    pub timeout: Duration,
    /// Where batches execute. `Host` until a namespace handle is supplied.
    pub target: ExecTarget,
}

impl Default for NftCli {
    fn default() -> Self {
        Self {
            bin: "/usr/sbin/nft".into(),
            timeout: Duration::from_secs(5),
            target: ExecTarget::Host,
        }
    }
}

impl NftCli {
    /// Backend that applies every batch inside the netns at `path` (the fd
    /// is opened and pinned once; each batch revalidates the inode).
    pub fn in_netns(path: impl AsRef<Path>) -> Result<Self, NftError> {
        Ok(Self {
            target: ExecTarget::Netns(Arc::new(Netns::open(path)?)),
            ..Default::default()
        })
    }

    /// Apply a JSON batch atomically (nft processes a batch as one transact).
    pub async fn apply(&self, batch: &Batch) -> Result<(), NftError> {
        if batch.is_empty() {
            return Ok(());
        }
        let payload = batch.to_json();
        self.run_json(&payload).await?;
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
        let out = self.run_json(&batch.to_string()).await?;
        Ok(serde_json::from_str(&out)?)
    }

    pub async fn poll_live(&self, table: &str) -> Result<PollState, NftError> {
        let t = self
            .list_json("table", Some(json!({"family": "inet", "name": table})))
            .await?;
        let c = self.list_json("counters", None).await?;
        Ok(parse_poll(&t, &c, table))
    }

    /// Probe the live ruleset (inside this backend's execution target) for
    /// rules that reference each grant set family. The daemon polls this at
    /// start and periodically so APPROVED can never silently mean
    /// "elements loaded but nothing filtering".
    pub async fn enforcement_status(&self, table: &str) -> Result<EnforcementStatus, NftError> {
        let doc = self.list_json("ruleset", None).await?;
        Ok(parse_enforcement(&doc, table))
    }

    /// Live port intervals of one `inet_service` set (the delegated-port
    /// sets live on the host stack in routed mode). Pure read; callers diff
    /// against this before add/delete (nft element ops are not idempotent).
    pub async fn set_ports(&self, table: &str, set: &str) -> Result<Vec<(u16, u16)>, NftError> {
        let doc = self
            .list_json("set", Some(json!({"family": "inet", "name": table})))
            .await?;
        Ok(parse_set_ports(&doc, table, set))
    }

    /// The one spawn helper: every `nft` subprocess starts here. Namespaced
    /// targets revalidate the cached netns inode first (fail closed), then
    /// setns in the child via [`setns_pre_exec`]; host batches run plain.
    async fn run_json(&self, payload: &str) -> Result<String, NftError> {
        let mut cmd = Command::new(&self.bin);
        cmd.env_clear();
        // nft 1.1.6: --json must precede -f.
        cmd.args(["--json", "-f", "-"]);
        match &self.target {
            ExecTarget::Host => {}
            ExecTarget::Netns(ns) => {
                ns.revalidate()?;
                // SAFETY (audited unsafe_code exception, like the daemon's
                // umask guard): setns_pre_exec returns a post-fork/pre-exec
                // closure doing only fcntl+setns syscalls on a parent-owned
                // nsfs fd. tokio falls back from posix_spawn to fork+exec
                // once pre_exec is installed, so the hook always runs.
                #[allow(unsafe_code)]
                unsafe {
                    cmd.pre_exec(setns_pre_exec(ns.fd()))
                };
            }
        }
        run_nft_json(cmd, payload, self.timeout).await
    }
}

/// Run one pre-configured (argv-pinned, env-cleared, target-attached) JSON
/// batch through the nft CLI on stdin and return stdout. A failed stdin
/// write means nft never saw the batch, so it is surfaced as an error rather
/// than letting the child fail or hang on empty stdin (an apply miss).
/// Stdout/stderr handles are taken before waiting so the timeout path can
/// still kill the child by &mut; on timeout the readers are reaped as well
/// (the kill closes their pipes, so they should EOF promptly, but they are
/// never left detached). Non-zero exit becomes [`NftError::Failed`] with the
/// captured stderr.
async fn run_nft_json(
    mut cmd: Command,
    payload: &str,
    timeout: Duration,
) -> Result<String, NftError> {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(NftError::Spawn)?;
    {
        use tokio::io::AsyncWriteExt;
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
/// Live grant elements arrive as `{"elem":{"val":{"concat":[...]},
/// "expires":f}}` with `expires` and `comment` siblings of `val`; the parser
/// also tolerates an `expires` nested inside `val`. The kernel echoes proto
/// numerically in some contexts, so a non-string concat slot 1 maps 6 to tcp
/// and anything else to udp. A malformed element (bad dst, wrong concat
/// arity, short or non-array port range) is skipped, never fatal: boot
/// reconcile and the stats poller share this parser and must survive odd
/// output rather than panic (OOBIDX-001). Counters are keyed by name,
/// restricted to the given table.
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
            let dir = match name.as_str() {
                SET_V4 | SET_V6 => Direction::Egress,
                SET_IGRANT_V4 | SET_IGRANT_V6 => Direction::Ingress,
                _ => continue,
            };
            let Some(elems) = set.get("elem").and_then(|v| v.as_array()) else {
                continue;
            };
            for el in elems {
                let wrapper = el.get("elem");
                let val = wrapper.and_then(|e| e.get("val")).or(el.get("val"));
                let Some(val) = val else { continue };
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
                        let Some(r) = v
                            .get("range")
                            .and_then(Value::as_array)
                            .filter(|r| r.len() >= 2)
                        else {
                            continue;
                        };
                        (
                            r[0].as_u64().unwrap_or(0) as u16,
                            r[1].as_u64().unwrap_or(0) as u16,
                        )
                    }
                    _ => continue,
                };
                elements.push(LiveElement {
                    set: name.clone(),
                    dir,
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

    // Delegated-port polling must read plain numbers, intervals, and the
    // wrapped element shape; service annotations ride on numeric vals;
    // strings, out-of-range numbers, and other tables/sets never leak in.
    #[test]
    fn parses_set_port_elements() {
        let doc = serde_json::json!({"nftables": [
            {"set": {"family":"inet","table":"tethys","name":"delegated_v4",
                "elem": [{"val":443}, {"val":[8000,8100],"service":"alt-redirect"},
                         {"val":"http"}, {"val":70000}]}},
            {"set": {"family":"inet","table":"other","name":"delegated_v4",
                "elem": [{"val":1}]}},
            {"set": {"family":"inet","table":"tethys","name":"delegated_v6",
                "elem": [{"elem":{"val":993}}]}},
        ]});
        assert_eq!(
            parse_set_ports(&doc, "tethys", "delegated_v4"),
            vec![(443, 443), (8000, 8100)]
        );
        assert_eq!(
            parse_set_ports(&doc, "tethys", "delegated_v6"),
            vec![(993, 993)]
        );
        assert!(parse_set_ports(&doc, "other2", "delegated_v4").is_empty());
        assert!(parse_set_ports(&doc, "tethys", "missing").is_empty());
    }

    // Port elements normalize through nft_range: single ports bare, ranges
    // dashed, the all-ports wildcard as the full space.
    #[test]
    fn port_elements_use_normalized_ranges() {
        let mut b = Batch::with_table("tethys");
        b.add_port("delegated_v4", &PortSpec { from: 443, to: 443 });
        b.add_port(
            "delegated_v4",
            &PortSpec {
                from: 8000,
                to: 8100,
            },
        );
        b.delete_port("delegated_v6", &PortSpec { from: 0, to: 0 });
        let cmds = b.to_json();
        assert!(cmds.contains(r#""elem":["443"]"#), "{cmds}");
        assert!(cmds.contains(r#""elem":["8000-8100"]"#), "{cmds}");
        assert!(
            cmds.contains(r#""delete""#) && cmds.contains(r#""elem":["0-65535"]"#),
            "{cmds}"
        );
    }
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // OOBIDX-001: short, non-array, and null ranges must skip the element
    // rather than panic, since boot reconcile and the stats poller share this
    // parser. Only the well-formed 2-element range loads.
    #[test]
    fn parse_poll_survives_malformed_ranges() {
        let doc = serde_json::json!({"nftables": [
            {"set": {"name": "grants_v4", "elem": [
                {"elem": {"val": {"concat": ["10.0.0.1", "tcp", {"range": [80]}]}}},
                {"elem": {"val": {"concat": ["10.0.0.2", "tcp", {"range": "nope"}]}}},
                {"elem": {"val": {"concat": ["10.0.0.3", "tcp", {"range": null}]}}},
                {"elem": {"val": {"concat": ["10.0.0.4", "tcp", {"range": [443, 449]}]}}}
            ]}}
        ]});
        let st = parse_poll(&doc, &serde_json::json!({"nftables": []}), "t");
        assert_eq!(
            st.elements.len(),
            1,
            "only the well-formed 2-elem range loads"
        );
        assert_eq!(st.elements[0].dst, "10.0.0.4");
        assert_eq!(
            (st.elements[0].port_from, st.elements[0].port_to),
            (443, 449)
        );
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
        assert_eq!(e.set_name(Direction::Egress), SET_V4);
    }

    #[test]
    fn wildcard_ports_and_v6_set_choice() {
        let e = GrantElem {
            dst: ElemDst::Ip(ip("fe80::1")),
            proto: Proto::Udp,
            port: PortSpec { from: 0, to: 0 },
        };
        assert_eq!(e.set_name(Direction::Egress), SET_V6);
        assert_eq!(e.carve_set_name(Direction::Egress), SET_CARVE_V6);
        // Ingress flips the family, never the element grammar.
        assert_eq!(e.set_name(Direction::Ingress), SET_IGRANT_V6);
        assert_eq!(e.carve_set_name(Direction::Ingress), SET_CARVE_IN_V6);
        let s = e.concat().to_string();
        assert!(s.contains("\"range\":[0,65535]"));
    }

    // serde_json sorts keys, so assert against the parsed structure rather
    // than substrings. The grant add must carry the elem wrapper with its
    // expires value and tethys:g7 comment; direction selects only the set
    // name — the element JSON is byte-identical across directions.
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
            Direction::Egress,
        );
        let j: serde_json::Value = serde_json::from_str(&b.to_json()).unwrap();
        let cmds = j["nftables"].as_array().unwrap();
        assert_eq!(cmds[0]["add"]["element"]["name"], "grants_v4");
        let e0 = &cmds[0]["add"]["element"]["elem"][0];
        assert_eq!(e0["elem"]["expires"], 600);
        assert_eq!(e0["elem"]["val"]["concat"][0], "203.0.113.7");
        assert_eq!(e0["elem"]["comment"], "tethys:g7");
    }

    #[test]
    fn grant_direction_selects_set_not_element() {
        let e = GrantElem {
            dst: ElemDst::Ip(ip("203.0.113.7")),
            proto: Proto::Tcp,
            port: PortSpec { from: 443, to: 443 },
        };
        let mut out = Batch::new();
        let mut inb = Batch::new();
        out.add_grant(&e, Duration::from_secs(60), 7, Direction::Egress);
        inb.add_grant(&e, Duration::from_secs(60), 7, Direction::Ingress);
        let cmd = |b: &Batch| -> Value {
            serde_json::from_str::<Value>(&b.to_json()).unwrap()["nftables"][0]["add"]["element"]
                .clone()
        };
        let (o, i) = (cmd(&out), cmd(&inb));
        assert_eq!(o["name"], SET_V4);
        assert_eq!(i["name"], SET_IGRANT_V4);
        // Value, TTL and comment are byte-identical across directions.
        assert_eq!(o["elem"], i["elem"]);
    }

    // Checks that carve sets carry no timeout flag, that the batch orders
    // sets (all four), then flushes (all four), then the element, and that
    // the carve element is a plain concat with no expires/comment wrapper.
    #[test]
    fn carve_batch_shape() {
        let mut b = Batch::new();
        b.ensure_carve_sets();
        b.flush_carves();
        b.add_carve(
            &GrantElem {
                dst: ElemDst::Ip("203.0.113.7".parse().unwrap()),
                proto: Proto::Tcp,
                port: PortSpec { from: 443, to: 443 },
            },
            Direction::Egress,
        );
        let cmds = serde_json::from_str::<Value>(&b.to_json()).unwrap()["nftables"]
            .as_array()
            .unwrap()
            .clone();
        // Four set adds, no timeout flag (key typing is covered by
        // ensure_base_netns_shape; the point here is install order)...
        assert_eq!(cmds[0]["add"]["set"]["name"], "carve_v4");
        assert_eq!(cmds[0]["add"]["set"]["flags"], json!(["interval"]));
        assert_eq!(cmds[2]["add"]["set"]["name"], "carve_in_v4");
        // ...then four flushes (stop.grants-safe reinstall order)...
        assert!(cmds[4]["flush"]["set"]["name"].as_str() == Some("carve_v4"));
        assert!(cmds[7]["flush"]["set"]["name"].as_str() == Some("carve_in_v6"));
        // ...then the plain-concat element.
        let e = &cmds[8]["add"]["element"];
        assert_eq!(e["name"], "carve_v4");
        assert_eq!(e["elem"][0]["concat"][1], json!("tcp"));
        assert!(e["elem"][0]["concat"].is_array());
    }

    // The netns table shape: both base chains hooked with policy drop, no
    // uid/skuid expressions anywhere (the whole namespace is policed by
    // construction), all four grant families present with the right address
    // slots, and each chain closed by counter+limit+log+drop. Rule bodies
    // are rebuilt via flush inside the same batch: chain add must precede
    // its flush, and the flush must precede that chain's rules, so a rerun
    // converges instead of duplicating.
    #[test]
    fn ensure_base_netns_shape() {
        let mut b = Batch::with_table("tethys_test");
        b.ensure_base();
        let json = b.to_json();
        assert!(
            !json.contains("skuid"),
            "netns shape carries no uid expressions"
        );
        let cmds = serde_json::from_str::<Value>(&json).unwrap()["nftables"]
            .as_array()
            .unwrap()
            .clone();
        assert!(
            !cmds
                .iter()
                .any(|c| c["add"]["chain"]["name"].as_str() == Some("scope")),
            "no uid scope chain in the netns shape"
        );
        assert!(
            !json.contains("\"jump\""),
            "base chains never jump out to scoping"
        );

        // Sets: daddr-keyed grants, saddr-keyed igrants, carve pairs.
        let set_addr = |name: &str| -> String {
            cmds.iter()
                .find(|c| c["add"]["set"]["name"].as_str() == Some(name))
                .unwrap_or_else(|| panic!("missing set {name}"))["add"]["set"]["type"]["typeof"]
                ["concat"][0]["payload"]["field"]
                .as_str()
                .unwrap()
                .to_string()
        };
        for (set, want) in [
            (SET_V4, "daddr"),
            (SET_V6, "daddr"),
            (SET_CARVE_V4, "daddr"),
            (SET_CARVE_V6, "daddr"),
            (SET_IGRANT_V4, "saddr"),
            (SET_IGRANT_V6, "saddr"),
            (SET_CARVE_IN_V4, "saddr"),
            (SET_CARVE_IN_V6, "saddr"),
        ] {
            assert_eq!(set_addr(set), want, "{set} address slot");
        }

        // Base chains: hooked, priority filter (0), policy drop.
        for (chain, hook) in [(CHAIN_EGRESS, "output"), (CHAIN_INGRESS, "input")] {
            let add = cmds
                .iter()
                .find(|c| c["add"]["chain"]["name"].as_str() == Some(chain))
                .unwrap();
            assert_eq!(add["add"]["chain"]["hook"], hook);
            assert_eq!(add["add"]["chain"]["prio"], 0);
            assert_eq!(add["add"]["chain"]["policy"], "drop");
        }

        // Idempotent rebuild: flush after chain add, before that chain's rules.
        let idx = |pred: &dyn Fn(&Value) -> bool| cmds.iter().position(pred).unwrap_or(usize::MAX);
        for chain in [CHAIN_EGRESS, CHAIN_INGRESS] {
            let add_i = idx(&|c| c["add"]["chain"]["name"].as_str() == Some(chain));
            let flush_i = idx(&|c| c["flush"]["chain"]["name"].as_str() == Some(chain));
            let rule_i = idx(&|c| {
                c["add"]["rule"]["chain"].as_str() == Some(chain)
                    && !c["add"]["rule"]["expr"][0]["match"]["left"]["concat"].is_null()
            });
            assert!(add_i < flush_i, "{chain}: chain declared before flush");
            assert!(flush_i < rule_i, "{chain}: rules only after flush");
        }

        // Every grant family is looked up from its base chain as a tcp AND
        // a udp concat rule; ingress gates on saddr + LOCAL dport, egress
        // stays daddr-keyed. A missing proto variant would silently leave
        // one protocol permanently dropped.
        let lookup = |set: &str| -> Vec<Value> {
            cmds.iter()
                .filter(|c| {
                    c["add"]["rule"]["expr"][0]["match"]["right"].as_str()
                        == Some(&format!("@{set}"))
                })
                .map(|c| c["add"]["rule"]["expr"][0].clone())
                .collect()
        };
        for set in [
            SET_CARVE_IN_V4,
            SET_CARVE_IN_V6,
            SET_IGRANT_V4,
            SET_IGRANT_V6,
        ] {
            let l = lookup(set);
            assert_eq!(l.len(), 2, "{set}: tcp + udp variants");
            for m in &l {
                assert_eq!(m["match"]["left"]["concat"][0]["payload"]["field"], "saddr");
                assert_eq!(m["match"]["left"]["concat"][2]["payload"]["field"], "dport");
            }
        }
        for set in [SET_CARVE_V4, SET_CARVE_V6, SET_V4, SET_V6] {
            let l = lookup(set);
            assert_eq!(l.len(), 2, "{set}: tcp + udp variants");
            for m in &l {
                assert_eq!(m["match"]["left"]["concat"][0]["payload"]["field"], "daddr");
            }
        }

        // Each base chain ends with its counted, rate-limited logged drop.
        let tail = |chain: &str| -> Value {
            cmds.iter()
                .rev()
                .find(|c| c["add"]["rule"]["chain"].as_str() == Some(chain))
                .unwrap()["add"]["rule"]["expr"]
                .clone()
        };
        let egress_tail = tail(CHAIN_EGRESS);
        assert_eq!(egress_tail[0]["counter"], COUNTER_DROPS);
        assert_eq!(egress_tail[1]["limit"]["rate"], DROP_LOG_RATE);
        assert_eq!(egress_tail[2]["log"]["prefix"], LOG_PREFIX_EGRESS);
        assert!(egress_tail[3].get("drop").is_some());
        let ingress_tail = tail(CHAIN_INGRESS);
        assert_eq!(ingress_tail[0]["counter"], COUNTER_DROPS_IN);
        assert_eq!(ingress_tail[2]["log"]["prefix"], LOG_PREFIX_INGRESS);

        // Replies pass in both chains (kill-on-revoke is step 4's job).
        for chain in [CHAIN_EGRESS, CHAIN_INGRESS] {
            assert!(cmds.iter().any(|c| {
                c["add"]["rule"]["chain"].as_str() == Some(chain)
                    && c["add"]["rule"]["expr"][0]["match"]["left"]["ct"]["key"].as_str()
                        == Some("state")
            }));
        }

        // ICMP/ICMPv6 must pass on BOTH hooks: dropping NDP/PMTU at input
        // breaks the namespace outright (INGRESS-REVIEW.md outage warning).
        for chain in [CHAIN_EGRESS, CHAIN_INGRESS] {
            for proto in ["icmp", "icmpv6"] {
                assert!(
                    cmds.iter().any(|c| {
                        c["add"]["rule"]["chain"].as_str() == Some(chain)
                            && c["add"]["rule"]["expr"][0]["match"]["right"].as_str() == Some(proto)
                    }),
                    "{proto} must pass at {chain}"
                );
            }
        }
    }

    #[test]
    fn parse_enforcement_requires_live_rule_references() {
        let doc = json!({"nftables": [
            {"table": {"family":"inet","name":"tethys"}},
            // Elements alone do not count.
            {"set":{"name":"grants_v4","elem":[{"elem":{"val":{"concat":["1.2.3.4","tcp",443]}}}]}},
            {"rule":{"family":"inet","table":"tethys","chain":"egress","expr":[
                {"match":{"op":"==","left":{"concat":["..."]},"right":"@grants_v4"}},{"accept":null}]}},
            {"rule":{"family":"inet","table":"tethys","chain":"egress","expr":[
                {"match":{"op":"==","left":{"concat":["..."]},"right":"@grants_v6"}},{"accept":null}]}},
            {"rule":{"family":"inet","table":"tethys","chain":"ingress","expr":[
                {"match":{"op":"==","left":{"concat":["..."]},"right":"@igrants_v4"}},{"accept":null}]}},
            // A rule in a different table must not light up our status.
            {"rule":{"family":"inet","table":"other","chain":"ingress","expr":[
                {"match":{"op":"==","left":{"concat":["..."]},"right":"@igrants_v6"}},{"accept":null}]}}
        ]});
        let st = parse_enforcement(&doc, "tethys");
        assert!(
            st.egress_active(),
            "both grant sets referenced by live rules"
        );
        assert!(
            !st.ingress_active(),
            "igrants_v6 only referenced in table `other`"
        );
        assert!(st.igrants_v4);
        assert!(!st.igrants_v6);
        assert!(!st.active());

        // All four wired -> fully active; empty/garbage docs -> all false.
        let mut full = doc.clone();
        full["nftables"].as_array_mut().unwrap().push(json!(
            {"rule":{"family":"inet","table":"tethys","chain":"ingress","expr":[
                {"match":{"op":"==","left":{"concat":["..."]},"right":"@igrants_v6"}},{"accept":null}]}}));
        assert!(parse_enforcement(&full, "tethys").active());
        assert!(!parse_enforcement(&json!({"nftables": []}), "tethys").active());
        assert!(!parse_enforcement(&json!("nope"), "tethys").egress_active());
    }

    // Netns revalidation is pure inode logic, testable on plain files: the
    // point is that a deleted or replaced path never silently executes a
    // batch against whatever stack owns it afterwards.
    #[test]
    fn netns_revalidate_detects_gone_and_replaced() {
        let dir = std::env::temp_dir().join(format!("tethys-netns-probe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("probe");
        std::fs::write(&path, b"a").unwrap();

        let ns = Netns::open(&path).expect("open");
        assert_eq!(ns.path(), path.as_path());
        ns.revalidate().expect("unchanged path validates");

        // Recreated (new inode at the same path) -> loud failure.
        std::fs::write(dir.join("fresh"), b"b").unwrap();
        std::fs::rename(dir.join("fresh"), &path).unwrap();
        match ns.revalidate() {
            Err(NftError::NetnsReplaced { .. }) => {}
            other => panic!("expected NetnsReplaced, got {other:?}"),
        }

        // Deleted -> loud failure (cached fd keeps working; the path does not).
        std::fs::remove_file(&path).unwrap();
        match ns.revalidate() {
            Err(NftError::NetnsGone { .. }) => {}
            other => panic!("expected NetnsGone, got {other:?}"),
        }

        assert!(matches!(
            Netns::open(dir.join("absent")),
            Err(NftError::NetnsOpen { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    // Dev/test default stays host-stack; netns is opted into explicitly.
    fn default_exec_target_is_host() {
        assert!(matches!(NftCli::default().target, ExecTarget::Host));
    }

    /// Every command must target the batch's table. A missed substitution
    /// deletes from the wrong table (ENOENT), which used to break revoke and
    /// stop runs under a non-default nft_table.
    #[test]
    fn every_command_targets_the_batches_table() {
        let mut b = Batch::with_table("tethys_alt");
        b.ensure_base();
        let e = GrantElem {
            dst: ElemDst::Ip(ip("203.0.113.7")),
            proto: Proto::Tcp,
            port: PortSpec { from: 443, to: 443 },
        };
        b.add_grant(&e, Duration::from_secs(60), 7, Direction::Egress);
        b.delete_grant(&e, Direction::Ingress);
        b.ensure_carve_sets();
        b.add_carve(&e, Direction::Egress);
        b.flush_carves();
        b.add_acct_set(7, Dir::Out, false);
        b.add_acct_elem(7, Dir::Out, &e);
        b.add_acct_rule(7, Dir::Out, Proto::Tcp, false);
        b.flush_chain(CHAIN_ACCT_OUT);
        b.add_counter("g7_out");
        b.delete_counter("g7_out");
        b.delete_set("tethys_m7_out");

        // Table references come in two shapes: `"table": "name"` inside
        // element/rule ops, or `"table": {"family":..,"name":..}`.
        fn walk(v: &Value, hits: &mut Vec<(String, Value)>) {
            match v {
                Value::Object(m) => {
                    for (k, x) in m {
                        if k == "table" {
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
                    &serde_json::json!("tethys_alt"),
                    "command with {k} hit wrong table: {cmd}"
                );
            }
        }
        assert!(!hits.is_empty(), "batch emitted no table references at all");
    }

    // The in-direction v6 rule must match ip6 saddr . l4proto . udp sport,
    // count into tethys_g7_in, and carry no verdict expr; the out-direction
    // set uses daddr/dport keys (cmds[2]) while the in-direction element
    // (cmds[3]) lands in tethys_m7_in with the prefix encoding.
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
        let r = &cmds[4]["add"]["rule"];
        assert_eq!(r["chain"], CHAIN_ACCT_IN);
        assert_eq!(r["comment"], "tethys:g7:in");
        let exprs = r["expr"].as_array().unwrap();
        assert_eq!(exprs.len(), 2, "match + counter only — never a verdict");
        assert_eq!(exprs[1]["counter"], "tethys_g7_in");
        let lc = exprs[0]["match"]["left"]["concat"].as_array().unwrap();
        assert_eq!(lc[0]["payload"]["protocol"], "ip6");
        assert_eq!(lc[0]["payload"]["field"], "saddr");
        assert_eq!(lc[2]["payload"]["protocol"], "udp");
        assert_eq!(lc[2]["payload"]["field"], "sport");
        assert!(exprs[0]["match"]["right"]
            .as_str()
            .unwrap()
            .starts_with("@tethys_m7_in"));
        let s_out = &cmds[2]["add"]["set"];
        assert_eq!(s_out["name"], "tethys_m7_out");
        assert_eq!(
            s_out["type"]["typeof"]["concat"][0]["payload"]["field"],
            "daddr"
        );
        assert_eq!(
            s_out["type"]["typeof"]["concat"][2]["payload"]["field"],
            "dport"
        );
        let e = &cmds[3]["add"]["element"];
        assert_eq!(e["name"], "tethys_m7_in");
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
                            {"range":[8000,8100]}]},"expires":12.0,"comment":"tethys:g7"}}]}},
            // Ingress elements parse through the same path but must be
            // attributed by set family; carve sets are NOT grant state and
            // must stay out of PollState entirely.
            {"set":{"name":SET_IGRANT_V6,"family":"inet","table":TABLE,
                "elem":[{"elem":{"val":{"concat":["2001:db8::5","tcp",443]},"expires":9.0,
                          "comment":"tethys:g9"}}]}},
            {"set":{"name":SET_CARVE_V4,"family":"inet","table":TABLE,
                "elem":[{"val":{"concat":["9.9.9.9","udp",53]}}]}}
        ]});
        let counters = json!({"nftables":[
            {"counter":{"name":"g7_out","table":TABLE,"packets":3,"bytes":120}},
            {"counter":{"name":"other","table":"elsewhere","packets":9,"bytes":9}}
        ]});
        let st = parse_poll(&table, &counters, TABLE);
        assert_eq!(
            st.elements.len(),
            3,
            "grants + igrants only; carve excluded"
        );
        assert_eq!(st.elements[0].dir, Direction::Egress);
        assert_eq!(st.elements[1].dir, Direction::Egress);
        assert_eq!(
            (st.elements[2].set.as_str(), st.elements[2].dst.as_str()),
            (SET_IGRANT_V6, "2001:db8::5")
        );
        assert_eq!(st.elements[2].dir, Direction::Ingress);
        assert_eq!(st.elements[2].comment.as_deref(), Some("tethys:g9"));
        assert!((st.elements[0].expires_secs - 41.9).abs() < 0.01);
        assert_eq!(st.elements[1].dst, "10.0.0.0/8");
        assert_eq!(
            (st.elements[1].port_from, st.elements[1].port_to),
            (8000, 8100)
        );
        assert_eq!(st.elements[0].comment, None);
        assert_eq!(st.elements[1].comment.as_deref(), Some("tethys:g7"));
        assert_eq!(st.counters.get("g7_out"), Some(&(3u64, 120u64)));
        assert!(!st.counters.contains_key("other"));
    }
}
