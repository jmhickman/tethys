//! rusqlite grant ledger (decision D8). Single writer task owns it; callers
//! go through a spawned actor to keep tokio happy (rusqlite is sync).
//!
//! DESIGN: grant lifecycle is a state MACHINE, and the types here make illegal
//! states unrepresentable rather than merely discouraged at runtime:
//!   - `GrantState` / `Proto` / `DenyCode` are enums, never bare strings.
//!   - A row cannot be *constructed* in a non-pending state (`NewGrant` has no
//!     state field; `GrantRow` is only produced by the loader).
//!   - Every mutation is a `Decide` variant that OWNS its legal origin states,
//!     its target state, and exactly the payload that transition may carry —
//!     so "approve with no expiry" or "deny with no reason" do not typecheck.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gk_core::types::Proto;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

/// Legal grant states. Wire/DB spelling is snake_case (admin `list` output and
/// audit history depend on it).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    Pending,
    Approved,
    Denied,
    /// kernel TTL reaped the element; ledger mirrors reality.
    Expired,
    /// operator kill (revoke / stop.grants).
    Revoked,
}

impl GrantState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            GrantState::Pending => "pending",
            GrantState::Approved => "approved",
            GrantState::Denied => "denied",
            GrantState::Expired => "expired",
            GrantState::Revoked => "revoked",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(GrantState::Pending),
            "approved" => Some(GrantState::Approved),
            "denied" => Some(GrantState::Denied),
            "expired" => Some(GrantState::Expired),
            "revoked" => Some(GrantState::Revoked),
            _ => None,
        }
    }
}

/// Why a grant was denied. `Legacy` exists ONLY to load rows written by older
/// binaries without dropping them; nothing constructs it (grant rows age out
/// within their TTL, so the variant disappears in practice).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyCode {
    HumanDenied,
    ApproverOffline,
    ApproverTimeout,
    InstallFailed,
    RestartOrphan,
    /// reconcile_on_boot found an approved row with no live attributed element
    /// (reboot semantics R9) — the row is reaped, not revived.
    RestartReconcile,
    #[serde(untagged)]
    Legacy(String),
}

impl DenyCode {
    fn as_str(&self) -> &str {
        match self {
            DenyCode::HumanDenied => "human_denied",
            DenyCode::ApproverOffline => "approver_offline",
            DenyCode::ApproverTimeout => "approver_timeout",
            DenyCode::InstallFailed => "install_failed",
            DenyCode::RestartOrphan => "restart_orphan",
            DenyCode::RestartReconcile => "restart_reconcile",
            DenyCode::Legacy(s) => s,
        }
    }
}

/// A request that has not been seen before: no state, no expiry, no verdict —
/// those are facts the ledger adds over time, not caller-supplied fields.
#[derive(Clone, Debug)]
pub struct NewGrant {
    pub idem_key: String,
    /// canonical request target ("host:x" | "ip:x" | "net:x")
    pub target: String,
    pub port_from: u16,
    pub port_to: u16,
    pub proto: Proto,
    pub reason: String,
    pub tool: String,
    pub ttl_secs: u64,
    pub created_at: u64,
}

/// A ledger row as it EXISTS (only the loader builds these — a row's state is
/// data, never an argument).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrantRow {
    pub id: i64,
    pub idem_key: Option<String>,
    pub target: String,
    /// installed destinations (post-resolution), as JSON array of strings
    pub dst_json: String,
    pub port_from: u16,
    pub port_to: u16,
    pub proto: Proto,
    pub reason: String,
    pub tool: String,
    pub ttl_secs: u64,
    pub granted_ttl_secs: Option<u64>,
    pub state: GrantState,
    pub created_at: u64,
    pub expires_at: Option<f64>, // unix seconds
    pub deny_code: Option<DenyCode>,
    pub note: Option<String>,
}

/// The ONLY way the state machine moves. Each variant hard-codes its legal
/// origins and carries exactly (and only) what that transition may write.
#[derive(Clone, Debug)]
pub enum Decide {
    /// pending -> approved
    Approve { expires_at: f64 },
    /// pending -> denied (a denial without a reason is unconstructible)
    Deny { code: DenyCode, note: Option<String> },
    /// approved -> revoked by operator action
    Revoke { at: f64, note: Option<String> },
    /// approved -> expired, mirrored from the kernel reaper (no human input)
    ExpireByKernel,
    /// approved -> expired on boot: no live attributed element was found (R9).
    /// Carries a note for audit honesty; distinct from the routine TTL reap.
    ReapRestart { at: f64, note: Option<String> },
}

impl Decide {
    fn target(&self) -> GrantState {
        match self {
            Decide::Approve { .. } => GrantState::Approved,
            Decide::Deny { .. } => GrantState::Denied,
            Decide::Revoke { .. } => GrantState::Revoked,
            Decide::ExpireByKernel | Decide::ReapRestart { .. } => GrantState::Expired,
        }
    }
    /// Single source of truth for legality; enforced in SQL's WHERE clause.
    fn legal_origins(&self) -> &'static [GrantState] {
        match self {
            Decide::Approve { .. } | Decide::Deny { .. } => &[GrantState::Pending],
            Decide::Revoke { .. }
            | Decide::ExpireByKernel
            | Decide::ReapRestart { .. } => &[GrantState::Approved],
        }
    }
    fn expires(&self) -> Option<f64> {
        match self {
            Decide::Approve { expires_at } => Some(*expires_at),
            Decide::Revoke { at, .. } | Decide::ReapRestart { at, .. } => Some(*at),
            Decide::Deny { .. } | Decide::ExpireByKernel => None,
        }
    }
    fn deny(&self) -> Option<(&DenyCode, &Option<String>)> {
        match self {
            Decide::Deny { code, note } => Some((code, note)),
            _ => None,
        }
    }
    fn note(&self) -> Option<&String> {
        match self {
            Decide::Revoke { note, .. } | Decide::ReapRestart { note, .. } => note.as_ref(),
            _ => None,
        }
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

enum LedgerCmd {
    Insert(NewGrant, tokio::sync::oneshot::Sender<Option<i64>>),
    Decide(i64, Decide, tokio::sync::oneshot::Sender<bool>),
    List(GrantState, tokio::sync::oneshot::Sender<Vec<GrantRow>>),
    FindActive(tokio::sync::oneshot::Sender<Vec<GrantRow>>),
    SetDst(i64, String, tokio::sync::oneshot::Sender<bool>),
    FindByIdem(String, tokio::sync::oneshot::Sender<Option<GrantRow>>),
    Audit(String, String, i64),
}

#[derive(Clone)]
pub struct Ledger {
    tx: mpsc::UnboundedSender<LedgerCmd>,
}

fn row_from(r: &rusqlite::Row) -> rusqlite::Result<GrantRow> {
    let state_raw: String = r.get(11)?;
    // Parse-don't-validate: a row whose state isn't in the closed vocabulary is
    // corrupt, not "some other state" — skip it loudly rather than model it.
    let Some(state) = GrantState::parse(&state_raw) else {
        tracing::error!(id = ?r.get::<_, i64>(0).ok(), state = %state_raw,
            "ledger row with unknown state skipped");
        return Err(rusqlite::Error::InvalidParameterName("unknown_state".into()));
    };
    let proto_raw: String = r.get(6)?;
    let proto = match proto_raw.as_str() {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        _ => {
            tracing::error!(id = ?r.get::<_, i64>(0).ok(), proto = %proto_raw,
                "ledger row with unknown proto skipped");
            return Err(rusqlite::Error::InvalidParameterName("unknown_proto".into()));
        }
    };
    Ok(GrantRow {
        id: r.get(0)?,
        idem_key: r.get(1)?,
        target: r.get(2)?,
        dst_json: r.get(3)?,
        port_from: r.get::<_, i64>(4)? as u16,
        port_to: r.get::<_, i64>(5)? as u16,
        proto,
        reason: r.get(7)?,
        tool: r.get(8)?,
        ttl_secs: r.get::<_, i64>(9)? as u64,
        granted_ttl_secs: r.get::<_, Option<i64>>(10)?.map(|v| v as u64),
        state,
        created_at: r.get::<_, i64>(12)? as u64,
        expires_at: r.get(13)?,
        deny_code: r
            .get::<_, Option<String>>(14)?
            .map(|c| match c.as_str() {
                "human_denied" => DenyCode::HumanDenied,
                "approver_offline" => DenyCode::ApproverOffline,
                "approver_timeout" => DenyCode::ApproverTimeout,
                "install_failed" => DenyCode::InstallFailed,
                "restart_orphan" => DenyCode::RestartOrphan,
                "restart_reconcile" | "restart-reconcile" => DenyCode::RestartReconcile,
                other => DenyCode::Legacy(other.to_string()),
            }),
        note: r.get(15)?,
    })
}

const COLS: &str = "id,idem_key,target,dst_json,port_from,port_to,proto,reason,tool,\
     ttl_secs,granted_ttl_secs,state,created_at,expires_at,deny_code,note";

impl Ledger {
    pub fn open(path: &Path) -> anyhow::Result<(Self, tokio::task::JoinHandle<()>)> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).ok();
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS grants(
               id INTEGER PRIMARY KEY,
               idem_key TEXT UNIQUE,
               target TEXT NOT NULL,
               dst_json TEXT NOT NULL DEFAULT '[]',
               port_from INTEGER NOT NULL, port_to INTEGER NOT NULL,
               proto TEXT NOT NULL,
               reason TEXT NOT NULL DEFAULT '', tool TEXT NOT NULL DEFAULT '',
               ttl_secs INTEGER NOT NULL,
               granted_ttl_secs INTEGER,
               state TEXT NOT NULL,
               created_at INTEGER NOT NULL,
               expires_at REAL,
               deny_code TEXT, note TEXT);
             CREATE TABLE IF NOT EXISTS audit(
               ts INTEGER NOT NULL, event TEXT NOT NULL,
               grant_id INTEGER NOT NULL, detail TEXT NOT NULL DEFAULT '');",
        )?;
        let (tx, mut rx) = mpsc::unbounded_channel::<LedgerCmd>();
        let h = tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    LedgerCmd::Insert(g, reply) => {
                        // human-paced volume: prepared-fresh per insert is fine.
                        let res = conn.execute(
                            "INSERT INTO grants(idem_key,target,dst_json,port_from,port_to,proto,\
                             reason,tool,ttl_secs,state,created_at) VALUES(?1,?2,'[]',?3,?4,?5,?6,?7,?8,'pending',?9)",
                            params![g.idem_key, g.target, g.port_from as i64, g.port_to as i64,
                                    proto_name(g.proto), g.reason, g.tool, g.ttl_secs as i64, g.created_at as i64],
                        );
                        // NOT last_insert_rowid alone: it retains the PREVIOUS rowid
                        // when this INSERT fails (UNIQUE idem violation would alias
                        // to a stale grant). changes()==1 proves THIS insert landed.
                        match res {
                            Ok(1) => {
                                let id = conn.last_insert_rowid();
                                let _ = reply.send(Some(id));
                            }
                            _ => {
                                tracing::debug!(target = %g.target, "insert rejected (dup idem key)");
                                let _ = reply.send(None);
                            }
                        }
                    }
                    LedgerCmd::Decide(id, d, reply) => {
                        // Legality is enforced HERE, in the WHERE clause: the row
                        // only flips if it currently sits in a legal origin state.
                        let origins = d.legal_origins();
                        let placeholders: Vec<String> = (0..origins.len())
                            .map(|i| format!("?{}", 6 + i))
                            .collect();
                        let sql = format!(
                            "UPDATE grants SET state=?2, expires_at=COALESCE(?3, expires_at), \
                             deny_code=COALESCE(?4, deny_code), note=COALESCE(?5, note), \
                             granted_ttl_secs=COALESCE(granted_ttl_secs, CAST(?3 - created_at AS INTEGER)) \
                             WHERE id=?1 AND state IN ({})",
                            placeholders.join(",")
                        );
                        let (deny_code, deny_note) = match d.deny() {
                            Some((c, n)) => (Some(c.as_str().to_string()), n.clone()),
                            None => (None, d.note().cloned()),
                        };
                        let mut stmt = match conn.prepare(&sql) {
                            Ok(s) => s,
                            Err(e) => {
                                let _ = reply.send(false);
                                tracing::error!(%e, "decide prepare failed");
                                continue;
                            }
                        };
                        // bind: 1=id, 2=target-state, 3=expires, 4=deny_code, 5=note,
                        // then legal origin states (?6+).
                        let n = match stmt.execute(rusqlite::params_from_iter(
                            std::iter::once(rusqlite::types::Value::Integer(id))
                                .chain(std::iter::once(rusqlite::types::Value::Text(
                                    d.target().as_str().to_string(),
                                )))
                                .chain(std::iter::once(
                                    d.expires()
                                        .map(rusqlite::types::Value::Real)
                                        .unwrap_or(rusqlite::types::Value::Null),
                                ))
                                .chain(std::iter::once(
                                    deny_code
                                        .map(rusqlite::types::Value::Text)
                                        .unwrap_or(rusqlite::types::Value::Null),
                                ))
                                .chain(std::iter::once(
                                    deny_note
                                        .map(rusqlite::types::Value::Text)
                                        .unwrap_or(rusqlite::types::Value::Null),
                                ))
                                .chain(origins.iter().map(|s| rusqlite::types::Value::Text(s.as_str().to_string()))),
                        )) {
                            Ok(n) => n,
                            Err(e) => {
                                tracing::error!(%e, "decide execute failed");
                                0
                            }
                        };
                        let _ = reply.send(n == 1);
                    }
                    LedgerCmd::List(state, reply) => {
                        let mut out = Vec::new();
                        if let Ok(mut st) = conn.prepare(&format!(
                            "SELECT {COLS} FROM grants WHERE state=?1 ORDER BY id DESC LIMIT 500"
                        )) {
                            if let Ok(rows) = st.query_map(params![state.as_str()], row_from) {
                                out = rows.flatten().collect();
                            }
                        }
                        let _ = reply.send(out);
                    }
                    LedgerCmd::FindActive(reply) => {
                        let mut out = Vec::new();
                        if let Ok(mut st) = conn.prepare(&format!(
                            "SELECT {COLS} FROM grants WHERE state='approved' AND expires_at > ?1"
                        )) {
                            if let Ok(rows) = st.query_map(params![now_secs() as f64], row_from) {
                                out = rows.flatten().collect();
                            }
                        }
                        let _ = reply.send(out);
                    }
                    LedgerCmd::SetDst(id, dst_json, reply) => {
                        // Persist post-resolution IPs (D-R3): revoke/cleanup use
                        // THESE, never a re-resolve at delete time (DNS may drift).
                        let n = conn
                            .execute(
                                "UPDATE grants SET dst_json=?2 WHERE id=?1 AND state='approved'",
                                params![id, dst_json],
                            )
                            .unwrap_or(0);
                        let _ = reply.send(n == 1);
                    }
                    LedgerCmd::FindByIdem(key, reply) => {
                        let row = conn
                            .query_row(
                                &format!("SELECT {COLS} FROM grants WHERE idem_key=?1"),
                                params![key],
                                row_from,
                            )
                            .ok();
                        let _ = reply.send(row);
                    }
                    LedgerCmd::Audit(event, detail, grant_id) => {
                        let _ = conn.execute(
                            "INSERT INTO audit(ts,event,grant_id,detail) VALUES(?1,?2,?3,?4)",
                            params![now_secs() as i64, event, grant_id, detail],
                        );
                    }
                }
            }
        });
        Ok((Self { tx }, h))
    }

    async fn ask<T>(&self, f: impl FnOnce(tokio::sync::oneshot::Sender<T>) -> LedgerCmd) -> T {
        let (tx, rx) = tokio::sync::oneshot::channel();
        // channel is unbounded + actor never blocks on us; send can't fail in practice
        self.tx.send(f(tx)).ok();
        rx.await.expect("ledger actor died")
    }

    /// Returns None when the idempotency key already exists (a re-delivery).
    pub async fn insert_pending(&self, g: NewGrant) -> Option<i64> {
        self.ask(move |reply| LedgerCmd::Insert(g, reply)).await
    }

    /// Attempt a state transition; false = rejected (row not in a legal origin
    /// state), which is the normal answer for racy/duplicate decisions.
    pub async fn decide(&self, id: i64, d: Decide) -> bool {
        self.ask(|reply| LedgerCmd::Decide(id, d, reply)).await
    }

    pub async fn list(&self, state: GrantState) -> Vec<GrantRow> {
        self.ask(|reply| LedgerCmd::List(state, reply)).await
    }
    pub async fn active(&self) -> Vec<GrantRow> {
        self.ask(|reply| LedgerCmd::FindActive(reply)).await
    }
    /// Persist resolved dst list for an APPROVED grant (returns false if the
    /// row is not approved — stale flips can't corrupt it).
    pub async fn set_dst(&self, id: i64, dst_json: String) -> bool {
        self.ask(move |reply| LedgerCmd::SetDst(id, dst_json, reply)).await
    }
    /// Idempotency lookup for replayed request ids.
    pub async fn find_by_idem(&self, key: &str) -> Option<GrantRow> {
        let k = key.to_string();
        self.ask(move |reply| LedgerCmd::FindByIdem(k, reply)).await
    }
    pub fn audit(&self, event: &str, grant_id: i64, detail: impl Into<String>) {
        self.tx
            .send(LedgerCmd::Audit(event.into(), detail.into(), grant_id))
            .ok();
    }
}

fn proto_name(p: Proto) -> &'static str {
    match p {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    }
}

pub fn ttl_expires(granted: Duration) -> f64 {
    now_secs() as f64 + granted.as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn newg(key: &str) -> NewGrant {
        NewGrant {
            idem_key: key.into(),
            target: "ip:203.0.113.9".into(),
            port_from: 80,
            port_to: 80,
            proto: Proto::Tcp,
            reason: "r".into(),
            tool: "t".into(),
            ttl_secs: 60,
            created_at: now_secs(),
        }
    }

    /// The transition table is enforced at the DB boundary: wrong-origin
    /// decisions flip zero rows, right-origin ones flip exactly one.
    #[tokio::test]
    async fn transitions_enforce_origin_state() {
        let dir = std::env::temp_dir().join(format!("gk-ledger-test-{}", now_secs()));
        let (ledger, actor) = Ledger::open(&dir.join("t.db")).unwrap();
        let gid = ledger.insert_pending(newg("k1")).await.expect("insert");

        let exp = now_secs() as f64 + 60.0;
        // pending -> approved
        assert!(ledger.decide(gid, Decide::Approve { expires_at: exp }).await);
        // approving again is rejected (no ghost rows from racy double-decide)
        assert!(!ledger.decide(gid, Decide::Approve { expires_at: exp }).await);
        // approved -> denied is UNEXPRESSIBLE as a Decide variant at all; the
        // nearest legal-looking one (Revoke) then Expire both target Approved.
        assert!(ledger.decide(gid, Decide::Revoke { at: now_secs() as f64, note: None }).await);
        // terminal: revoked -> anything = false
        assert!(!ledger.decide(gid, Decide::ExpireByKernel).await);
        assert_eq!(
            ledger.find_by_idem("k1").await.unwrap().state,
            GrantState::Revoked
        );

        // separate row: deny path records code+note
        let gid2 = ledger.insert_pending(newg("k2")).await.expect("insert");
        assert!(ledger
            .decide(
                gid2,
                Decide::Deny { code: DenyCode::HumanDenied, note: Some("out of scope".into()) }
            )
            .await);
        let r = ledger.find_by_idem("k2").await.unwrap();
        assert_eq!(r.state, GrantState::Denied);
        assert_eq!(r.deny_code, Some(DenyCode::HumanDenied));
        assert_eq!(r.note.as_deref(), Some("out of scope"));
        // Deny from a denied row: rejected
        assert!(!ledger.decide(gid2, Decide::Deny { code: DenyCode::HumanDenied, note: None }).await);

        actor.abort();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn dup_idem_key_rejected_and_findable_across_states() {
        let dir = std::env::temp_dir().join(format!("gk-idem-{}", now_secs()));
        let (ledger, actor) = Ledger::open(&dir.join("t.db")).unwrap();
        let gid = ledger.insert_pending(newg("req-x")).await.expect("insert");
        assert!(ledger.insert_pending(newg("req-x")).await.is_none(), "UNIQUE must reject dup");
        let found = ledger.find_by_idem("req-x").await.expect("must find row by idem key");
        assert_eq!(found.id, gid);
        assert_eq!(found.proto, Proto::Tcp); // typed proto survived the round-trip
        ledger.decide(gid, Decide::Approve { expires_at: now_secs() as f64 + 5.0 }).await;
        ledger.decide(gid, Decide::Revoke { at: now_secs() as f64, note: None }).await;
        let found = ledger.find_by_idem("req-x").await.expect("still found after revoke");
        assert_eq!(found.state, GrantState::Revoked);
        actor.abort();
        std::fs::remove_dir_all(&dir).ok();
    }
}
