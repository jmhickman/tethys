//! rusqlite grant ledger. A single writer task owns the connection; callers
//! go through an actor because rusqlite is synchronous.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gk_core::types::Proto;
use rusqlite::{params, Connection};

use tokio::sync::mpsc;

/// Ledger/wire vocabulary types live in gk-core (shared verbatim with gk-tui
/// over admin.sock); re-exported so daemon code says `crate::ledger::…`.
pub use gk_core::wire::{DenyCode, GrantRow, GrantState};

/// New request. State, expiry, and verdict are filled in later.
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

/// State transition. Origin and payload are enforced in SQL.
#[derive(Clone, Debug)]
pub enum Decide {
    /// pending -> approved
    Approve { expires_at: f64 },
    /// pending -> denied
    Deny {
        code: DenyCode,
        note: Option<String>,
    },
    /// approved -> revoked by operator action
    Revoke { at: f64, note: Option<String> },
    /// approved -> expired, mirrored from the kernel reaper (no human input)
    ExpireByKernel,
    /// approved -> expired at startup: no live kernel element (grants do not
    /// survive reboot). Distinct from the routine TTL reap for the audit trail.
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
    /// Legal origin states; enforced in the UPDATE WHERE clause.
    fn legal_origins(&self) -> &'static [GrantState] {
        match self {
            Decide::Approve { .. } | Decide::Deny { .. } => &[GrantState::Pending],
            Decide::Revoke { .. } | Decide::ExpireByKernel | Decide::ReapRestart { .. } => {
                &[GrantState::Approved]
            }
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
    History(
        Option<GrantState>,
        u32,
        tokio::sync::oneshot::Sender<Vec<GrantRow>>,
    ),
    FindActive(tokio::sync::oneshot::Sender<Vec<GrantRow>>),
    SetDst(
        i64,
        String,
        tokio::sync::oneshot::Sender<Result<(), String>>,
    ),
    FindByIdem(String, tokio::sync::oneshot::Sender<Option<GrantRow>>),
    Audit(String, String, i64),
}

#[derive(Clone)]
pub struct Ledger {
    tx: mpsc::UnboundedSender<LedgerCmd>,
}

fn row_from(r: &rusqlite::Row) -> rusqlite::Result<GrantRow> {
    let state_raw: String = r.get(11)?;
    // Unknown state is corrupt; skip rather than inventing a variant.
    let Some(state) = GrantState::parse(&state_raw) else {
        tracing::error!(id = ?r.get::<_, i64>(0).ok(), state = %state_raw,
            "ledger row with unknown state skipped");
        return Err(rusqlite::Error::InvalidParameterName(
            "unknown_state".into(),
        ));
    };
    let proto_raw: String = r.get(6)?;
    let proto = match proto_raw.parse::<Proto>() {
        Ok(p) => p,
        Err(_) => {
            tracing::error!(id = ?r.get::<_, i64>(0).ok(), proto = %proto_raw,
                "ledger row with unknown proto skipped");
            return Err(rusqlite::Error::InvalidParameterName(
                "unknown_proto".into(),
            ));
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
        // serde is the single parse path (alias covers the pre-kebab spelling;
        // anything else loads as Unknown rather than dropping the row).
        deny_code: r.get::<_, Option<String>>(14)?.map(|c| {
            serde_json::from_value::<DenyCode>(serde_json::Value::String(c.clone()))
                .unwrap_or(DenyCode::Unknown(c))
        }),
        note: r.get(15)?,
    })
}

const COLS: &str = "id,idem_key,target,dst_json,port_from,port_to,proto,reason,tool,\
     ttl_secs,granted_ttl_secs,state,created_at,expires_at,deny_code,note";

impl Ledger {
    pub fn open(path: &Path) -> anyhow::Result<(Self, tokio::task::JoinHandle<()>)> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)
                .map_err(|e| anyhow::anyhow!("create {}: {e}", p.display()))?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            // WAL + NORMAL: durable within the last few commits at worst on
            // power loss — grants are reconciled against kernel truth at
            // boot anyway. busy_timeout keeps a hot reader from erroring out.
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA busy_timeout=5000;
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
        // ASYNCBLOCK-001: rusqlite is synchronous; running the whole command
        // loop on a tokio worker parks that worker for every WAL fsync under
        // disk pressure. blocking_recv() + spawn_blocking keeps the async
        // runtime free and needs no second channel type.
        let h = tokio::task::spawn_blocking(move || {
            while let Some(cmd) = rx.blocking_recv() {
                match cmd {
                    LedgerCmd::Insert(g, reply) => {
                        let res = conn.execute(
                            "INSERT INTO grants(idem_key,target,dst_json,port_from,port_to,proto,\
                             reason,tool,ttl_secs,state,created_at) VALUES(?1,?2,'[]',?3,?4,?5,?6,?7,?8,'pending',?9)",
                            params![g.idem_key, g.target, g.port_from as i64, g.port_to as i64,
                                    g.proto.to_string(), g.reason, g.tool, g.ttl_secs as i64, g.created_at as i64],
                        );
                        // last_insert_rowid keeps the previous rowid on UNIQUE
                        // failure; changes()==1 means this insert landed.
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
                        let origins = d.legal_origins();
                        let placeholders: Vec<String> =
                            (0..origins.len()).map(|i| format!("?{}", 6 + i)).collect();
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
                        let n =
                            match stmt.execute(rusqlite::params_from_iter(
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
                                    .chain(origins.iter().map(|s| {
                                        rusqlite::types::Value::Text(s.as_str().to_string())
                                    })),
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
                    LedgerCmd::History(state, limit, reply) => {
                        // Decided rows for the TUI, newest first. Optional state filter.
                        let q = match state {
                            Some(_) => format!(
                                "SELECT {COLS} FROM grants WHERE state!=?1 AND state=?2 \
                                 ORDER BY id DESC LIMIT ?3"
                            ),
                            None => format!(
                                "SELECT {COLS} FROM grants WHERE state!=?1 \
                                 ORDER BY id DESC LIMIT ?2"
                            ),
                        };
                        let mut out = Vec::new();
                        if let Ok(mut st) = conn.prepare(&q) {
                            let rows = match state {
                                Some(s) => st.query_map(
                                    params![GrantState::Pending.as_str(), s.as_str(), limit as i64],
                                    row_from,
                                ),
                                None => st.query_map(
                                    params![GrantState::Pending.as_str(), limit as i64],
                                    row_from,
                                ),
                            };
                            if let Ok(rows) = rows {
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
                        // Persist resolved IPs; revoke uses these, not a fresh
                        // lookup. RESDISC-002: a DB fault must not masquerade
                        // as "row not approved" — the caller fail-closes on it.
                        match conn.execute(
                            "UPDATE grants SET dst_json=?2 WHERE id=?1 AND state IN ('pending','approved')",
                            params![id, dst_json],
                        ) {
                            Ok(0) => {
                                let _ = reply.send(Err("row left pending/approved".into()));
                            }
                            Ok(_) => {
                                let _ = reply.send(Ok(()));
                            }
                            Err(e) => {
                                tracing::error!(id, %e, "set_dst UPDATE failed");
                                let _ = reply.send(Err(format!("db fault: {e}")));
                            }
                        }
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
                        // RESDISC-001: the approval trail must not fail
                        // silently — a full DB would otherwise erase forensics
                        // with zero operator signal while grants keep flowing.
                        if let Err(e) = conn.execute(
                            "INSERT INTO audit(ts,event,grant_id,detail) VALUES(?1,?2,?3,?4)",
                            params![now_secs() as i64, event, grant_id, detail],
                        ) {
                            tracing::error!(%e, event, grant_id, "audit INSERT failed — trail incomplete");
                        }
                    }
                }
            }
        });
        Ok((Self { tx }, h))
    }

    async fn ask<T>(&self, f: impl FnOnce(tokio::sync::oneshot::Sender<T>) -> LedgerCmd) -> T {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.tx.send(f(tx)).ok();
        rx.await.expect("ledger actor died")
    }

    /// None if the idempotency key already exists.
    pub async fn insert_pending(&self, g: NewGrant) -> Option<i64> {
        self.ask(move |reply| LedgerCmd::Insert(g, reply)).await
    }

    /// False if the row is not in a legal origin state (racy/duplicate).
    pub async fn decide(&self, id: i64, d: Decide) -> bool {
        self.ask(|reply| LedgerCmd::Decide(id, d, reply)).await
    }

    pub async fn list(&self, state: GrantState) -> Vec<GrantRow> {
        self.ask(|reply| LedgerCmd::List(state, reply)).await
    }
    /// Decided rows (any state except pending), newest first. `state` narrows
    /// to one terminal state; `limit` bounds the page.
    pub async fn history(&self, state: Option<GrantState>, limit: u32) -> Vec<GrantRow> {
        self.ask(|reply| LedgerCmd::History(state, limit, reply))
            .await
    }
    pub async fn active(&self) -> Vec<GrantRow> {
        self.ask(LedgerCmd::FindActive).await
    }
    /// Persist resolved dst list for an approved grant. Err distinguishes a
    /// DB fault from "row not approved" (RESDISC-002); both are hard failures
    /// on the approval path — without the pinned resolution, revoke could
    /// tear down the wrong elements and leave stale egress until TTL.
    pub async fn set_dst(&self, id: i64, dst_json: String) -> Result<(), String> {
        self.ask(move |reply| LedgerCmd::SetDst(id, dst_json, reply))
            .await
    }
    /// Idempotency lookup for replayed request ids.
    pub async fn find_by_idem(&self, key: &str) -> Option<GrantRow> {
        let k = key.to_string();
        self.ask(move |reply| LedgerCmd::FindByIdem(k, reply)).await
    }
    pub fn audit(&self, event: &str, grant_id: i64, detail: impl Into<String>) {
        if let Err(e) = self
            .tx
            .send(LedgerCmd::Audit(event.into(), detail.into(), grant_id))
        {
            tracing::error!(%e, "audit command lost — ledger actor gone");
        }
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

    /// Wrong-origin decisions flip zero rows; right-origin flips exactly one.
    #[tokio::test]
    async fn transitions_enforce_origin_state() {
        let dir = std::env::temp_dir().join(format!("gk-ledger-test-{}", now_secs()));
        let (ledger, actor) = Ledger::open(&dir.join("t.db")).unwrap();
        let gid = ledger.insert_pending(newg("k1")).await.expect("insert");

        let exp = now_secs() as f64 + 60.0;
        assert!(
            ledger
                .decide(gid, Decide::Approve { expires_at: exp })
                .await
        );
        assert!(
            !ledger
                .decide(gid, Decide::Approve { expires_at: exp })
                .await
        );
        assert!(
            ledger
                .decide(
                    gid,
                    Decide::Revoke {
                        at: now_secs() as f64,
                        note: None
                    }
                )
                .await
        );
        // terminal: revoked -> anything = false
        assert!(!ledger.decide(gid, Decide::ExpireByKernel).await);
        assert_eq!(
            ledger.find_by_idem("k1").await.unwrap().state,
            GrantState::Revoked
        );

        // separate row: deny path records code+note
        let gid2 = ledger.insert_pending(newg("k2")).await.expect("insert");
        assert!(
            ledger
                .decide(
                    gid2,
                    Decide::Deny {
                        code: DenyCode::HumanDenied,
                        note: Some("out of scope".into())
                    }
                )
                .await
        );
        let r = ledger.find_by_idem("k2").await.unwrap();
        assert_eq!(r.state, GrantState::Denied);
        assert_eq!(r.deny_code, Some(DenyCode::HumanDenied));
        assert_eq!(r.note.as_deref(), Some("out of scope"));
        // Deny from a denied row: rejected
        assert!(
            !ledger
                .decide(
                    gid2,
                    Decide::Deny {
                        code: DenyCode::HumanDenied,
                        note: None
                    }
                )
                .await
        );

        actor.abort();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn history_excludes_pending_filters_and_limits() {
        let dir = std::env::temp_dir().join(format!("gk-hist-{}", now_secs()));
        let (ledger, actor) = Ledger::open(&dir.join("t.db")).unwrap();

        // 3 decided rows in distinct terminal states + 1 still pending
        let a = ledger.insert_pending(newg("h-a")).await.unwrap();
        ledger
            .decide(
                a,
                Decide::Approve {
                    expires_at: now_secs() as f64 + 60.0,
                },
            )
            .await;
        let b = ledger.insert_pending(newg("h-b")).await.unwrap();
        ledger
            .decide(
                b,
                Decide::Deny {
                    code: DenyCode::HumanDenied,
                    note: Some("n".into()),
                },
            )
            .await;
        let c = ledger.insert_pending(newg("h-c")).await.unwrap();
        // Revoke originates from Approved; pending origin is rejected.
        ledger
            .decide(
                c,
                Decide::Approve {
                    expires_at: now_secs() as f64 + 60.0,
                },
            )
            .await;
        ledger
            .decide(
                c,
                Decide::Revoke {
                    at: now_secs() as f64,
                    note: None,
                },
            )
            .await;
        // flip a approved row to expired via the kernel path
        ledger.decide(a, Decide::ExpireByKernel).await;
        let _d = ledger.insert_pending(newg("h-pending")).await.unwrap();

        let all = ledger.history(None, 100).await;
        // newest first; approved row landed in expired, pending excluded
        assert_eq!(
            all.iter().map(|r| r.state).collect::<Vec<_>>(),
            vec![GrantState::Revoked, GrantState::Denied, GrantState::Expired]
        );
        assert!(all.iter().all(|r| r.state != GrantState::Pending));

        let only_denied = ledger.history(Some(GrantState::Denied), 100).await;
        assert_eq!(only_denied.len(), 1);
        assert_eq!(only_denied[0].idem_key.as_deref(), Some("h-b"));
        assert_eq!(only_denied[0].deny_code, Some(DenyCode::HumanDenied));

        let page = ledger.history(None, 2).await;
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].id, c, "limit must keep the NEWEST rows");

        // revoked-only filter proves state narrowing on a second value
        assert_eq!(
            ledger.history(Some(GrantState::Revoked), 100).await.len(),
            1
        );

        actor.abort();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn dup_idem_key_rejected_and_findable_across_states() {
        let dir = std::env::temp_dir().join(format!("gk-idem-{}", now_secs()));
        let (ledger, actor) = Ledger::open(&dir.join("t.db")).unwrap();
        let gid = ledger.insert_pending(newg("req-x")).await.expect("insert");
        assert!(
            ledger.insert_pending(newg("req-x")).await.is_none(),
            "UNIQUE must reject dup"
        );
        let found = ledger
            .find_by_idem("req-x")
            .await
            .expect("must find row by idem key");
        assert_eq!(found.id, gid);
        assert_eq!(found.proto, Proto::Tcp);
        ledger
            .decide(
                gid,
                Decide::Approve {
                    expires_at: now_secs() as f64 + 5.0,
                },
            )
            .await;
        ledger
            .decide(
                gid,
                Decide::Revoke {
                    at: now_secs() as f64,
                    note: None,
                },
            )
            .await;
        let found = ledger
            .find_by_idem("req-x")
            .await
            .expect("still found after revoke");
        assert_eq!(found.state, GrantState::Revoked);
        actor.abort();
        std::fs::remove_dir_all(&dir).ok();
    }
}
