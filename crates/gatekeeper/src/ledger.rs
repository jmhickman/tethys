//! rusqlite grant ledger (decision D8). Single writer task owns it; callers
//! go through a spawned actor to keep tokio happy (rusqlite is sync).

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrantRow {
    pub id: i64,
    pub idem_key: Option<String>,
    /// canonical request target ("host:x" | "ip:x" | "net:x")
    pub target: String,
    /// installed destinations (post-resolution), as JSON array of strings
    pub dst_json: String,
    pub port_from: u16,
    pub port_to: u16,
    pub proto: String,
    pub reason: String,
    pub tool: String,
    pub ttl_secs: u64,
    pub granted_ttl_secs: Option<u64>,
    pub state: String, // pending|approved|denied|expired|revoked
    pub created_at: u64,
    pub expires_at: Option<f64>, // unix seconds
    pub deny_code: Option<String>,
    pub note: Option<String>,
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

enum LedgerCmd {
    Insert(GrantRow, tokio::sync::oneshot::Sender<rusqlite::Result<i64>>),
    Decide(
        i64,
        String, // new state
        Vec<String>, // required current state(s)
        Option<f64>,
        Option<String>,
        Option<String>,
        tokio::sync::oneshot::Sender<bool>,
    ),
    List(String, tokio::sync::oneshot::Sender<Vec<GrantRow>>),
    FindActive(tokio::sync::oneshot::Sender<Vec<GrantRow>>),
    MarkExpired(Vec<i64>, tokio::sync::oneshot::Sender<()>),
    SetDst(
        i64,
        String,
        tokio::sync::oneshot::Sender<bool>,
    ),
    Audit(String, String, i64),
}

#[derive(Clone)]
pub struct Ledger {
    tx: mpsc::UnboundedSender<LedgerCmd>,
}

fn row_from(r: &rusqlite::Row) -> rusqlite::Result<GrantRow> {
    Ok(GrantRow {
        id: r.get(0)?,
        idem_key: r.get(1)?,
        target: r.get(2)?,
        dst_json: r.get(3)?,
        port_from: r.get::<_, i64>(4)? as u16,
        port_to: r.get::<_, i64>(5)? as u16,
        proto: r.get(6)?,
        reason: r.get(7)?,
        tool: r.get(8)?,
        ttl_secs: r.get::<_, i64>(9)? as u64,
        granted_ttl_secs: r.get::<_, Option<i64>>(10)?.map(|v| v as u64),
        state: r.get(11)?,
        created_at: r.get::<_, i64>(12)? as u64,
        expires_at: r.get(13)?,
        deny_code: r.get(14)?,
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
                                    g.proto, g.reason, g.tool, g.ttl_secs as i64, g.created_at as i64],
                        );
                        // NOT last_insert_rowid alone: it retains the PREVIOUS rowid
                        // when this INSERT fails (UNIQUE idem violation would alias
                        // to a stale grant). changes()==1 proves THIS insert landed.
                        match res {
                            Ok(1) => {
                                let id = conn.last_insert_rowid();
                                let _ = reply.send(Ok(id));
                            }
                            _ => {
                                let _ = reply.send(Err(rusqlite::Error::QueryReturnedNoRows));
                            }
                        }
                    }
                    LedgerCmd::Decide(id, state, from_states, expires, deny_code, note, reply) => {
                        // caller declares legal origin state(s); prevents ghost rows
                        // (e.g. revoke of an approved row silently matching nothing).
                        // Bind layout: ?1 id, ?2 new-state, ?3 expires, ?4 deny_code,
                        // ?5 note; from-states start at ?6 — placeholder numbers MUST match.
                        let placeholders: Vec<String> = (0..from_states.len().max(1))
                            .map(|i| format!("?{}", 6 + i))
                            .collect();
                        let sql = format!(
                            "UPDATE grants SET state=?2, expires_at=?3, deny_code=?4, note=?5, \
                             granted_ttl_secs=COALESCE(granted_ttl_secs, CAST(?3 - created_at AS INTEGER)) \
                             WHERE id=?1 AND state IN ({})",
                            placeholders.join(",")
                        );
                        let mut stmt = match conn.prepare(&sql) {
                            Ok(s) => s,
                            Err(e) => {
                                let _ = reply.send(false);
                                tracing::error!(%e, "decide prepare failed");
                                continue;
                            }
                        };
                        // bind: 1=id, 2=state, 3=expires, 4=deny_code, 5=note, then from-states
                        let n = match stmt.execute(rusqlite::params_from_iter(
                            std::iter::once(rusqlite::types::Value::Integer(id))
                                .chain(std::iter::once(rusqlite::types::Value::Text(state)))
                                .chain(std::iter::once(
                                    expires.map(rusqlite::types::Value::Real)
                                        .unwrap_or(rusqlite::types::Value::Null),
                                ))
                                .chain(std::iter::once(
                                    deny_code.map(rusqlite::types::Value::Text)
                                        .unwrap_or(rusqlite::types::Value::Null),
                                ))
                                .chain(std::iter::once(
                                    note.map(rusqlite::types::Value::Text)
                                        .unwrap_or(rusqlite::types::Value::Null),
                                ))
                                .chain(from_states.iter().map(|s| rusqlite::types::Value::Text(s.clone()))),
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
                            if let Ok(rows) = st.query_map(params![state], row_from) {
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
                    LedgerCmd::MarkExpired(ids, reply) => {
                        for id in ids {
                            let _ = conn.execute(
                                "UPDATE grants SET state='expired' WHERE id=?1 AND state='approved'",
                                params![id],
                            );
                        }
                        let _ = reply.send(());
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

    pub async fn insert_pending(&self, g: &GrantRow) -> Option<i64> {
        let g = g.clone();
        self.ask(move |reply| LedgerCmd::Insert(g, reply))
            .await
            .ok()
    }
    pub async fn decide_from(
        &self,
        id: i64,
        state: &str,
        from_states: &[&str],
        expires_at: Option<f64>,
        deny_code: Option<String>,
        note: Option<String>,
    ) -> bool {
        self.ask(|reply| {
            LedgerCmd::Decide(
                id,
                state.into(),
                from_states.iter().map(|s| s.to_string()).collect(),
                expires_at,
                deny_code,
                note,
                reply,
            )
        })
        .await
    }

    /// approve/deny transitions — legal only from 'pending'
    pub async fn decide(
        &self,
        id: i64,
        state: &str,
        expires_at: Option<f64>,
        deny_code: Option<String>,
        note: Option<String>,
    ) -> bool {
        self.decide_from(id, state, &["pending"], expires_at, deny_code, note)
            .await
    }
    pub async fn list(&self, state: &str) -> Vec<GrantRow> {
        self.ask(|reply| LedgerCmd::List(state.into(), reply)).await
    }
    pub async fn active(&self) -> Vec<GrantRow> {
        self.ask(|reply| LedgerCmd::FindActive(reply)).await
    }
    pub async fn mark_expired(&self, ids: &[i64]) {
        let ids = ids.to_vec();
        self.ask(move |reply| LedgerCmd::MarkExpired(ids, reply))
            .await
    }
    /// Persist resolved dst list for an APPROVED grant (returns false if the
    /// row is not approved — stale flips can't corrupt it).
    pub async fn set_dst(&self, id: i64, dst_json: String) -> bool {
        self.ask(move |reply| LedgerCmd::SetDst(id, dst_json, reply)).await
    }
    pub fn audit(&self, event: &str, grant_id: i64, detail: impl Into<String>) {
        self.tx
            .send(LedgerCmd::Audit(event.into(), detail.into(), grant_id))
            .ok();
    }
}

pub fn ttl_expires(granted: Duration) -> f64 {
    now_secs() as f64 + granted.as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: from-state placeholder numbering in Decide (?1..=id/state/exp/deny/note,
    /// origin states at ?6+). A misnumbered bind silently flips zero rows.
    #[tokio::test]
    async fn decide_transitions_enforce_origin_state() {
        let dir = std::env::temp_dir().join(format!("gk-ledger-test-{}", now_secs()));
        let (ledger, actor) = Ledger::open(&dir.join("t.db")).unwrap();

        let row = GrantRow {
            id: 0,
            idem_key: Some("k1".into()),
            target: "ip:203.0.113.9".into(),
            dst_json: "[]".into(),
            port_from: 80,
            port_to: 80,
            proto: "tcp".into(),
            reason: "r".into(),
            tool: "t".into(),
            ttl_secs: 60,
            granted_ttl_secs: None,
            state: "pending".into(),
            created_at: now_secs(),
            expires_at: None,
            deny_code: None,
            note: None,
        };
        let gid = ledger.insert_pending(&row).await.expect("insert");

        // pending -> approved (legal)
        assert!(ledger.decide(gid, "approved", Some(now_secs() as f64 + 60.0), None, None).await);
        // pending -> denied now ILLEGAL (already approved; wrong origin)
        assert!(!ledger.decide(gid, "denied", None, Some("x".into()), None).await);
        // approved -> revoked via decide_from (legal) — the revoke/stop path
        assert!(ledger
            .decide_from(gid, "revoked", &["approved"], Some(now_secs() as f64), None, Some("stop".into()))
            .await);
        // double-revoke is a no-op false (no ghost flips)
        assert!(!ledger
            .decide_from(gid, "revoked", &["approved"], Some(now_secs() as f64), None, None)
            .await);

        let _ = ledger.list("revoked").await; // sanity query path
        actor.abort();
        std::fs::remove_dir_all(&dir).ok();
    }
}
