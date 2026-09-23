//! admin.sock: the human side. Approvals, decisions, snapshots, subscribe —
//! everything the TUI sends. Reads state through `State`, flips the ledger,
//! installs/tears down kernel elements via `crate::install`.

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use gk_core::nft::{Batch, GrantElem};
use gk_core::protocol::{
    admin, method, EvDecided, EvStopped, RpcRequest, RpcResponse, SubscribeAck,
};
use gk_core::types::PortSpec;
use gk_core::wire::{GrantState, PendingRowWire};

use crate::install::{rebuild_acct, row_elems, sweep_grant_objs};
use crate::ledger::{now_secs, Decide};
use crate::server::{emit, peer_cred, resp_line, CountGuard, HumanDecision, State};

pub(crate) async fn handle_admin(stream: UnixStream, st: Arc<State>) {
    // TOCTOU-001 defense-in-depth: the 0600 inode mode is the primary gate;
    // SO_PEERCRED makes it enforced rather than assumed. Admitted: root (or
    // the configured admin uid) and the daemon's own euid (dev/test runs
    // where nobody is root). Unreadable creds fail closed, like mcp.sock.
    let self_uid = nix::unistd::geteuid().as_raw();
    let ok = match peer_cred(&stream) {
        Some(c) => c.uid() == self_uid || st.cfg.admin_peer_uid == Some(c.uid()),
        None => false,
    };
    if !ok {
        tracing::warn!(
            uid = ?peer_cred(&stream).map(|c| c.uid()),
            admin_uid = ?st.cfg.admin_peer_uid,
            self_uid,
            "admin peer rejected by SO_PEERCRED"
        );
        return;
    }
    tracing::info!(uid = ?peer_cred(&stream).map(|c| c.uid()), "admin client connected");
    // RAII: a panic in the loop (e.g. ledger actor death) must not leave a
    // phantom admin online — that would disable ApproverOffline forever.
    let _online = CountGuard::inc(&st.admins_online);
    let mut sub_rx = st.events.subscribe();
    let (mut r, mut w) = stream.into_split();
    let mut lines = BufReader::new(&mut r).lines();
    loop {
        tokio::select! {
            ev = sub_rx.recv() => {
                match ev {
                    Ok(msg) => { if w.write_all(msg.as_bytes()).await.is_err() { break } }
                    Err(_) => break, // lagged/closed
                }
            }
            l = lines.next_line() => {
                let line = match l {
                    Ok(Some(s)) => s,
                    _ => break,
                };
                let req: RpcRequest = match serde_json::from_str(line.trim()) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let resp = handle_admin_cmd(&req, &st).await;
                if w.write_all(format!("{}\n", resp_line(&resp)).as_bytes()).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// Deserialize admin params; a shape error is a client error (-32602), never
/// a silent "no such request". Absent/null params deserialize as `{}` so
/// commands with all-optional fields (list.history) keep their defaults.
fn params_as<T: serde::de::DeserializeOwned>(req: &RpcRequest) -> Result<T, RpcResponse> {
    let p = match &req.params {
        Some(p @ serde_json::Value::Object(_)) => p.clone(),
        _ => serde_json::json!({}),
    };
    serde_json::from_value(p)
        .map_err(|e| RpcResponse::err(&req.id, -32602, format!("bad params: {e}")))
}

async fn handle_admin_cmd(req: &RpcRequest, st: &Arc<State>) -> RpcResponse {
    admin_cmd(req, st).await.unwrap_or_else(|err| err)
}

/// Ok = the reply; Err = an already-built error reply (params shape etc.).
async fn admin_cmd(req: &RpcRequest, st: &Arc<State>) -> Result<RpcResponse, RpcResponse> {
    match req.method.as_str() {
        method::APPROVE => {
            let admin::Approve { grant_id, ttl_secs } = params_as(req)?;
            let tx = st.pending.lock().await.remove(&grant_id);
            match tx {
                Some(tx) => {
                    tx.send(HumanDecision::Approve { ttl_secs }).ok();
                    Ok(RpcResponse::ok(
                        &req.id,
                        serde_json::json!({"queued": true}),
                    ))
                }
                None => Ok(RpcResponse::err(&req.id, -32004, "no such pending request")),
            }
        }
        method::DENY => {
            let admin::Deny { grant_id, note } = params_as(req)?;
            let tx = st.pending.lock().await.remove(&grant_id);
            match tx {
                Some(tx) => {
                    tx.send(HumanDecision::Deny { note }).ok();
                    Ok(RpcResponse::ok(
                        &req.id,
                        serde_json::json!({"queued": true}),
                    ))
                }
                None => Ok(RpcResponse::err(&req.id, -32004, "no such pending request")),
            }
        }
        method::REVOKE => {
            let admin::GrantId { grant_id } = params_as(req)?;
            revoke(st, grant_id).await;
            Ok(RpcResponse::ok(
                &req.id,
                serde_json::json!({"revoked": grant_id.to_string()}),
            ))
        }
        method::LIST_GRANTS => {
            let rows = st.ledger.list(GrantState::Approved).await;
            Ok(RpcResponse::ok(&req.id, rows))
        }
        method::LIST_ALLOW => {
            let out: Vec<serde_json::Value> = st
                .cfg
                .allow
                .iter()
                .map(|(t, p, proto)| {
                    serde_json::json!({
                        "target": t.canonical(),
                        "port_from": p.from,
                        "port_to": p.to,
                        "proto": proto,
                    })
                })
                .collect();
            Ok(RpcResponse::ok(&req.id, out))
        }
        method::LIST_PENDING => {
            // Snapshot for TUI reconnect. Only rows with a live decision channel are decidable.
            let rows = st.ledger.list(GrantState::Pending).await;
            let live = st.pending.lock().await;
            let out: Vec<PendingRowWire> = rows
                .into_iter()
                .map(|r| {
                    let waiting = live.contains_key(&r.id);
                    PendingRowWire { row: r, waiting }
                })
                .collect();
            Ok(RpcResponse::ok(&req.id, out))
        }
        method::LIST_HISTORY => {
            // Decided rows. Unknown state or a pending filter is a client
            // error, not a silent empty (serde rejects junk spellings).
            let h: admin::History = params_as(req)?;
            if h.state == Some(GrantState::Pending) {
                return Ok(RpcResponse::err(
                    &req.id,
                    -32602,
                    "bad history state \"pending\"",
                ));
            }
            let limit = match h.limit {
                Some(l) if (1..=1000).contains(&l) => l,
                Some(_) => return Ok(RpcResponse::err(&req.id, -32602, "limit must be 1..=1000")),
                None => 100,
            };
            let rows = st.ledger.history(h.state, limit).await;
            Ok(RpcResponse::ok(&req.id, rows))
        }
        method::STOP_GRANTS => Ok(stop_grants(req, st).await),
        method::SUBSCRIBE => Ok(RpcResponse::ok(
            &req.id,
            SubscribeAck {
                events: [
                    method::EV_REQUEST_NEW,
                    method::EV_DECIDED,
                    method::EV_EXPIRED,
                    method::EV_STOPPED,
                    method::EV_TRAFFIC,
                    method::EV_ERROR,
                ]
                .map(String::from)
                .to_vec(),
                // TUI countdown needs the timeout; version detects daemon skew.
                approver_timeout_secs: st.cfg.approver_timeout_secs,
                version: env!("CARGO_PKG_VERSION").into(),
            },
        )),
        _ => Ok(RpcResponse::err(&req.id, -32601, "unknown method")),
    }
}

/// Emergency stop: terminate grants; baseline rules untouched.
async fn stop_grants(req: &RpcRequest, st: &Arc<State>) -> RpcResponse {
    tracing::info!("stop.grants invoked");
    let mut n = 0usize;
    let rows = st.ledger.list(GrantState::Approved).await;
    let mut b = Batch::with_table(&st.cfg.nft_table);
    for g in &rows {
        let proto = g.proto;
        let port = PortSpec {
            from: g.port_from,
            to: g.port_to,
        };
        match row_elems(g).await {
            Ok(dsts) => {
                for d in dsts {
                    b.delete_grant(&GrantElem {
                        dst: d,
                        proto,
                        port,
                    });
                }
                n += 1;
            }
            Err(e) => tracing::error!(id = g.id, %e, "stop.grants resolve failed"),
        }
    }
    if !st.cfg.dry_run && n > 0 {
        if let Err(e) = st.nft.apply(&b).await {
            // Atomic batch hit a missing element: retry per grant, tolerate ENOENT.
            tracing::warn!(%e, "stop.grants batch failed; per-grant fallback");
            let mut ok = 0usize;
            for g in &rows {
                let proto = g.proto;
                let port = PortSpec {
                    from: g.port_from,
                    to: g.port_to,
                };
                if let Ok(dsts) = row_elems(g).await {
                    let mut gb = Batch::with_table(&st.cfg.nft_table);
                    for d in dsts {
                        gb.delete_grant(&GrantElem {
                            dst: d,
                            proto,
                            port,
                        });
                    }
                    match st.nft.apply(&gb).await {
                        Ok(()) => ok += 1,
                        Err(e2) if e2.to_string().contains("No such file") => ok += 1, // already gone
                        Err(e2) => {
                            tracing::error!(id = g.id, %e2, "stop.grants per-grant delete failed")
                        }
                    }
                }
            }
            n = ok;
        }
    }
    // deny everything currently pending + flip rows
    let pendings: Vec<i64> = st.pending.lock().await.keys().copied().collect();
    for gid in pendings {
        if let Some(tx) = st.pending.lock().await.remove(&gid) {
            tx.send(HumanDecision::Deny {
                note: Some("stopped by operator".into()),
            })
            .ok();
        }
    }
    // flip rows (pending ones were just denied above via their channels)
    for g in &rows {
        st.ledger
            .decide(
                g.id,
                Decide::Revoke {
                    at: now_secs() as f64,
                    note: Some("stop.grants".into()),
                },
            )
            .await;
    }
    // accounting follows the ledger: chains flush empty, objects swept.
    if let Err(e) = rebuild_acct(st).await {
        tracing::warn!(%e, "acct rebuild after stop.grants failed");
    }
    for g in &rows {
        sweep_grant_objs(st, g.id).await;
    }
    emit(st, method::EV_STOPPED, EvStopped { grants_removed: n });
    RpcResponse::ok(&req.id, serde_json::json!({"revoked": n}))
}

async fn revoke(st: &Arc<State>, gid: i64) {
    if let Some(tx) = st.pending.lock().await.remove(&gid) {
        tx.send(HumanDecision::Deny {
            note: Some("revoked".into()),
        })
        .ok();
    }
    let rows = st.ledger.list(GrantState::Approved).await;
    if let Some(g) = rows.iter().find(|g| g.id == gid) {
        let proto = g.proto;
        let port = PortSpec {
            from: g.port_from,
            to: g.port_to,
        };
        if !st.cfg.dry_run {
            match row_elems(g).await {
                Ok(dsts) => {
                    let mut b = Batch::with_table(&st.cfg.nft_table);
                    for d in dsts {
                        b.delete_grant(&GrantElem {
                            dst: d,
                            proto,
                            port,
                        });
                    }
                    if let Err(e) = st.nft.apply(&b).await {
                        tracing::error!(gid, %e, "revoke delete failed");
                    }
                }
                Err(e) => tracing::error!(gid, %e, "revoke resolve failed"),
            }
        }
    }
    if !st
        .ledger
        .decide(
            gid,
            Decide::Revoke {
                at: now_secs() as f64,
                note: None,
            },
        )
        .await
    {
        tracing::warn!(
            gid,
            "revoke: no approved row to flip (pending-only or already decided)"
        );
    }
    if let Err(e) = rebuild_acct(st).await {
        tracing::warn!(gid, %e, "acct rebuild after revoke failed");
    }
    sweep_grant_objs(st, gid).await;
    emit(
        st,
        method::EV_DECIDED,
        EvDecided::Revoked {
            grant_id: gid.to_string(),
        },
    );
}
