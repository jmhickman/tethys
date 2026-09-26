//! admin.sock: the human side. Approvals, decisions, snapshots, subscribe,
//! everything the TUI sends. Reads state through `State`, flips the ledger,
//! installs/tears down kernel elements via `crate::install`.

use std::sync::Arc;

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use tethys_core::nft::{Batch, GrantElem};
use tethys_core::protocol::{
    admin, method, EvDecided, EvStopped, RpcRequest, RpcResponse, SubscribeAck,
};
use tethys_core::types::PortSpec;
use tethys_core::wire::{GrantState, PendingRowWire};

use crate::install::{rebuild_acct, row_elems, sweep_grant_objs};
use crate::ledger::{now_secs, Decide};
use crate::server::{
    emit, peer_cred, read_frame_resumable, resp_line, CountGuard, Frame, HumanDecision, State,
};

/// Serve one admin.sock client: gate on peer credentials, then loop over
/// broadcast events and request frames until either breaks. The 0600 inode
/// mode is the primary access gate; the SO_PEERCRED check makes it enforced
/// rather than assumed (TOCTOU-001). Admitted peers: root (or the configured
/// admin uid) and the daemon's own euid for dev/test runs where nobody is
/// root; unreadable creds fail closed, like mcp.sock. The admins_online
/// guard is RAII because a panic in the loop (e.g. ledger actor death) must
/// not leave a phantom admin online, which would disable ApproverOffline
/// forever. Frames share the slow-loris/oversize pattern from mcp.sock even
/// though this socket is root-only; a lagged or closed broadcast ends the
/// session.
pub(crate) async fn handle_admin(stream: UnixStream, st: Arc<State>) {
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
    let _online = CountGuard::inc(&st.admins_online);
    let mut sub_rx = st.events.subscribe();
    let (mut r, mut w) = stream.into_split();
    let mut reader = BufReader::new(&mut r);
    // CANCELSAFETY-001: this read future is cancelled whenever the sibling
    // broadcast branch wins the select. Bytes tokio already moved out of the
    // BufReader live in `buf`, so the read must be resumable (never clears)
    // and only cleared here, after a complete line has been consumed —
    // otherwise a partial operator frame is silently stranded and lost.
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    loop {
        tokio::select! {
            ev = sub_rx.recv() => {
                match ev {
                    Ok(msg) => { if w.write_all(msg.as_bytes()).await.is_err() { break } }
                    Err(_) => break,
                }
            }
            f = read_frame_resumable(&mut reader, &mut buf) => {
                let line = match f {
                    Frame::Line(s) => s,
                    Frame::TooLong | Frame::Idle | Frame::Eof => break,
                };
                // The complete line now lives in `line`; the buffer is free
                // for the next frame even if parsing below fails.
                buf.clear();
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

/// Dispatch one admin command. Ok = the reply; Err = an already-built error
/// reply (params shape etc.). list.pending snapshots rows for TUI reconnect,
/// marking decidable only those with a live decision channel. list.history
/// returns decided rows; an unknown state or a pending filter is a client
/// error, not a silent empty result (serde rejects junk spellings), and limit
/// must be 1..=1000 (default 100). The subscribe ack carries the approver
/// timeout for the TUI countdown and the daemon version to detect skew.
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
                .allow
                .read()
                .await
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
        method::RELOAD_ALLOW => reload_allow(req, st).await,
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
                approver_timeout_secs: st.cfg.approver_timeout_secs,
                version: env!("CARGO_PKG_VERSION").into(),
            },
        )),
        _ => Ok(RpcResponse::err(&req.id, -32601, "unknown method")),
    }
}

/// Emergency stop: terminate grants; baseline rules untouched. Three
/// phases: delete kernel elements (one atomic batch; if it hits a missing
/// element, retry per grant and, on failure, re-poll the kernel — a grant
/// counts as removed only when no live element attributed to it remains),
/// deny everything pending through its decision channel, then flip approved
/// rows to revoked. Accounting follows the ledger: chains flush empty and
/// per-grant objects are swept.
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
                        // STRCMP-001: classify structurally, never by
                        // substring-matching rendered error text. A failed
                        // delete counts as removed only if a fresh poll_live
                        // shows no live element still attributed to this
                        // grant; anything else is reported as a failure so
                        // the kill switch never overstates teardown.
                        Err(e2) => {
                            if grant_elems_gone(st, g.id).await {
                                tracing::warn!(id = g.id, %e2,
                                    "stop.grants per-grant delete failed but poll_live shows no live elements; counted removed");
                                ok += 1;
                            } else {
                                tracing::error!(id = g.id, %e2,
                                    "stop.grants per-grant delete failed; kernel elements may still be live")
                            }
                        }
                    }
                }
            }
            n = ok;
        }
    }
    let pendings: Vec<i64> = st.pending.lock().await.keys().copied().collect();
    for gid in pendings {
        if let Some(tx) = st.pending.lock().await.remove(&gid) {
            tx.send(HumanDecision::Deny {
                note: Some("stopped by operator".into()),
            })
            .ok();
        }
    }
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
    if let Err(e) = rebuild_acct(st).await {
        tracing::warn!(%e, "acct rebuild after stop.grants failed");
    }
    for g in &rows {
        sweep_grant_objs(st, g.id).await;
    }
    emit(st, method::EV_STOPPED, EvStopped { grants_removed: n });
    RpcResponse::ok(&req.id, serde_json::json!({"revoked": n}))
}

/// True iff a fresh kernel poll shows no live grant element still
/// attributed to `gid` (STRCMP-001). Attribution is the `tethys:g<gid>`
/// comment that `add_grant` stamps — the same convention boot reconcile
/// uses; unattributed elements belong to nobody provable and are ignored.
/// A poll failure means kernel truth is unknown, so this fails CLOSED: an
/// unverifiable delete is never counted as removed.
async fn grant_elems_gone(st: &Arc<State>, gid: i64) -> bool {
    match st.nft.poll_live(&st.cfg.nft_table).await {
        Ok(p) => no_live_elems_for(&p.elements, gid),
        Err(e) => {
            tracing::error!(gid, %e, "stop.grants: poll_live after failed delete failed; treating grant as still live");
            false
        }
    }
}

/// Pure half of [`grant_elems_gone`]: no element in the kernel view carries
/// this grant's attribution comment. Elements with no (or unparseable)
/// comment are not attributed to anyone and never keep a grant alive.
fn no_live_elems_for(elements: &[tethys_core::nft::LiveElement], gid: i64) -> bool {
    !elements
        .iter()
        .any(|el| crate::reconcile::grant_gid_of_comment(&el.comment) == Some(gid))
}

/// `reload.allow`: re-read the config file's allow list and reinstall the
/// carve sets, so operators can adjust to drift mid-engagement without a
/// daemon restart (which would drop nothing but costs a blip + journal
/// noise). Swap st.allow first, then install: install_carves snapshots
/// st.allow, so a failure after the swap leaves kernel and state consistent
/// with each other (both new); failure before it is unreachable since the
/// parse already passed.
/// Refused when the daemon started with --allow flags: those replace the file
/// entirely, and silently switching authority between file and flags is worse
/// than asking for a restart. The whole file is re-read and re-parsed (not
/// just `allow`, unknown keys still rejected), so an operator breaking
/// something else in it gets a refusal rather than a list parsed from a file
/// that would no longer boot.
async fn reload_allow(req: &RpcRequest, st: &Arc<State>) -> Result<RpcResponse, RpcResponse> {
    if st.cfg.allow_from_cli {
        return Err(RpcResponse::err(
            &req.id,
            -32001,
            "allow list came from CLI flags; restart to change it",
        ));
    }
    let text = std::fs::read_to_string(&st.cfg.config_path).map_err(|e| {
        RpcResponse::err(
            &req.id,
            -32001,
            format!("read {}: {e}", st.cfg.config_path.display()),
        )
    })?;
    let file: crate::config::FileConfig = toml::from_str(&text).map_err(|e| {
        RpcResponse::err(
            &req.id,
            -32001,
            format!("parse {}: {e}", st.cfg.config_path.display()),
        )
    })?;
    let mut fresh = Vec::with_capacity(file.allow.len());
    for entry in &file.allow {
        match crate::config::parse_allow(entry) {
            Ok(v) => fresh.extend(v),
            Err(e) => {
                return Err(RpcResponse::err(
                    &req.id,
                    -32001,
                    format!("config `allow`: {e}"),
                ))
            }
        }
    }
    *st.allow.write().await = fresh;
    crate::install::install_carves(st)
        .await
        .map_err(|e| RpcResponse::err(&req.id, -32001, format!("carve reinstall failed: {e}")))?;
    let n = st.allow.read().await.len();
    tracing::info!(entries = n, "reload.allow: operator allow list reinstalled");
    Ok(RpcResponse::ok(&req.id, serde_json::json!({"reloaded": n})))
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

#[cfg(test)]
mod tests {
    use super::*;
    use tethys_core::nft::LiveElement;
    use tethys_core::types::Proto;

    fn elem(comment: Option<&str>) -> LiveElement {
        LiveElement {
            set: "grants_v4".into(),
            dst: "10.0.0.1".into(),
            proto: Proto::Tcp,
            port_from: 443,
            port_to: 443,
            expires_secs: 60.0,
            comment: comment.map(String::from),
        }
    }

    // STRCMP-001: only an element attributed to THIS grant keeps it alive.
    // A live element belonging to another grant (or to nobody) must not make
    // this one's teardown count as failed, and this grant's own surviving
    // element must never count as removed.
    #[test]
    fn stop_grants_classifies_teardown_by_attribution() {
        assert!(no_live_elems_for(&[], 7));
        assert!(no_live_elems_for(&[elem(Some("tethys:g8")), elem(None)], 7));
        assert!(!no_live_elems_for(
            &[elem(Some("tethys:g8")), elem(Some("tethys:g7"))],
            7
        ));
        // An unattributed lookalike is not attribution.
        assert!(no_live_elems_for(
            &[elem(Some("g7")), elem(Some("tethys:gate7"))],
            7
        ));
    }
}
