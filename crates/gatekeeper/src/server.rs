//! Gatekeeper runtime core: shared state, startup, accept loops, background
//! reconcilers, and the MCP-side `access.request` pipeline.
//!
//! `mcp.sock` accepts requests but cannot approve; approvals arrive on
//! `admin.sock` (0600, see [`crate::admin`]). No approver connected → deny
//! immediately; silent past timeout → auto-deny.
//!
//! Kernel install/teardown lives in [`crate::install`], boot reconciliation
//! in [`crate::reconcile`] — the same split gk-tui got in the last round.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, oneshot, Mutex};

use gk_core::nft::{counter_in, counter_out, Batch, NftCli};
use gk_core::protocol::*;
use gk_core::types::{fmt_ttl, parse_ttl, PortSpec, SpecError, Target};
use serde::Serialize;

use crate::admin::handle_admin;
use crate::install::{
    install_carves, install_grant, install_scope, rebuild_acct, sweep_grant_objs,
};
use crate::ledger::{
    now_secs, ttl_expires, Decide, DenyCode, GrantRow, GrantState, Ledger, NewGrant,
};
use crate::reconcile::reconcile_on_boot;
use crate::Config;

pub struct State {
    pub cfg: Config,
    pub ledger: Ledger,
    pub nft: NftCli,
    /// pending requests awaiting a human: id -> decision channel
    pub pending: Mutex<HashMap<i64, oneshot::Sender<HumanDecision>>>,
    /// fire-and-forget events for all admin clients
    pub events: broadcast::Sender<String>,
    pub admins_online: AtomicUsize,
}

pub enum HumanDecision {
    Approve { ttl_secs: Option<u64> },
    Deny { note: Option<String> },
}

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let (ledger, _actor) = Ledger::open(&cfg.db)?;
    let st = Arc::new(State {
        cfg: cfg.clone(),
        ledger,
        nft: NftCli::default(),
        pending: Mutex::new(HashMap::new()),
        events: broadcast::channel(256).0,
        admins_online: AtomicUsize::new(0),
    });

    // Idempotent; fail startup if install fails so enforcement is never off.
    if !st.cfg.dry_run {
        let mut b = Batch::with_table(&st.cfg.nft_table);
        b.ensure_base();
        st.nft
            .apply(&b)
            .await
            .map_err(|e| anyhow::anyhow!("nft base install failed: {e}"))?;
        tracing::info!("nft base table ready");
        install_carves(&st).await?;
        install_scope(&st).await?;
        reconcile_on_boot(&st).await;
    } else {
        tracing::warn!("--dry-run: nft objects not installed (dev mode)");
    }

    for path in [&st.cfg.mcp_socket, &st.cfg.admin_socket] {
        let _ = std::fs::remove_file(path);
    }
    // TOCTOU-001: bind() creates the inode at 0777&~umask and it is live
    // immediately; a connect() before the chmod would hold a permanent
    // admin session (socket perms are checked at connect only). Tighten
    // umask so both sockets are born owner-rw-only, then restore. admin.sock
    // stays 0600; mcp.sock is widened to its group below when pinned.
    struct UmaskGuard(libc::mode_t);
    impl Drop for UmaskGuard {
        fn drop(&mut self) {
            unsafe { libc::umask(self.0) };
        }
    }
    let _umask = UmaskGuard(unsafe { libc::umask(0o177) });
    let mcp = UnixListener::bind(&st.cfg.mcp_socket)?;
    let admin = UnixListener::bind(&st.cfg.admin_socket)?;
    drop(_umask);
    debug_assert_eq!(
        std::fs::metadata(&st.cfg.admin_socket)?.permissions().mode() & 0o777,
        0o600,
        "admin.sock must be born 0600 (umask-guarded bind)"
    );
    // mcp.sock: reachable only by mcp_user's group (identity is still checked
    // per connection via SO_PEERCRED); with no resolved gid the socket stays
    // owner-only, which in dev means whoever started the daemon.
    if let Some(gid) = st.cfg.mcp_sock_gid {
        use std::os::unix::fs::{chown, PermissionsExt};
        chown(&st.cfg.mcp_socket, None, Some(gid))?;
        std::fs::set_permissions(&st.cfg.mcp_socket, std::fs::Permissions::from_mode(0o660))?;
    }

    spawn_expiry_reconciler(st.clone());
    if !st.cfg.dry_run {
        spawn_stats_poller(st.clone());
    }

    {
        let st = st.clone();
        tokio::spawn(async move {
            loop {
                match admin.accept().await {
                    Ok((s, _)) => {
                        let st = st.clone();
                        tokio::spawn(handle_admin(s, st));
                    }
                    Err(e) => tracing::error!("admin accept: {e}"),
                }
            }
        });
    }

    tracing::info!(
        mcp = %st.cfg.mcp_socket.display(),
        admin = %st.cfg.admin_socket.display(),
        "gatekeeper listening"
    );
    loop {
        match mcp.accept().await {
            Ok((s, _)) => {
                let st = st.clone();
                tokio::spawn(handle_mcp(s, st));
            }
            Err(e) => tracing::error!("mcp accept: {e}"),
        }
    }
}

/// Kernel reaps elements via TTL; this loop flips ledger rows + notifies.
fn spawn_expiry_reconciler(st: Arc<State>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            // list(Approved), not active(): active() hides expired rows this loop flips.
            let approved = st.ledger.list(GrantState::Approved).await;
            let now = now_secs() as f64;
            let expired: Vec<i64> = approved
                .iter()
                .filter(|g| g.expires_at.map(|e| e <= now).unwrap_or(true))
                .map(|g| g.id)
                .collect();
            if !expired.is_empty() {
                for id in &expired {
                    st.ledger.decide(*id, Decide::ExpireByKernel).await;
                    emit(
                        &st,
                        method::EV_EXPIRED,
                        EvExpired {
                            grant_id: id.to_string(),
                        },
                    );
                }
                // kernel already reaped the elements (TTL); now mirror the
                // ledger into accounting chains and drop dead objects.
                if let Err(e) = rebuild_acct(&st).await {
                    tracing::warn!(%e, "acct rebuild after expiry failed");
                }
                for id in &expired {
                    sweep_grant_objs(&st, *id).await;
                }
            }
        }
    });
}

/// Stats poller (~2s). Ledger for identity/countdown; named counters for
/// bytes. Runs only while an admin is connected.
fn spawn_stats_poller(st: Arc<State>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if st.admins_online.load(Ordering::SeqCst) == 0 {
                continue;
            }
            let rows = st.ledger.list(GrantState::Approved).await;
            if rows.is_empty() {
                continue;
            }
            let counters_json = match st.nft.list_json("counters", None).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(%e, "traffic poll: counter list failed");
                    continue;
                }
            };
            let poll = gk_core::nft::parse_poll(
                &serde_json::json!({ "nftables": [] }),
                &counters_json,
                &st.cfg.nft_table,
            );
            let now = now_secs();
            let mut stats: Vec<GrantStat> = Vec::new();
            for g in &rows {
                let b_out = poll
                    .counters
                    .get(&counter_out(g.id))
                    .map(|c| c.1)
                    .unwrap_or(0);
                let b_in = poll
                    .counters
                    .get(&counter_in(g.id))
                    .map(|c| c.1)
                    .unwrap_or(0);
                let stat = GrantStat {
                    grant_id: g.id.to_string(),
                    name: g.target.clone(),
                    dst: serde_json::from_str(&g.dst_json).unwrap_or_default(),
                    dst_port: PortSpec {
                        from: g.port_from,
                        to: g.port_to,
                    },
                    proto: g.proto,
                    seconds_remaining: g
                        .expires_at
                        .map(|e| (e as u64).saturating_sub(now))
                        .unwrap_or(0),
                    bytes_sent: b_out,
                    bytes_received: b_in,
                };
                stats.push(stat);
            }
            emit(&st, method::EV_TRAFFIC, EvTraffic { grants: stats });
        }
    });
}

pub(crate) fn peer_cred(s: &UnixStream) -> Option<tokio::net::unix::UCred> {
    s.peer_cred().ok()
}

// ------------------------------------------------------------------ MCP side

async fn handle_mcp(stream: UnixStream, st: Arc<State>) {
    // Fail CLOSED: with a pinned uid configured, an unreadable peer credential
    // is grounds for rejection — never an anonymous pass.
    if let Some(want) = st.cfg.mcp_peer_uid {
        match peer_cred(&stream) {
            Some(c) if c.uid() == want => {}
            other => {
                tracing::warn!(uid = ?other.map(|c| c.uid()), "mcp peer rejected by SO_PEERCRED");
                return;
            }
        }
    }
    let (r, mut w) = stream.into_split();
    let (resp_tx, mut resp_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let writer = tokio::spawn(async move {
        while let Some(line) = resp_rx.recv().await {
            if let Err(e) = w.write_all(format!("{line}\n").as_bytes()).await {
                tracing::warn!(%e, "mcp writer died");
                break;
            }
        }
        tracing::debug!("mcp writer task exiting (channel closed)");
    });
    // Connection must outlive in-flight requests; approval can arrive minutes later.
    let inflight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut lines = BufReader::new(r).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let req: RpcRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(%e, "bad json on mcp sock");
                continue;
            }
        };
        if req.method != method::ACCESS_REQUEST {
            resp_tx
                .send(rpc_err_str(
                    &req.id,
                    -32601,
                    "only access.request is served here",
                ))
                .ok();
        } else {
            inflight.fetch_add(1, Ordering::SeqCst);
            let tx = resp_tx.clone();
            let done = inflight.clone();
            dispatch_access(req, st.clone(), move |s: String| {
                tx.send(s).ok();
                done.fetch_sub(1, Ordering::SeqCst);
            });
        }
    }
    tracing::debug!("mcp client EOF; awaiting in-flight tasks");
    drop(resp_tx); // our copy goes; clones live in in-flight tasks
    while inflight.load(Ordering::SeqCst) > 0 {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tracing::debug!("mcp conn fully closed");
    let _ = writer.await;
}

/// access.request pipeline: validate → dedup → ledger → human or auto-deny.
/// `respond` is called exactly once with the serialized JSON-RPC reply line.
fn dispatch_access(req: RpcRequest, st: Arc<State>, respond: impl Fn(String) + Send + 'static) {
    tokio::spawn(async move {
        let id = req.id.clone();
        let inner = respond;
        let dbg_id = id.clone();
        let respond = move |s: String| {
            tracing::debug!(id = %dbg_id, len = s.len(), "responding on mcp conn");
            inner(s);
        };
        let params: AccessRequestParams = match req.params.map(serde_json::from_value) {
            Some(Ok(p)) => p,
            _ => {
                respond(rpc_err_str(&id, -32602, "invalid params"));
                return;
            }
        };

        let target = match pick_target(&params) {
            Ok(t) => t,
            Err(e) => {
                respond(rpc_err_str(&id, -32602, e.to_string()));
                return;
            }
        };
        if let Err(e) = params.dst_port.validate() {
            respond(rpc_err_str(&id, -32602, e.to_string()));
            return;
        }
        let ttl = match parse_ttl(&params.ttl_requested) {
            Ok(t) => t,
            Err(e) => {
                respond(rpc_err_str(&id, -32602, e.to_string()));
                return;
            }
        };

        // dedup: already covered by an active identical grant?
        let active = st.ledger.active().await;
        if let Some(g) = active.iter().find(|g| {
            g.target == target.canonical()
                && g.proto == params.proto
                && (g.port_from, g.port_to) == (params.dst_port.from, params.dst_port.to)
        }) {
            let resp = RpcResponse::ok(
                &id,
                Verdict::AlreadyGranted {
                    grant_id: g.id.to_string(),
                    expires_at: g.expires_at.map(fmt_unix),
                    note: None,
                },
            );
            respond(resp_line(&resp));
            return;
        }

        // No approver connected: deny immediately rather than queueing.
        if st.admins_online.load(Ordering::SeqCst) == 0 {
            let resp = RpcResponse::ok(
                &id,
                Verdict::Denied {
                    reason_code: DenyReason::ApproverOffline,
                    grant_id: None,
                    note: None,
                },
            );
            respond(resp_line(&resp));
            return;
        }

        let reason = sanitize(&params.reason);
        let tool = sanitize(&params.tool);
        let gid = match st
            .ledger
            .insert_pending(NewGrant {
                idem_key: id.clone(),
                target: target.canonical(),
                port_from: params.dst_port.from,
                port_to: params.dst_port.to,
                proto: params.proto,
                reason: reason.clone(),
                tool: tool.clone(),
                ttl_secs: ttl.as_secs(),
                created_at: now_secs(),
            })
            .await
        {
            Some(gid) => gid,
            None => {
                // UNIQUE idem_key = redelivery. Do not re-popup; return the original row.
                match st.ledger.find_by_idem(&id).await {
                    Some(orig) => respond(replay_verdict(&orig)),
                    None => respond(rpc_err_str(&id, -32001, "duplicate request id")),
                }
                return;
            }
        };
        st.ledger.audit("request", gid, target.canonical());

        let (tx, rx) = oneshot::channel::<HumanDecision>();
        st.pending.lock().await.insert(gid, tx);
        let popup_target = target.canonical();
        emit(
            &st,
            method::EV_REQUEST_NEW,
            // created_at lets a reconnecting TUI render honest "waiting m:ss"
            EvRequestNew {
                grant_id: gid.to_string(),
                target: popup_target,
                dst_port: params.dst_port,
                proto: params.proto,
                reason,
                tool,
                ttl_requested: params.ttl_requested,
                created_at: now_secs(),
            },
        );

        let verdict = match tokio::time::timeout(
            Duration::from_secs(st.cfg.approver_timeout_secs),
            rx,
        )
        .await
        {
            Ok(Ok(HumanDecision::Approve { ttl_secs })) => {
                let granted = cap_ttl(ttl_secs.map(Duration::from_secs).unwrap_or(ttl), &st);
                match install_grant(&st, &target, params.dst_port, gid, params.proto, granted).await
                {
                    Ok((eff, dsts)) => {
                        let exp = ttl_expires(granted);
                        if !st
                            .ledger
                            .decide(gid, Decide::Approve { expires_at: exp })
                            .await
                        {
                            tracing::error!(gid, "ledger failed to flip pending->approved");
                        }
                        // Persist this DNS resolution so later delete uses the same IPs.
                        let dst_json = serde_json::to_string(
                            &dsts.iter().map(|d| d.canonical()).collect::<Vec<_>>(),
                        )
                        .unwrap_or_else(|_| "[]".into());
                        if !st.ledger.set_dst(gid, dst_json).await {
                            tracing::warn!(
                                gid,
                                "set_dst: row not approved when persisting resolution"
                            );
                        }
                        // Accounting is best-effort; stats never gate enforcement.
                        if let Err(e) = rebuild_acct(&st).await {
                            tracing::warn!(gid, %e, "acct rebuild failed (stats degraded only)");
                        }
                        st.ledger.audit("approved", gid, format!("{eff:?}"));
                        emit(
                            &st,
                            method::EV_DECIDED,
                            EvDecided::Approved {
                                grant_id: gid.to_string(),
                                ttl_granted: fmt_ttl(granted),
                                expires_at: fmt_unix(exp),
                            },
                        );
                        Verdict::Approved {
                            grant_id: gid.to_string(),
                            effective: eff,
                            ttl_granted: fmt_ttl(granted),
                            expires_at: fmt_unix(exp),
                        }
                    }
                    Err(e) => {
                        // nft apply failed: kernel keeps prior state; deny rather than half-install.
                        tracing::error!(gid, %e, "nft install failed — denying");
                        st.ledger
                            .decide(
                                gid,
                                Decide::Deny {
                                    code: DenyCode::InstallFailed,
                                    note: Some(e.clone()),
                                },
                            )
                            .await;
                        Verdict::Denied {
                            reason_code: DenyReason::InstallFailed,
                            grant_id: Some(gid.to_string()),
                            note: Some(format!("enforcement failed: {e}")),
                        }
                    }
                }
            }
            Ok(Ok(HumanDecision::Deny { note })) => {
                st.ledger
                    .decide(
                        gid,
                        Decide::Deny {
                            code: DenyCode::HumanDenied,
                            note: note.clone(),
                        },
                    )
                    .await;
                Verdict::Denied {
                    reason_code: DenyReason::HumanDenied,
                    grant_id: Some(gid.to_string()),
                    note,
                }
            }
            // Err(RecvError)=sender dropped (shutdown) or Elapsed=approver silent → both deny
            Ok(Err(_)) | Err(_) => {
                st.ledger
                    .decide(
                        gid,
                        Decide::Deny {
                            code: DenyCode::ApproverTimeout,
                            note: None,
                        },
                    )
                    .await;
                Verdict::Denied {
                    reason_code: DenyReason::ApproverTimeout,
                    grant_id: Some(gid.to_string()),
                    note: None,
                }
            }
        };

        let resp = RpcResponse::ok(&id, &verdict);
        // Notify TUI for every verdict that has a row. Offline denies have neither.
        if let Verdict::Denied {
            grant_id: Some(gid),
            reason_code,
            note,
        } = &verdict
        {
            emit(
                &st,
                method::EV_DECIDED,
                EvDecided::Denied {
                    grant_id: gid.clone(),
                    reason_code: *reason_code,
                    note: note.clone(),
                },
            );
        }
        respond(resp_line(&resp));
    });
}

// ------------------------------------------------------------------- helpers

fn pick_target(p: &AccessRequestParams) -> Result<Target, SpecError> {
    let given = [&p.dst_host, &p.dst_ip, &p.dst_net]
        .iter()
        .filter(|x| x.is_some())
        .count();
    if given != 1 {
        return Err(SpecError::TargetCardinality(given));
    }
    if let Some(h) = &p.dst_host {
        let ok = !h.is_empty()
            && h.len() <= 253
            && h.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
        if !ok {
            return Err(SpecError::BadHost(h.clone()));
        }
        return Ok(Target::Host(h.clone()));
    }
    if let Some(i) = &p.dst_ip {
        return Ok(Target::Ip(i.parse()?));
    }
    if let Some(n) = &p.dst_net {
        let net: ipnet::IpNet = n
            .parse()
            .map_err(|e| SpecError::BadNetStr(format!("{n}: {e}")))?;
        return Ok(Target::Net(net));
    }
    unreachable!()
}

fn cap_ttl(d: Duration, st: &State) -> Duration {
    let max = parse_ttl(&st.cfg.max_ttl).unwrap_or(Duration::from_secs(4 * 3600));
    d.min(max)
}

/// Verdict for a redelivered request id. No second popup.
fn replay_verdict(orig: &GrantRow) -> String {
    let gid = orig.id.to_string();
    let d = match orig.state {
        GrantState::Pending => Verdict::Denied {
            // Pending original is not a grant; deny the replay, no second popup.
            reason_code: DenyReason::AlreadyPending,
            grant_id: Some(gid.clone()),
            note: Some(
                "request with this id is already pending approval (no second popup); \
                 do not treat as granted — await the original verdict or re-request \
                 with a new id"
                    .into(),
            ),
        },
        GrantState::Approved => Verdict::AlreadyGranted {
            grant_id: gid.clone(),
            expires_at: orig.expires_at.map(fmt_unix),
            note: None,
        },
        GrantState::Expired | GrantState::Revoked => Verdict::Denied {
            reason_code: DenyReason::GrantExpired,
            grant_id: Some(gid.clone()),
            note: Some(format!(
                "re-delivered request id {}; that grant is {} — re-request with a new id",
                orig.id,
                orig.state.as_str()
            )),
        },
        GrantState::Denied => Verdict::Denied {
            // replay the ORIGINAL denial, reason and human note included
            reason_code: match orig.deny_code.as_ref() {
                Some(DenyCode::ApproverOffline) => DenyReason::ApproverOffline,
                Some(DenyCode::ApproverTimeout) => DenyReason::ApproverTimeout,
                Some(DenyCode::InstallFailed) => DenyReason::InstallFailed,
                _ => DenyReason::HumanDenied,
            },
            grant_id: Some(gid.clone()),
            note: orig.note.clone(),
        },
    };
    resp_line(&RpcResponse::ok(orig.idem_key.as_deref().unwrap_or(""), &d))
}

/// Strip control chars so free text can't spoof TUI rows.
fn sanitize(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(280).collect()
}

/// UTC RFC3339 from unix seconds.
pub fn fmt_unix(secs: f64) -> String {
    use chrono::{DateTime, SecondsFormat};
    DateTime::from_timestamp(secs.max(0.0) as i64, 0)
        .map(|dt| dt.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_else(|| "-".into())
}

/// Broadcast one event to connected approvers. Serialization failure is
/// logged and the event dropped — a daemon never panics on the wire.
pub(crate) fn emit(st: &State, method: &str, params: impl Serialize) {
    let params = match serde_json::to_value(params) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(%e, method, "event serialization failed; dropped");
            return;
        }
    };
    let mut o = match serde_json::to_value(RpcRequest {
        jsonrpc: JsonRpcVersion::V2_0,
        id: String::new(),
        method: method.into(),
        params: Some(params),
    }) {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(%e, method, "event serialization failed; dropped");
            return;
        }
    };
    if let Some(m) = o.as_object_mut() {
        m.remove("id"); // notifications carry no id member
    }
    match serde_json::to_string(&o) {
        Ok(mut s) => {
            s.push('\n');
            let _ = st.events.send(s);
        }
        Err(e) => tracing::error!(%e, method, "event serialization failed; dropped"),
    }
}

/// Serialize a response to its wire line; failure degrades to a fixed
/// internal-error reply rather than panicking the connection task.
pub(crate) fn resp_line(resp: &RpcResponse) -> String {
    serde_json::to_string(resp).unwrap_or_else(|e| {
        tracing::error!(%e, "response serialization failed");
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"serialization failed"}}"#
            .to_string()
    })
}

fn rpc_err_str(id: &str, code: i32, msg: impl Into<String>) -> String {
    resp_line(&RpcResponse::err(id, code, msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gk_core::types::Proto;

    #[test]
    fn unix_ts_to_rfc3339_known_values() {
        assert_eq!(fmt_unix(0.0), "1970-01-01T00:00:00Z");
        assert_eq!(fmt_unix(1_757_925_600.0), "2025-09-15T08:40:00Z");
    }

    #[test]
    fn sanitize_strips_control_and_truncates() {
        let evil = "ok\r\n\x1b[31mGK: APPROVE ALL\x00";
        let s = sanitize(evil);
        assert!(!s.contains('\r') && !s.contains('\n') && !s.contains('\x1b'));
        assert!(sanitize(&"x".repeat(9999)).len() <= 280);
    }

    #[test]
    fn replay_verdict_per_state() {
        let row = |state: GrantState, deny: Option<DenyCode>, note: Option<&str>| GrantRow {
            id: 42,
            idem_key: Some("req-abc".into()),
            target: "ip:10.0.0.1".into(),
            dst_json: "[]".into(),
            port_from: 80,
            port_to: 80,
            proto: Proto::Tcp,
            reason: String::new(),
            tool: String::new(),
            ttl_secs: 60,
            granted_ttl_secs: None,
            state,
            created_at: 0,
            expires_at: Some(1_757_925_600.0),
            deny_code: deny,
            note: note.map(String::from),
        };
        let parse = |s: String| -> serde_json::Value { serde_json::from_str(&s).unwrap() };

        let v = parse(replay_verdict(&row(GrantState::Approved, None, None)));
        assert_eq!(v["id"], "req-abc");
        assert_eq!(v["result"]["decision"], "already_granted");
        assert_eq!(v["result"]["grant_id"], "42");

        let v = parse(replay_verdict(&row(GrantState::Expired, None, None)));
        assert_eq!(v["result"]["decision"], "denied");
        assert_eq!(v["result"]["reason_code"], "grant_expired");

        let v = parse(replay_verdict(&row(
            GrantState::Denied,
            Some(DenyCode::ApproverTimeout),
            None,
        )));
        assert_eq!(v["result"]["reason_code"], "approver_timeout");

        let v = parse(replay_verdict(&row(
            GrantState::Denied,
            Some(DenyCode::HumanDenied),
            Some("out of scope"),
        )));
        assert_eq!(v["result"]["reason_code"], "human_denied");
        assert_eq!(v["result"]["note"], "out of scope");

        // reply id must equal the replayed request id (idem key)
        let v = parse(replay_verdict(&row(GrantState::Pending, None, None)));
        assert_eq!(v["id"], "req-abc");
        assert_eq!(v["result"]["decision"], "denied");
        assert_eq!(v["result"]["reason_code"], "already_pending");
    }

    #[test]
    fn target_cardinality_enforced() {
        let p = AccessRequestParams {
            dst_host: None,
            dst_ip: None,
            dst_net: None,
            dst_port: PortSpec { from: 80, to: 80 },
            proto: Proto::Tcp,
            reason: String::new(),
            tool: String::new(),
            ttl_requested: "1m".into(),
        };
        assert!(matches!(
            pick_target(&p),
            Err(SpecError::TargetCardinality(0))
        ));

        let p2 = AccessRequestParams {
            dst_ip: Some("1.2.3.4".into()),
            dst_net: Some("10.0.0.0/8".into()),
            ..p.clone()
        };
        assert!(matches!(
            pick_target(&p2),
            Err(SpecError::TargetCardinality(2))
        ));

        let p3 = AccessRequestParams {
            dst_host: Some("bad$(host)".into()),
            ..p.clone()
        };
        assert!(
            pick_target(&p3).is_err(),
            "shell metachars must not pass host regex"
        );

        let p4 = AccessRequestParams {
            dst_net: Some("172.16.0.0/12".into()),
            ..p.clone()
        };
        assert_eq!(pick_target(&p4).unwrap().canonical(), "net:172.16.0.0/12");
    }
}
