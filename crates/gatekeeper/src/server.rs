//! Gatekeeper runtime: two unix sockets, pending-request state machine,
//! kernel-TTL-backed grants, periodic expiry reconciliation.
//!
//! Threat model (docs §trust): `mcp.sock` accepts requests but can NEVER
//! approve; approvals only arrive on `admin.sock` (0600 root). Approver-absent
//! rules per decision R2: no admin connected → immediate deny; admin silent
//! past timeout → auto-deny.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, oneshot, Mutex};

use gk_core::nft::{
    acct_set, counter_in, counter_out, Batch, CHAIN_ACCT_IN, CHAIN_ACCT_OUT, Dir, ElemDst,
    GrantElem, NftBackend, NftCli,
};
use gk_core::protocol::*;
use gk_core::types::{fmt_ttl, parse_ttl, PortSpec, Proto, SpecError, Target};

use crate::ledger::{now_secs, ttl_expires, GrantRow, Ledger};
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

    // Base objects (idempotent adds; failure is fatal — fail-closed posture).
    if !st.cfg.dry_run {
        let mut b = Batch::new();
        b.ensure_base();
        st.nft
            .apply(&b)
            .await
            .map_err(|e| anyhow::anyhow!("nft base install failed: {e}"))?;
        tracing::info!("nft base table ready");
        reconcile_on_boot(&st).await;
    } else {
        tracing::warn!("--dry-run: nft objects NOT installed (dev mode)");
    }

    for path in [&st.cfg.mcp_socket, &st.cfg.admin_socket] {
        let _ = std::fs::remove_file(path);
    }
    let mcp = UnixListener::bind(&st.cfg.mcp_socket)?;
    let admin = UnixListener::bind(&st.cfg.admin_socket)?;
    std::fs::set_permissions(&st.cfg.admin_socket, std::fs::Permissions::from_mode(0o600))?;
    // mcp.sock: reachable only by mcp_user's group (identity still enforced via
    // SO_PEERCRED per connection); without a resolved gid stay root-only (dev).
    if let Some(gid) = st.cfg.mcp_sock_gid {
        use std::os::unix::fs::{chown, PermissionsExt};
        chown(&st.cfg.mcp_socket, None, Some(gid))?;
        std::fs::set_permissions(&st.cfg.mcp_socket, std::fs::Permissions::from_mode(0o660))?;
    }

    // expiry reconciler: kernel reaps elements via TTL; we flip ledger rows + notify.
    {
        let st = st.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                // NOTE: must be list("approved"), NOT active() — active() filters
                // `expires_at > now` in SQL, which would hide exactly the expired
                // rows this loop exists to flip (regression caught by enforcement E2E).
                let approved = st.ledger.list("approved").await;
                let now = now_secs() as f64;
                let expired: Vec<i64> = approved
                    .iter()
                    .filter(|g| g.expires_at.map(|e| e <= now).unwrap_or(true))
                    .map(|g| g.id)
                    .collect();
                if !expired.is_empty() {
                    st.ledger.mark_expired(&expired).await;
                    for id in &expired {
                        let _ = st.events.send(json_line(&notification(
                            method::EV_EXPIRED,
                            serde_json::json!({"grant_id": id.to_string()}),
                        )));
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

    // Traffic stats poller (~2 s, decision R4): ledger supplies identity +
    // countdown; named counter objects supply bytes. Deliberately polling —
    // no payloads, no per-packet logging. Only runs when an admin is watching
    // (the only consumer), which also keeps idle nft churn at zero.
    if !st.cfg.dry_run {
        let st = st.clone();
        tokio::spawn(async move {
            use std::time::Instant;
            // gid -> (last total bytes, when counters last advanced)
            let mut seen: HashMap<i64, (u64, Instant)> = HashMap::new();
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                if st.admins_online.load(Ordering::SeqCst) == 0 {
                    continue;
                }
                let rows = st.ledger.list("approved").await;
                if rows.is_empty() {
                    seen.clear();
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
                );
                let now = now_secs();
                let mut stats: Vec<GrantStat> = Vec::new();
                for g in &rows {
                    let b_out = poll.counters.get(&counter_out(g.id)).map(|c| c.1).unwrap_or(0);
                    let b_in = poll.counters.get(&counter_in(g.id)).map(|c| c.1).unwrap_or(0);
                    let total = b_out + b_in;
                    let since_moved = match seen.get(&g.id) {
                        None => {
                            // first sighting: baseline only, don't claim motion
                            seen.insert(g.id, (total, Instant::now()));
                            None
                        }
                        Some((prev_total, last)) => {
                            if total != *prev_total {
                                seen.insert(g.id, (total, Instant::now()));
                                Some(0)
                            } else {
                                Some(last.elapsed().as_secs())
                            }
                        }
                    };
                    stats.push(GrantStat {
                        grant_id: g.id.to_string(),
                        name: g.target.clone(),
                        dst: g.dst_json.clone(),
                        dst_port: PortSpec { from: g.port_from, to: g.port_to },
                        proto: str_to_proto(&g.proto),
                        seconds_remaining: g
                            .expires_at
                            .map(|e| (e as u64).saturating_sub(now))
                            .unwrap_or(0),
                        secs_since_last_packet: since_moved,
                        bytes_sent: b_out,
                        bytes_received: b_in,
                    });
                }
                seen.retain(|gid, _| rows.iter().any(|g| g.id == *gid));
                let _ = st.events.send(json_line(&notification(
                    method::EV_TRAFFIC,
                    serde_json::json!({ "grants": stats }),
                )));
            }
        });
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

fn peer_cred(s: &UnixStream) -> Option<tokio::net::unix::UCred> {
    s.peer_cred().ok()
}

// ------------------------------------------------------------------ MCP side

async fn handle_mcp(stream: UnixStream, st: Arc<State>) {
    if let (Some(want), Some(cred)) = (st.cfg.mcp_peer_uid, peer_cred(&stream)) {
        if cred.uid() != want {
            tracing::warn!(uid = cred.uid(), "mcp peer rejected by SO_PEERCRED");
            return;
        }
    }
    let (r, mut w) = stream.into_split();
    // responses from spawned request tasks arrive here and are the ONLY writer.
    let (resp_tx, mut resp_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let writer = tokio::spawn(async move {
        while let Some(line) = resp_rx.recv().await {
            // NDJSON framing: readers use read_line; ALWAYS terminate with \n.
            if let Err(e) = w.write_all(format!("{line}\n").as_bytes()).await {
                tracing::warn!(%e, "mcp writer died");
                break;
            }
        }
        tracing::debug!("mcp writer task exiting (channel closed)");
    });
    // In-flight request counter: the connection (and writer!) must outlive every
    // dispatched request, even after client EOF — approval can arrive minutes later.
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
                .send(rpc_err_str(&req.id, -32601, "only access.request is served here"))
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
fn dispatch_access(
    req: RpcRequest,
    st: Arc<State>,
    respond: impl Fn(String) + Send + 'static,
) {
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
                && g.proto == proto_str(params.proto)
                && (g.port_from, g.port_to) == (params.dst_port.from, params.dst_port.to)
        }) {
            let resp = RpcResponse::ok(
                &id,
                AccessDecision {
                    decision: Decision::Approved,
                    grant_id: Some(g.id.to_string()),
                    dedup: true,
                    effective: None,
                    ttl_granted: None,
                    expires_at: g.expires_at.map(fmt_unix),
                    reason_code: None,
                    note: None,
                },
            );
            respond(serde_json::to_string(&resp).unwrap());
            return;
        }

        // R2a: no approver connected -> immediate deny
        if st.admins_online.load(Ordering::SeqCst) == 0 {
            let resp = RpcResponse::ok(
                &id,
                AccessDecision {
                    decision: Decision::Denied,
                    grant_id: None,
                    dedup: false,
                    effective: None,
                    ttl_granted: None,
                    expires_at: None,
                    reason_code: Some(DenyReason::ApproverOffline),
                    note: None,
                },
            );
            respond(serde_json::to_string(&resp).unwrap());
            return;
        }

        let row = GrantRow {
            id: 0,
            idem_key: Some(id.clone()),
            target: target.canonical(),
            dst_json: "[]".into(),
            port_from: params.dst_port.from,
            port_to: params.dst_port.to,
            proto: proto_str(params.proto).to_string(),
            reason: sanitize(&params.reason),
            tool: sanitize(&params.tool),
            ttl_secs: ttl.as_secs(),
            granted_ttl_secs: None,
            state: "pending".into(),
            created_at: now_secs(),
            expires_at: None,
            deny_code: None,
            note: None,
        };
        let gid = match st.ledger.insert_pending(&row).await {
            Some(gid) => gid,
            None => {
                // duplicate idempotency key (UNIQUE violation) — same client retry
                respond(rpc_err_str(&id, -32001, "duplicate request id"));
                return;
            }
        };
        st.ledger.audit("request", gid, row.target.clone());

        let (tx, rx) = oneshot::channel::<HumanDecision>();
        st.pending.lock().await.insert(gid, tx);
        let _ = st.events.send(json_line(&notification(
            method::EV_REQUEST_NEW,
            serde_json::json!({
                "grant_id": gid.to_string(),
                "target": row.target,
                "dst_port": params.dst_port,
                "proto": params.proto,
                "reason": row.reason,
                "tool": row.tool,
                "ttl_requested": params.ttl_requested,
            }),
        )));

        let decision = match tokio::time::timeout(
            Duration::from_secs(st.cfg.approver_timeout_secs),
            rx,
        )
        .await
        {
            Ok(Ok(HumanDecision::Approve { ttl_secs })) => {
                let granted = cap_ttl(ttl_secs.map(Duration::from_secs).unwrap_or(ttl), &st);
                match install_grant(&st, &row, gid, params.proto, granted).await {
                    Ok((eff, dsts)) => {
                        let exp = ttl_expires(granted);
                        if !st.ledger.decide(gid, "approved", Some(exp), None, None).await {
                            tracing::error!(gid, "ledger failed to flip pending->approved");
                        }
                        // Persist this exact resolution (R3): later revoke/expiry
                        // cleanup deletes THESE elements — DNS may drift by then.
                        let dst_json = serde_json::to_string(
                            &dsts.iter().map(|d| d.canonical()).collect::<Vec<_>>(),
                        )
                        .unwrap_or_else(|_| "[]".into());
                        if !st.ledger.set_dst(gid, dst_json).await {
                            tracing::warn!(gid, "set_dst: row not approved when persisting resolution");
                        }
                        // Accounting is best-effort: stats never gate enforcement.
                        if let Err(e) = rebuild_acct(&st).await {
                            tracing::warn!(gid, %e, "acct rebuild failed (stats degraded only)");
                        }
                        st.ledger.audit("approved", gid, format!("{eff:?}"));
                        let _ = st.events.send(json_line(&notification(
                            method::EV_DECIDED,
                            serde_json::json!({
                                "grant_id": gid.to_string(),
                                "state": "approved",
                                "ttl_granted": fmt_ttl(granted),
                                "expires_at": fmt_unix(exp),
                            }),
                        )));
                        AccessDecision {
                            decision: Decision::Approved,
                            grant_id: Some(gid.to_string()),
                            dedup: false,
                            effective: Some(eff),
                            ttl_granted: Some(fmt_ttl(granted)),
                            expires_at: Some(fmt_unix(exp)),
                            reason_code: None,
                            note: None,
                        }
                    }
                    Err(e) => {
                        // fail-closed: apply error keeps prior kernel state; deny.
                        tracing::error!(gid, %e, "nft install failed — denying");
                        st.ledger
                            .decide(gid, "denied", None, Some("install_failed".into()), Some(e.clone()))
                            .await;
                        AccessDecision {
                            decision: Decision::Denied,
                            grant_id: Some(gid.to_string()),
                            dedup: false,
                            effective: None,
                            ttl_granted: None,
                            expires_at: None,
                            reason_code: Some(DenyReason::HumanDenied),
                            note: Some(format!("enforcement failed: {e}")),
                        }
                    }
                }
            }
            Ok(Ok(HumanDecision::Deny { note })) => {
                st.ledger
                    .decide(gid, "denied", None, Some("human_denied".into()), note.clone())
                    .await;
                AccessDecision {
                    decision: Decision::Denied,
                    grant_id: Some(gid.to_string()),
                    dedup: false,
                    effective: None,
                    ttl_granted: None,
                    expires_at: None,
                    reason_code: Some(DenyReason::HumanDenied),
                    note,
                }
            }
            // Err(RecvError)=sender dropped (shutdown) or Elapsed=approver silent → both deny
            Ok(Err(_)) | Err(_) => {
                st.ledger
                    .decide(gid, "denied", None, Some("approver_timeout".into()), None)
                    .await;
                AccessDecision {
                    decision: Decision::Denied,
                    grant_id: Some(gid.to_string()),
                    dedup: false,
                    effective: None,
                    ttl_granted: None,
                    expires_at: None,
                    reason_code: Some(DenyReason::ApproverTimeout),
                    note: None,
                }
            }
        };

        let resp = RpcResponse::ok(&id, &decision);
        respond(serde_json::to_string(&resp).unwrap());
    });
}

/// Install kernel elements for a grant. Host targets resolved here (D-R3):
/// the human approves name+IPs together; kernel gets IPs only.
/// Returns (effective view, all installed dsts) — dsts get persisted to
/// dst_json so later deletes use THIS resolution, not a fresh DNS lookup.
async fn install_grant(
    st: &Arc<State>,
    row: &GrantRow,
    gid: i64,
    proto: Proto,
    ttl: Duration,
) -> Result<(EffectiveGrant, Vec<ElemDst>), String> {
    let port = PortSpec { from: row.port_from, to: row.port_to };
    let dsts = target_elems(&parse_canonical_target(&row.target)?).await?;

    let mut b = Batch::new();
    for d in &dsts {
        b.add_grant(&GrantElem { dst: d.clone(), proto, port }, ttl, gid);
    }
    if !st.cfg.dry_run {
        st.nft.apply(&b).await.map_err(|e| e.to_string())?;
    }
    let eff_dst = match &dsts[0] {
        ElemDst::Ip(ip) => ip.to_string(),
        ElemDst::Net(n) => n.to_string(),
    };
    Ok((EffectiveGrant { dst: eff_dst, dst_port: port, proto }, dsts))
}

async fn target_elems(t: &Target) -> Result<Vec<ElemDst>, String> {
    match t {
        Target::Ip(ip) => Ok(vec![ElemDst::Ip(*ip)]),
        Target::Net(n) => Ok(vec![ElemDst::Net(*n)]),
        Target::Host(h) => resolve_host(h).await,
    }
}

async fn resolve_host(h: &str) -> Result<Vec<ElemDst>, String> {
    let addrs = tokio::net::lookup_host((h, 0))
        .await
        .map_err(|e| format!("resolve {h}: {e}"))?;
    let mut out: Vec<ElemDst> = addrs.map(|a| ElemDst::Ip(a.ip())).collect();
    out.sort_by_key(|e| match e {
        ElemDst::Ip(ip) => ip.to_string(),
        _ => String::new(),
    });
    out.dedup();
    if out.is_empty() {
        return Err(format!("no addresses for host {h}"));
    }
    Ok(out)
}

/// Dsts for a ledger row: the PERSISTED resolution (dst_json) when present —
/// never a fresh DNS lookup at delete time (R3: elements were approved for
/// specific IPs; re-resolving could delete/keep the wrong ones). Legacy rows
/// with empty dst_json fall back to resolving the target.
async fn row_elems(st: &Arc<State>, row: &GrantRow) -> Result<Vec<ElemDst>, String> {
    let stored: Vec<String> = serde_json::from_str(&row.dst_json).unwrap_or_default();
    if !stored.is_empty() {
        let out: Vec<ElemDst> = stored.iter().filter_map(|s| ElemDst::from_canonical(s)).collect();
        if out.is_empty() {
            return Err(format!("dst_json unparseable: {}", row.dst_json));
        }
        return Ok(out);
    }
    let _ = st;
    target_elems(&parse_canonical_target(&row.target)?).await
}

/// Rebuild both accounting chains from the ledger's approved rows (R4).
/// Count-only rules, no verdicts — enforcement never depends on this.
async fn rebuild_acct(st: &Arc<State>) -> Result<(), String> {
    if st.cfg.dry_run {
        return Ok(());
    }
    let rows = st.ledger.list("approved").await;
    let mut b = Batch::new();
    b.flush_chain(CHAIN_ACCT_OUT);
    b.flush_chain(CHAIN_ACCT_IN);
    for g in &rows {
        let dsts = match row_elems(st, g).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(id = g.id, %e, "acct: dst resolution failed (stats only)");
                continue;
            }
        };
        let proto = str_to_proto(&g.proto);
        let port = PortSpec { from: g.port_from, to: g.port_to };
        for dir in [Dir::Out, Dir::In] {
            for v6 in [false, true] {
                let fam: Vec<&ElemDst> = dsts.iter().filter(|d| d.is_v6() == v6).collect();
                if fam.is_empty() {
                    continue;
                }
                b.add_counter(&dir.counter(g.id));
                b.add_acct_set(g.id, dir, v6);
                for d in fam {
                    b.add_acct_elem(g.id, dir, &GrantElem { dst: d.clone(), proto, port });
                }
                b.add_acct_rule(g.id, dir, proto, v6);
            }
        }
    }
    st.nft.apply(&b).await.map_err(|e| e.to_string())
}

/// Per-grant best-effort object sweep after a grant leaves the approved set.
/// Runs AFTER rebuild_acct (which flushes all acct rules), so every object is
/// unreferenced; one tiny batch per object since deletes are not idempotent.
async fn sweep_grant_objs(st: &Arc<State>, gid: i64) {
    if st.cfg.dry_run {
        return;
    }
    let mut names: Vec<(bool, String)> = Vec::new(); // (is_counter, name)
    for dir in [Dir::Out, Dir::In] {
        for v6 in [false, true] {
            names.push((false, acct_set(gid, dir, v6)));
        }
        names.push((true, dir.counter(gid)));
    }
    for (is_counter, name) in names {
        let mut b = Batch::new();
        if is_counter {
            b.delete_counter(&name);
        } else {
            b.delete_set(&name);
        }
        // ENOENT/EBUSY are tolerable: worst case a dead object lingers until
        // the next full wipe; nothing here can affect enforcement.
        if let Err(e) = st.nft.apply(&b).await {
            tracing::debug!(gid, %e, obj = %name, "acct sweep delete (ignored)");
        }
    }
}

// ---------------------------------------------------------------- reconciliation
//
// Boot policy (user decision 2026-09-17): grants are EPHEMERAL across reboots —
// the kernel/netns teardown is the reaper, the gatekeeper never revives a grant.
// Across crashes/restarts within one boot, live kernel elements (attributed via
// their `gk:g<gid>` comments) are ADOPTED; the ledger follows the kernel, and
// the gatekeeper takes NO corrective action on enforcement state — orphaned
// elements are left for their kernel TTL to reap.

/// Parse a `gk:g<gid>` attribution comment.
fn grant_gid_of_comment(c: &Option<String>) -> Option<i64> {
    c.as_deref()?.strip_prefix("gk:g")?.parse().ok()
}

/// Reconcile ledger against kernel truth at startup (see policy block above).
async fn reconcile_on_boot(st: &Arc<State>) {
    let elements = match st.nft.poll_live().await {
        Ok(p) => p.elements,
        Err(e) => {
            // Can't read kernel truth → assume none of our grants exist
            // (reboot-like). Fails closed: stale 'approved' rows would lie.
            tracing::error!(%e, "reconcile: cannot read nft state; reaping all ledger rows");
            Vec::new()
        }
    };
    let live_gids: std::collections::HashSet<i64> =
        elements.iter().filter_map(|el| grant_gid_of_comment(&el.comment)).collect();

    // Approved rows: adopt iff an element attributed to the row is live AND the
    // ledger expiry hasn't passed. Everything else is reaped — no revival.
    let now = now_secs() as f64;
    let mut adopted: std::collections::HashSet<i64> = std::collections::HashSet::new();
    for g in st.ledger.list("approved").await {
        let adopt = live_gids.contains(&(g.id as i64))
            && g.expires_at.map(|e| e > now).unwrap_or(false);
        if adopt {
            adopted.insert(g.id);
            tracing::info!(gid = g.id, target = %g.target, "reconcile: adopted live kernel grant");
            continue;
        }
        st.ledger
            .decide_from(g.id, "expired", &["approved"], Some(now), None, Some("restart-reconcile".into()))
            .await;
        st.ledger.audit("reconcile", g.id, format!("reaped: {} -> expired (no live attributed element or lapsed)", g.target));
        tracing::info!(gid = g.id, "reconcile: reaped stale approved row");
    }

    // Pending rows cannot survive a restart: their oneshot channels lived in the
    // dead process and the MCP client connection is gone.
    for g in st.ledger.list("pending").await {
        st.ledger
            .decide_from(g.id, "denied", &["pending"], None, Some("restart_orphan".into()), Some("daemon restarted before decision".into()))
            .await;
        st.ledger.audit("reconcile", g.id, "pending row denied: orphaned by restart");
    }

    // Orphaned live elements (attributed to a row we just reaped/denied — the
    // crash window between nft apply and ledger flip): NOT deleted. Kernel TTL
    // expires them normally. Unattributed elements (pre-marker binary or an
    // operator hand) likewise: warn only. Accounting rebuild below simply won't
    // cover them, which is honest — their ledger rows don't exist anymore.
    for el in &elements {
        match grant_gid_of_comment(&el.comment) {
            Some(gid) if !adopted.contains(&gid) => {
                tracing::warn!(gid, dst = %el.dst, ttl = el.expires_secs,
                    "reconcile: orphaned grant element left for kernel TTL (no corrective action)");
            }
            None => {
                tracing::warn!(dst = %el.dst,
                    "reconcile: unattributed element in grant set (left alone; check table ownership)");
            }
            _ => {}
        }
    }

    // Accounting is derived state (counters only) — rebuild from the adopted set.
    if let Err(e) = rebuild_acct(st).await {
        tracing::warn!(%e, "reconcile: acct rebuild failed");
    }
}

// ---------------------------------------------------------------- admin side

async fn handle_admin(stream: UnixStream, st: Arc<State>) {
    if let Some(c) = peer_cred(&stream) {
        tracing::info!(uid = c.uid(), "admin client connected");
    }
    st.admins_online.fetch_add(1, Ordering::SeqCst);
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
                if w.write_all(format!("{}\n", serde_json::to_string(&resp).unwrap()).as_bytes()).await.is_err() {
                    break;
                }
            }
        }
    }
    st.admins_online.fetch_sub(1, Ordering::SeqCst);
}

async fn handle_admin_cmd(req: &RpcRequest, st: &Arc<State>) -> RpcResponse {
    match req.method.as_str() {
        method::APPROVE => match parse_id_ttl(req) {
            Some((gid, ttl)) => {
                let tx = st.pending.lock().await.remove(&gid);
                match tx {
                    Some(tx) => {
                        tx.send(HumanDecision::Approve { ttl_secs: ttl }).ok();
                        RpcResponse::ok(&req.id, serde_json::json!({"queued": true}))
                    }
                    None => RpcResponse::err(&req.id, -32004, "no such pending request"),
                }
            }
            None => RpcResponse::err(&req.id, -32602, "need grant_id (+ttl_secs?)"),
        },
        method::DENY => {
            let gid = parse_id(req);
            let note = req
                .params
                .as_ref()
                .and_then(|p| p.get("note"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let tx = match gid {
                Some(gid) => st.pending.lock().await.remove(&gid),
                None => None,
            };
            match tx {
                Some(tx) => {
                    tx.send(HumanDecision::Deny { note }).ok();
                    RpcResponse::ok(&req.id, serde_json::json!({"queued": true}))
                }
                None => RpcResponse::err(&req.id, -32004, "no such pending request"),
            }
        }
        method::REVOKE => match parse_id(req) {
            Some(gid) => {
                revoke(st, gid).await;
                RpcResponse::ok(&req.id, serde_json::json!({"revoked": gid.to_string()}))
            }
            None => RpcResponse::err(&req.id, -32602, "need grant_id"),
        },
        method::LIST_GRANTS => {
            let rows = st.ledger.list("approved").await;
            RpcResponse::ok(&req.id, serde_json::to_value(rows).unwrap())
        }
        method::STOP_GRANTS => {
            // R8 kill switch: terminate GRANTS only — baseline rules untouched.
            tracing::info!("stop.grants invoked");
            let mut n = 0usize;
            let rows = st.ledger.list("approved").await;
            let mut b = Batch::new();
            for g in &rows {
                let proto = str_to_proto(&g.proto);
                let port = PortSpec { from: g.port_from, to: g.port_to };
                match row_elems(st, g).await {
                    Ok(dsts) => {
                        for d in dsts {
                            b.delete_grant(&GrantElem { dst: d, proto, port });
                        }
                        n += 1;
                    }
                    Err(e) => tracing::error!(id = g.id, %e, "stop.grants resolve failed"),
                }
            }
            if !st.cfg.dry_run && n > 0 {
                if let Err(e) = st.nft.apply(&b).await {
                    // atomic batch hit something stale (ghost element): retry per-grant,
                    // tolerating ENOENT (already gone), then continue regardless.
                    tracing::warn!(%e, "stop.grants batch failed; per-grant fallback");
                    let mut ok = 0usize;
                    for g in &rows {
                        let proto = str_to_proto(&g.proto);
                        let port = PortSpec { from: g.port_from, to: g.port_to };
                        if let Ok(dsts) = row_elems(st, g).await {
                            let mut gb = Batch::new();
                            for d in dsts {
                                gb.delete_grant(&GrantElem { dst: d, proto, port });
                            }
                            match st.nft.apply(&gb).await {
                                Ok(()) => ok += 1,
                                Err(e2) if e2.to_string().contains("No such file") => ok += 1, // already gone
                                Err(e2) => tracing::error!(id = g.id, %e2, "stop.grants per-grant delete failed"),
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
                    tx.send(HumanDecision::Deny { note: Some("stopped by operator".into()) }).ok();
                }
            }
            // flip rows (pending ones were just denied above via their channels)
            for g in &rows {
                st.ledger
                    .decide_from(g.id, "revoked", &["approved"], Some(now_secs() as f64), None, Some("stop.grants".into()))
                    .await;
            }
            // accounting follows the ledger: chains flush empty, objects swept.
            if let Err(e) = rebuild_acct(st).await {
                tracing::warn!(%e, "acct rebuild after stop.grants failed");
            }
            for g in &rows {
                sweep_grant_objs(st, g.id).await;
            }
            let _ = st.events.send(json_line(&notification(
                method::EV_DECIDED,
                serde_json::json!({"state": "all_stopped", "grants_removed": n}),
            )));
            RpcResponse::ok(&req.id, serde_json::json!({"revoked": n}))
        }
        method::SUBSCRIBE => RpcResponse::ok(
            &req.id,
            serde_json::json!({"events": ["grant.request.new","grant.decided","grant.expired"]}),
        ),
        _ => RpcResponse::err(&req.id, -32601, "unknown method"),
    }
}

async fn revoke(st: &Arc<State>, gid: i64) {
    if let Some(tx) = st.pending.lock().await.remove(&gid) {
        tx.send(HumanDecision::Deny { note: Some("revoked".into()) }).ok();
    }
    let rows = st.ledger.list("approved").await;
    if let Some(g) = rows.iter().find(|g| g.id == gid) {
        let proto = str_to_proto(&g.proto);
        let port = PortSpec { from: g.port_from, to: g.port_to };
        if !st.cfg.dry_run {
            match row_elems(st, g).await {
                Ok(dsts) => {
                    let mut b = Batch::new();
                    for d in dsts {
                        b.delete_grant(&GrantElem { dst: d, proto, port });
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
        .decide_from(gid, "revoked", &["approved"], Some(now_secs() as f64), None, None)
        .await
    {
        tracing::warn!(gid, "revoke: no approved row to flip (pending-only or already decided)");
    }
    if let Err(e) = rebuild_acct(st).await {
        tracing::warn!(gid, %e, "acct rebuild after revoke failed");
    }
    sweep_grant_objs(st, gid).await;
    let _ = st.events.send(json_line(&notification(
        method::EV_DECIDED,
        serde_json::json!({"grant_id": gid.to_string(), "state": "revoked"}),
    )));
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
            && h.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
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
            .map_err(|e| SpecError::BadHost(format!("bad cidr {n}: {e}")))?;
        return Ok(Target::Net(net));
    }
    unreachable!()
}

fn parse_canonical_target(t: &str) -> Result<Target, String> {
    if let Some(h) = t.strip_prefix("host:") {
        Ok(Target::Host(h.into()))
    } else if let Some(i) = t.strip_prefix("ip:") {
        i.parse().map(Target::Ip).map_err(|e| e.to_string())
    } else if let Some(n) = t.strip_prefix("net:") {
        n.parse().map(Target::Net).map_err(|e| e.to_string())
    } else {
        Err(format!("bad canonical target: {t}"))
    }
}

fn cap_ttl(d: Duration, st: &State) -> Duration {
    let max = parse_ttl(&st.cfg.max_ttl).unwrap_or(Duration::from_secs(4 * 3600));
    d.min(max)
}

/// Strip control chars so free-text can't spoof TUI rows (docs §hardening).
fn sanitize(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(280).collect()
}

fn proto_str(p: Proto) -> &'static str {
    match p {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    }
}
fn str_to_proto(s: &str) -> Proto {
    if s == "udp" { Proto::Udp } else { Proto::Tcp }
}

/// Minimal UTC RFC3339 (civil-from-days, Hinnant algorithm) — no chrono dep for scaffold.
pub fn fmt_unix(secs: f64) -> String {
    let secs = secs.max(0.0) as u64;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn parse_id(req: &RpcRequest) -> Option<i64> {
    req.params.as_ref()?.get("grant_id")?.as_str()?.parse().ok()
}

fn parse_id_ttl(req: &RpcRequest) -> Option<(i64, Option<u64>)> {
    let id = parse_id(req)?;
    let ttl = req.params.as_ref()?.get("ttl_secs").and_then(|v| v.as_u64());
    Some((id, ttl))
}

fn notification(method: &str, params: serde_json::Value) -> RpcRequest {
    RpcRequest {
        jsonrpc: JsonRpcVersion::V2_0,
        id: String::new(),
        method: method.into(),
        params: Some(params),
    }
}

fn json_line(v: &RpcRequest) -> String {
    // notifications per JSON-RPC 2.0: no id member
    let mut o = serde_json::to_value(v).unwrap();
    if let Some(m) = o.as_object_mut() {
        m.remove("id");
    }
    let mut s = serde_json::to_string(&o).unwrap();
    s.push('\n');
    s
}

fn rpc_err_str(id: &str, code: i32, msg: impl Into<String>) -> String {
    serde_json::to_string(&RpcResponse::err(id, code, msg)).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(matches!(pick_target(&p), Err(SpecError::TargetCardinality(0))));

        let p2 = AccessRequestParams {
            dst_ip: Some("1.2.3.4".into()),
            dst_net: Some("10.0.0.0/8".into()),
            ..p.clone()
        };
        assert!(matches!(pick_target(&p2), Err(SpecError::TargetCardinality(2))));

        let p3 = AccessRequestParams {
            dst_host: Some("bad$(host)".into()),
            ..p.clone()
        };
        assert!(pick_target(&p3).is_err(), "shell metachars must not pass host regex");

        let p4 = AccessRequestParams {
            dst_net: Some("172.16.0.0/12".into()),
            ..p.clone()
        };
        assert_eq!(pick_target(&p4).unwrap().canonical(), "net:172.16.0.0/12");
    }
}
