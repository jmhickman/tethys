---
id: CHANSTARVE-001
bug_class: channel-starvation
title: Orphaned oneshot Senders leak in `pending` map forever after approver timeout (unbounded memory/ledger growth)
location: crates/gatekeeper/src/server.rs:400
function: dispatch_access
confidence: High
worker: worker-2
also_known_as: [CANCELSAFETY-001]
locations:
  - crates/gatekeeper/src/server.rs:400
fp_verdict: TRUE_POSITIVE
fp_rationale: "Verified all `st.pending` mutation sites (insert server.rs:400; removes only admin.rs:78/92/248/279) — the timeout arm at server.rs:506 denies and responds but never removes the entry, so every timed-out attacker request leaks a map entry + denied ledger row, repeatable at attacker rate with fresh ids (both merged framings describe this same reachable leak)"
severity: MEDIUM
attack_vector: Local
exploitability: Reliable
severity_rationale: "Deterministic per-request leak (HashMap + SQLite row) of the root daemon driven entirely by the unprivileged uid — local resource DoS; needs an approver online (normal steady state) and one timeout period per entry, but is guaranteed once entered"
---

## Description
`dispatch_access` enqueues a `oneshot::Sender<HumanDecision>` into `st.pending` for every request that reaches the approval stage. The map entry is removed **only** by admin-side actions (`approve`, `deny`, `revoke`, `stop.grants` — `admin.rs:78, 92, 248, 279`). When the request times out waiting for a human (`tokio::time::timeout(..., rx)` at `server.rs:418`), the `Ok(Err(_)) | Err(_)` arm at `server.rs:506-521` denies the grant in the ledger and responds to the client — but **never removes the entry from `st.pending`**. The Receiver half was consumed by the timed-out `rx.await`, so the Sender is orphaned: no one will ever send on it, and no daemon-side path ever reclaims it.

The attacker (agent uid, fully controls the framed JSON on `mcp.sock`) controls the request `id`, which is used verbatim as the ledger `idem_key` (`server.rs:375`). The dedup check at `server.rs:338-354` only matches *approved-active* grants, not pending ones, so N requests with distinct ids and identical target/port create N ledger rows plus N permanently-leaked map entries. Nothing is garbage-collected until an operator runs `stop.grants`. This is unbounded, attacker-rate-controlled growth of the `pending` HashMap and the `grants` table (rows pile up in `denied` state; the `LIMIT 500` on list queries hides them but the table still grows) — a slow memory/DoS burn on the root daemon.

Secondary effect: after the timeout, a late admin `approve` for that gid finds the stale Sender, sends on it (send fails silently — receiver gone), and replies `{"queued": true}` to the approver even though the grant was already denied — but the memory leak is the security-relevant part.

## Code
```rust
// server.rs:399-400 — sender enqueued; only admin paths ever remove it
let (tx, rx) = oneshot::channel::<HumanDecision>();
st.pending.lock().await.insert(gid, tx);

// server.rs:418-422, 506-521 — timeout arm: deny + respond, NO map cleanup
let verdict = match tokio::time::timeout(
    Duration::from_secs(st.cfg.approver_timeout_secs),
    rx,
)
.await
{
    ...
    // Err(RecvError)=sender dropped (shutdown) or Elapsed=approver silent → both deny
    Ok(Err(_)) | Err(_) => {
        st.ledger.decide(gid, Decide::Deny { code: DenyCode::ApproverTimeout, note: None }).await;
        Verdict::Denied { reason_code: DenyReason::ApproverTimeout, grant_id: Some(gid.to_string()), note: None }
    }   // <-- st.pending still holds the orphaned `tx` for gid
};
```

## Data flow
- **Source:** attacker-chosen JSON-RPC `id` + request body on `mcp.sock` (`handle_mcp` → `dispatch_access`); each unique id passes dedup (`server.rs:338`) and the UNIQUE `idem_key` insert (`server.rs:372-386`).
- **Sink:** `st.pending.lock().await.insert(gid, tx)` at `server.rs:400` — HashMap entry that no timeout/shutdown path ever removes.
- **Validation:** none on entry lifetime; the only removal paths are admin `approve`/`deny`/`revoke` (`admin.rs:78, 92, 279`) and operator `stop.grants` (`admin.rs:246-254`). Reaching the insert requires an approver to be online (`server.rs:357`), which is the normal steady state with the TUI running.

## Reachability trace
`handle_mcp (mcp.sock, SO_PEERCRED-passing agent uid) → dispatch_access → insert_pending → st.pending.insert(gid, tx) → timeout(elapsed) → deny + respond → [entry orphaned]` — repeatable at attacker rate with fresh ids.

## Impact
Unbounded growth of the root daemon's `pending` HashMap (one `String`-keyed entry + oneshot node per timed-out request) and of the SQLite `grants` table, driven entirely by an unprivileged local user. Sustained flooding yields gradual memory exhaustion / DB bloat in the enforcement daemon (DoS of the egress-control plane). No privilege escalation; integrity impact is limited to stale `waiting=false` rows in `list.pending` snapshots and misleading `{"queued": true}` replies for dead gids.

## Mitigations checked
- No TTL/GC on `st.pending`; no removal in the `Elapsed` or `RecvError` arms (verified by enumerating every `pending` mutation site: `server.rs:400` insert; `admin.rs:78, 92, 248, 279` removes — all admin-initiated).
- Dedup at `server.rs:338` only covers *approved-active* grants, not pending entries; idempotency rejects only *duplicate ids*, and the attacker varies the id.
- `admins_online == 0` short-circuit (`server.rs:357`) denies before the insert, but does not help while any approver is connected (normal operation).
- No `Semaphore`/rate limiter anywhere in the request pipeline.

## Recommendation
Remove the map entry when the decision wait completes by any path other than a real human send — e.g. after the `timeout(...)` match, unconditionally `st.pending.lock().await.remove(&gid);` (safe: on the approve/deny paths `admin.rs` already removed it, so the second remove is a no-op), or hold the guard via a scopeguard tied to the `rx` future lifetime. Additionally consider bounding total pending entries per uid to cap attacker-driven ledger growth.
