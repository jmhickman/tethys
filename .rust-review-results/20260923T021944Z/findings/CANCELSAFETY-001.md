---
id: CANCELSAFETY-001
bug_class: cancel-safety
title: pending approval map entry inserted before long await is never removed on the timeout/deny path (half-written state)
location: crates/gatekeeper/src/server.rs:400
function: dispatch_access
confidence: Medium
worker: worker-13
merged_into: CHANSTARVE-001
---

## Description
`dispatch_access` mutates shared state (`st.pending.insert(gid, tx)`), then awaits the human decision with `tokio::time::timeout(approver_timeout_secs, rx)`. On the approve and human-deny paths the map entry is removed — but only as a side effect of the admin handler's `.remove(&grant_id)` (admin.rs:78/92). On the **timeout / sender-dropped** path (`Ok(Err(_)) | Err(_)` at server.rs:506) and on the **nft install-failed** path, the task flips the ledger row to Denied and responds — but never removes `gid` from `st.pending`. The mutation made before the await is left half-committed: a dead `oneshot::Sender` stays in the map forever. There is no Drop guard or scopeguard restoring the invariant (checked), and no sweep of `pending` anywhere else in the daemon (rg-verified: `st.pending` is only touched at server.rs:41, 58, 400 and in admin.rs remove/lookup sites).

## Code
```rust
// server.rs:399-400 — mutation BEFORE the long await
let (tx, rx) = oneshot::channel::<HumanDecision>();
st.pending.lock().await.insert(gid, tx);
...
// server.rs:418-423 — long await
let verdict = match tokio::time::timeout(
    Duration::from_secs(st.cfg.approver_timeout_secs),
    rx,
).await { ...
    // server.rs:506-521 — timeout path: ledger flipped to Denied,
    // but st.pending.remove(&gid) is NEVER called here
    Ok(Err(_)) | Err(_) => {
        st.ledger.decide(gid, Decide::Deny { code: DenyCode::ApproverTimeout, note: None }).await;
        Verdict::Denied { reason_code: DenyReason::ApproverTimeout, ... }
    }
};
// ... respond(...) — no pending-map cleanup on this path
```

## Data flow
- **Source:** attacker (agent uid) opening `mcp.sock` and sending `access.request` lines with unique ids while one admin is connected but silent (`admins_online > 0`, so requests are not instantly denied)
- **Sink:** `st.pending: Mutex<HashMap<i64, oneshot::Sender<HumanDecision>>>` at `crates/gatekeeper/src/server.rs:400`, never cleaned on the timeout path
- **Validation:** none — no TTL, no sweep task, no removal in `dispatch_access`; the expiry reconciler only walks ledger rows, not the pending map

## Reachability trace
`handle_mcp → dispatch_access (spawned) → st.pending.insert(gid, tx) → timeout(rx) elapses → decide(Deny::ApproverTimeout) → respond — entry leaked`

## Impact
Two effects. (1) Unbounded growth of `st.pending`: each timed-out request permanently leaks a map entry + oneshot sender; an unprivileged agent can spray requests at any rate the accept loop allows, giving slow memory growth in the root daemon (LOCAL_UNPRIVILEGED DoS). (2) Stale-entry race: after timeout-deny, an admin `approve` for that gid still finds `Some(tx)`, sends to a dropped receiver (`.ok()` swallows it), and replies `{"queued": true}` — the approver is told a decision was queued on a request that was already denied, with no kernel grant installed. The ledger stays correct (decide enforces origin state), so this is state/liveness corruption rather than fail-open.

## Mitigations checked
- `Drop`/scopeguard cleanup: none in scope.
- Expiry reconciler (`spawn_expiry_reconciler`): iterates ledger Approved rows only; does not touch `pending`.
- `stop_grants`/`revoke` do remove entries, but only when an operator acts.
- Ledger-side protection intact: `Decide::legal_origins` rejects double-flips, so the stale sender cannot resurrect a denied row.

## Recommendation
Remove the map entry on every exit path of the decision block, e.g. immediately after the `timeout(...)` match: `st.pending.lock().await.remove(&gid);` (removal is idempotent and races safely with admin approve — whoever removes first owns the send), or wrap the sender in a small guard whose `Drop` removes the gid from `pending`.
