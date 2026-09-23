---
id: ATOMICRACE-001
bug_class: atomic-race
title: admins_online counter leaks upward when the admin task panics (fetch_add with no RAII guard)
location: crates/gatekeeper/src/admin.rs:26
function: handle_admin
confidence: Medium
worker: worker-3
fp_verdict: LIKELY_TP
fp_rationale: "Unguarded fetch_add/fetch_sub pair confirmed at admin.rs:26/54 (no RAII guard); leak permanently disables the approver-offline fast-deny, but the attacker cannot reach admin.sock — triggering requires an internal panic (e.g. ledger actor death via ask().expect), which is plausible but not directly attacker-driven"
severity: MEDIUM
attack_vector: Local
exploitability: Difficult
severity_rationale: "Once triggered by any admin-task panic, every agent request from the unprivileged uid degrades to queue-and-timeout with pending-row growth on the root daemon (local DoS amplification); still fails closed, so not HIGH"
---

## Description
`handle_admin` increments the shared `State::admins_online` atomic on entry
(`fetch_add`, line 26) and decrements it only as the *last statement* of the
function body (`fetch_sub`, line 54). There is no RAII guard tying the
decrement to the task's lifetime. The task runs under `tokio::spawn` (accepted
connections are spawned at `crates/gatekeeper/src/server.rs:106`), so any panic
inside the loop — or any future cancellation of the task — unwinds through the
spawn boundary, runs drops, but **skips the trailing `fetch_sub`**. The
counter then permanently over-reports online approvers.

`admins_online` is not telemetry-only: it gates two security-relevant
behaviors:

1. `dispatch_access` at `crates/gatekeeper/src/server.rs:357` fast-denies with
   `ApproverOffline` when `admins_online.load() == 0`. A leaked count > 0
   disables this fast path forever: every subsequent agent request is inserted
   as a *pending* ledger row, emits a popup event no one receives, and blocks
   until the full `approver_timeout_secs` elapses before auto-denying. The
   unprivileged agent uid can drive this from `mcp.sock`, turning immediate
   denies into long-lived pending rows (ledger growth + latency DoS against the
   approval pipeline).
2. `spawn_stats_poller` at `crates/gatekeeper/src/server.rs:173` only idles
   when the count is 0; a leaked count makes it poll `nft list_json` every 2s
   forever.

A concrete panic source reachable from this task's await points: every ledger
call funnels through `Ledger::ask` (`crates/gatekeeper/src/ledger.rs:358-362`)
which does `rx.await.expect("ledger actor died")` — if the ledger actor task
ever dies, any admin command panics inside `handle_admin_cmd`, leaking the
count.

## Code
```rust
pub(crate) async fn handle_admin(stream: UnixStream, st: Arc<State>) {
    if let Some(c) = peer_cred(&stream) {
        tracing::info!(uid = c.uid(), "admin client connected");
    }
    st.admins_online.fetch_add(1, Ordering::SeqCst);      // line 26 — no guard
    let mut sub_rx = st.events.subscribe();
    // ... loop with awaits that can panic (ledger ask().expect(...), etc.) ...
    st.admins_online.fetch_sub(1, Ordering::SeqCst);      // line 54 — skipped on unwind
}
```

## Data flow
- **Source:** panic/cancellation of a spawned `handle_admin` task (trigger examples: ledger actor death surfacing via `ask().expect`, future refactor adding an abort/timeout wrapper).
- **Sink:** permanent +1 on `State::admins_online`, read at `crates/gatekeeper/src/server.rs:357` (deny fast-path) and `:173` (stats poller gate).
- **Validation:** none — nothing reconciles the counter against live connections.

## Reachability trace
`run()` accept loop (`server.rs:103-106`) → `tokio::spawn(handle_admin)` → `fetch_add` → panic inside loop → task boundary swallows unwind → `fetch_sub` never runs → subsequent `handle_mcp` → `dispatch_access` → `admins_online.load() == 0` is false forever.

## Impact
Persistent misreporting of approver presence after a single admin-task panic. Security-relevant behavior change: the fail-fast "no approver → deny immediately" path (a documented hardening property) silently degrades to queue-and-timeout for every request from the unprivileged agent uid, and the stats poller never idles. Availability/latency degradation of the approval pipeline; no privilege bypass (still fails closed at timeout).

## Mitigations checked
- No RAII guard / `scopeguard` / drop type around the increment — verified by reading `admin.rs:22-55`.
- `tokio::spawn` catches panics per task, so the daemon survives and the leak persists (no crash-restart to heal it).
- No periodic reconciliation of `admins_online` against actual live connections.
- Ordering is `SeqCst`, so the bug is sequencing/leakage, not memory ordering.
- No `#![forbid(unsafe_code)]` needed here; entirely a safe-code atomic-sequencing flaw.

## Recommendation
Tie the decrement to task lifetime with a guard: e.g. a small RAII type whose `Drop` does `fetch_sub`, created right after `fetch_add` (`let _guard = AdminGuard(&st.admins_online);`), or restructure so the increment/decrement pair wraps the whole body in a `scopeguard::defer!`. Same treatment for the sibling site `ATOMICRACE-002`.
