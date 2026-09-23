---
id: RESEXHAUST-001
bug_class: resource-exhaustion
title: Uncapped per-connection request fan-out on mcp.sock — unbounded response channel, unbounded task spawn, unbounded ledger growth
location: crates/gatekeeper/src/server.rs:247
function: handle_mcp
confidence: High
worker: worker-4
fp_verdict: TRUE_POSITIVE
fp_rationale: "Verified at server.rs:247/281-288: per-line `tokio::spawn` with `inflight` counted but never capped, `mpsc::unbounded_channel` replies buffered in daemon RAM when the client stops reading, and one UNIQUE-id ledger row per distinct id — a single SO_PEERCRED-passing process drives RAM/tasks/DB linearly with zero backpressure"
severity: MEDIUM
attack_vector: Local
exploitability: Reliable
severity_rationale: "Deterministic attacker-rate resource exhaustion (tasks + reply strings + SQLite rows) of the root enforcement daemon from one unprivileged socket — local DoS per the local-criteria table; no panic or race needed"
---

## Description
`mcp.sock` is fully attacker-controlled (the agent uid connects and streams NDJSON). For every
`access.request` line received, `handle_mcp`:
1. spawns a fresh `tokio` task via `dispatch_access` with **no per-connection or global in-flight cap** (`inflight` is only counted, never checked against a limit),
2. pushes the reply through `resp_tx`, an `mpsc::unbounded_channel` — if the client stops reading its side of the socket, replies queue in daemon RAM without bound, and
3. inserts a new ledger row per unique request id (`idem_key TEXT UNIQUE`), so a flood of distinct ids grows the SQLite DB and the `pending` HashMap without bound until each request hits the 300 s approver timeout.

There is also no cap on the number of concurrent mcp.sock connections (each spawns a reader task + writer task). A single unprivileged agent process can therefore drive RAM, task count, and DB size linearly in its send rate, with no backpressure anywhere on the untrusted path.

## Code
```rust
// crates/gatekeeper/src/server.rs:247
let (resp_tx, mut resp_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
...
// crates/gatekeeper/src/server.rs:281-287 — counted but never capped
inflight.fetch_add(1, Ordering::SeqCst);
let tx = resp_tx.clone();
let done = inflight.clone();
dispatch_access(req, st.clone(), move |s: String| {
    tx.send(s).ok();
    done.fetch_sub(1, Ordering::SeqCst);
});
```

## Data flow
- **Source:** arbitrary NDJSON `access.request` frames on `mcp.sock` (SO_PEERCRED-gated to the agent uid — same uid as the attacker) at `crates/gatekeeper/src/server.rs:260-288`
- **Sink:** `mpsc::UnboundedSender::send` at `server.rs:285` (reply buffering), `tokio::spawn` per line (`dispatch_access`, `server.rs:302`), and `LedgerCmd::Insert` per unique id (`ledger.rs:196-215`)
- **Validation:** none on count. `sanitize()` caps only `reason`/`tool` at 280 chars; `req.id` (the idempotency key stored forever) has no length cap, and neither does the request count.

## Reachability trace
`agent process → connect(mcp.sock) → handle_mcp loop → for each line: dispatch_access spawn → resp_tx.send / ledger.insert_pending` — reachable from a single unprivileged process with one socket, no approval needed (denies also produce reply lines).

## Impact
Availability loss of the root daemon's accept/dispatch capacity and host RAM/disk: an attacker streaming N requests makes the daemon allocate O(N) tasks + O(N) buffered reply strings (if the attacker simply never reads responses) + O(N) SQLite rows. No panic required — pure exhaustion. Worst case with an approver online: thousands of queued popups and a pending HashMap that only drains at the 300 s timeout rate.

## Mitigations checked
- `inflight` AtomicUsize exists but is only used for EOF draining (`while inflight > 0 { sleep }`), never compared to a maximum — not a budget.
- broadcast channel for admin events is bounded (256) — the mcp reply path is not.
- `sanitize()` caps two string fields, not counts or the `id` field.
- No `SO_RCVBUF`/per-uid connection limit, no `try_send`, no `take(MAX)` anywhere on this path.

## Recommendation
Bound the untrusted path: a per-connection in-flight cap (e.g. reject with -32000 once > K unanswered requests), replace the reply `unbounded_channel` with a bounded channel + `try_send` backpressure, and add a global pending-request budget before `insert_pending` (deny with a "system busy" reason code beyond it).
