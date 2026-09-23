---
id: RESDISC-001
bug_class: result-discarded
title: Audit-log INSERT error silently discarded — security-relevant audit records can vanish without a trace
location: crates/gatekeeper/src/ledger.rs:347
function: open
confidence: High
worker: worker-9
fp_verdict: TRUE_POSITIVE
fp_rationale: "Verified `let _ = conn.execute(INSERT INTO audit...)` at ledger.rs:347 with no log (sibling Decide arm logs via tracing::error!), plus `.ok()` on the channel send in `audit()` — an attacker who induces disk pressure (e.g. grant-flood DB bloat) silently erases the root-side approval trail while grants continue"
severity: MEDIUM
attack_vector: Local
exploitability: Difficult
severity_rationale: "Integrity/forensics loss across the mcp.sock→approval boundary: unprivileged attacker can blind the audit log of privileged decisions, but needs a DB write fault (disk full/EIO) to trigger — no control bypass"
---

## Description
The ledger actor writes every security-relevant event (grant request, approval, revoke, restart reconcile, expiry) into the `audit` table, but the INSERT result is discarded with `let _ = conn.execute(...)`. A failed audit write (disk full, I/O error, SQLITE_FULL, schema corruption) loses the record **silently** — no tracing log at all, unlike every other DB failure in this actor (`decide prepare failed`, `decide execute failed` are both logged via `tracing::error!`). The `audit` table is the persisted integrity sink that answers "who approved what and when" for the egress-control daemon; a local attacker who can fill the filesystem (or any transient I/O fault) permanently erases the approval trail while the daemon keeps granting traffic as if nothing happened. The finder guidance explicitly forbids waving away a discarded result on a persisted/audit sink.

A sibling discard compounds this: `Ledger::audit()` at `crates/gatekeeper/src/ledger.rs:396-399` sends the command with `.ok()`, so if the ledger actor task has died, audit events are dropped in flight too — and unlike the query paths (`ask()` panics with `"ledger actor died"`), the fire-and-forget `audit()` never learns the actor is gone.

## Code
```rust
LedgerCmd::Audit(event, detail, grant_id) => {
    let _ = conn.execute(
        "INSERT INTO audit(ts,event,grant_id,detail) VALUES(?1,?2,?3,?4)",
        params![now_secs() as i64, event, grant_id, detail],
    );
}
```
Compare with the sibling arm a few lines above, which does log its failure:
```rust
Err(e) => {
    tracing::error!(%e, "decide execute failed");
    0
}
```

## Data flow
- **Source:** every `st.ledger.audit(...)` call site — e.g. `crates/gatekeeper/src/server.rs:394` (`audit("request", gid, target)`), `crates/gatekeeper/src/server.rs:456` (`audit("approved", gid, ...)`), `crates/gatekeeper/src/reconcile.rs:49-56` (reconcile reaps)
- **Sink:** `conn.execute("INSERT INTO audit ...")` at `crates/gatekeeper/src/ledger.rs:347`, result discarded via `let _ =`
- **Validation:** none — no log, no retry, no propagated error; the caller (`audit()`, itself `.ok()`-ing the channel send) has no way to observe failure

## Reachability trace
`handle_mcp → dispatch_access → st.ledger.audit("request", ...)` → `tx.send(LedgerCmd::Audit)` (send itself `.ok()`-discarded at ledger.rs:399) → ledger actor arm → `let _ = conn.execute(INSERT INTO audit)`

## Impact
Silent loss of audit/integrity records for grant approvals, revokes, and restart reconciliation. Under the daemon's own fail-safe posture ("enforcement is never off", decisions are traceable), an attacker who fills the DB filesystem — or any routine I/O fault — gets grants approved with **zero** durable trail and zero operator signal (no log line). Post-incident forensics on a privilege-boundary crossing (mcp.sock → approval) become impossible for the affected window.

## Mitigations checked
- Error handled on another path? No — `let _ =` discards; unlike `Decide`, there is no `tracing::error!`.
- Caller inspects? No — `Ledger::audit()` returns `()`, and its own channel send is also `.ok()`-discarded.
- WAL mode / single-writer actor reduces BUSY contention but not ENOSPC/EIO/corruption.
- No `debug_assert!`, no test asserting audit durability on failure.

## Recommendation
Log the failure at minimum, mirroring the Decide arm:
```rust
if let Err(e) = conn.execute(
    "INSERT INTO audit(ts,event,grant_id,detail) VALUES(?1,?2,?3,?4)",
    params![now_secs() as i64, event, grant_id, detail],
) {
    tracing::error!(%e, event, grant_id, "audit insert failed — trail incomplete");
}
```
If audit completeness is a policy requirement, escalate (count failures, trip a health flag the TUI surfaces, or fail closed on sustained audit-write failure).
