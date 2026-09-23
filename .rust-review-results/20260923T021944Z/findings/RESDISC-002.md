---
id: RESDISC-002
bug_class: result-discarded
title: SetDst UPDATE error swallowed by `.unwrap_or(0)` — DB failure conflated with "row not approved", resolution silently unpersisted
location: crates/gatekeeper/src/ledger.rs:333
function: open
confidence: Medium
worker: worker-9
fp_verdict: TRUE_POSITIVE
fp_rationale: "Verified `.unwrap_or(0)` at ledger.rs:333 conflates DB error with 'row not approved', and the caller warn names the wrong cause; with `dst_json` left '[]' the revoke path tears down from the wrong resolution, risking stale kernel elements (continued egress after revoke) — a real correctness gap on the enforcement path, gated on a DB write fault"
severity: MEDIUM
attack_vector: Local
exploitability: Difficult
severity_rationale: "When triggered the impact crosses the boundary in the attacker's favor (stale egress element survives revoke, fail-open direction until TTL), but requires a DB write fault at exactly approval time — limited privilege-boundary crossing, hard to force"
---

## Description
The `LedgerCmd::SetDst` arm persists the DNS resolution for an approved grant (`dst_json`) so that later revoke/rebuild deletes exactly the IPs that were installed in the kernel. The UPDATE's `rusqlite::Result<usize>` is reduced with `.unwrap_or(0)`, which **erases the error class**: a genuine DB write failure (I/O error, disk full, locked/corrupt DB) becomes indistinguishable from the legitimate "row is not in approved state" outcome. The only observable trace is a `tracing::warn!` at the caller that names the *wrong* cause (`"set_dst: row not approved when persisting resolution"`), so an operator sees a benign-looking message while the persistence actually failed.

The consequence is not cosmetic: with `dst_json` left at its `'[]'` default, the revoke path falls back to whatever re-derivation it does from the row rather than the pinned resolution the comment promises (`// Persist resolved IPs; revoke uses these, not a fresh lookup.`), so kernel elements installed for the original resolution can be missed or mismatched on teardown — stale-egress risk after revoke.

## Code
```rust
LedgerCmd::SetDst(id, dst_json, reply) => {
    // Persist resolved IPs; revoke uses these, not a fresh lookup.
    let n = conn
        .execute(
            "UPDATE grants SET dst_json=?2 WHERE id=?1 AND state='approved'",
            params![id, dst_json],
        )
        .unwrap_or(0);
    let _ = reply.send(n == 1);
}
```

## Data flow
- **Source:** resolved destination set produced after a human approval on the mcp.sock request path (`dispatch_access`, `crates/gatekeeper/src/server.rs:438-449` — `serde_json::to_string(&dsts...)` then `st.ledger.set_dst(gid, dst_json)`)
- **Sink:** `conn.execute("UPDATE grants SET dst_json=...")` at `crates/gatekeeper/src/ledger.rs:328-332`; error discarded via `.unwrap_or(0)` at :333
- **Validation:** caller checks the returned bool but cannot distinguish error from not-approved; no error is logged with its true cause

## Reachability trace
`handle_mcp → dispatch_access → (Approve) install_grant → st.ledger.set_dst(gid, dst_json) → LedgerCmd::SetDst arm → conn.execute(...).unwrap_or(0)` → later `admin.rs revoke → row_elems(g)` reads `dst_json`

## Impact
A DB write fault at approval time leaves the grant's persisted resolution empty while enforcement is already installed in the kernel. The misleading warn hides the fault; subsequent revoke/accounting operate on `'[]'` instead of the pinned IPs, risking stale nft elements (continued egress after revoke) or failed sweeps until the element TTLs out.

## Mitigations checked
- Error not fully ignored — it collapses to `false`, and the caller logs a warn — but with an incorrect diagnosis and no `%e`, defeating triage.
- Kernel element TTL bounds the stale-egress window for grants that carry one; allow-list-style/permanent elements would not self-heal.
- No retry, no `debug_assert!`, no test covering the DB-error branch (tests exercise only the success path).

## Recommendation
Match on the result:
```rust
let n = match conn.execute(
    "UPDATE grants SET dst_json=?2 WHERE id=?1 AND state='approved'",
    params![id, dst_json],
) {
    Ok(n) => n,
    Err(e) => {
        tracing::error!(%e, id, "set_dst execute failed");
        let _ = reply.send(false);
        continue;
    }
};
let _ = reply.send(n == 1);
```
and consider having the approval path treat a `set_dst` failure as a hard error (deny/rollback) since revoke correctness depends on it.
