---
id: LOSSYFROM-001
bug_class: lossy-from-into
title: i64→u16 `as` truncation of port range on every ledger row load — out-of-range DB values silently wrap into wrong enforcement ports
location: crates/gatekeeper/src/ledger.rs:142
function: row_from
confidence: Medium
worker: worker-9
fp_verdict: LIKELY_FP
fp_rationale: "The truncation is real (verified `as u16` at ledger.rs:142-143) but unreachable by the defined attacker: write path bounds values from u16, DB file is root-owned and not attacker-writable, and the failure direction is fail-closed (extra block), so no privilege boundary crosses in the attacker's favor — valid hardening note, not an attacker-triggerable bug"
---

## Description
`row_from` is the single deserialization path for every `grants` row, and it narrows the SQLite INTEGER columns with bare `as` casts instead of range-checked conversion:

```rust
port_from: r.get::<_, i64>(4)? as u16,
port_to:   r.get::<_, i64>(5)? as u16,
```

SQLite INTEGER has no range constraint — the schema (`port_from INTEGER NOT NULL`) accepts any i64. The write path happens to store values produced from `u16` fields (`g.port_from as i64` at ledger.rs:200), so under normal operation the round-trip is lossless. But **nothing validates the column on read**: any row whose stored value leaves the u16 domain — DB corruption, a partial write, or a future writer/migration/ops `UPDATE` that stores e.g. `8080+65536` or `-1` — loads as a *different, silently wrapped* port (`70656 → 5120`, `-1 → 65535`). There is no `< MAX` check upstream (FP carve-out does not apply) and `TryFrom` is not used (the other FP carve-out).

The loaded value is not cosmetic: `GrantRow.port_from/port_to` are fed straight back into kernel enforcement on the teardown/rebuild paths — `admin.rs:196-197/221-222/289-290` build the `PortSpec` for `delete_grant` on stop/revoke, and `install.rs:193-194` uses them for rebuild. A wrapped value means the daemon deletes (or re-derives) rules for the **wrong port range**, leaving the actually-installed kernel element unattributed/stale or mis-reconciling accounting.

The same pattern sits two lines below (`ttl_secs: ... as u64`, `created_at: ... as u64` at ledger.rs:147-150 — a negative stored value wraps to ~2^64), but those fields are only rendered in the TUI/verdict text, so they fail LOSSYFROM gate 2 (security-relevant path) and are noted here rather than filed separately.

## Code
```rust
Ok(GrantRow {
    id: r.get(0)?,
    ...
    port_from: r.get::<_, i64>(4)? as u16,   // ← silent truncation / wrap
    port_to: r.get::<_, i64>(5)? as u16,     // ← same
    proto,
    ...
    ttl_secs: r.get::<_, i64>(9)? as u64,
    granted_ttl_secs: r.get::<_, Option<i64>>(10)?.map(|v| v as u64),
    ...
    created_at: r.get::<_, i64>(12)? as u64,
```

## Data flow
- **Source:** `grants.port_from` / `grants.port_to` INTEGER columns in the SQLite ledger (`LedgerCmd::List/History/FindActive/FindByIdem` all route through `row_from`)
- **Sink:** `r.get::<_, i64>(4)? as u16` at crates/gatekeeper/src/ledger.rs:142 (and :143), consumed by revoke/rebuild enforcement in `admin.rs:196,221,289` and `install.rs:193`
- **Validation:** none on read — no range check between `r.get::<i64>` and the `as u16`; only the write path implicitly bounds values

## Reachability trace
`admin.sock approve/stop/revoke → admin.rs stop_grants()/revoke() → st.ledger.list(Approved) → LedgerCmd::List → row_from (:142 as u16) → PortSpec{from,to} → nft delete_grant`

## Impact
A stored value outside 0..=65535 loads as a wrapped port with no error and no log. Revoke/rebuild then targets the wrong nft concat key: the live kernel element for the true port is missed (stale egress until TTL) while reconcile logs an "orphaned element" warning that misattributes the cause. Fail-safe direction (extra block, not fail-open), but it defeats the pin-to-persisted-resolution design and audit accuracy.

## Mitigations checked
- Prior explicit `< MAX` check: absent on read path.
- `TryFrom`/`try_into`: not used; plain `as`.
- Write path bounds values implicitly (`g.port_from as i64` from a `u16`), which is why confidence is Medium, not High — exploitation requires the DB to hold an out-of-domain value (corruption/partial write/out-of-band edit; file itself is root-owned, so not attacker-writable under this threat model).
- No `debug_assert!`, no test with out-of-range column values.

## Recommendation
Use checked conversion and treat out-of-domain as corrupt-row (same policy as the unknown-state/unknown-proto guards earlier in the same function):
```rust
let pf = u16::try_from(r.get::<_, i64>(4)?)
    .map_err(|_| rusqlite::Error::InvalidParameterName("port_out_of_range".into()))?;
```
or add `CHECK(port_from BETWEEN 0 AND 65535)` to the schema in `Ledger::open` *and* keep the read-side `try_from`. Apply the same treatment to `port_to`, and to `ttl_secs`/`created_at` if they ever gain enforcement meaning.
