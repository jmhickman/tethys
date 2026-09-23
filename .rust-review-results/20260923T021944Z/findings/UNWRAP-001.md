---
id: UNWRAP-001
bug_class: unwrap-on-untrusted
title: parse_poll unwraps `range` as array after only an existence check — non-array nft JSON output panics reconcile/stats paths
location: crates/core/src/nft.rs:619
function: parse_poll
confidence: Medium
worker: worker-4
merged_into: OOBIDX-001
---

## Description
`parse_poll` consumes the JSON emitted by the external `nft --json` binary (a subprocess output —
i.e. data produced outside the process and shaped by kernel/nft version behaviour). For the port
field of a grant-set element it guards on key *presence* only:

`v if v.get("range").is_some()` — then immediately `v["range"].as_array().unwrap()`.

If `range` is present but not a JSON array (string, object, number — any nft-version or
kernel-dump variation, or a hand-edited/foreign object in the same table), the `unwrap()` panics.
Every sibling extraction in the same function uses the safe pattern
(`.and_then(|v| v.as_array())` + `continue`, `unwrap_or(0)`), showing the intended discipline; this
is the one site that assumes the type.

Panic blast radius depends on caller:
- `reconcile_on_boot` (startup, `reconcile.rs:17` → `poll_live` → `parse_poll`): panic propagates
  out of `run()` before the listeners bind — the enforcement daemon fails to start at all.
- `spawn_stats_poller` (`server.rs:187` calls `parse_poll` directly on `list counters` output):
  tokio swallows the task panic, so the traffic-stats poller silently dies forever (availability
  degradation of the approval UI's live data).

## Code
```rust
// crates/core/src/nft.rs:613-624
let (pf, pt) = match &concat[2] {
    Value::Number(n) => {
        let p = n.as_u64().unwrap_or(0) as u16;
        (p, p)
    }
    v if v.get("range").is_some() => {
        let r = v["range"].as_array().unwrap();      // <-- existence checked, TYPE not
        (
            r[0].as_u64().unwrap_or(0) as u16,       // also: r[0]/r[1] index — OOB if range has <2 items
            r[1].as_u64().unwrap_or(0) as u16,
        )
    }
    _ => continue,
};
```

## Data flow
- **Source:** stdout of `/usr/sbin/nft --json -f -` (`run_nft_json`, `nft.rs:482-551`) returned by `NftCli::list_json` / `poll_live`; element contents partly seeded by agent-requested port ranges installed via `add_grant`
- **Sink:** `Vec::as_array().unwrap()` at `crates/core/src/nft.rs:619` (and slice indexing `r[0]`, `r[1]` at 621-622, which panic on a short array)
- **Validation:** `get("range").is_some()` — presence only; no `as_array()` check, no length check on the array

## Reachability trace
Boot: `main → server::run → reconcile_on_boot → NftCli::poll_live → list_json → parse_poll → unwrap`.
Runtime: `spawn_stats_poller → nft.list_json("counters") → parse_poll` (`server.rs:180-191`).

## Impact
Under LOCAL_UNPRIVILEGED the attacker cannot directly rewrite nft's JSON, but the panic is a real
single-point failure on externally-produced data: any version drift or foreign element that renders
`range` non-array (or shorter than 2) prevents the root daemon from starting (fail-closed outage of
all egress enforcement + every agent blocked) or kills the stats poller permanently. The agent does
influence the *content* of these ranges through its grant requests, so this dump is not fully
trusted data either.

## Mitigations checked
- `.is_some()` guard present but checks key presence, not JSON type — pro-forma guard, not a proof.
- All neighbouring fields in the same parser use `and_then`/`unwrap_or` — this site is an outlier.
- No `catch_unwind` around `reconcile_on_boot`; no panic hook; workspace has no `panic = "abort"` (default unwind).
- No fuzzing of `parse_poll` (no harness found).

## Recommendation
Match structurally: `v.get("range").and_then(Value::as_array).filter(|r| r.len() >= 2)` then `continue` otherwise — mirroring the style used for `concat`, `elem`, and `prefix` a few lines above.
