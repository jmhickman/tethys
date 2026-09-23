---
id: OOBIDX-001
bug_class: out-of-bounds-index
title: nft JSON "range" array indexed at [0]/[1] with no length check in parse_poll
location: crates/core/src/nft.rs:621
function: parse_poll
confidence: Medium
worker: worker-5
also_known_as: [UNWRAP-001]
locations:
  - crates/core/src/nft.rs:621
  - crates/core/src/nft.rs:619
fp_verdict: LIKELY_TP
fp_rationale: "Both merged framings verified in one construct (nft.rs:618-623): `as_array().unwrap()` plus unbounded `r[0]`/`r[1]` on external-process JSON, while every sibling extraction is defensive — the missing checks are unconditional and a short/non-array `range` panics the boot reconcile (daemon fails to start) or permanently kills the stats poller; reachability by the agent depends on an nft-version/format quirk rather than direct taint, hence LIKELY not TP"
severity: MEDIUM
attack_vector: Local
exploitability: Difficult
severity_rationale: "Panic on externally-produced JSON: boot-path abort is a fail-closed outage of all egress enforcement, steady-state kill silently stops accounting — local availability impact on the root daemon, but requires an nft output variation the agent cannot directly force"
---

## Description
`parse_poll` parses the JSON emitted by the external `nft --json list table` process. For the destination-port element it validates the enclosing `concat` array (`if concat.len() != 3 { continue; }`, nft.rs:589) but then, on the `"range"` branch, indexes the inner range array at fixed positions `r[0]` and `r[1]` without ever checking that the array has at least two elements. Any well-formed JSON where `"range"` is an array of length 0 or 1 makes `r[0]`/`r[1]` panic with `index out of bounds`. The parser is written defensively everywhere else (`as_str().unwrap_or(...)`, `as_u64().unwrap_or(0)`, `continue` on unexpected shapes) — this is the one spot that assumes a shape it never verifies.

The array contents come from an external process's stdout (kernel-echoed set element data), not from a type-checked internal structure, so the length invariant is not enforced by the compiler anywhere on this path.

## Code
```rust
// crates/core/src/nft.rs:613-624 (parse_poll)
let (pf, pt) = match &concat[2] {
    Value::Number(n) => {
        let p = n.as_u64().unwrap_or(0) as u16;
        (p, p)
    }
    v if v.get("range").is_some() => {
        let r = v["range"].as_array().unwrap();
        (
            r[0].as_u64().unwrap_or(0) as u16,   // <-- no r.len() >= 2 check
            r[1].as_u64().unwrap_or(0) as u16,   // <-- panics if len < 2
        )
    }
    _ => continue,
};
```

## Data flow
- **Source:** stdout of the `nft --json -f -` child process (`run_nft_json`, nft.rs:504-551), i.e. external-process / kernel-set-element JSON consumed by `poll_live` (nft.rs:473-478) and by the traffic-poll loop's direct `parse_poll` call (server.rs:187).
- **Sink:** `r[0]` / `r[1]` indexing of `Value::Array` at crates/core/src/nft.rs:621-622.
- **Validation:** none on the range array's length — only the enclosing `concat.len() == 3` and `v.get("range").is_some()` are checked; a `"range": []` or `"range": [443]` value passes both guards.

## Reachability trace
1. Boot: `main.rs:74 → reconcile_on_boot (reconcile.rs:16-17) → nft.poll_live → parse_poll → r[0]`.
2. Steady state: traffic-poll `tokio::spawn` loop (`server.rs:170-190`) → `st.nft.list_json("counters", …)` → `parse_poll` every 2 s.

## Impact
A malformed/short `range` array panics inside the root daemon:
- On the boot path (`reconcile_on_boot` is `.await`ed from `main`), the panic aborts daemon startup entirely — with the nft table already installed, that is a fail-open/fail-closed availability event for all agent egress.
- In the steady-state poll task, the panic kills the spawned task; traffic accounting and expiry reporting silently stop for the rest of the process lifetime (tokio isolates the panic to the task, so nothing restarts it).

Taint caveat for the judge: the array length is set by the `nft` binary/kernel echo rather than directly by the unprivileged agent (the daemon itself always writes 2-element ranges via `json!({"range": [f, t]})` at nft.rs:156), so exploitability under LOCAL_UNPRIVILEGED depends on a version/format quirk of nft output; the *missing bounds check* itself is unconditional.

## Mitigations checked
- `concat.len() != 3` guard exists but does not bound the inner `range` array.
- No `catch_unwind` / panic hook around `parse_poll`; no supervisor restarts the poll task.
- `.as_u64().unwrap_or(0)` tolerates wrong *value* types but not missing *positions*.
- `serde_json::Value` string indexing (`v["range"]`) never panics, which masks the fact that positional indexing on arrays does.
- No fuzzing or MIRI coverage of this parser (per codebase context); release profile sets no `overflow-checks`/panic overrides (workspace Cargo.toml only sets `[profile.dev] debug = 0`).

## Recommendation
Parse positionally-checked:
```rust
v if v.get("range").is_some() => {
    let Some(r) = v["range"].as_array().filter(|a| a.len() >= 2) else { continue };
    (
        r[0].as_u64().unwrap_or(0) as u16,
        r[1].as_u64().unwrap_or(0) as u16,
    )
}
```
