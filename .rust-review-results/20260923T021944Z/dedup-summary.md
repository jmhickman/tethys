---
stage: dedup-judge
total_findings_in: 19
working_set_size: 19
unparseable_locations: 0
multi_locations: 0
tier1_merges: 0
tier2_merges: 0
tier3_merges: 2
primaries_after_dedup: 17
related_groups: 4
---

# Dedup Summary

Threat model: LOCAL_UNPRIVILEGED (root egress-control daemon; attacker = agent uid on `mcp.sock`).

## Location parse health
| Class | Count | Example IDs |
|-------|-------|-------------|
| parseable (`path:line`) | 19 | ARITHOFL-001, CHANSTARVE-001, TOCTOU-001, ... |
| markdown-link (recovered) | 0 | — |
| multi-location (skipped Tier 1) | 0 | — |
| unparseable (skipped Tier 1) | 0 | — |

All 19 findings parsed to a clean `(path, line)`; no `merged_into` present on input (fresh pass), no prior `also_known_as`.

## Tier 1 — exact-location same-class merges (deterministic)
No `(path, line, bug_class)` bucket contained more than one finding. Notably, CANCELSAFETY-001 and CHANSTARVE-001 share the exact location `crates/gatekeeper/src/server.rs:400` but carry different `bug_class` values (`cancel-safety` vs `channel-starvation`), so the class-scoped Tier-1 key correctly refused to collapse them; they were re-examined in Tier 3.

## Tier 2 — same construct in same function (snippet-confirmed)
No `(path, function, bug_class)` bucket contained more than one finding (RESDISC-001/002 share `open`+class but sit at ledger.rs:347 vs :333 in different actor arms — different constructs; RESEXHAUST-001/003 share `handle_mcp`+class but are unbounded-channel/spawn fan-out at :247 vs unbounded line framing at :259 — different constructs). Zero merges.

## Tier 3 — cross-class same-bug merges (LLM-confirmed)
| Primary | Merged IDs | Function | Merged classes | Rationale |
|---------|------------|----------|----------------|-----------|
| CHANSTARVE-001 (High) | CANCELSAFETY-001 (Medium) | dispatch_access | cancel-safety | Same `st.pending.lock().await.insert(gid, tx)` at server.rs:400 and the same `Ok(Err(_)) \| Err(_)` timeout arm at server.rs:506 that never removes the entry — one defect ("orphaned pending entry after approver timeout"), one worker labels it a cancel-safety half-commit, the other a channel/sender leak. Same source (agent uid via mcp.sock), same sink (st.pending). Primary keeps `channel-starvation`; confidence max of group = High (already primary's). |
| OOBIDX-001 (Medium) | UNWRAP-001 (Medium) | parse_poll | unwrap-on-untrusted | Same `v if v.get("range").is_some()` block at nft.rs:619-622 in `parse_poll` — same sink construct (`as_array().unwrap()` + `r[0]`/`r[1]` on the untrusted nft-JSON `range` array), 2 lines apart, identical data flow (nft subprocess stdout → boot reconcile / stats poller panic). One defect labeled OOB-index by one worker and unwrap-on-untrusted by the other; both findings' own recommendations are the same single fix. Tie on confidence → lexicographically smallest id wins (`OOBIDX-001` < `UNWRAP-001`). Absorbed class recorded: unwrap-on-untrusted (no longer appears in primary counts). |

## Tier 4 — Related (NOT merged — cross-reference only)
| Pattern | Finding IDs | Shared fix location |
|---------|-------------|---------------------|
| Atomic counter incremented without an RAII/guard-backed decrement; a panic between add and sub leaks the count (same fix family, explicitly cross-referenced by worker-3) | ATOMICRACE-001, ATOMICRACE-002 | crates/gatekeeper/src/admin.rs, crates/gatekeeper/src/server.rs |
| Unbounded attacker-driven growth on the mcp.sock path (no rate/count/size caps between ingress and ledger) | RESEXHAUST-001, RESEXHAUST-002, RESEXHAUST-003, CHANSTARVE-001 (absorbing CANCELSAFETY-001), STRCMP-001 (case-churn multiplies rows) | crates/gatekeeper/src/server.rs (+ install.rs) |
| Blocking disk I/O executed directly on a tokio task (no `spawn_blocking` anywhere in `crates/`) | ASYNCBLOCK-001, ASYNCBLOCK-002 | crates/gatekeeper/src/ledger.rs, crates/gk-tui/src/ui.rs |
| Build-time hardening gaps on the root daemon manifests (same worker, adjacent manifest lines :1/:3, different classes — deliberately NOT merged) | CARGOLINT-001, MSRV-001 | crates/gatekeeper/Cargo.toml (+ workspace Cargo.toml) |

## Bug-class counts (primaries only, after dedup)
| Bug class | Count |
|-----------|-------|
| arithmetic-overflow | 1 |
| async-blocking | 2 |
| atomic-race | 2 |
| cancel-safety | 0 (merged into channel-starvation primary) |
| cargo-lint-config | 1 |
| channel-starvation | 1 |
| lossy-from-into | 1 |
| msrv-mismatch | 1 |
| out-of-bounds-index | 1 |
| result-discarded | 2 |
| resource-exhaustion | 3 |
| string-comparison | 1 |
| toctou | 1 |
| unwrap-on-untrusted | 0 (merged into out-of-bounds-index primary) |
| **Total primaries** | **17** |
