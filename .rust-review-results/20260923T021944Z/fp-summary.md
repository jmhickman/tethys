---
stage: fp-judge
threat_model: LOCAL_UNPRIVILEGED
primaries_evaluated: 17
true_positives: 13
likely_tp: 3
likely_fp: 1
false_positives: 0
out_of_scope: 0
---

# FP-Judge Summary

Threat model: LOCAL_UNPRIVILEGED — attacker is the unprivileged agent uid speaking framed JSON on `mcp.sock`; the privilege boundary is the root daemon and its approval channel (`admin.sock`). Dedup ran (see `dedup-summary.md`); two Tier-3 merges were judged as groups (CHANSTARVE-001 ⊃ CANCELSAFETY-001; OOBIDX-001 ⊃ UNWRAP-001), each receiving one verdict.

## Verdict counts (primaries)
| Verdict | Count |
|---------|-------|
| TRUE_POSITIVE | 13 |
| LIKELY_TP | 3 |
| LIKELY_FP | 1 |
| FALSE_POSITIVE | 0 |
| OUT_OF_SCOPE | 0 |

## Per-primary verdicts
| ID | Bug class | Verdict | Severity | Rationale |
|----|-----------|---------|----------|-----------|
| ARITHOFL-001 | arithmetic-overflow | TRUE_POSITIVE | MEDIUM | Attacker TTL frame reaches unchecked `n * mult` (types.rs:127) before any approval; debug deploy build panics the dispatch task + wedges drain loop, release wraps |
| ASYNCBLOCK-001 | async-blocking | TRUE_POSITIVE | MEDIUM | Blocking rusqlite commits on tokio workers (zero spawn_blocking in crates/), fed unbounded by attacker flood — daemon-wide latency DoS |
| ASYNCBLOCK-002 | async-blocking | TRUE_POSITIVE | LOW | Sync /proc reads in gk-tui async draw; attacker can amplify event volume but blast radius is the approver TUI only |
| ATOMICRACE-001 | atomic-race | LIKELY_TP | MEDIUM | Unguarded admins_online fetch_add/fetch_sub (admin.rs:26/54) confirmed; leak kills approver-offline fast-deny forever, but trigger needs an internal panic, not direct attacker input |
| ATOMICRACE-002 | atomic-race | TRUE_POSITIVE | MEDIUM | inflight fetch_sub only in respond closure (server.rs:281-294); pre-respond panic wedges EOF drain loop forever — ARITHOFL-001 is a concrete attacker-triggered panic source |
| CARGOLINT-001 | cargo-lint-config | TRUE_POSITIVE | LOW | No [lints]/#![forbid]/CI anywhere; unsafe-free today — valid hardening gap, always in scope at LOW |
| CHANSTARVE-001 (⊃ CANCELSAFETY-001) | channel-starvation | TRUE_POSITIVE | MEDIUM | Timeout arm (server.rs:506) never removes `st.pending` entry; attacker-rate leak of map entries + denied ledger rows, both merged framings describe the same reachable defect |
| LOSSYFROM-001 | lossy-from-into | LIKELY_FP | — | i64→u16 truncation real but attacker-unreachable: write path bounds values, DB root-owned, failure direction fail-closed — no boundary crossing in attacker's favor |
| MSRV-001 | msrv-mismatch | TRUE_POSITIVE | LOW | No rust-version/rust-toolchain.toml while let-else used pervasively — build-hygiene hardening gap at LOW |
| OOBIDX-001 (⊃ UNWRAP-001) | out-of-bounds-index | LIKELY_TP | MEDIUM | `as_array().unwrap()` + unchecked `r[0]`/`r[1]` on nft subprocess JSON (nft.rs:618-623); boot-reconcile panic = fail-closed outage, poller panic = silent accounting stop; taint is nft-version quirk, not direct agent control |
| RESDISC-001 | result-discarded | TRUE_POSITIVE | MEDIUM | Audit INSERT `let _ =` with no log (ledger.rs:347) — attacker-induced disk pressure silently erases the approval trail |
| RESDISC-002 | result-discarded | TRUE_POSITIVE | MEDIUM | `.unwrap_or(0)` conflates DB error with not-approved (ledger.rs:333); unpersisted dst_json risks stale egress element surviving revoke (fail-open direction) |
| RESEXHAUST-001 | resource-exhaustion | TRUE_POSITIVE | MEDIUM | Uncapped spawn + unbounded reply channel + per-id ledger row on mcp.sock — deterministic O(attacker-rate) RAM/task/DB growth |
| RESEXHAUST-002 | resource-exhaustion | TRUE_POSITIVE | MEDIUM | rebuild_acct O(all approved rows) + nft subprocess per approve/expire event, attacker-driven grant churn (1s TTLs legal) |
| RESEXHAUST-003 | resource-exhaustion | TRUE_POSITIVE | MEDIUM | `lines()` with no max-line cap or idle timeout (server.rs:259) — newline-free streams grow daemon RAM linearly in bytes written |
| STRCMP-001 | string-comparison | TRUE_POSITIVE | MEDIUM | Wire path preserves host case (server.rs:564) vs lowercased config path (config.rs:152); case-sensitive dedup `==` — trivial case-churn defeats approval dedup |
| TOCTOU-001 | toctou | LIKELY_TP | HIGH | bind→chmod window on admin.sock + no uid gate in handle_admin → permanent unauthenticated approver session; default systemd UMask=0022 incidentally blocks connect, so deployment-dependent |

## Common FP patterns observed
- Attacker-unreachable data-integrity pattern — LOSSYFROM-001's `as` truncation is real code smell but every source of an out-of-domain value (DB corruption, ops UPDATE) sits outside the attacker's write capability and the wrap direction is fail-closed; under LOCAL_UNPRIVILEGED a defect that crosses no privilege boundary in the attacker's favor is LIKELY_FP, not LOW.
- (No FALSE_POSITIVE or OUT_OF_SCOPE verdicts: every worker premise survived source verification, and no finding was local-config/root-only-triggered.)

## Areas that need deeper analysis
- TOCTOU-001: confirm the deployed systemd unit's effective `UMask=` (none set → 0022) and whether any supported non-systemd/dev launch path runs with a permissive umask; a `peer_cred().uid() != 0` reject in `handle_admin` would make this moot regardless of the race outcome.
- OOBIDX-001: pin the tested `nft` version range and consider a regression fixture feeding `parse_poll` short/non-array `range` values — the panic is unconditional once such output occurs, but no known nft version currently emits it.
- ATOMICRACE-001: determine whether any attacker-influenced path can kill the ledger actor task (every `ask().expect("ledger actor died")` caller would then panic, arming both atomic-leak findings).
