# rust-review run summary — gatekeeper (2026-09-23)

## Resolved parameters
- threat_model: LOCAL_UNPRIVILEGED
- severity_filter: all
- finding_scope_root: `crates/` (workspace: core, gatekeeper, gk-mcp, gk-tui; 17 .rs files, ~6.4 KLoC)
- context_roots: `.` (repo root, read-only)
- Capability flags: has_unsafe=false, has_ffi=false, has_concurrency=true, has_async=true, has_packed_repr=false, has_fs_io=true
- Cargo manifest: workspace (`/home/hermes-agent/gatekeeper/Cargo.toml`)

## Execution adaptation (Hermes environment)
The skill's Claude-Code `Agent` subagent model is unavailable here; each worker/judge ran as a
`hermes chat -Q --oneshot` CLI invocation with the agent protocol inlined into the prompt
(`combined-prompts/worker-N.txt`). Per user direction, concurrency capped at 2 (local model host),
so "parallel waves" became an `xargs -P 2` queue. Model: the session's local Qwen3.8-flash-next.
`uv` was installed via pip (required a gatekeeper egress grant to pypi.org, approved).

## Worker outcomes (all 17 completed; all validated by validate_artifacts.py)
| worker | cluster | claimed | shard | coverage | status | notes |
|---|---|---|---|---|---|---|
| 1 | unsafe-boundary | 0 | ok | coverage/worker-1.md | completed | |
| 2 | concurrency-locking | 1 | ok | coverage/worker-2.md | completed | |
| 3 | concurrency-data-race | 2 | ok | coverage/worker-3.md | completed | |
| 4 | panic-dos-1 | 5 | ok | coverage/worker-4.md | completed | |
| 5 | panic-dos-2 | 1 | ok | coverage/worker-5.md | completed | |
| 6 | recursion-dos-1 | 0 | ok | coverage/worker-6.md | completed | |
| 7 | recursion-dos-2 | 0 | ok | coverage/worker-7.md | completed | |
| 8 | recursion-dos-3 | 0 | ok | coverage/worker-8.md | completed | |
| 9 | error-handling-1 | 3 | ok | coverage/worker-9.md | completed | |
| 10 | error-handling-2 | 0 | ok | coverage/worker-10.md | completed | |
| 11 | logic-correctness-1 | 1 | ok | coverage/worker-11.md | completed | |
| 12 | logic-correctness-2 | 0 | ok | coverage/worker-12.md | completed | |
| 13 | async-runtime | 3 | ok | coverage/worker-13.md | completed | attempt 2 (attempt 1 killed by host OOM/session kill; prefix space cleared before retry) |
| 14 | static-hygiene | 2 | ok | coverage/worker-14.md | completed | |
| 15 | resource-handling | 0 | ok | coverage/worker-15.md | completed | |
| 16 | input-os-safety | 1 | ok | coverage/worker-16.md | completed | attempt 2 (same as worker-13) |
| 17 | info-disclosure | 0 | ok | coverage/worker-17.md | completed | |

No worker reported `truncated at hard cap`. No non-retryable aborts.

## Index reconciliation
- `findings-index.txt`: **19** lines (built from disk).
- Sum of worker claims: 15 + 3 (w13) + 1 (w16) = **19** — matches, no mismatch.
- Orphans (on disk but in no shard): none.

## Judge / SARIF / report status
- dedup-judge: **complete** — 19 findings → 17 primaries (0 tier-1, 0 tier-2, 2 tier-3 cross-class merges, 4 related groups). `dedup-summary.md` written. First attempt was lost to a foreground timeout in the orchestrator harness; re-run completed cleanly (idempotent by design).
- fp-judge: **complete** — 17 primaries → 13 TRUE_POSITIVE, 3 LIKELY_TP, 1 LIKELY_FP, 0 FALSE_POSITIVE, 0 OUT_OF_SCOPE. Survivors: 1 HIGH + 12 MEDIUM/LOW (16 reported). `fp-summary.md`, `REPORT.md` (judge-authored), `REPORT.sarif` written.
- Phase 8b safety net: SARIF generator re-run idempotently — `REPORT.sarif` has 16 results, no skipped-findings warnings. `REPORT.md` present (judge-authored, not overwritten).
- All Success Criteria verified: 17/17 clusters completed+validated; every primary has `fp_verdict`+`fp_rationale`; survivors carry severity/attack_vector/exploitability; REPORT.md + REPORT.sarif exist.
