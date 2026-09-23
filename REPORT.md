---
stage: final-report
threat_model: LOCAL_UNPRIVILEGED
severity_filter: all
total_primaries: 17
reported_findings: 16
---

# Rust Security Review — Final Report

**Project:** gatekeeper — root-run egress-control daemon (nftables enforcement, SQLite grant ledger, MCP approval pipeline)
**Threat Model:** LOCAL_UNPRIVILEGED — attacker is the unprivileged agent uid: arbitrary framed JSON on `mcp.sock` (SO_PEERCRED-gated to same uid), gk-mcp stdio. The privilege boundary is the root daemon and its 0600 `admin.sock` approval channel.
**Severity Filter:** all
**Primaries (after dedup):** 17 (two Tier-3 merged groups judged as single findings)
**Reported:** 16 (after FP filter; 1 LIKELY_FP dropped — see `fp-summary.md`)

## Severity distribution (reported)
| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH     | 1 |
| MEDIUM   | 12 |
| LOW      | 3 |

(The remaining 1 primary was LIKELY_FP — LOSSYFROM-001, see `fp-summary.md`. No FALSE_POSITIVE or OUT_OF_SCOPE verdicts: every worker premise survived source verification.)

## HIGH (1)

### TOCTOU-001 — admin.sock is connectable between bind() and the 0600 chmod; handle_admin enforces no uid check, so the window is the only access control
- **Location:** `crates/gatekeeper/src/server.rs:83` (`run`)
- **Attack vector:** Local (connect(2) race at daemon start/restart)
- **Exploitability:** Difficult (bind→chmod race window; default systemd UMask=0022 incidentally blocks "other" connect, but nothing in code guarantees it)
- **Also affects:** — (standalone primary)
- **FP verdict:** LIKELY_TP — bind→chmod gap and log-only `peer_cred` verified; a connect won inside the window yields a permanent unauthenticated root-side approver session; exploitability is deployment-umask-dependent.
- **Severity rationale:** Full privilege-boundary crossing (forged approvals / revokes / `stop.grants` with root-daemon authority — near privilege-escalation to approval control); reduced one level for the race window and the default-umask block. Dev runs, e2e scripts, and permissive-umask supervisors are fully exposed.

**Description:** The entire privilege boundary of the approval channel rests on `admin.sock` being mode 0600 — but the mode is not established atomically with the socket's creation. `UnixListener::bind()` at server.rs:83 creates the socket inode with permissions `0777 & ~umask`, and only afterwards does server.rs:84 apply `set_permissions(..., 0o600)`. Between those two syscalls the socket is live in the filesystem and accept()-able. Unix socket permissions are checked at `connect()` time only: a client that connects inside the window keeps a fully-functional admin session *forever*, even after the 0600 chmod lands. Crucially, `handle_admin` (admin.rs:22-25) reads `SO_PEERCRED` purely to log it — there is **no uid gate** on the admin command loop. Whatever connects inside the window may issue `approve`, `deny`, `revoke`, and `stop.grants`. An unprivileged local process can spin a tight `connect()` loop on `/run/gatekeeper/admin.sock` and win the race whenever the daemon starts or restarts (`Restart=on-failure`, RestartSec=2s), crossing the root boundary and forging approvals for its own grants. With systemd's default UMask=0022 the inode is 0755 and "other" lacks write permission, so connect fails — but that is an accident of deployment config, not a code guarantee; manual runs, dev mode (`--dry-run`), e2e scripts, or any supervisor with umask 0000/0002 make the window world-connectable.

**Code:**
```rust
// crates/gatekeeper/src/server.rs:83-84
let admin = UnixListener::bind(&st.cfg.admin_socket)?;   // socket live, mode = 0777 & ~umask
std::fs::set_permissions(&st.cfg.admin_socket, std::fs::Permissions::from_mode(0o600))?; // hardened after

// crates/gatekeeper/src/admin.rs:23-25 — credentials logged, never enforced
if let Some(c) = peer_cred(&stream) {
    tracing::info!(uid = c.uid(), "admin client connected");
}
```

**Data flow:** `connect(2)` on admin.sock from any local process during the bind→set_permissions window → accept loop (server.rs:103-110) → `handle_admin` → `admin_cmd` (`approve`/`deny`/`revoke`/`stop_grants`) → ledger `Decide::Approve` + `install_grant` nft element. No validation at accept time; `peer_cred` is logged only.

**Impact:** A local unprivileged process that wins the startup race obtains a persistent root-side approver session: it can approve its own pending egress grants (defeating the human-approval boundary entirely), revoke others', or fire `stop.grants`. No further authentication exists on the admin channel. Even where the default systemd umask closes the connect path, the documented invariant "admin.sock (0600, root only)" is unenforced and silently breaks under any deployment/dev change of umask.

**Recommendation:** Make the mode precede visibility: wrap the two binds with `libc::umask(0o177)` (restore after), or create the socket via `socket(2)` + `fchmod` on the fd before `bind`. Independently, add defense-in-depth in `handle_admin`: reject any connection whose `peer_cred().uid()` is not 0 (or a configured admin uid) instead of merely logging it — then the chmod window no longer carries the whole boundary.

---

## MEDIUM (12)

### ARITHOFL-001 — Attacker-controlled TTL multiply `n * mult` in parse_ttl overflows
- **Location:** `crates/core/src/types.rs:127` (`parse_ttl`) — **Verdict:** TRUE_POSITIVE, Reliable
- Unbounded attacker `ttl_requested` (e.g. `"9999999999999999999h"`) hits plain `n * mult`. The deploy script builds debug (`deploy/enforcement_e2e.sh:14`, no `--release`; workspace sets no `overflow-checks`), so the multiply **panics** the spawned `dispatch_access` task on the very first frame — request never answered (gk-mcp hangs 6 min) and, because `done.fetch_sub` lives only in the `respond` closure, the connection's EOF drain loop (`server.rs:292-294`) spins forever. In release the multiply silently wraps, so the granted TTL no longer means what the approver saw (`cap_ttl` clamps only after parse). Fix: `checked_mul` + explicit `[profile.release] overflow-checks = true`. Details: `findings/ARITHOFL-001.md`.

### ASYNCBLOCK-001 — Ledger actor runs synchronous rusqlite I/O on a tokio worker thread
- **Location:** `crates/gatekeeper/src/ledger.rs:197` (`open`) — **Verdict:** TRUE_POSITIVE, Difficult
- Every INSERT/UPDATE/SELECT (incl. WAL fsync) executes synchronously inside the single spawned actor task; zero `spawn_blocking`/`block_in_place` in `crates/` (rg-verified). An mcp.sock flood plus disk pressure parks async worker threads, delaying accept loops, approvals, and the expiry reconciler — liveness degradation of the security-critical daemon. Fix: move the `Connection` onto a blocking thread / dedicated OS thread, or bound stalls via `PRAGMA synchronous=NORMAL` + `busy_timeout`. Details: `findings/ASYNCBLOCK-001.md`.

### ATOMICRACE-001 — admins_online counter leaks upward when the admin task panics
- **Location:** `crates/gatekeeper/src/admin.rs:26` (`handle_admin`) — **Verdict:** LIKELY_TP, Difficult
- `fetch_add` at :26 / `fetch_sub` at :54 with no RAII guard; a panic inside the loop (e.g. ledger actor death via `ask().expect("ledger actor died")`) unwinds past the decrement. A permanently >0 count disables the `ApproverOffline` fast-deny (`server.rs:357`) forever — every agent request becomes a pending row that waits the full approver timeout — and pins the stats poller active. Trigger requires an internal panic rather than direct attacker input, hence LIKELY_TP. Fix: Drop-guard the increment. Details: `findings/ATOMICRACE-001.md`.

### ATOMICRACE-002 — inflight counter leak wedges handle_mcp in an endless drain loop
- **Location:** `crates/gatekeeper/src/server.rs:281` (`handle_mcp`) — **Verdict:** TRUE_POSITIVE, Difficult
- `done.fetch_sub(1)` runs only inside the `respond` closure; any pre-respond panic in `dispatch_access` leaves the per-connection counter >0, so the post-EOF drain loop (`:292-294`) never terminates — leaked spinning task holding `Arc<State>` and the socket, repeatable per connection. ARITHOFL-001's ttl-overflow panic is a concrete attacker-triggered source in the deployed debug build. Fix: RAII decrement guard or decrement on `JoinHandle` completion. Details: `findings/ATOMICRACE-002.md`.

### CHANSTARVE-001 — Orphaned oneshot Senders leak in `pending` map forever after approver timeout
- **Location:** `crates/gatekeeper/src/server.rs:400` (`dispatch_access`) — **Verdict:** TRUE_POSITIVE (group incl. CANCELSAFETY-001), Reliable
- The timeout arm `Ok(Err(_)) | Err(_)` (`server.rs:506`) denies and responds but never removes the `st.pending` entry; removals exist only on admin paths (`admin.rs:78,92,248,279`). Attacker varies the request id (dedup at `:338` matches only approved-active grants), so N requests → N leaked map entries + N denied ledger rows, unbounded until an operator runs `stop.grants`. Secondary: a late admin approve on a dead gid replies `{"queued": true}` for an already-denied grant. Both merged framings (channel-starvation / cancel-safety) describe this same leak — one verdict for the group. Fix: unconditional `st.pending.remove(&gid)` after the timeout match, plus a per-uid pending budget. Details: `findings/CHANSTARVE-001.md`, `findings/CANCELSAFETY-001.md` (absorbed).

### OOBIDX-001 — nft JSON "range" array unwrapped and indexed with no type/length check in parse_poll
- **Location:** `crates/core/src/nft.rs:619-622` (`parse_poll`) — **Verdict:** LIKELY_TP (group incl. UNWRAP-001), Difficult
- `v["range"].as_array().unwrap()` checks presence but not type, and `r[0]`/`r[1]` assume length ≥ 2 — the only non-defensive extraction in an otherwise `unwrap_or`/`continue`-style parser. A short or non-array `range` in `nft --json` output panics boot `reconcile_on_boot` (daemon never starts → fail-closed outage for all agent egress) or permanently kills the stats poller task (`server.rs:187`). Taint caveat: the array shape comes from the nft binary/kernel echo, not directly from the agent (the daemon always writes 2-element ranges), so LIKELY_TP rather than TP; the missing check itself is unconditional. Fix: `v.get("range").and_then(Value::as_array).filter(|r| r.len() >= 2)` else `continue`. Details: `findings/OOBIDX-001.md`, `findings/UNWRAP-001.md` (absorbed).

### RESDISC-001 — Audit-log INSERT error silently discarded
- **Location:** `crates/gatekeeper/src/ledger.rs:347` (`open`) — **Verdict:** TRUE_POSITIVE, Difficult
- `let _ = conn.execute("INSERT INTO audit ...")` with no log (the sibling Decide arm logs via `tracing::error!`), and `Ledger::audit()` `.ok()`-discards the channel send too. An attacker who fills the DB filesystem — plausibly via grant-flood DB bloat — permanently erases the approval trail with zero operator signal while grants keep flowing; post-incident forensics across the mcp.sock→approval boundary become impossible for the window. Fix: log the failure like Decide; escalate (health flag / fail-closed) if audit completeness is policy. Details: `findings/RESDISC-001.md`.

### RESDISC-002 — SetDst UPDATE error swallowed by `.unwrap_or(0)`
- **Location:** `crates/gatekeeper/src/ledger.rs:333` (`open`) — **Verdict:** TRUE_POSITIVE, Difficult
- A DB write fault is conflated with "row not approved"; the caller's warn names the wrong cause. `dst_json` stays `'[]'`, so revoke tears down from a re-derivation instead of the pinned resolution — the installed kernel element can survive revoke (stale egress, fail-open direction) until TTL. Fix: match on the result, log `%e`, and treat set_dst failure as a hard error on the approval path. Details: `findings/RESDISC-002.md`.

### RESEXHAUST-001 — Uncapped per-connection request fan-out on mcp.sock
- **Location:** `crates/gatekeeper/src/server.rs:247` (`handle_mcp`) — **Verdict:** TRUE_POSITIVE, Reliable
- Per-line `tokio::spawn` with `inflight` counted but never capped, replies through an `mpsc::unbounded_channel` (RAM-buffered when the client stops reading), one UNIQUE-id ledger row per distinct id, and no connection limit. One unprivileged process drives daemon RAM, task count, and DB size linearly in send rate with zero backpressure. Fix: per-connection in-flight cap, bounded reply channel with `try_send`, global pending budget. Details: `findings/RESEXHAUST-001.md`.

### RESEXHAUST-002 — rebuild_acct is O(approved rows) per event and spawns an nft subprocess each time
- **Location:** `crates/gatekeeper/src/install.rs:175` (`rebuild_acct`) — **Verdict:** TRUE_POSITIVE, Difficult
- Every approve/expiry/revoke/stop rebuilds all accounting from all approved rows (per-row DNS + 2 dirs × 2 families) and shells out to `/usr/sbin/nft`; mass expiry additionally sweeps ~5 nft processes per grant. The attacker controls grant count and TTL ("1s" is legal), so approving N grants costs O(N²) batch work + N subprocess spawns, and the shared ledger actor serializes the churn behind every other connection. `LIMIT 500` bounds one scan, not the event product. Fix: debounced/coalesced rebuilds, incremental accounting, per-uid grant budget. Details: `findings/RESEXHAUST-002.md`.

### RESEXHAUST-003 — Unbounded NDJSON line length on mcp.sock
- **Location:** `crates/gatekeeper/src/server.rs:259` (`handle_mcp`) — **Verdict:** TRUE_POSITIVE, Reliable
- `BufReader::lines()` accumulates until `\n` with no max length and no read/idle timeout; a few newline-free streams make the root daemon allocate linearly in attacker-written bytes (host OOM pressure), and slow-loris connections pin reader/writer tasks forever. `sanitize()` applies only after the full line is buffered and parsed. Fix: capped `read_until(b'\n')` framing + per-connection idle timeout. Details: `findings/RESEXHAUST-003.md`.

### STRCMP-001 — Grant dedup compares case-sensitive host targets while DNS identity is case-insensitive
- **Location:** `crates/gatekeeper/src/server.rs:340` (`dispatch_access`) — **Verdict:** TRUE_POSITIVE, Reliable
- `pick_target` keeps the wire host's case verbatim (`server.rs:564`) while config `allow` entries lowercase (`config.rs:152`); the dedup gate is a case-sensitive `==` on `canonical()`. `Api.X.com` vs `api.x.com` resolve identically but dedup-miss: new row, new popup that looks different to the human, and a separate kernel element with an independent TTL. Case-churn is a cheap way to multiply overlapping grants, re-prompt the approver into silently refreshing egress, and fragment the documented canonical-identity invariant. Fix: `h.to_ascii_lowercase()` in `pick_target`. Details: `findings/STRCMP-001.md`.

---

## LOW (3)

### ASYNCBLOCK-002 — TUI render path does synchronous /proc reads inside the tokio main task
- **Location:** `crates/gk-tui/src/ui.rs:693` (`hostname`) — **Verdict:** TRUE_POSITIVE, Difficult
- `hostname()` and `primary_network()` re-read `/proc` on every draw (500 ms tick + per event + per keypress) with no caching, stalling the single-threaded approval UI. Attacker can amplify draw frequency via a daemon-event flood, but blast radius is the gk-tui process only — approver-visible lag, root daemon unaffected. Fix: compute once at startup or cache. Details: `findings/ASYNCBLOCK-002.md`.

### CARGOLINT-001 — Unsafe-free security crates declare no [lints]; unsafe_code not denied
- **Location:** `crates/gatekeeper/Cargo.toml:1` — **Verdict:** TRUE_POSITIVE, Theoretical
- No `[lints]` table, no crate-level `#![deny/forbid]`, no clippy.toml/RUSTFLAGS/CI anywhere; `rg unsafe crates` is empty today, so `unsafe_code = "forbid"` is a free, enforceable invariant for the root daemon — currently true only by accident. Standard hardening-gap class at LOW. Fix: `[workspace.lints]` with `unsafe_code = "forbid"` + clippy CI. Details: `findings/CARGOLINT-001.md`.

### MSRV-001 — No rust-version (MSRV) declared; no rust-toolchain.toml
- **Location:** `crates/gatekeeper/Cargo.toml:3` — **Verdict:** TRUE_POSITIVE, Theoretical
- Code depends on ≥1.65 features (pervasive let-else) while nothing declares or pins a minimum; no CI pins the compiler used to build the deployed root binary → non-reproducible builds and silent toolchain drift across deploy hosts. Build-hygiene gap at LOW. Fix: `rust-version` in `[workspace.package]` + pinned CI toolchain. Details: `findings/MSRV-001.md`.

---

## Scope notes
- Findings scope: `crates/` (workspace members `core`, `gatekeeper`, `gk-mcp`, `gk-tui`); repo root files (`Cargo.toml`, `deploy/`) used as read-only context. `target/` excluded. No findings outside scope were reported.
- Dedup ran before this pass (2 Tier-3 cross-class merges): CHANSTARVE-001 ⊃ CANCELSAFETY-001 and OOBIDX-001 ⊃ UNWRAP-001 — each group judged once from all its framings; absorbed files carry `merged_into` and are not reported separately.
- Related-but-unmerged clusters worth a single coordinated fix each (per dedup Tier-4): the atomic-counter RAII family (ATOMICRACE-001/002), the unbounded-mcp-path family (RESEXHAUST-001/002/003, CHANSTARVE-001, STRCMP-001), blocking-I/O-on-runtime (ASYNCBLOCK-001/002), and manifest hardening (CARGOLINT-001, MSRV-001).
- `admin.sock` shares the unbounded-`lines()` pattern of RESEXHAUST-003 but is 0600 root-only — outside the LOCAL_UNPRIVILEGED attacker model.
- Deployed build is debug (`deploy/enforcement_e2e.sh:14`, no `--release`); several verdicts (ARITHOFL-001 panic-vs-wrap) are profile-sensitive and were judged against the deployed configuration.

## Artifacts
- `findings/*.md` — individual finding files (frontmatter carries `fp_verdict`, `severity`, `merged_into`, `also_known_as`)
- `fp-summary.md` — FP-judge summary
- `dedup-summary.md` — dedup summary
- `REPORT.sarif` — SARIF 2.1.0 machine-readable export of the same findings
