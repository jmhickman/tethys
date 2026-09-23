---
id: ARITHOFL-001
bug_class: arithmetic-overflow
title: Attacker-controlled TTL multiply `n * mult` in parse_ttl overflows — panics on the deployed (debug) build, wraps silently in release
location: crates/core/src/types.rs:127
function: parse_ttl
confidence: High
worker: worker-4
fp_verdict: TRUE_POSITIVE
fp_rationale: "Attacker TTL frame on mcp.sock reaches unchecked `n * mult` on the first request with no approval needed (verified types.rs:127); deployed debug build panics the dispatch task and wedges its drain loop, release silently wraps"
severity: MEDIUM
attack_vector: Local
exploitability: Reliable
severity_rationale: "Unprivileged attacker crashes a root-daemon task and leaks a spinning connection task per request (local DoS of the approval path); tokio per-task catch prevents process abort, so not HIGH"
---

## Description
`parse_ttl` parses the attacker-supplied `ttl_requested` string from `access.request` into a `u64`
with no upper bound and multiplies by the unit multiplier (3600 for `h`) with plain `*`. No
`overflow-checks =` is set anywhere in the workspace (`Cargo.toml` defines only `[profile.dev]
debug = 0`), so:

- **Debug/dev profile (overflow-checks=true, and this is what the deploy script builds —
  `deploy/enforcement_e2e.sh:14` runs `cargo build --workspace -q` with no `--release`):** the
  multiply **panics** ("attempt to multiply with overflow") for any `n > u64::MAX/3600`
  (e.g. `ttl_requested: "9999999999999999999h"`). Verified with a standalone rustc probe: debug
  build panics, `-O` build wraps.
- **Release profile:** silent wrap — the requested TTL becomes an arbitrary value mod 2^64 with no
  error (a *release-silent wrap*, not a panic), corrupting the grant duration semantics.

The panic fires inside the `dispatch_access` spawned task (`server.rs:302`, after `parse_ttl` at
`server.rs:329`). tokio catches the unwind per-task, so the daemon process survives, but:
1. the client's request is never answered (gk-mcp hangs its full 6-minute read timeout), and
2. `done.fetch_sub(1)` runs only inside the `respond` closure — a panic before `respond` leaves the
   per-connection `inflight` counter permanently > 0, so `handle_mcp`'s EOF drain loop
   (`while inflight.load() > 0 { sleep }`, `server.rs:292-294`) spins forever and leaks its task on
   every connection that saw such a request.

## Code
```rust
// crates/core/src/types.rs:115-128
pub fn parse_ttl(s: &str) -> Result<Duration, SpecError> {
    let s = s.trim();
    let (num, mult) = match s.as_bytes().last().copied() {
        Some(b's') => (&s[..s.len() - 1], 1u64),
        Some(b'm') => (&s[..s.len() - 1], 60),
        Some(b'h') => (&s[..s.len() - 1], 3600),
        _ => return Err(SpecError::BadTtl(s.to_string())),
    };
    let n: u64 = num.parse().map_err(|_| SpecError::BadTtl(s.to_string()))?;
    if n == 0 {
        return Err(SpecError::BadTtl(s.to_string()));
    }
    Ok(Duration::from_secs(n * mult))   // <-- unchecked multiply on untrusted n
}
```

## Data flow
- **Source:** `ttl_requested: String` in `AccessRequestParams`, deserialized from attacker-framed JSON on `mcp.sock` (`crates/core/src/protocol.rs:171`)
- **Sink:** `n * mult` at `crates/core/src/types.rs:127`
- **Validation:** only `n != 0` and digit parseability; no upper bound before the multiply. The later `cap_ttl` clamp (`server.rs:578`) runs *after* this function returns, so it cannot prevent the overflow/panic.

## Reachability trace
`agent → gk-mcp request_traffic_grant (or raw mcp.sock frame) → handle_mcp → dispatch_access → parse_ttl(&params.ttl_requested) → n * mult` — first frame on the socket reaches it; no approval needed to trigger.

## Impact
Under the deployed debug build: per-request task panic — unanswered requests, leaked spinning `handle_mcp` tasks per connection (slow task leak DoS), and a wedged MCP tool call for 6 minutes each. Under a release build: silent TTL wrap — an attacker can make a requested "forever" TTL land on any wrapped value (in the fail-closed direction, since `cap_ttl` still clamps the top, but the granted duration no longer means what was approved/displayed; `ttl_granted` shown to the human approver is re-derived from the wrapped value).

## Mitigations checked
- `overflow-checks`: unset in workspace → true in dev (deploy build → panic), false in release (silent wrap).
- `cap_ttl` (`server.rs:578`): clamps after parse — does not gate the multiply.
- No `checked_mul` anywhere near this path; negative TTL impossible (parsed as `u64`).
- tokio per-task catch: keeps the process alive but converts the panic into a hung request + leaked drain loop, so "the daemon survives" is not a mitigation for availability of the request path.

## Recommendation
Use `n.checked_mul(mult).ok_or(SpecError::BadTtl(s.to_string()))?` (and consider rejecting TTLs beyond a sanity bound before the multiply), plus an explicit `[profile.release] overflow-checks = true` so release binaries match dev semantics on this attacker-facing parser.
