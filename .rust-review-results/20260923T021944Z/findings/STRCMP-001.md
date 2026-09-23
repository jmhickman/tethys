---
id: STRCMP-001
bug_class: string-comparison
title: Grant dedup compares case-sensitive canonical host targets while DNS identity is case-insensitive (config path lowercases, wire path does not)
location: crates/gatekeeper/src/server.rs:340
function: dispatch_access
confidence: High
worker: worker-11
fp_verdict: TRUE_POSITIVE
fp_rationale: "Verified the inconsistency directly: pick_target keeps wire host case verbatim (server.rs:564) while parse_allow lowercases (config.rs:152), and the dedup gate compares canonical strings with case-sensitive `==` (server.rs:340) — DNS identity is case-insensitive, so the agent uid trivially defeats dedup/approval by case-churn"
severity: MEDIUM
attack_vector: Local
exploitability: Reliable
severity_rationale: "Crosses the approval boundary in the attacker's favor: per-case-variant new rows, popups, and independent-TTL kernel elements let an agent re-prompt the human into silently refreshing egress and fragment the ledger invariant — integrity DoS rather than scope escape, so MEDIUM"
---

## Description
The `Target::canonical()` doc comment (crates/core/src/types.rs:104) states it is the
"Stable canonical string used for dedup keys + ledger display". The active-grant dedup in
`dispatch_access` relies on exact case-sensitive string equality of that canonical form.
But host normalization is inconsistent across the two entry paths for the same value class
(hostnames):

- Config `allow` entries: `parse_allow` lowercases hosts via
  `Target::Host(target_s.to_ascii_lowercase())` (crates/gatekeeper/src/config.rs:152).
- Wire access requests: `pick_target` validates the charset but keeps the attacker's case
  verbatim — `return Ok(Target::Host(h.clone()))` (crates/gatekeeper/src/server.rs:564).

DNS hostnames are case-insensitive, so `host:Api.Anthropic.com` and `host:api.anthropic.com`
denote the same endpoint and resolve to the same IPs (`resolve_host` → `lookup_host`), yet
their canonical strings differ under `==`. An attacker (the agent uid, which fully controls
`dst_host` on `mcp.sock`) can trivially vary case to defeat the dedup gate.

## Code
```rust
// crates/gatekeeper/src/server.rs:338-343 — dedup gate (case-sensitive ==)
let active = st.ledger.active().await;
if let Some(g) = active.iter().find(|g| {
    g.target == target.canonical()
        && g.proto == params.proto
        && (g.port_from, g.port_to) == (params.dst_port.from, params.dst_port.to)
}) { ... AlreadyGranted ... }

// crates/gatekeeper/src/server.rs:556-564 — wire host kept verbatim
if let Some(h) = &p.dst_host {
    let ok = !h.is_empty() && h.len() <= 253
        && h.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if !ok { return Err(SpecError::BadHost(h.clone())); }
    return Ok(Target::Host(h.clone()));   // no to_ascii_lowercase()
}

// crates/gatekeeper/src/config.rs:152 — config path normalizes case
Target::Host(target_s.to_ascii_lowercase())
```

## Data flow
- **Source:** `AccessRequestParams.dst_host` in the attacker-framed JSON on `mcp.sock`
  (`handle_mcp` → `dispatch_access`, crates/gatekeeper/src/server.rs:310).
- **Sink:** case-sensitive canonical-string equality `g.target == target.canonical()` at
  crates/gatekeeper/src/server.rs:340 (the dedup/AlreadyGranted gate), and the same canonical
  string written to the ledger at server.rs:376.
- **Validation:** `pick_target` bounds charset/length but performs no case normalization;
  nothing downstream folds case before the `==`.

## Reachability trace
`handle_mcp (SO_PEERCRED ok) → dispatch_access → pick_target (case preserved) → ledger.active() → find(|g| g.target == target.canonical())` — miss → `insert_pending` → approver popup.

## Impact
An agent with one approved grant for `api.anthropic.com:443` re-requests
`API.anthropic.com:443`: dedup misses, a **new** grant row is created and a **new** approval
popup shows a target string that looks different to the human approver while enforcing the
identical IP set. Each case variant gets its own kernel elements with an independent TTL, so
case-churn is a cheap way to (a) multiply overlapping grants for one endpoint, (b) re-prompt
the approver into silently extending/refreshing egress to an already-approved host, and
(c) fragment the ledger/dedup invariant that canonical() is documented to provide. Also
cross-path confusion: a config `allow` host is stored lowercased while the same host arriving
on the wire keeps its case, so the two spellings never match each other's canonical form.

## Mitigations checked
- `pick_target` charset validation rejects `:` and whitespace (no prefix-injection into the
  `host:`/`ip:`/`net:` canonical namespace) — but does nothing about case.
- Idempotency dedup (`idem_key`, server.rs:389) keys on the request id, not the target, so it
  does not catch case variants.
- Enforcement itself is IP-based post-resolution, so this is a dedup/approval-integrity bug,
  not a direct scope escape.
- No `to_lowercase`/`eq_ignore_ascii_case` anywhere on the wire path (checked crates/core +
  crates/gatekeeper).

## Recommendation
Normalize host targets once at ingress: in `pick_target`, return
`Target::Host(h.to_ascii_lowercase())` so `canonical()` is a true identity key on both paths,
matching `parse_allow`'s existing lowercasing. (Existing mixed-case ledger rows can be handled
by a one-time normalization or by comparing case-insensitively during migration.)
