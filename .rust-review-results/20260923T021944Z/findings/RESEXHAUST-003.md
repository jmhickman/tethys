---
id: RESEXHAUST-003
bug_class: resource-exhaustion
title: Unbounded NDJSON line length on mcp.sock — one unterminated line grows daemon RAM without limit
location: crates/gatekeeper/src/server.rs:259
function: handle_mcp
confidence: High
worker: worker-4
fp_verdict: TRUE_POSITIVE
fp_rationale: "Verified `BufReader::new(r).lines()` at server.rs:259 with no max-line cap and no read/idle timeout — tokio `Lines` accumulates unbounded bytes per connection before any protocol validation; `sanitize()` runs only after the full line is buffered and parsed, and admin.sock's same pattern is correctly out of model (0600 root-only)"
severity: MEDIUM
attack_vector: Local
exploitability: Reliable
severity_rationale: "A few newline-free streams make the root daemon allocate linearly in attacker-written bytes (OOM pressure on the whole host) — deterministic local memory DoS reachable with the first byte on the socket"
---

## Description
The MCP connection loop reads requests with `BufReader::lines()`. tokio's `AsyncBufReadExt::lines`
accumulates bytes into a single `String` until it sees `\n` (or EOF) with **no maximum line length**
(it errors only past `usize::MAX`). An attacker who connects to `mcp.sock` (0660, group of the agent
gid — the agent uid itself is always allowed) and streams bytes without ever sending a newline
forces the root daemon to buffer the entire stream in RAM, one `String` per connection. There is no
read timeout either: the loop awaits `lines.next_line()` indefinitely, so slow-loris style trickle
connections are held open forever, each with its reader task, writer task, and (growing) line
buffer. The parsed JSON has no size cap upstream (`serde_json::from_str` runs on whatever arrives).

## Code
```rust
// crates/gatekeeper/src/server.rs:259-265
let mut lines = BufReader::new(r).lines();      // no line-length limit, no read timeout
while let Ok(Some(line)) = lines.next_line().await {
    let line = line.trim();
    if line.is_empty() { continue; }
    let req: RpcRequest = match serde_json::from_str(line) { ... };
```

## Data flow
- **Source:** raw bytes written to `mcp.sock` by the agent uid (`crates/gatekeeper/src/server.rs:260`)
- **Sink:** tokio `Lines` internal `String` accumulator (grows per byte until `\n`), then `serde_json::from_str` on the whole line (`server.rs:265`)
- **Validation:** none — no `take(MAX_BYTES)`, no read/idle timeout, no message-size framing check. `sanitize()` (280 chars) applies only to two fields *after* the full line is buffered and parsed.

## Reachability trace
`agent process → connect(mcp.sock) → SO_PEERCRED passes (same uid) → handle_mcp → lines.next_line()` — first byte on the socket reaches the unbounded accumulator before any protocol validation.

## Impact
Memory-exhaustion DoS of the root daemon: a handful of connections each streaming hundreds of MB with no newline make the daemon allocate linearly in attacker-written bytes (OOM pressure on the whole host, since this is the enforcement daemon). Combined with RESEXHAUST-001 (no connection cap), N such connections multiply the effect. No panic required; the process thrashes or gets OOM-killed, and egress enforcement state depends on it.

## Mitigations checked
- Socket permissions (0660 + SO_PEERCRED) gate *who*, not volume — the agent uid is the attacker.
- `admin.sock` path (`admin.rs:29`) has the same pattern but is 0600 root-only, outside the threat model.
- No read timeout, no `BufReader` capacity cap, no max-frame constant anywhere in `crates/gatekeeper/src/server.rs`.

## Recommendation
Replace `lines()` with a capped read (e.g. `AsyncBufReadExt::read_until(b'\n', buf)` rejecting `buf.len() > MAX_FRAME`, or an explicit size-limited framing helper), and add an idle-read timeout per connection so stalled senders cannot pin tasks and buffers indefinitely.
