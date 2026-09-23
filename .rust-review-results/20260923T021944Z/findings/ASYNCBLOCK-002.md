---
id: ASYNCBLOCK-002
bug_class: async-blocking
title: TUI render path does synchronous /proc reads inside the tokio main task every 500 ms tick
location: crates/gk-tui/src/ui.rs:693
function: hostname
confidence: Medium
worker: worker-13
fp_verdict: TRUE_POSITIVE
fp_rationale: "Synchronous /proc reads inside the gk-tui async draw path verified (ui.rs:693/703, no caching); attacker can amplify draw frequency via daemon-event flood, but blast radius is the approver TUI process only"
severity: LOW
attack_vector: Local
exploitability: Difficult
severity_rationale: "Privilege-boundary crossing with minimal impact: approver-visible UI lag only; root daemon unaffected and per-read cost is microseconds"
---

## Description
`gk-tui`'s main loop (`crates/gk-tui/src/main.rs:73`, a `tokio::select!` on the `#[tokio::main]` runtime) calls `terminal.draw(|f| ui::draw(...))` from inside its async branches. `ui::draw` → `draw_header` (ui.rs:52-53) synchronously reads two `/proc` files via `std::fs::read_to_string` — `/proc/sys/kernel/hostname` in `hostname()` and `/proc/net/route` in `primary_network()` (ui.rs:703) — on every draw. Draws happen at least every 500 ms from the tick branch, plus once per inbound daemon event and once per keypress. These are blocking `std::fs` calls executed directly on the async runtime's task (no `spawn_blocking`, no caching); while they run, the select loop cannot poll its other branches, so keystroke delivery and daemon-event processing are stalled inside the same single-threaded UI task that processes approvals.

## Code
```rust
// crates/gk-tui/src/ui.rs:692
fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")   // blocking read on the runtime task
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".into())
}

// crates/gk-tui/src/main.rs:73-96 (async run() loop)
tokio::select! {
    _ = tick.tick() => {
        ...
        terminal.draw(|f| ui::draw(f, &app, st))?;   // -> draw_header -> hostname() + primary_network()
    }
    ...
}
```

## Data flow
- **Source:** daemon event volume on `admin.sock` (each inbound line triggers an extra `terminal.draw`), plus the fixed 500 ms tick
- **Sink:** `std::fs::read_to_string` at `crates/gk-tui/src/ui.rs:693` (and ui.rs:703) executed inside the async select loop
- **Validation:** none — results are not cached; the files are re-read on every draw

## Reachability trace
`main → run() → tokio::select!{ tick | ev_rx | key_rx } → terminal.draw → ui::draw → draw_header → hostname()/primary_network() → std::fs::read_to_string`

## Impact
Blocking file I/O on the runtime thread of the approver UI: under a flood of daemon events (an unprivileged agent can drive `EV_REQUEST_NEW`/`EV_DECIDED` volume via `mcp.sock`), every event forces a draw, and each draw performs two synchronous `/proc` reads on the task that also must deliver keystrokes and approval commands. Individually cheap; collectively this is UI-latency amplification in the human approval path (approver-visible lag while the agent keeps firing requests). Confidence is Medium because per-read cost is small — the defect class (blocking std::fs inside an async task) unambiguously holds, severity is for the judge.

## Mitigations checked
- `spawn_blocking` / `block_in_place`: absent in `crates/gk-tui` (rg-verified).
- Caching of hostname/network info: none — recomputed per draw.
- `tokio::fs`: not used anywhere in gk-tui.
- Single-thread impact bounded to the TUI process (not the root daemon), which limits blast radius.

## Recommendation
Compute `hostname()` and `primary_network()` once at startup (or cache with a long TTL in `App`), or move them behind `tokio::task::spawn_blocking`. Both values are effectively static for the life of the session.
