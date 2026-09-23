---
id: ATOMICRACE-002
bug_class: atomic-race
title: per-connection inflight counter leak wedges handle_mcp in an endless drain loop when a dispatch task panics
location: crates/gatekeeper/src/server.rs:281
function: handle_mcp
confidence: Medium
worker: worker-3
fp_verdict: TRUE_POSITIVE
fp_rationale: "fetch_sub only inside the respond closure confirmed at server.rs:281-294; any pre-respond panic in dispatch_access wedges the EOF drain loop forever — and ARITHOFL-001's ttl-overflow panic is a concrete attacker-triggered source in the deployed debug build"
severity: MEDIUM
attack_vector: Local
exploitability: Difficult
severity_rationale: "One permanently spinning task + socket hold per triggered connection, repeatable at attacker connection rate (local resource DoS on root daemon); requires a panic per connection rather than a single frame, hence Difficult"
---

## Description
`handle_mcp` tracks in-flight approval requests with a per-connection
`Arc<AtomicUsize>`: `fetch_add(1)` at line 281 before spawning the
`dispatch_access` task, and the matching `done.fetch_sub(1)` at line 286 only
*inside* the `respond` callback. After client EOF, the connection task spins
`while inflight.load() > 0 { sleep(50ms) }` (lines 292-294) before awaiting the
writer.

If the spawned `dispatch_access` task panics at any await point **before**
invoking `respond`, the unwind drops the task's captured future — including the
`done` (`Arc` clone) and `tx` clones held in the closure — but never executes
`fetch_sub`. The counter is stuck > 0 forever, so the drain loop at line 292
never terminates: the `handle_mcp` task leaks permanently, holding `Arc<State>`,
the read half of the socket, and spinning every 50 ms. This is a safe-code
resource DoS reachable per connection by the unprivileged agent uid.

Panic sources on the dispatch path are real: every ledger operation goes
through `Ledger::ask` (`crates/gatekeeper/src/ledger.rs:361`,
`rx.await.expect("ledger actor died")`), and `install_grant`/`rebuild_acct`
(`server.rs:426-451`) await through code with `expect`/indexing paths; any
panic there unwinds past `respond`. Note the increment ordering itself is
correct (add happens synchronously before `tokio::spawn` inside
`dispatch_access`, so no lost-increment race) — the flaw is exclusively the
unguarded decrement.

## Code
```rust
let inflight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
// ...
inflight.fetch_add(1, Ordering::SeqCst);                    // line 281
let tx = resp_tx.clone();
let done = inflight.clone();
dispatch_access(req, st.clone(), move |s: String| {
    tx.send(s).ok();
    done.fetch_sub(1, Ordering::SeqCst);                    // line 286 — only on the respond path
});
// ...
drop(resp_tx);
while inflight.load(Ordering::SeqCst) > 0 {                 // line 292 — wedges if sub skipped
    tokio::time::sleep(Duration::from_millis(50)).await;
}
let _ = writer.await;
```

## Data flow
- **Source:** attacker-controlled `access.request` line on `mcp.sock` (agent uid) that spawns a dispatch task which then panics (e.g. ledger actor death via `ask().expect`, panic inside `install_grant` path).
- **Sink:** `while inflight.load() > 0` drain loop at `crates/gatekeeper/src/server.rs:292` never observes zero; task never exits.
- **Validation:** none — no timeout or bound on the drain loop, no RAII decrement.

## Reachability trace
`mcp.accept()` (`server.rs:120`) → `tokio::spawn(handle_mcp)` → EOF after in-flight request → `dispatch_access` task panics before `respond` → `fetch_sub` skipped → drain loop spins forever.

## Impact
Per-occurrence permanent task + memory leak (Arc<State>, socket halves, channel senders) plus a perpetual 50 ms poll; an agent uid that can repeatedly trigger the panic condition can accumulate wedged connection tasks and degrade the daemon. No grant-scope or approval bypass — enforcement state is unaffected.

## Mitigations checked
- `tokio::spawn` isolates the panic (daemon survives), which is exactly why the leak persists rather than crashing loudly.
- Writer-side ordering is sound: buffered `tx.send` lines are still drained after senders drop, so no response loss — only the counter is broken.
- No `JoinHandle` error check on the dispatch task's completion that could recover the count (`dispatch_access` discards its handle at `server.rs:302`).
- Ordering `SeqCst` everywhere; not a memory-ordering bug.

## Recommendation
Make the decrement exception-safe: clone `inflight` into a guard whose `Drop` does `fetch_sub(1)` (respond then merely disarms/replaces it), or have `dispatch_access` return its `JoinHandle` and decrement on completion regardless of panic (`handle.await` error branch). Also bound the drain loop with a maximum wait.
