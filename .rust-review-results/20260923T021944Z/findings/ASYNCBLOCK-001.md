---
id: ASYNCBLOCK-001
bug_class: async-blocking
title: Ledger actor performs synchronous rusqlite disk I/O directly inside a tokio async task (no spawn_blocking)
location: crates/gatekeeper/src/ledger.rs:197
function: open
confidence: High
worker: worker-13
fp_verdict: TRUE_POSITIVE
fp_rationale: "Blocking rusqlite commits run on tokio worker threads; zero spawn_blocking/block_in_place in crates/ (rg-verified) and the actor is fed by an uncapped unbounded channel from the attacker-controlled mcp.sock path"
severity: MEDIUM
attack_vector: Local
exploitability: Difficult
severity_rationale: "Daemon-wide latency/liveness degradation of the root enforcement daemon under attacker flood plus disk pressure (local DoS); stalls are small on fast storage, hence Difficult not Reliable"
---

## Description
The entire grant ledger is a single `tokio::spawn`ed async task whose command loop executes rusqlite (`Connection::execute`, `prepare`, `query_map`) synchronously on a tokio worker thread. rusqlite is pure blocking file I/O: every `INSERT`, `UPDATE`, and `SELECT` — including WAL fsync on commits — parks an async worker thread for the duration of the disk operation. Nothing in `crates/` uses `spawn_blocking` or `block_in_place` (verified: zero matches). Under disk pressure (WAL checkpoint, slow storage, or an attacker spraying ledger writes via `mcp.sock`), these stalls block every other task scheduled on that worker — accept loops, approval handling, the expiry reconciler — because the runtime cannot preempt a blocking syscall. The connection open itself (`Connection::open` + `CREATE TABLE` batch at ledger.rs:171-191, a *sync* fn called from async `server::run()`) also runs schema DDL on the runtime thread at startup.

## Code
```rust
let h = tokio::spawn(async move {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            LedgerCmd::Insert(g, reply) => {
                let res = conn.execute(              // <-- blocking SQLite write (WAL fsync)
                    "INSERT INTO grants(idem_key,target,...) VALUES(...)",
                    params![...],
                );
                ...
            }
            LedgerCmd::Decide(id, d, reply) => {
                let mut stmt = match conn.prepare(&sql) { ... };   // blocking
                let n = match stmt.execute(...) { ... };           // blocking
                ...
            }
            // every other arm: conn.query_map / conn.execute — all synchronous
```

## Data flow
- **Source:** attacker-controlled `access.request` lines on `mcp.sock` (each triggers `insert_pending`, `find_by_idem`, `active()` ledger commands; `handle_mcp` spawns a task per request with no rate limit)
- **Sink:** synchronous `rusqlite::Connection` calls at `crates/gatekeeper/src/ledger.rs:197` (and every other arm of the actor loop, lines 196–352)
- **Validation:** none — unbounded `mpsc::unbounded_channel` feeds the actor; no batching, no `spawn_blocking` offload

## Reachability trace
`handle_mcp → dispatch_access → st.ledger.insert_pending(..) → Ledger::ask → rx.recv() in spawned actor → conn.execute (blocking)`

## Impact
A local unprivileged attacker floods `mcp.sock` with framed requests; each enqueues ledger work on the single actor task, whose synchronous SQLite commits (with WAL fsync) stall a tokio worker thread. With the default multi-thread runtime this degrades into measurable daemon-wide latency (approvals, expiry reaping, admin events delayed); on constrained storage it is a straightforward resource-exhaustion DoS of the enforcement control plane. Not memory-unsafe, but a liveness failure of a security-critical daemon under the LOCAL_UNPRIVILEGED model.

## Mitigations checked
- `spawn_blocking` / `block_in_place`: absent everywhere in `crates/` (rg-verified).
- WAL mode (`journal_mode=WAL`) reduces reader/writer contention but does not make commits non-blocking.
- `busy_timeout`, `synchronous=N`, or checkpoint tuning: not configured.
- No rate limiting between `mcp.sock` ingress and ledger inserts.

## Recommendation
Wrap the actor body's DB work in `tokio::task::spawn_blocking` (move the `Connection` onto a dedicated blocking thread — rusqlite connections are `Send`, so the actor can hold it inside the blocking closure), or run the ledger on its own OS thread with a std `sync_channel`. Alternatively set `PRAGMA synchronous=NORMAL`/`busy_timeout` to bound stalls, but offloading is the correct fix.
