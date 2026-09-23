---
id: RESEXHAUST-002
bug_class: resource-exhaustion
title: rebuild_acct is O(approved rows) per approve/expire event and spawns an nft subprocess each time — quadratic churn driven by attacker-created grants
location: crates/gatekeeper/src/install.rs:175
function: rebuild_acct
confidence: Medium
worker: worker-4
fp_verdict: TRUE_POSITIVE
fp_rationale: "Verified rebuild_acct (install.rs:175-219) re-lists all approved rows and spawns a fresh nft subprocess on every approve/expiry/revoke/stop, and sweep_grant_objs applies per-object deletes via further nft batches — attacker controls grant count/TTL ('1s' legal), so event volume is attacker-driven; LIMIT 500 bounds one rebuild's scan but not the O(N^2) event/product churn"
severity: MEDIUM
attack_vector: Local
exploitability: Difficult
severity_rationale: "CPU/subprocess-spawn exhaustion of the root daemon, amplified through the shared ledger actor so all connections see latency (local DoS); requires an approving workflow to churn many grants rather than a single frame, hence Difficult"
---

## Description
Every grant approval (`server.rs:449`), every expiry batch (`server.rs:156`), every revoke, and
every `stop.grants` calls `rebuild_acct`, which re-lists **all** approved rows and rebuilds the
entire accounting state from scratch — per row it resolves dsts (possibly DNS) and emits
2 directions × 2 families of counters/sets/elements/rules — then applies one full nft batch via a
fresh `/usr/sbin/nft` subprocess (`run_nft_json`, `crates/core/src/nft.rs:482`). The number of
approved rows is not capped anywhere (no global grant budget), and the attacker (agent uid) fully
controls how many grants exist and when they are created — hence when they expire. Approving N
grants one by one costs O(N) rebuilds × O(N) rows = **O(N²)** batch construction plus N subprocess
spawns; the expiry reconciler adds another full rebuild plus, per expired grant, `sweep_grant_objs`
which spawns **4 more nft subprocesses per grant** (`install.rs:237-248`). With a cooperative
approver (or any workflow that approves many short-TTL grants — `"1s"` is a legal TTL), an agent
turns each approval into a workload proportional to total live grants, and each mass-expiry into
~5 nft processes per grant.

## Code
```rust
// crates/gatekeeper/src/install.rs:175-219
pub(crate) async fn rebuild_acct(st: &Arc<State>) -> Result<(), String> {
    ...
    let rows = st.ledger.list(GrantState::Approved).await;   // ALL approved rows, every call
    let mut b = Batch::with_table(&st.cfg.nft_table);
    b.flush_chain(CHAIN_ACCT_OUT);
    b.flush_chain(CHAIN_ACCT_IN);
    for g in &rows {                                         // O(rows) per event
        let dsts = match row_elems(g).await { ... };         // may DNS-resolve
        for dir in [Dir::Out, Dir::In] { for v6 in [false, true] { ... } }
    }
    st.nft.apply(&b).await.map_err(|e| e.to_string())        // one nft subprocess per call
}
```

## Data flow
- **Source:** number and TTL of `access.request` grants created by the agent uid (mcp.sock), approved by the human or denied at timeout
- **Sink:** full-table accounting rebuild + `Command::new("/usr/sbin/nft")` spawn at `crates/core/src/nft.rs:487`, invoked once per approval/expiry and 4× per expired grant via `sweep_grant_objs`
- **Validation:** none — no cap on concurrent approved grants, no incremental accounting, no debounce/coalescing of rebuilds (`tokio::time::sleep(2)` loop runs a rebuild per expiry batch regardless of size)

## Reachability trace
`access.request → dispatch_access approve arm → install_grant → rebuild_acct (server.rs:449)` and
`spawn_expiry_reconciler → rebuild_acct (server.rs:156) → sweep_grant_objs × N (server.rs:159-161)`

## Impact
CPU/process-spawn exhaustion of the root daemon: with N live grants, each approval burns an O(N)
JSON batch build and a synchronous nft subprocess; mass expiry of N grants burns ~5N subprocesses.
The stats poller and reconciler share the same single-threaded actor (`ledger.ask`), so rebuild
backpressure delays ledger decisions for every other connection — availability loss, no panic.

## Mitigations checked
- `Ledger::list` caps at `LIMIT 500` rows — bounds one rebuild's row scan but not the number of events.
- nft subprocess has a 5 s timeout (`nft.rs:441`) — bounds a stuck child, not spawn volume.
- `dry_run` skips rebuild entirely (dev only).
- No grant-count budget, no rebuild coalescing/debounce found anywhere in `crates/`.

## Recommendation
Coalesce rebuilds (dirty-flag + single debounced task instead of per-event synchronous rebuild),
make accounting incremental (add/delete only the affected grant's chain objects), and cap live
approved grants per uid so O(rows) has a protocol max.
