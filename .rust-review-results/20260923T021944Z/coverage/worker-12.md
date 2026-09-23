# Coverage gate — worker-12 (cluster logic-correctness-2)

| Pass prefix | Bug class               | Outcome |
|-------------|-------------------------|---------|
| NONDET      | nondeterminism          | cleared (`HashMap`/`HashSet` sites enumerated via `rg '\bHashMap\b\|\bHashSet\b'` — server.rs:41 pending-map, nft.rs:428/640 counters-map, install.rs:90 seen-set, reconcile.rs:25/32 gid-sets; every site is `.get()`/`.contains()`/dedup-insert or an order-independent per-key sweep (admin.rs:246), no map iteration feeds a hash/signature/canonical-serialization/replicated-state consumer; `resolve_host` sorts+dedups IPs before batch/`dsts[0]` use; serde_json has no `preserve_order`, floats serialized only via fixed-precision RFC3339 strings) |
| KEYMUT      | collection-key-mutation | cleared (seed `peek_mut\|RefCell\|Cell\|BinaryHeap\|mem::forget\|ManuallyDrop` returned zero matches in crates/; all stored keys are `Copy` primitives or immutable `String`/tuple keys with no interior mutability and no `&mut`-to-stored-key path) |
