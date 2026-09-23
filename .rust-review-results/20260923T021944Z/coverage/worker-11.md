# Coverage gate — worker-11 (cluster logic-correctness-1)

| Pass prefix | Bug class                  | Outcome |
|-------------|----------------------------|---------|
| ORDEQHASH   | ord-eq-hash                | cleared (seed `impl … (Ord\|PartialOrd\|Eq\|PartialEq\|Hash) … for` returned zero hits — all trait impls are `#[derive]`, incl. hand-checked `GrantState::ALL` spelling table pinned by test in crates/core/src/wire.rs) |
| FLOATEDGE   | float-edge                 | cleared (seed `\b(f32\|f64)\b` inspected: all f64 sites are daemon-produced `expires_at`/`now_secs()` timestamps — authz comparisons `e > now` / `e <= now` at reconcile.rs:34, server.rs:140 and DB filter ledger.rs:320 take NaN→false which is fail-closed; casts are `secs.max(0.0) as i64` (server.rs:635) and `(e as u64)` saturating (server.rs:215); no attacker-controlled float enters a length/index/authz site — wire TTL path is integer `parse_ttl`) |
| STRCMP      | string-comparison          | filed: STRCMP-001 |
| SERFIELDS   | serialize-struct-mismatch  | cleared (seed `serialize_(struct\|tuple\|seq\|map)\(` returned zero hits; `rg "impl Serialize"` shows only generic bounds `impl Serialize`, no manual serializer impls — all serde is derived) |
