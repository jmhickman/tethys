# Coverage gate — worker-4 (cluster panic-dos-1)

| Pass prefix | Bug class            | Outcome                                                                                                                                                          |
|-------------|----------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| RESEXHAUST  | resource-exhaustion  | filed: RESEXHAUST-001, RESEXHAUST-002, RESEXHAUST-003                                                                                                             |
| UNWRAP      | unwrap-on-untrusted  | filed: UNWRAP-001                                                                                                                                                 |
| ARITHOFL    | arithmetic-overflow  | filed: ARITHOFL-001 (Phase A: `overflow-checks =` unset in workspace; deploy builds debug profile via `cargo build --workspace -q`; no attacker-reachable `/` or `%` by zero — all divisors are constants or `.max(1)`-clamped)  |
| ASSERTREACH | assertion-reachable  | cleared (only non-test panic macro is `unreachable!()` at server.rs:575, statically dominated by the `given != 1` cardinality check above it; every other `assert!/unwrap` site lies inside `#[cfg(test)]` modules — verified per-file) |
