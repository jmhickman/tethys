# Coverage gate — worker-5 (cluster panic-dos-2)

| Pass prefix    | Bug class             | Outcome                                                        |
|----------------|-----------------------|----------------------------------------------------------------|
| OOBIDX         | out-of-bounds-index   | filed: OOBIDX-001                                              |
| STRSLICE       | str-slice-boundary    | cleared (only `&s[..s.len()-1]` in `parse_ttl`, cut before a matched ASCII `s`/`m`/`h` byte — always a char boundary; no `split_at`/`String::truncate` in crates) |
| REFCELLPANIC   | refcell-borrow-panic  | cleared (no `RefCell`/`borrow_mut` anywhere in crates; the two `.borrow()` sites are tokio `watch::Receiver::borrow` in gk-tui, which cannot conflict) |
