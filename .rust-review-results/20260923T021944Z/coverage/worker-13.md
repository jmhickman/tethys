# Coverage gate — worker-13 (cluster async-runtime)

| Pass prefix   | Bug class      | Outcome                                                                                                                                     |
|---------------|----------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| ASYNCBLOCK    | async-blocking | filed: ASYNCBLOCK-001, ASYNCBLOCK-002                                                                                                       |
| CANCELSAFETY  | cancel-safety  | filed: CANCELSAFETY-001                                                                                                                     |
| SELECTBIAS    | select-bias    | cleared (all 3 `tokio::select!` sites inspected: conn.rs:81 uses `biased;` with priority branch first; admin.rs:31 / gk-tui main.rs:73 have no cancel-vs-work branch needing deterministic order; `broadcast::recv` and `Lines::next_line` verified cancel-safe in tokio 1.53.1 source) |
