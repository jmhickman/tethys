# Coverage gate — worker-2 (cluster concurrency-locking)

| Pass prefix | Bug class            | Outcome                                                        |
|-------------|----------------------|----------------------------------------------------------------|
| DLOCK       | double-lock-deadlock | cleared (all 7 `st.pending.lock()` sites audited: no nested/re-acquire of the same tokio Mutex within a live guard scope — admin.rs:78/92/246/279 statement-scoped temporaries, admin.rs:135 guard held only over `contains_key`, server.rs:400 single insert) |
| ABBA        | abba-deadlock        | cleared (codebase has exactly one mutex + one actor mailbox; lock-order graph has no edges between two locks, hence no cycles) |
| CONDVAR     | condvar-misuse       | cleared (`rg '\bCondvar\b'` over crates/ returned zero matches) |
| CHANSTARVE  | channel-starvation   | filed: CHANSTARVE-001                                          |
| ONCEREENTRY | once-reentrancy      | cleared (`rg 'call_once\|get_or_init\|OnceLock\|OnceCell\|LazyLock'` over crates/ returned zero matches) |
| REENTRANT   | reentrancy-unsafe    | cleared (no `sigaction`/`libc::signal`/`signal_hook`/`nix::sys::signal` handlers registered anywhere in crates/; no lock held across user-callback/dyn-dispatch invocation — audited every `.lock()` site and `Ledger::ask` closure) |
