# Coverage gate — worker-17 (cluster info-disclosure)

| Pass prefix | Bug class        | Outcome |
|-------------|------------------|---------|
| PTREXPOSE   | pointer-exposure | cleared (Phase-A seed `\bas\s+usize\b|\{[^{}]*:[^{}]*p\}|\.(addr|expose_provenance|expose_addr)\(\)` run via rg over crates/: only arithmetic `as usize` in gk-tui layout code (main.rs:191, ui.rs:317-800), no pointer-derived addresses; corroborating searches for `{:p}` formats, `.addr()`/`.expose_provenance()`, `*const`/`*mut`/`NonNull`/`ptr::addr`/`Box::into_raw`/`as *const` and any `unsafe` in crates/ returned zero matches — no pointer→integer derivation exists, so Gate 1 cannot hold) |
