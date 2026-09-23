# Coverage gate — worker-14 (cluster static-hygiene)

| Pass prefix | Bug class         | Outcome                                                                                                              |
|-------------|-------------------|----------------------------------------------------------------------------------------------------------------------|
| CARGOLINT   | cargo-lint-config | filed: CARGOLINT-001                                                                                                 |
| MSRV        | msrv-mismatch     | filed: MSRV-001                                                                                                      |
| DEPRECAPI   | deprecated-api    | cleared (no `mem::uninitialized` / `intrinsics` / `core_intrinsics` hits; fresh `cargo check` + `cargo clippy --workspace --all-targets` emitted zero deprecation warnings) |
