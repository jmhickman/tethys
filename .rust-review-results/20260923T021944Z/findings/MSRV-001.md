---
id: MSRV-001
bug_class: msrv-mismatch
title: No rust-version (MSRV) declared in workspace or any member manifest, and no rust-toolchain.toml
location: crates/gatekeeper/Cargo.toml:3
function: (file-level)
confidence: High
worker: worker-14
fp_verdict: TRUE_POSITIVE
fp_rationale: "Verified no rust-version in workspace or member manifests and no rust-toolchain.toml, while let-else (>=1.65) is used pervasively — a valid build-hygiene hardening gap, always in scope at LOW"
severity: LOW
attack_vector: Local
exploitability: Theoretical
severity_rationale: "Build-reproducibility/toolchain-drift gap on a root daemon; no runtime data flow, nothing attacker-triggerable"
---

## Description
Gate 1 of the MSRV finder fires directly: no `rust-version` field exists in `[workspace.package]` or in any member manifest (`rg -n "rust-version|\[lints" crates/*/Cargo.toml Cargo.toml` → empty), and there is no `rust-toolchain.toml` pinning the build. The code already depends on post-1.65 language features — pervasive `let ... else` (stabilized in Rust 1.65) in e.g. `crates/gatekeeper/src/ledger.rs:119`, `crates/core/src/nft.rs:559-586`, `crates/gk-tui/src/ui.rs:185,434` — but the minimum is nowhere declared or enforced.

Consequences for a root-run security daemon: (a) builds on an older distro toolchain fail with confusing feature errors rather than cargo's clear "requires rustc X" message; (b) dependency resolution cannot use MSRV-aware version picking, so `Cargo.lock` drift can silently pull in crates that require a newer compiler or drop patches; (c) with no CI at all (`no .github/workflows`), nothing pins the compiler used to build the deployed binary, so security-relevant codegen/std fixes vary per build host.

## Code
```toml
# Cargo.toml [workspace.package] — rust-version absent:
[workspace.package]
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
```
```rust
// crates/gatekeeper/src/ledger.rs:119 — requires rustc >= 1.65 (let-else)
let Some(state) = GrantState::parse(&state_raw) else {
```

## Data flow
N/A — file-level finding (no attacker-controlled data flow)

## Reachability trace
N/A — file-level finding (no attacker-controlled data flow)

## Impact
Unpinned, undeclared minimum toolchain for a root-privileged daemon: non-reproducible builds, no MSRV-aware dependency resolution, and silent build breakage or drift across deploy hosts. Hygiene/portability gap; no direct remote exploit.

## Mitigations checked
- `rust-version` in workspace or member manifests: absent (all four crates + workspace).
- `rust-toolchain.toml`: absent (repo-wide find returned nothing).
- CI pinning a toolchain (`cargo +<msrv> check`): no CI workflows exist.

## Recommendation
Add `rust-version = "1.85"` (or the chosen floor ≥ 1.65 for let-else, and high enough for the resolved dependency graph in `Cargo.lock`) to `[workspace.package]` so all members inherit it, and pin CI with `cargo +<msrv> check --workspace`.
