---
id: CARGOLINT-001
bug_class: cargo-lint-config
title: Unsafe-free security crates declare no [lints] — unsafe_code not denied, so future unsafe can land silently in the root daemon
location: crates/gatekeeper/Cargo.toml:1
function: (file-level)
confidence: High
worker: worker-14
fp_verdict: TRUE_POSITIVE
fp_rationale: "No [lints] table, no #![deny/forbid], no CI anywhere (rg-verified); crates are unsafe-free today so deny(unsafe_code) is a free, enforceable invariant — a valid hardening gap, always in scope at LOW"
severity: LOW
attack_vector: Local
exploitability: Theoretical
severity_rationale: "Defense-in-depth: missing lint config on the root-daemon manifests; no data flow, nothing attacker-triggerable — latent gap only"
---

## Description
The workspace and all four member manifests (`core`, `gatekeeper`, `gk-mcp`, `gk-tui`) contain no `[lints]` table, there is no `clippy.toml`, no `.cargo/config.toml` RUSTFLAGS, no CI, and no crate-level `#![deny(...)]`/`#![forbid(...)]` attributes anywhere in `crates/` (verified: `rg '#!\[' crates` → empty; `rg 'rust-version|\[lints' crates/*/Cargo.toml Cargo.toml` → empty).

The gate condition for `unsafe_code` holds: `rg -n unsafe crates` returns **zero matches** — all four crates are currently unsafe-free. `unsafe_code` is allow-by-default, so nothing prevents a future commit from introducing an unchecked `unsafe` block into the root-run daemon (`gatekeeper`) or its wire-parsing core (`gk-core`) without any build-time signal. Given this project's threat model (root daemon parsing attacker-framed JSON from `mcp.sock`), keeping the crates provably unsafe-free is a meaningful, enforceable hardening invariant — today it is only true by accident.

Additionally, no lint is escalated to `deny` at all, so any future `-D warnings`-style regression (e.g. an introduced `unused_must_use` violation on a `Result` from the ledger/nft call path) compiles clean instead of failing the build.

## Code
```toml
# crates/gatekeeper/Cargo.toml — entire file; no [lints] table
[package]
name = "gatekeeper"
version.workspace = true
edition.workspace = true
license.workspace = true
```

## Data flow
N/A — file-level finding (no attacker-controlled data flow)

## Reachability trace
N/A — file-level finding (no attacker-controlled data flow)

## Impact
No compile-time guarantee that the privilege-boundary crates stay unsafe-free; a future `unsafe` block (or a downgraded lint) enters the root daemon's grant/nft path with no review trigger. Hardening gap rather than an active exploit.

## Mitigations checked
- `[lints]` in workspace or member manifests: absent (all four).
- `clippy.toml` / `.cargo/config.toml` RUSTFLAGS: absent.
- Crate attributes `#![deny/forbid(...)]`: absent (`rg '#!\[' crates` empty).
- CI enforcing `-D warnings`: no `.github/workflows` at all.
- `unsafe` present in `crates/`: none — so `deny(unsafe_code)` cannot break the build (gate 1 of the finder satisfied).

## Recommendation
Add to each member manifest (or a shared `[workspace.lints]` referenced via `[lints] workspace = true`):
```toml
[lints.rust]
unsafe_code = "forbid"

[lints.clippy]
all = { level = "warn", priority = -1 }
```
and add CI running `cargo clippy --workspace --all-targets -- -D warnings`.
