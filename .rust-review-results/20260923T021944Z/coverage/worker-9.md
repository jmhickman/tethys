# Coverage gate — worker-9 (cluster error-handling-1)

| Pass prefix | Bug class             | Outcome                                                                    |
|-------------|-----------------------|----------------------------------------------------------------------------|
| RESDISC     | result-discarded      | filed: RESDISC-001, RESDISC-002                                            |
| DROPPANIC   | drop-panic            | cleared (no `impl … Drop for` / `fn drop(` anywhere in crates/)            |
| LOSSYFROM   | lossy-from-into       | filed: LOSSYFROM-001                                                       |
| LOSSYSTR    | lossy-str-conversion  | cleared (`from_utf8_lossy` only at nft.rs:548/551 on nft-subprocess JSON-escaped output, error/display paths — no security decision fed) |

Searches run (ripgrep, whole `crates/` tree):
- `let\s+_\s*=` → 18 hits; each inspected: ledger.rs:347 audit INSERT (filed), ledger.rs:328-333 SetDst `.unwrap_or(0)` error-collapse (filed as RESDISC-002), ledger.rs oneshot `reply.send` ×9 (receiver-gone, caller accepts — FP), server.rs:80 stale-socket unlink (bind surfaces real failure — FP), server.rs:296 `writer.await` (writer logs its own write errors; connection closing — FP), server.rs:668 broadcast send (no-subscribers documented in fn comment — FP), nft.rs:532-537 kill/reap on timeout path (Err(Timeout) propagates to caller — FP), gk-tui/ui.rs:881 test-only.
- `impl\b[^\n]*\bDrop\s+for` → 0 hits; re-checked with `fn drop\(|impl Drop` → 0 hits. DROPPANIC structurally empty.
- `impl From<…> for` / `impl Into<` → only `impl Into<String>` argument-position generics (no conversion narrowing); full `\bas\s+\w` sweep reviewed: ledger.rs:142-150 i64→u16/u64 on row load (filed LOSSYFROM-001 at primary sink :142), nft.rs:615-622 `as_u64().unwrap_or(0) as u16` on kernel-echoed ports bounded by nft's own u16 domain, gk-tui casts display-only, gk-mcp nanos→u64 widening-safe.
- `from_utf8_lossy|to_string_lossy|to_str\(\)\.unwrap_or` → 2 hits (nft.rs:548/551); nft emits JSON with non-ASCII escaped (\uXXXX), comments are machine-generated ASCII `gk:g<gid>`, and the strings land in `NftError::stderr` / parsed-JSON stats paths, not path/allowlist/token decisions. No `to_str().unwrap_or*` or OsStr/args_os/var_os lossy sites in crates/.
- `BufWriter` → 0 hits (BUFFLUSH pass not assigned to this worker; noted for completeness).
