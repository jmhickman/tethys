# Coverage gate — worker-7 (cluster recursion-dos-2)

| Pass prefix | Bug class                        | Outcome |
|-------------|----------------------------------|---------|
| RECURSEFMT  | recursive-format-stack-overflow  | cleared (no unbounded-depth Value reaches a format/Serialize sink: all deserialize sites are default serde_json `from_str`/`from_value` — no `from_reader`, `disable_recursion_limit()`, `serde_stacker`, or bincode/postcard — so every `serde_json::Value` is ≤128 deep; zero `{:?}`/`{:#?}` format sites in crates/, only `tracing` `?`-fields are `Option<i64>`/`Option<u32>`; no crate-local recursive types per Phase-A seeds) |

## Notes (evidence for the clear)

Phase A — recursive-type map:
- Seeds `Box<\s*Self\s*>|Vec<\s*Self\s*>|Option<\s*Box<\s*Self`, `(Rc|Arc)<\s*(Self|...)`, `HashMap<[^,>]+,\s*(Self|Box<\s*Self)` over `crates/`: all empty. No crate-local recursive enum/struct (no Value/Node/Expr/AST shapes).
- Library recursive types present: `serde_json::Value` in `RpcRequest.params` / `RpcResponse.result` (crates/core/src/protocol.rs), `GrantRequest.dst_port` (crates/gk-mcp/src/main.rs:44), nft list/poll values (crates/core/src/nft.rs).
- Only hand-written Display impl in scope: `Proto` (crates/core/src/types.rs:46) — non-recursive, flat.

Phase B — untrusted sources landing in rec_map types:
- `mcp.sock`: `serde_json::from_str::<RpcRequest>` at crates/gatekeeper/src/server.rs:265 (attacker-framed NDJSON; params is `Option<Value>`).
- gk-mcp stdio (agent harness): rmcp `Parameters<GrantRequest>`, `dst_port: serde_json::Value` at crates/gk-mcp/src/main.rs:44; re-wrapped via `json!({...})` and re-parsed with `from_value` at main.rs:77–88.
- `admin.sock`: `from_str::<RpcRequest>` (crates/gatekeeper/src/admin.rs:43) — root-only 0600, trusted side.
- nft JSON: `serde_json::from_str` of `nft --json` stdout at crates/core/src/nft.rs:470 — produced by the root-run `nft` binary (trusted, shallow output).
- Ledger `dst_json`: `from_str::<Vec<String>>` at crates/gatekeeper/src/install.rs:160 — flat array written by the daemon itself from `Vec<ElemDst>` (server.rs:438).

Phase C RECURSEFMT — sinks checked and why each is bounded:
- All decode sites use default serde_json recursion cap (128): grep for `disable_recursion_limit|stacker|without_recursion` in crates/ → none; no `from_reader`; no bincode/postcard/serde_yaml/toml-value on the attacker path (`toml::from_str` at config.rs/main.rs:91 parses root-owned config into a flat `FileConfig`).
- Format sinks: zero `{:?}` / `{:#?}` occurrences in crates/ (only `format!("{eff:?}")`-style Debug of flat typed structs — see server.rs:453 audit of `EffectiveGrant`, non-recursive). `tracing` value-recordings use `%e`/`%s` on Display-bounded strings or `?` on `Option<i64>`/`Option<u32>` (ledger.rs:120,130; server.rs:241).
- Serialize sinks: `serde_json::to_string`/`to_value` on `RpcResponse`/events (server.rs:643–680, admin.rs, gk-tui conn.rs:137) re-emit Values that entered through capped default serde_json parses; depth ≤ ~130 after the `json!` wrapper — orders of magnitude below overflow (~10^4–10^5 frames needed). Per finder guidance, default-capped serde_json values are explicitly not a RECURSEFMT candidate.
- gk-mcp `render_verdict` (main.rs:152) consumes `from_str`-capped Values; formats only typed `Verdict` fields (Strings/PortSpec), never raw deep Value Debug.

Conclusion: no recursive value with attacker-controlled unbounded depth reaches a format/Serialize/log sink. RECURSEFMT cleared, 0 findings.
