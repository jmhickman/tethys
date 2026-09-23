# Coverage gate — worker-6 (cluster recursion-dos-1)

| Pass prefix | Bug class                            | Outcome                                                                                                                                                                                                                                              |
|-------------|--------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| RECURSEDES  | recursive-deserialize-stack-overflow | cleared (no bincode/postcard/custom-codec sites; all untrusted deserializes are serde_json with derived Deserialize and the default 128-frame cap intact — `unbounded_depth` absent from Cargo.lock/`cargo tree -e features`, no `disable_recursion_limit`/`serde_stacker`; toml site is root-owned config) |

## Evidence (seeds run)

- Phase A recursive-type seeds (`Box<Self>`, `Vec<Self>`, `Option<Box<Self>>`, `Rc/Arc<Self…>`, `HashMap<_, Self>`) over `crates/`: **empty** — no crate-local recursive types. Library recursive types present: `serde_json::Value` (`RpcRequest.params` / `RpcResponse.result` at `crates/core/src/protocol.rs:17,27`; `crates/core/src/nft.rs` parse sinks; `crates/gk-tui/src/conn.rs:94`).
- Phase B deserialize seeds (`from_str|from_slice|from_reader|from_value|Deserializer|deserialize`): all sites enumerated —
  - untrusted: `crates/gatekeeper/src/server.rs:265` (mcp.sock → `RpcRequest`, contains `Value`) and gk-mcp stdio via rmcp (`crates/gk-mcp/src/main.rs:87,100,153`) — serde_json default cap applies (FP-reject rule: derived Deserialize, no `disable_recursion_limit()`).
  - trusted: admin.sock (`admin.rs:43,65`, root-only 0600), daemon→TUI events (`gk-tui/src/app.rs:216-385`), nft output (`nft.rs:470`), DB-sourced `Vec<String>` (`install.rs:160`, `server.rs:208` — non-recursive target), root-owned config toml (`main.rs:91`, non-recursive target, toml_edit ~80 cap regardless).
  - `from_value` sites walk Values already bounded at ≤128 by their originating parse; the sole custom helper `de_grant_id` (`protocol.rs:108`) recurses through the normal serde API (still capped) and sits on trusted admin.sock.
- Gate-3 knob seeds (`disable_recursion_limit|without_recursion_limit|serde_stacker|unbounded_depth`) over crates/ + Cargo.toml: **empty**. Lock/tree check: `cargo tree -e features -i serde_json` shows only `default`/`std`/`alloc`; grep for `unbounded_depth` in resolved feature graph: 0 hits.
- Other-codec seeds (`bincode|postcard|ciborium|ron|serde_yaml|prost|rmp`) over crates/ + Cargo.toml: **empty**.
