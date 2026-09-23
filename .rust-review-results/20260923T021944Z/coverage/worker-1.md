# Coverage gate — worker-1 (cluster unsafe-boundary)

Phase A note: full unsafe_map built over `crates/` (17 .rs files, all 14 Phase-A rg seeds run, plus a broad `\bunsafe\b` sweep and cross-checked with plain `grep -rn 'unsafe'`). Result: zero `unsafe` blocks, zero `unsafe fn`, zero `unsafe impl`, zero FFI (`extern "C"`), zero `transmute`, zero raw-pointer types/methods/extractions, zero `get_unchecked`/`ptr::*`, zero `#[repr(...)]` (any), zero `debug_assert*`. `[profile.release]` not present in any manifest (no `debug-assertions = true` relevant). Enum inventory (17 enums) cross-checked: all are serde string-renamed/untagged/tagged — deserialization matches declared variants and errors on unknown strings (no integer→discriminant fabrication); no raw-byte enum reads.

| Pass prefix | Bug class            | Outcome                                      |
|-------------|----------------------|----------------------------------------------|
| URAPI       | unsafe-reaching-api  | cleared (no `unsafe` blocks/fns anywhere in crates/ — empty unsafe_map, hence empty URAPI set) |
| TRANS       | transmute-misuse     | cleared (no `transmute`/`transmute_copy` call sites) |
| RAWPTR      | raw-pointer-arith    | cleared (no raw-pointer types, `.add/.offset/.read/.write`, or `ptr::` ops; only hit was ratatui `event::read()`, safe API) |
| PTRCAST     | pointer-cast         | cleared (no `as *const/*mut` casts; all `as usize` hits are plain integer width casts in gk-tui layout math, no pointer side) |
| REPRC       | repr-c-layout        | cleared (no `#[repr(...)]` attributes at all and no FFI/unsafe boundary where a struct layout is observed) |
| ENUMUB      | enum-discriminant    | cleared (17 enums, all serde string-tagged/renamed with checked variant matching; no int→enum transmute, `ptr::read`, or niche raw writes) |
| SAFETYDOC   | safety-doc           | cleared (zero `unsafe { }` blocks and zero `unsafe fn` to document) |
| DEBUGSAFETY | debug-assert-safety  | cleared (no `debug_assert*` occurrences in crates/) |
