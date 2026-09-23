# Coverage gate — worker-15 (cluster resource-handling)

| Pass prefix | Bug class         | Outcome                                                                                      |
|-------------|-------------------|----------------------------------------------------------------------------------------------|
| RAWFD       | raw-fd-lifecycle  | cleared (no `from_raw_fd`/`into_raw_fd`/`as_raw_fd`/`RawFd`/`OwnedFd`/`libc::close/dup/open/pipe/socket` sites — all fd owners are RAII `UnixStream`/`File`/`Connection`) |
| DROPSKIP    | destructor-skip   | cleared (no `mem::forget`/`ManuallyDrop`/`process::exit`/`libc::exit`; no `impl Drop` in crates/ — only test-only `actor.abort()` in ledger.rs tests) |
