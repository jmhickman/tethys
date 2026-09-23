# Coverage gate — worker-3 (cluster concurrency-data-race)

| Pass prefix    | Bug class           | Outcome                                                                      |
|----------------|---------------------|------------------------------------------------------------------------------|
| ATOMICRACE     | atomic-race         | filed: ATOMICRACE-001, ATOMICRACE-002                                        |
| SENDSYNCBOUND  | send-sync-bounds    | cleared (no `unsafe`/`transmute`/`thread::Builder`/manual `unsafe impl Send/Sync` in crates/ — all spawns are `tokio::spawn`/`std::thread::spawn` which enforce `Send + 'static`) |
| SHMRACE        | shared-memory-race  | cleared (no `MAP_SHARED`/`mmap`/`shm_open`/`memfd_create`/`memmap2` anywhere in crates/ — IPC is Unix-socket message passing only) |
