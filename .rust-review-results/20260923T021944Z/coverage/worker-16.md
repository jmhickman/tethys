# Coverage gate — worker-16 (cluster input-os-safety)

| Pass prefix | Bug class           | Outcome                                      |
|-------------|---------------------|----------------------------------------------|
| PATHJOIN    | path-traversal-join | cleared (seeds `\.join\(|\.push\(|PathBuf` ran; no attacker-controlled component ever joined into a fs path — joins are string-joins or test-only `temp_dir().join(literal)`; all PathBuf sinks come from root-owned CLI/config) |
| TOCTOU      | toctou              | filed: TOCTOU-001                            |
