# Coverage gate — worker-10 (cluster error-handling-2)

| Pass prefix | Bug class           | Outcome                                                        |
|-------------|---------------------|----------------------------------------------------------------|
| BUFFLUSH    | bufwriter-unflushed | cleared (no `BufWriter`/`LineWriter`/`BufStream` in crates/ — rg seed empty, rc=1; all write sinks are unbuffered `write_all` with error handling or explicitly flushed) |
