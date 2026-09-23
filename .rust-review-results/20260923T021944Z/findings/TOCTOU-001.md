---
id: TOCTOU-001
bug_class: toctou
title: admin.sock is connectable between bind() and the 0600 chmod; handle_admin enforces no uid check, so the window is the only access control
location: crates/gatekeeper/src/server.rs:83
function: run
confidence: Medium
worker: worker-16
fp_verdict: LIKELY_TP
fp_rationale: "Verified bind→chmod gap at server.rs:83-84 (mode = 0777&~umask at bind, 0600 applied after; Unix perms checked only at connect()) and no uid gate in handle_admin (admin.rs:23-25 logs peer_cred only) — a connect won inside the window yields a permanent unauthenticated root-side approver session; under systemd's default UMask=0022 the window is incidentally non-connectable for 'other', so exploitability depends on deployment umask rather than being guaranteed"
severity: HIGH
attack_vector: Local
exploitability: Difficult
severity_rationale: "Full privilege-boundary crossing — forged approvals/revokes/stop.grants as the root daemon's approver (near-privilege-escalation to approval authority) — reduced one level for the race window and the default-umask block; dev/permissive-umask deployments are fully exposed"
---

## Description
The entire privilege boundary of the approval channel rests on `admin.sock` being mode 0600 — but the mode is not established atomically with the socket's creation. `UnixListener::bind()` at server.rs:83 creates the socket inode with permissions `0777 & ~umask`, and only afterwards does server.rs:84 apply `set_permissions(..., 0o600)`. Between those two syscalls the socket is live in the filesystem and accept()-able. Unix socket permissions are checked at `connect()` time only: a client that connects inside the window keeps a fully-functional admin session *forever*, even after the 0600 chmod lands.

Crucially, `handle_admin` (crates/gatekeeper/src/admin.rs:22-25) reads `SO_PEERCRED` purely to log it — there is **no uid gate** on the admin command loop. Whatever connects inside the bind→chmod window may issue `approve`, `deny`, `revoke`, and `stop.grants`. Under the LOCAL_UNPRIVILEGED threat model, an unprivileged local process (the agent) can spin a tight `connect()` loop on `/run/gatekeeper/admin.sock` and win the race whenever the daemon starts or restarts (`Restart=on-failure`, RestartSec=2s — restarts are frequent, and the agent may itself be able to trigger daemon panics via malformed mcp.sock input), crossing the root boundary and forging approvals for its own grants.

Exploitability of the window depends on the daemon's umask at bind time: with systemd's default `UMask=0022` the inode is created 0755, and "other" lacks write permission so `connect()` from an unprivileged uid fails (Linux requires write permission on the socket inode to connect). But nothing in the code enforces that: manual runs, dev mode (`--dry-run`), the e2e scripts, or any supervisor with a permissive umask (0000/0002 is common in shells) make the window world-connectable. The deployment unit even documents the boundary as "admin.sock (0600, root only)" — a property the code does not actually guarantee at creation.

## Code
```rust
// crates/gatekeeper/src/server.rs:79-91
for path in [&st.cfg.mcp_socket, &st.cfg.admin_socket] {
    let _ = std::fs::remove_file(path);
}
let mcp = UnixListener::bind(&st.cfg.mcp_socket)?;
let admin = UnixListener::bind(&st.cfg.admin_socket)?;   // <-- socket live here, mode = 0777 & ~umask
std::fs::set_permissions(&st.cfg.admin_socket, std::fs::Permissions::from_mode(0o600))?; // <-- hardened here
// mcp.sock: reachable only by mcp_user's group ...
if let Some(gid) = st.cfg.mcp_sock_gid {
    use std::os::unix::fs::{chown, PermissionsExt};
    chown(&st.cfg.mcp_socket, None, Some(gid))?;
    std::fs::set_permissions(&st.cfg.mcp_socket, std::fs::Permissions::from_mode(0o660))?;
}
```

```rust
// crates/gatekeeper/src/admin.rs:22-26 — credentials logged, never enforced
pub(crate) async fn handle_admin(stream: UnixStream, st: Arc<State>) {
    if let Some(c) = peer_cred(&stream) {
        tracing::info!(uid = c.uid(), "admin client connected");
    }
    st.admins_online.fetch_add(1, Ordering::SeqCst);
    ...
```

## Data flow
- **Source:** `connect(2)` on `admin.sock` from any local process that can resolve the path during the bind→set_permissions window at daemon startup (unprivileged agent uid).
- **Sink:** admin JSON-RPC command loop in `handle_admin` → `admin_cmd` (`approve` / `deny` / `revoke` / `stop_grants` → ledger `Decide::Approve` + `install_grant` nft element).
- **Validation:** none at accept time — `peer_cred` is logged only (admin.rs:23-25); the 0600 mode that is supposed to be the access control is installed *after* bind returns, and permission checks do not retroactively drop already-established unix connections.

## Reachability trace
`main() → server::run() → UnixListener::bind(admin.sock) [window] → accept loop (server.rs:103-110) → handle_admin → admin_cmd(APPROVE) → ledger.decide(Approve) → install_grant`

## Impact
A local unprivileged process that wins the startup race obtains a persistent root-side approver session: it can approve its own pending egress grants (defeating the human-approval boundary entirely), revoke others', or fire `stop.grants`. The privilege crossing is complete — no further authentication exists on the admin channel. Even where the default systemd umask closes the connect path, the invariant "0600 before anyone can connect" is unenforced and silently breaks under any deployment/dev change of umask.

## Mitigations checked
- `SO_PEERCRED` uid check: present for `mcp.sock` (`handle_mcp`/`peer_cred` gating against `mcp_peer_uid`), **absent** for `admin.sock` — only logged.
- systemd unit (`deploy/gatekeeper.service`): no explicit `UMask=` directive, so the default 022 applies and incidentally makes the window non-connectable for "other" — an accident of deployment config, not a code guarantee; the unit is also documented as substitutable ("any account ... may be substituted", dev runs, e2e scripts).
- `remove_file` before bind (server.rs:79-80): unlink never follows symlinks, so no symlink-swap primitive for the attacker here; and `/run/gatekeeper` is root-owned (context: not attacker-writable), so the attacker cannot pre-create a conflicting inode to force fail-closed EADDRINUSE either.
- `set_permissions` errors are propagated (`?`) — startup aborts on chmod failure, but that does not close the window that already opened at bind.
- No `O_EXCL`-style atomic primitive exists for unix socket creation; the standard fix is a restrictive umask around bind (or fchmod via `sockattach`-style fd handling / `socket()`+bind with pre-set mode).

## Recommendation
Make the mode precede visibility: wrap the two binds with `libc::umask(0o177)` (restore after), or create the socket via `socket(2)` and `fchmod` on the fd semantics available through `socket2` before `bind`. Independently, add defense-in-depth in `handle_admin`: reject any connection whose `peer_cred().uid()` is not 0 (or the configured admin uid) instead of merely logging it — then the chmod window no longer carries the whole boundary.
