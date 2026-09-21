# Deploying gatekeeper

Three binaries, one daemon:

| binary        | runs as            | role                                        |
|---------------|--------------------|---------------------------------------------|
| `gatekeeper`  | root (systemd)     | grant ledger + nftables enforcer            |
| `gk-tui`, `scopeadm` | root / sudo | human approver — needs `admin.sock` (0600) |
| `gk-mcp`      | harness user       | MCP server, spawned by the agent harness    |

## Threat model in one paragraph

Approval authority lives on `admin.sock`, which the daemon creates 0600 —
only the account running gatekeeper (root here) can connect. Everything the
agent side can do is *submit* a grant request over `mcp.sock`, which a human
must approve. The agent user being unable to read/write `admin.sock` is the
boundary. `mcp_user` (below) is NOT a security boundary against the agent —
in the stdio topology below it is the same uid as the agent itself; treat it
as deployment plumbing, not identity proofing.

## Production topology (unprivileged harness)

The agent harness runs as an unprivileged user (example: `hermes-agent`) and
spawns gk-mcp itself as a stdio MCP child process. gk-mcp then dials
`mcp.sock`. There is no separate service user, and nothing to install for
gk-mcp beyond the binary.

1. **Users.** One unprivileged harness user is enough:

   ```
   useradd --system --create-home --shell /usr/sbin/nologin hermes-agent
   ```

2. **`/etc/gatekeeper/config.toml`** — start from `config.example.toml` and
   set BOTH identity knobs to the harness user:

   ```toml
   agent_user = "hermes-agent"   # baseline egress block applies to this uid
   mcp_user   = "hermes-agent"   # SO_PEERCRED gate + mcp.sock group ownership
   ```

   This is the step people miss: gk-mcp runs as a child of the harness, so if
   `mcp_user` names some other account every `tools/call` dies with
   `mcp peer rejected by SO_PEERCRED` in the journal (initialize and
   tools/list still succeed — they never touch the daemon).

3. **Enable the enforcement units only:**

   ```
   install -m 0644 deploy/gatekeeper-baseline.service deploy/gatekeeper.service /etc/systemd/system/
   install -m 0644 deploy/gatekeeper-baseline.nft /etc/gatekeeper/baseline.nft
   systemctl daemon-reload
   systemctl enable --now gatekeeper-baseline.service gatekeeper.service
   ```

   Do NOT enable `gk-mcp.socket` / `gk-mcp@.service` — see Legacy below.

4. **Harness MCP config** (`mcp.json` in the Hermes Capabilities UI, or the
   equivalent in any MCP client):

   ```json
   {
     "mcpServers": {
       "gatekeeper": { "command": "/usr/local/bin/gk-mcp" }
     }
   }
   ```

   Optional: `--gatekeeper-socket /run/gatekeeper/mcp.sock` is already the
   default; pass it only for non-default socket paths.

5. **Approver side.** Run `gk-tui` (or `scopeadm`) as root — or under sudo —
   on the machine. Nothing to configure; the admin socket path is the default.

## Legacy: socket-activated gk-mcp (`gk-mcp.socket`, `gk-mcp@.service`)

These units implement an older topology: systemd accepts connections on a
unix socket and spawns one gk-mcp per connection as a dedicated service user
(`mcp_user` = separate account, e.g. `gk-mcp-service`). They are still used
by the dev box in this repo (root harness there makes the stdio peer-cred
story awkward; see below) but are **not** recommended for new deployments:

- the connecting client must be able to reach `mcp-server.sock` (0660,
  root:root unless you set `SocketUser`/`SocketGroup`), AND
- the spawned gk-mcp must run as `mcp_user` for the peer-cred gate — which
  only an accepting daemon like systemd can arrange.

If you do use them: enable `gk-mcp.socket`, keep `mcp_user` = that service
user, and make sure the harness connects to `/run/gatekeeper/mcp-server.sock`
via a stdio bridge (e.g. `systemd-run --pipe ... gk-mcp` as root, or any
unix-socket relay running as `mcp_user`).

## Dev-box exception (this repo's host)

The harness here runs as **root**, so the plain stdio topology would have
gk-mcp connecting as uid 0 and failing the peer-cred gate. The dev box
therefore keeps `mcp_user = "gk-mcp-service"` + socket activation, and gives
the root harness a stdio→socket bridge in its mcp.json:

```json
{
  "mcpServers": {
    "gatekeeper": {
      "command": "systemd-run",
      "args": ["--pipe", "--quiet", "-p", "User=gk-mcp-service", "/usr/local/bin/gk-mcp"]
    }
  }
}
```

`systemd-run --pipe` spawns gk-mcp as the service user with stdio wired to
the harness, which is exactly what the peer-cred gate wants.

## Smoke test

After deploying: `scopeadm pendings` should print an empty result; a
`tools/call request_traffic_grant` from the harness should surface a pending
row in `gk-tui`, and approving it should show the target in
`nft list set inet gatekeeper grants_v4` with an expiry.
