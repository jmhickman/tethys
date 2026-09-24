# Deploying Tethys

Three binaries, one daemon:

| binary        | runs as            | role                                        |
|---------------|--------------------|---------------------------------------------|
| `tethysd`     | root (systemd)     | grant ledger + nftables enforcer            |
| `tethys`      | root / sudo        | human approver — needs `admin.sock` (0600)  |
| `tethys-mcp`  | harness user       | MCP server, spawned by the agent harness    |

## Threat model in one paragraph

Approval authority lives on `admin.sock`, which the daemon creates 0600 —
only the account running tethysd (root here) can connect. Everything the
agent side can do is *submit* a grant request over `mcp.sock`, which a human
must approve. The agent user being unable to read/write `admin.sock` is the
boundary. Enforcement is UID-SCOPED: the egress drop applies only to
`agent_user`'s uid; everyone else on the box (human admins, system services)
egresses freely — the sandbox is the agent's, not the host's.

## Production topology (unprivileged harness)

The agent harness runs as an unprivileged user (example: `hermes-agent`) and
spawns tethys-mcp itself as a stdio MCP child process. tethys-mcp then dials
`mcp.sock`. There is no separate service user, and nothing to install for
tethys-mcp beyond the binary.

1. **Users.** One unprivileged harness user is enough:

   ```
   useradd --system --create-home --shell /usr/sbin/nologin hermes-agent
   ```

2. **`/etc/tethys/config.toml`** — start from `config.example.toml` and
   set the identity knob to the harness user:

   ```toml
   agent_user = "hermes-agent"   # baseline egress block applies to this uid;
                                 # mcp.sock accepts peers as this uid too
   ```

   There is deliberately no second identity to keep in sync: the account
   whose egress is policed is the same one mcp.sock accepts requests from,
   because tethys-mcp runs as a child of the harness.

3. **Enable the enforcement units only:**

   ```
   install -m 0644 deploy/tethys-baseline.service deploy/tethysd.service /etc/systemd/system/
   install -m 0644 deploy/tethys-baseline.nft /etc/tethys/baseline.nft
   systemctl daemon-reload
   systemctl enable --now tethys-baseline.service tethysd.service
   ```

4. **Harness MCP config** (`mcp.json` in the Hermes Capabilities UI, or the
   equivalent in any MCP client):

   ```json
   {
     "mcpServers": {
       "tethys": { "command": "/usr/local/bin/tethys-mcp" }
     }
   }
   ```

   Optional: `--daemon-socket /run/tethys/mcp.sock` is already the
   default; pass it only for non-default socket paths.

5. **Approver side.** Run `tethys` as root — or under sudo — on the machine.
   Nothing to configure; the admin socket path is the default.

## Smoke test

After deploying: `tethys` should open with an empty live table; a
`tools/call request_traffic_grant` from the harness should surface a pending
row in `tethys`, and approving it should show the target in
`nft list set inet tethys grants_v4` with an expiry.
