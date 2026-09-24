# Tethys

Tethys puts an AI agent behind a firewall that a human holds the keys to.
It confines one unprivileged account on a Linux host (typically whatever
user your agent harness runs as) so that every outbound connection is
dropped at the kernel. You may specify standing exceptions (links to local or cloud models, software repos, etc) Grants expire on their own;
nothing needs tending. 


## How it works

Tethys consists of three binaries and a static ruleset:

| component | runs as | role |
|-----------|------------------|----------------------------------------------------|
| `tethysd` | root (systemd) | grant ledger and nftables enforcer |
| `tethys-mcp` | harness user | MCP server the agent harness spawns; a thin proxy with exactly one tool |
| `tethys` | root or sudo | the approver's terminal UI |
| `baseline.nft` | applied at boot | default-deny egress policy; `tethysd` never edits its rules |

The agent sees a single MCP tool, `request_traffic_grant`. It calls the
tool with a destination, a port range, a TTL, and a reason; the call blocks
while a human decides, and returns the effective verdict. Approved destinations are installed as nftables set elements
carrying kernel timeouts, so expiry is enforced by netfilter itself.

Enforcement is scoped to one uid, so the human admin on the same machine
is never ambushed by their own firewall. The approval channel is a 0600
unix socket owned by root, which means the policed account can ask but not
allow.

## Install

On a host that can reach GitHub, with the tag pinned to the release you
want:

```sh
curl -fsSL https://raw.githubusercontent.com/jmhickman/tethys/vX.Y.Z/install.sh | sudo sh
```

The installer picks the correct prebuilt tarball for your architecture,
verifies its checksum, installs the binaries and systemd units, seeds a
configuration file (does not clobber existing configurations), and asks before
turning enforcement on. Local and air-gapped installs work too: release
archives are self-installing, and `install.sh --source` accepts a tarball,
a directory of assets, or an unpacked tree without touching the network.

The full guide — building from source, configuration reference, systemd
details, the security model in plain terms — is in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). The condensed operator checklist
lives in [deploy/README.md](deploy/README.md), and every configuration knob
is annotated in [config.example.toml](config.example.toml).

## Approving

Run `tethys` as root (or under sudo) on the host. Pending requests arrive
as they're made; approve or deny, and the live table shows what's currently
open with countdowns. Dropped packets are counted and logged with a
`TETHYS-DROP:` prefix.

## Configuration

The daemon reads `/etc/tethys/config.toml`. Each account has a specific role:
*  `agent_user` - The account against which the `nftables` rules are applied.
*  `admin_user` - The approving user. May be a user in the `sudoers` file or root. 

The `allow` list holds egress
that's always permitted (model backends, mirrors, infrastructure) and everything else flows through the approval pipeline with `max_ttl` as the hard ceiling on any grant. Unknown keys in
the file or a missing configured user aborts startup.

## Status

Version 2026.9.1 is a beta-quality release. While the enforcement path has been through a round of
adversarial security review, the software is unproven in production environments as of now. Use with caution, and apply defense-in-depth principles when containing and regulating agentic workflows.

## License

Apache-2.0. See [LICENSE](LICENSE).
