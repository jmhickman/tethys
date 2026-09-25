# TETHYS(5)

## NAME

**Tethys** - scope enforcement for an agent's outbound traffic: a grant
ledger, an nftables enforcer, and a human-in-the-loop approval path.

## DESCRIPTION

Tethys confines one unprivileged account on a Linux host to an explicit set
of network destinations. Everything that account sends out is
dropped at the kernel unless the destination matches a standing operator
carve-out or a temporary grant. Grants exist only after a human approver
says yes. They expire on their own; no process tends them.

The system consists of three binaries and one static ruleset:

| component | runs as | role |
|-----------|------------------|--------------------------------------------------|
| `tethysd` | root (systemd) | grant ledger and `nftables` enforcer; owns all kernel state derived from grants |
| `tethys-mcp` | harness user | MCP server spawned by the agent harness; a thin stateless proxy that forwards requests to `tethysd` |
| `tethys` | root or sudo | the approver's terminal UI, attached to the admin socket |
| `baseline.nft` | applied at boot | static default-deny egress policy; Tethys never edits its rules |

The agent itself never talks to `tethysd` directly. The harness spawns
`tethys-mcp` as a stdio MCP child; `tethys-mcp` connects to the daemon over a
unix socket and passes along exactly one tool call, `request_traffic_grant`.
The daemon records the request, opens it to the approver, installs the kernel
elements if it is approved, and returns the effective verdict as text. The
MCP layer holds no approval power and no netfilter access; if it is
compromised or bypassed entirely, the security model is unaffected.

Approval authority lives on `admin.sock`, which the daemon creates mode 0600:
only the account running `tethysd` can connect without privilege escalation.
Enforcement is scoped by uid. Only traffic originating from `agent_user`'s uid
passes through the policy, so human admins and system services on the same host
egress freely. The sandbox contains the agentic harness, not the machine.

## REQUIREMENTS

Tethys requires Linux with `nftables`; the ruleset grammar was verified against
nft 1.1.6 and the kernel shipped with recent Proxmox hosts. Building from
source needs a Rust toolchain at version 1.87 or newer. Installation of the
binaries, the configuration file, and the SystemD units requires root.

A deployment needs one unprivileged account to police (the harness user) and
one privileged account to approve (typically root). No network access is
required at build time beyond cargo's registry fetch.

## INSTALLATION

Tethys is installed in one of three ways: by way of the installer script and
a prebuilt release tarball, by unpacking such a tarball by hand, or by
building from source. All three land the same files in the same places; they
differ only in who does the fetching and the building.

### With the installer script

The shortest path on a host that can reach GitHub:

```sh
curl -fsSL https://raw.githubusercontent.com/jmhickman/tethys/vX.Y.Z/install.sh | sudo sh
```

Edit the tag in the URL to the desired release. The script detects the 
machine's architecture, downloads the matching release tarball and its 
checksum file, and stops if the sha256 does not match. It then installs
the binaries to `/usr/local/bin`, the baseline ruleset and SystemD units 
to their system paths, seeds `/etc/tethys/config.toml` from the shipped 
example (an existing configuration is never overwritten), and runs 
`systemctl enable` on both units. It asks before starting enforcement, 
because the baseline changes the host's egress policy immediately.

`--help` lists the full option set: `--stage` with `--prefix` stages files
under a tree of your choosing without root or SystemD (for packagers and
rootless installs), `--version` selects a tag without pinning the URL,
`--source` installs from a local directory of release assets instead of the
network, and `--dry-run` shows what would change.

### From a tarball by hand

Release assets are named `tethys-<version>-<target>.tar.gz`, where target
is the platform name Rust builds for; `x86_64-unknown-linux-gnu` covers
ordinary x86-64 Linux hosts and `x86_64-unknown-linux-musl` covers hosts
where a fully static binary is preferred. Each archive contains:

```
tethys-<version>-<target>/
  install.sh  uninstall.sh
  bin/tethysd  bin/tethys-mcp  bin/tethys
  share/tethys/baseline.nft
  share/tethys/tethysd.service
  share/tethys/tethys-baseline.service
  share/tethys/config.example.toml
```

The archive is self-installing: from inside an unpacked tree, `sh install.sh`
performs the host deployment without touching the network. It also accepts
`--source` naming a release directory (as `scripts/make-dist.sh` lays out in
`dist/`), a `.tar.gz`, or an unpacked tree. The version is taken from the
artifact's name, so these invocations need no other options.

Verify the checksum, unpack, and install the pieces where the units expect
them:

```sh
sha256sum -c tethys-0.2.0-x86_64-unknown-linux-gnu.tar.gz.sha256
tar xzf tethys-0.2.0-x86_64-unknown-linux-gnu.tar.gz
cd tethys-0.2.0-x86_64-unknown-linux-gnu
install -m 0755 bin/tethysd bin/tethys-mcp bin/tethys /usr/local/bin/
install -d /etc/tethys
install -m 0644 share/tethys/baseline.nft /etc/tethys/baseline.nft
install -m 0644 share/tethys/*.service /etc/systemd/system/
```

Then continue at SYSTEMD SERVICES below.

### From source

Build from source when the deployment needs an unreleased change, or when
you prefer to compile what runs as root:

```sh
cargo build --release
sh scripts/make-dist.sh $(rustc -vV | sed -n 's/^host: //')
```

The second command assembles the same tarball the releases carry (under
`dist/`, with a checksum file beside it), so the hand-unpack steps above
apply verbatim. Or install straight from the build tree:

```sh
install -m 0755 target/release/tethysd    /usr/local/bin/tethysd
install -m 0755 target/release/tethys-mcp /usr/local/bin/tethys-mcp
install -m 0755 target/release/tethys     /usr/local/bin/tethys
```

`tethys-mcp` needs no further installation step in any of the three routes.
It is spawned per session by whatever MCP client the harness uses, and it
reads no configuration file; the socket path it dials has a built-in default
that matches the daemon's.

## USERS AND IDENTITIES

Tethys works around two configurable users:

`agent_user`: the account upon which all egress rules are applied, and the 
only account whose requests on `mcp.sock` the daemon accepts. The baseline's
scope chain exempts every uid except this one before the egress drop runs. 
The same uid gates `mcp.sock` via SO_PEERCRED (and that account's group owns
 the socket), because `tethys-mcp` runs as a child of the harness and shares 
its uid by construction. 

⚠️ If the account does not exist when the daemon starts,
enforcement **widens** rather than vanishing: with no uid to scope to, the
policy covers *all* uids on the host until the account is provisioned and
the daemon restarts. The `mcp.sock` peer pin is inactive in the same
situation.

`admin_user`: the account admitted on `admin.sock`. The socket's 0600 mode is
the primary gate; the uid check via `SO_PEERCRED` is defense in depth against
a swapped socket inode. A missing `admin_user` aborts startup unless the
dev-only `--allow-missing-users` flag is set.

In the common single-harness deployment, create exactly one unprivileged
account and point `agent_user` at it:

```sh
useradd --system --create-home hermes-agent
```

## CONFIGURATION

The daemon reads one TOML file, by default `/etc/tethys/config.toml`. Pass
`--config` to use a different location. A missing file is not an error: the
daemon warns and uses its built-in defaults. **A malformed file will cause the
daemon to fail to load**, and so does any unknown key in it.

Configuration can also arrive as command-line flags. An administrator may configure
the daemon via `ExecStart` in the service file. `tethysd` uses defaults, then
the TOML file, then flags in that order to determine live configuration. `--allow`
is NOT additive with an `allow` key in the configuration file. It acts as an override.

The file `config.example.toml` contains the following fields:

`mcp_socket`, `admin_socket`
: Paths of the two unix sockets. Defaults `/run/tethys/mcp.sock` and
`/run/tethys/admin.sock`. The parent directory is created at startup if
absent; under systemd, `RuntimeDirectory=` creates it beforehand.

`db`
: Path to the SQLite grant ledger (WAL mode). Default
`/var/lib/tethys/ledger.db`. Under systemd, `StateDirectory=` provides
the directory. The ledger is the durable record of requests and verdicts;
kernel state is reconciled from it at every start.

`nft_table`
: The `nftables` table the daemon owns, default `tethys`. One deployment
owns one table. Change it only to run a second, independent instance against
the same kernel.

`max_ttl`
: This is the maximum time a grant may be active. It **overrides** any value 
supplied by the user in the console (`tethys`) that would exceed it. Grant TTLs 
in excess of this value are reduced to it. The value accepts `Ns`/`Nm`/`Nh`.

`approver_timeout_secs`
: Seconds a pending request may sit without a decision before it is denied
automatically. Default 300. No decision is recorded as a denial.

`agent_user`, `admin_user`
: The identities described above.

`allow`
: The operator allow list: egress that is always permitted, installed into
the baseline's carve sets at every daemon start. See THE ALLOW LIST.

`dry_run`
: When true, the daemon binds its sockets and maintains the ledger but
installs nothing into nftables. Intended for development and for rehearsing
a configuration change before committing to enforcement.

### The allow list

Each entry names a destination, optionally narrowed by port and protocol:

```
target[:port[-port]][/(tcp|udp)]
target[:p1,p2[-p3],...][/(tcp|udp)]
```

The target may be a hostname, a literal address, or a CIDR block. Omitting
the port means all ports; omitting the protocol means tcp. Ports may also be
given as a comma-separated list of single ports and ranges; each element is
installed as its own rule for the same target.

Hostnames are resolved once, when the daemon starts, and the resulting
addresses are what the kernel enforces. Two consequences follow. First, if a
hostname's address changes while the daemon runs, the stale grant stays in
force until `systemctl restart tethysd` re-resolves it. Second, an entry
whose hostname will not resolve stops the daemon from starting at all,
rather than being quietly skipped. A DNS outage therefore appears as a
service that fails to start, and `journalctl -u tethysd` names the entry
that failed.

```toml
allow = [
  "192.168.1.5:1234",          # local OpenAI-compatible server
  "api.anthropic.com:443",     # Anthropic API
  "151.101.0.0/16:80-443",     # some CDN CIDR, port range
  "time.example.net:123/udp",  # explicit udp
]
```

The config file is the only authority for this list and the daemon never edits
the file itself. At every start it rebuilds the kernel's copy of the list
from scratch, which has two practical effects. First, edits you make to `allow` 
do not take effect until the next restart of `tethysd`. Second, rules added by 
hand with the `nft` command are not integrated into the allow list.
Manage this list through the config file only.

Beyond the allow list, the baseline itself always accepts loopback traffic,
established and related connections, DHCP, DNS in both directions of the
protocol pair, and ICMP/ICMPv6, so that resolution and reachability checks
are never impeded.

## SYSTEMD SERVICES

There are two SystemD units which are started in order. The baseline must exist 
before the daemon starts, because the daemon installs grant elements into sets 
the baseline declares.

`tethys-baseline.service` is a oneshot that applies
`/etc/tethys/baseline.nft` and remains active. 

`tethysd.service` runs
`tethysd` itself, with `ProtectSystem=strict`, ambient capabilities limited to
`CAP_NET_ADMIN` (for the `nft` invocations) and `CAP_CHOWN` (to group-own
`mcp.sock`). Its runtime and state directories are managed by SystemD.

The firewall rules are split between two owners, and neither writes in the
other's territory. `/etc/tethys/baseline.nft` defines the structure: which
traffic is examined, which decisions are taken (accept or drop), and the
named sets that hold destinations. Those parts never change while Tethys
runs. `tethysd` fills the sets and nothing else: approved grants go into
`grants_v4`/`grants_v6` (each entry carries its own expiry clock, which is
how grants lapse without a timer process), the allow list goes into
`carve_v4`/`carve_v6`, and the policed uid goes into the `scope` chain.

The practical benefit is that one command shows the entire policy in force:

```sh
nft list table inet tethys
```

You see the fixed rules from the baseline file, the grant entries with their
remaining lifetimes, the allow-list entries, and counters for exempt and
dropped traffic, all in one listing.

> **Note:** Do not reapply the baseline file while any grant is live. The
> file begins by *creating* its sets (`add set`), and `nft` rejects a command
> that creates a set which already exists, aborting the whole load partway
> through. The kernel is then in a half-applied state until you finish the
> sequence below. To change the baseline ruleset, stop the daemon, delete the
> table (which removes all sets and grants atomically), reapply the file, and
> start again:

```sh
systemctl stop tethysd \
  && nft delete table inet tethys || true \
  && nft -f /etc/tethys/baseline.nft \
  && systemctl start tethysd
```

> **Note:** Deleting the table deletes every live grant with it. Agents whose
> destinations were approved will find their traffic blocked again until new
> grants are approved. This is the cost of changing the baseline, not a bug:
> only the `nft delete table` step clears the sets, and the sets must be
> cleared for the file to reload. Ordinary restarts of `tethysd.service` do
> not touch live grants; the daemon re-adopts them from the kernel on boot.

If the egress policy ever locks you out of the machine, reach it through a
console and run `nft delete table inet tethys`. That removes all enforcement
at once; the baseline can be reapplied later with `systemctl start
tethys-baseline`.

## MCP INTEGRATION

Register `tethys-mcp` with the agent harness the way any stdio MCP server is
registered. In Hermes, this is `mcp.json` under Capabilities; other clients
have an equivalent stanza:

```json
{
  "mcpServers": {
    "tethys": { "command": "/usr/local/bin/tethys-mcp" }
  }
}
```

The server exposes a single tool, `request_traffic_grant`, whose arguments
name exactly one destination (`dst_host`, `dst_ip`, or `dst_net`), a protocol,
a port range, a TTL, the requesting tool, and a reason. The reason is shown to
the approver verbatim. The call blocks until it is granted or the timeout elapses. 
The response is the *effective* grant. The request's TTL may have been reduced
by either the `max_ttl` configuration value or by the approver. The ports may have
been adjusted as well.

⚠️ Setting the `agent_user` configuration value incorrectly will cause
loss of connectivity from the MCP server to the grant submission socket. 

## OPERATIONS

The approver's console application is the `tethys` binary. It should be run as root
or via sudo:

The application presents a TUI with a small information bar. Pending
requests appear as a modal dialog when they arrive. Approving a grant applies the
requested attributes to the active firewall rules. The elements are then displayed
in a row. You may punch into the selected row for more details via Enter. All requests,
whether approved or denied, are recorded in a sqlite ledger. The ledger is 
located in `/var/lib/tethys`.

A typical grant flow is as follows:  
`tethys` opens the current live table ->  
a `request_traffic_grant` call from the harness appears as a pending row ->  
a modal dialog appears with the details of the requested grant ->  
approving it creates a row with several informational columns ->  
a message is sent back to the agent via the MCP server ->  
traffic to the destination succeeds for the agent user ->  

After expiry the element is removed without any explicit action by the user. 

`tethys` displays dropped packets as well, allowing the user to note potentially broken
pipes.

## UNINSTALL

`uninstall.sh` (shipped beside `install.sh` in the release archive) removes
a host deployment. 

The configuration file and the SQLite ledger survive by default as the ledger
is an auditing artifact. Pass `--purge` to remove them as well.

```sh
sh uninstall.sh            # remove enforcement and binaries, keep config + ledger
sh uninstall.sh --purge    # remove everything Tethys installed
sh uninstall.sh --dry-run  # show what would happen, change nothing
```

If you prefer by hand, the equivalent sequence is:

```sh
systemctl disable --now tethysd.service tethys-baseline.service
rm /etc/systemd/system/tethysd.service /etc/systemd/system/tethys-baseline.service
systemctl daemon-reload
nft delete table inet tethys
rm /usr/local/bin/tethysd /usr/local/bin/tethys-mcp /usr/local/bin/tethys
rm /etc/tethys/baseline.nft /etc/tethys/config.example.toml
rm -rf /etc/tethys
rm -rf /var/lib/tethys
```

## SECURITY MODEL

The boundary is deliberately narrow: the agent user cannot read or write
`admin.sock`, and therefore cannot approve anything. Everything reachable
from the agent's side (harness, MCP server, socket) can *ask*, never
*allow*.

Some gotchas worth noting:

* An unresolvable `agent_user` **widens enforcement to the whole host**
rather than narrowing it to nothing. 
* A configuration file with unknown keys will cause the daemon to fail to load.
This is intentionally noisy, as the baseline `nftables` rules applied to the 
host are quite restrictive.
* The agent **should not be able to execute commands as another user**; 
the security assumptions are predicated on a single-user harness. If the model 
learns it can `su` into a user that is not subject to the baseline `nftables` rules, 
it will happily route around your enforcement. 
This applies to `ssh` as well; if the agent can perform a local `ssh` into 
another identity, it can egress the host.
* Similarly, if there is a service listening on the loopback address that would 
provide egress (a SOCKS proxy, etc), the default `nftables` would not block it,
as it allows loopback connections without approvals.
* DNS is a default allowed protocol and it is possible to egress information 
via DNS requests. If the agent is compromised, it is highly likely to choose this
method of egress. DNS resolution monitoring is advised.

## FILES

```
/etc/tethys/config.toml        daemon configuration (TOML; unknown keys rejected)
/etc/tethys/baseline.nft       static egress baseline, applied at boot
/run/tethys/mcp.sock           request socket (group-owned by agent_user)
/run/tethys/admin.sock         approval socket (0600)
/var/lib/tethys/ledger.db      SQLite grant ledger (WAL)
```

## SEE ALSO

`deploy/README.md` for the condensed operator checklist, and
`config.example.toml` for the annotated configuration reference.
