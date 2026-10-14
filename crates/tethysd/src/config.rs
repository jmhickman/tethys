//! File-based configuration (TOML) with CLI overrides.
//! Precedence: built-in defaults < config file < CLI flags.

use std::path::PathBuf;

use serde::Deserialize;

fn default_mcp_socket() -> PathBuf {
    "/run/tethys/mcp.sock".into()
}
fn default_admin_socket() -> PathBuf {
    "/run/tethys/admin.sock".into()
}
fn default_db() -> PathBuf {
    "/var/lib/tethys/ledger.db".into()
}
fn default_nft_table() -> String {
    tethys_core::nft::TABLE.into()
}
fn default_max_ttl() -> String {
    "4h".into()
}
fn default_approver_timeout() -> u64 {
    300
}
/// The username the model-run tooling executes under. Configurable on
/// purpose: different harnesses ship under different names (hermes-agent
/// is just the common default here).
fn default_agent_user() -> String {
    "hermes-agent".into()
}
/// The username allowed to drive admin.sock. The 0600 socket mode is the
/// primary gate; the SO_PEERCRED uid check (against this account's uid,
/// resolved at startup) is defense-in-depth against the bind/chmod race and
/// any deployment that loosens the mode.
fn default_admin_user() -> String {
    "root".into()
}

/// `[netns]` — the enforcement namespace provisioning operates on. Parsed
/// leniently here (shape only); `provision::Spec::from_netns` does the
/// strict, mode-aware validation and derives addresses. The daemon
/// REQUIRES the section (netns mode is the only mode); `tethysd` run-mode
/// startup aborts without it, --dry-run excepted.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetnsFile {
    /// Namespace name; live at `<dir>/<name>` (systemd drop-in points
    /// `NetworkNamespacePath=` at this file).
    pub name: String,
    /// Directory holding the nsfs file. Production default `/run/netns`;
    /// overridable so root-gated tests never touch the real one.
    #[serde(default)]
    pub dir: Option<PathBuf>,
    /// "routed" (default; host is the namespace's router) or "bridge"
    /// (veth stapled into an operator bridge, real LAN address).
    #[serde(default = "default_netns_mode")]
    pub mode: String,
    /// Host-side veth end. Default `vh-<name>` truncated to IFNAMSIZ.
    #[serde(default)]
    pub host_veth: Option<String>,
    /// Namespace-side veth end (default "veth0").
    #[serde(default)]
    pub ns_veth: Option<String>,
    /// routed: IPv4 point-to-network carrying both veth ends; host takes
    /// the first address, the namespace the second. Required in routed mode.
    #[serde(default)]
    pub prefix4: Option<String>,
    /// routed: optional site-routed IPv6 /64 (or shorter) for a real GUA
    /// pair. Absent => fixed ULA pair; enforcement guarantees are identical,
    /// only the address remotes see differs.
    #[serde(default)]
    pub prefix6: Option<String>,
    /// routed: fixed source address for IPv6 masquerade when the container
    /// has several GUAs and egress must pin to one. Default: plain
    /// masquerade (outgoing interface address).
    #[serde(default)]
    pub masq_src6: Option<String>,
    /// bridge: operator-managed bridge the host veth end is stapled into.
    /// Required in bridge mode.
    #[serde(default)]
    pub bridge: Option<String>,
    /// bridge: namespace addresses as CIDRs (v4 and/or v6), operator-
    /// assigned LAN addresses. Required (non-empty) in bridge mode.
    #[serde(default)]
    pub addrs: Vec<String>,
    /// bridge: optional default-route gateways (the LAN's).
    #[serde(default)]
    pub gw4: Option<String>,
    #[serde(default)]
    pub gw6: Option<String>,
}

fn default_netns_mode() -> String {
    "routed".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    #[serde(default = "default_mcp_socket")]
    pub mcp_socket: PathBuf,
    #[serde(default = "default_admin_socket")]
    pub admin_socket: PathBuf,
    #[serde(default = "default_db")]
    pub db: PathBuf,
    /// nftables table the daemon owns. One per deployment; tests point this
    /// at a private table so they never touch production kernel state.
    #[serde(default = "default_nft_table")]
    pub nft_table: String,
    #[serde(default = "default_max_ttl")]
    pub max_ttl: String,
    #[serde(default = "default_approver_timeout")]
    pub approver_timeout_secs: u64,
    #[serde(default = "default_agent_user")]
    pub agent_user: String,
    #[serde(default = "default_admin_user")]
    pub admin_user: String,
    /// Operator allow list (see parse_allow). Installed into carve sets at startup.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Operator INBOUND allow list, same grammar. Installed into the
    /// carve_in sets; in routed mode its ports are permanently delegated
    /// on the host (DNAT). No CLI flag by design (step 2026.10.1 decision).
    #[serde(default)]
    pub allow_in: Vec<String>,
    /// Host ports that are NEVER delegated to the guarded namespace. An
    /// ingress grant (or `allow_in` entry) whose port overlaps this list is
    /// refused, and provisioning installs a pre-DNAT guard rule so even a
    /// stale or hand-added delegation cannot capture these ports: the host
    /// stack keeps answering them (sshd etc.). Grammar: comma-separated
    /// ports or ranges ("22", "8080-8090", "53,67-68"). Boot-only: change
    /// requires a daemon restart + reprovision, no reload RPC.
    #[serde(default)]
    pub reserved_ports: Vec<String>,
    /// dry-run: never touch nftables (state machine + sockets only)
    #[serde(default)]
    pub dry_run: bool,
    /// Enforcement namespace ([netns]); required by `tethysd provision`.
    #[serde(default)]
    pub netns: Option<NetnsFile>,
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            mcp_socket: default_mcp_socket(),
            admin_socket: default_admin_socket(),
            db: default_db(),
            nft_table: default_nft_table(),
            max_ttl: default_max_ttl(),
            approver_timeout_secs: default_approver_timeout(),
            agent_user: default_agent_user(),
            admin_user: default_admin_user(),
            allow: Vec::new(),
            allow_in: Vec::new(),
            reserved_ports: Vec::new(),
            dry_run: false,
            netns: None,
        }
    }
}

/// Parse one `allow` entry. Grammar (same vocabulary as grants: the operator
/// spells *what*, tethysd resolves and installs):
///
///   host[:port[-port]][/(tcp|udp)]        e.g. api.anthropic.com:443
///   ip[:port[-port]][/(tcp|udp)]          e.g. 192.168.1.5:1234
///   cidr[:port[-port]][/(tcp|udp)]        e.g. 151.101.0.0/16:80-443
///   target[:p1,p2[-p3],...][/(tcp|udp)]   comma list shares one target
///   [v6]:port                             bracketed form for literal v6
///
/// Port omitted => all ports; proto omitted => tcp. A comma-separated port
/// list expands to one (target, port, proto) triple per element, so
/// "host:80,443" installs the same two carve elements as writing the host
/// twice. Only a literal /tcp or /udp suffix is read as a protocol, so a
/// CIDR's slash leaves the string intact; a bare colon-bearing target that
/// does not end in a port-shaped suffix is treated whole (v6 without port).
/// Returns the parsed triples exactly like access requests carry them.
pub fn parse_allow(
    s: &str,
) -> anyhow::Result<
    Vec<(
        tethys_core::types::Target,
        tethys_core::types::PortSpec,
        tethys_core::types::Proto,
    )>,
> {
    use tethys_core::types::{PortSpec, Proto, Target};
    let s = s.trim();
    anyhow::ensure!(!s.is_empty(), "empty allow entry");

    let (rest, proto) = match s.rsplit_once('/') {
        Some((r, p)) => match p.to_ascii_lowercase().as_str() {
            "tcp" => (r, Proto::Tcp),
            "udp" => (r, Proto::Udp),
            _ => (s, Proto::Tcp),
        },
        None => (s, Proto::Tcp),
    };
    let rest = rest.trim();

    let (target_s, port): (String, &str) = if let Some(inner) = rest.strip_prefix('[') {
        let (host, p) = inner
            .split_once("]:")
            .ok_or_else(|| anyhow::anyhow!("allow {s:?}: bracketed target needs :port"))?;
        (host.to_string(), p)
    } else if !rest.contains(':') {
        (rest.to_string(), "")
    } else {
        match rest.rsplit_once(':') {
            Some((t, p))
                if !p.is_empty()
                    && p.chars()
                        .all(|c| c.is_ascii_digit() || c == '-' || c == ',') =>
            {
                (t.to_string(), p)
            }
            _ => (rest.to_string(), ""),
        }
    };

    let target = if let Ok(ip) = target_s.parse::<std::net::IpAddr>() {
        Target::Ip(ip)
    } else if let Ok(n) = target_s.parse::<ipnet::IpNet>() {
        Target::Net(n)
    } else {
        anyhow::ensure!(
            !target_s.is_empty()
                && !target_s.contains(char::is_whitespace)
                && target_s
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')),
            "allow {s:?}: bad target {target_s:?}"
        );
        Target::Host(target_s.to_ascii_lowercase())
    };

    let specs: Vec<PortSpec> = if port.is_empty() {
        vec![PortSpec { from: 0, to: 0 }]
    } else {
        let mut out = Vec::new();
        for part in port.split(',') {
            let spec = if let Some((a, b)) = part.split_once('-') {
                PortSpec {
                    from: a.trim().parse()?,
                    to: b.trim().parse()?,
                }
            } else {
                let p = part.trim().parse::<u16>()?;
                PortSpec { from: p, to: p }
            };
            out.push(
                spec.validate()
                    .map_err(|e| anyhow::anyhow!("allow {s:?}: {e}"))?,
            );
        }
        out
    };
    Ok(specs
        .into_iter()
        .map(|spec| (target.clone(), spec, proto))
        .collect())
}

/// Parse `reserved_ports` entries into normalized, sorted, deduplicated
/// nft port ranges. Grammar: comma-separated single ports or ranges
/// ("22", "8080-8090", "53,67-68"). A bad or inverted entry is a boot
/// error — reserved ports are an enforcement knob, so a typo must abort,
/// not silently under-protect.
pub fn parse_reserved_ports(entries: &[String]) -> anyhow::Result<Vec<(u16, u16)>> {
    use tethys_core::types::PortSpec;
    let mut out: Vec<(u16, u16)> = Vec::new();
    for e in entries {
        for part in e.split(',') {
            let part = part.trim();
            anyhow::ensure!(!part.is_empty(), "reserved_ports {e:?}: empty list element");
            let spec = if let Some((a, b)) = part.split_once('-') {
                PortSpec {
                    from: a.trim().parse()?,
                    to: b.trim().parse()?,
                }
            } else {
                let p = part.trim().parse::<u16>()?;
                PortSpec { from: p, to: p }
            };
            spec.validate()
                .map_err(|err| anyhow::anyhow!("reserved_ports {e:?}: {err}"))?;
            out.push(spec.nft_range());
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Ingress-delegation constraint for operator allow-list entries (used at
/// boot and by reload.allow): a wildcard port would DNAT EVERY host port
/// into the namespace, and a reserved port must never leave the host
/// stack. Both abort (boot) or refuse (reload) rather than install a
/// hijack the approver never asked for.
pub fn validate_ingress_specs(
    entries: &[(
        tethys_core::types::Target,
        tethys_core::types::PortSpec,
        tethys_core::types::Proto,
    )],
    reserved: &[(u16, u16)],
    what: &str,
) -> anyhow::Result<()> {
    use tethys_core::types::ranges_overlap;
    for (t, p, _) in entries {
        anyhow::ensure!(
            !p.is_all(),
            "{what} {}: explicit port required — '*' would delegate every host port into the namespace",
            t.canonical()
        );
        if let Some((lo, hi)) = reserved.iter().find(|r| ranges_overlap(p.nft_range(), **r)) {
            anyhow::bail!(
                "{what} {}: port {lo}-{hi} is reserved by operator",
                t.canonical()
            );
        }
    }
    Ok(())
}

/// Resolve a unix user name to its uid. A username named in config that does
/// not exist on the box is a deployment error: without the account, the peer
/// check on mcp.sock cannot hold.
pub fn resolve_gid(user: &str) -> anyhow::Result<u32> {
    match nix::unistd::User::from_name(user) {
        Ok(Some(u)) => Ok(u.gid.as_raw()),
        _ => Err(anyhow::anyhow!("cannot resolve gid for {user:?}")),
    }
}

pub fn resolve_uid(user: &str) -> anyhow::Result<u32> {
    match nix::unistd::User::from_name(user) {
        Ok(Some(u)) => Ok(u.uid.as_raw()),
        Ok(None) => Err(anyhow::anyhow!(
            "configured user {user:?} does not exist — create it or fix config (use --allow-missing-users for dev)"
        )),
        Err(e) => Err(anyhow::anyhow!("getpwnam({user}): {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_toml_fills_defaults() {
        let f: FileConfig = toml::from_str("db = '/tmp/x.db'\n").unwrap();
        assert_eq!(f.db, PathBuf::from("/tmp/x.db"));
        assert_eq!(f.agent_user, "hermes-agent");
        assert_eq!(f.approver_timeout_secs, 300);
        assert!(!f.dry_run);
    }

    #[test]
    fn unknown_keys_rejected() {
        let bad = toml::from_str::<FileConfig>("agent_userrr = 'x'\n");
        assert!(bad.is_err(), "unknown config keys must be rejected");
    }

    // Covers every grammar arm: host:port, ip + udp suffix, CIDR + port
    // range, bare target (all ports), comma lists expanding to one triple per
    // port or range, and error cases (empty, inverted range, non-numeric and
    // empty list elements).
    #[test]
    fn allow_entries_parse() {
        use tethys_core::types::{Proto, Target};
        let (t, p, proto) = parse_allow("api.anthropic.com:443").unwrap().pop().unwrap();
        assert_eq!(t, Target::Host("api.anthropic.com".into()));
        assert_eq!((p.from, p.to), (443, 443));
        assert_eq!(proto, Proto::Tcp);
        let (t, p, proto) = parse_allow("192.168.1.5:1234/udp").unwrap().pop().unwrap();
        assert!(matches!(t, Target::Ip(_)));
        assert_eq!((p.from, p.to), (1234, 1234));
        assert_eq!(proto, Proto::Udp);
        let (t, p, _) = parse_allow("151.101.0.0/16:80-443").unwrap().pop().unwrap();
        assert!(matches!(t, Target::Net(_)));
        assert_eq!((p.from, p.to), (80, 443));
        let (t, p, _) = parse_allow("198.51.100.7").unwrap().pop().unwrap();
        assert!(p.is_all());
        assert!(matches!(t, Target::Ip(_)));
        let v = parse_allow("host.example:80,443,8000-8100/tcp").unwrap();
        assert_eq!(v.len(), 3);
        assert!(v
            .iter()
            .all(|(t, _, pr)| *t == Target::Host("host.example".into()) && *pr == Proto::Tcp));
        assert_eq!((v[0].1.from, v[0].1.to), (80, 80));
        assert_eq!((v[1].1.from, v[1].1.to), (443, 443));
        assert_eq!((v[2].1.from, v[2].1.to), (8000, 8100));
        assert!(parse_allow("").is_err());
        assert!(parse_allow("host:443-80").is_err());
        assert!(parse_allow("host:notaport").is_err());
        assert!(parse_allow("host:80,,443").is_err());
    }

    // reserved_ports: comma lists, ranges, normalization + dedup + sort,
    // and error cases (empty element, inverted range, non-numeric).
    #[test]
    fn reserved_ports_parse_and_normalize() {
        assert_eq!(
            parse_reserved_ports(&["22".into()]).unwrap(),
            vec![(22, 22)]
        );
        assert_eq!(
            parse_reserved_ports(&["8080-8090".into(), "22,22".into(), " 53 ".into()]).unwrap(),
            vec![(22, 22), (53, 53), (8080, 8090)]
        );
        // "0" is the wildcard spelling: normalized to the full space.
        assert_eq!(
            parse_reserved_ports(&["0".into()]).unwrap(),
            vec![(0, 65535)]
        );
        assert!(parse_reserved_ports(&["80-22".into()]).is_err());
        assert!(parse_reserved_ports(&["22,".into()]).is_err());
        assert!(parse_reserved_ports(&["ssh".into()]).is_err());
    }

    // Ingress carves may not wildcard (would delegate every host port)
    // and may not touch a reserved port; clean entries pass.
    #[test]
    fn ingress_specs_reject_wildcard_and_reserved() {
        use tethys_core::types::{PortSpec, Proto, Target};
        let ip: std::net::IpAddr = "203.0.113.5".parse().unwrap();
        let t = Target::Ip(ip);
        let entry = |from, to| (t.clone(), PortSpec { from, to }, Proto::Tcp);
        let reserved = vec![(22, 22), (8080, 8090)];
        assert!(validate_ingress_specs(&[entry(0, 0)], &reserved, "allow_in").is_err());
        assert!(validate_ingress_specs(&[entry(22, 22)], &reserved, "allow_in").is_err());
        // Overlap, not just equality: 8079-8081 bites the 8080-8090 range.
        assert!(validate_ingress_specs(&[entry(8079, 8081)], &reserved, "allow_in").is_err());
        assert!(validate_ingress_specs(
            &[entry(443, 443), entry(8091, 8091)],
            &reserved,
            "allow_in"
        )
        .is_ok());
    }

    #[test]
    fn root_resolves_and_missing_user_fails() {
        assert_eq!(resolve_uid("root").unwrap(), 0);
        assert!(resolve_uid("definitely-not-a-user-xyz").is_err());
    }
}
