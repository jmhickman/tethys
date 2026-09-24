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
fn default_agent_user() -> String {
    // The username the model-run tooling executes under. Configurable on
    // purpose: different harnesses ship under different names
    // (hermes-agent is just the common default here).
    "hermes-agent".into()
}
fn default_admin_user() -> String {
    // The username allowed to drive admin.sock. The 0600 socket mode is the
    // primary gate; the SO_PEERCRED uid check (against this account's uid,
    // resolved at startup) is defense-in-depth against the bind/chmod race
    // and any deployment that loosens the mode.
    "root".into()
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
    /// dry-run: never touch nftables (state machine + sockets only)
    #[serde(default)]
    pub dry_run: bool,
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
            dry_run: false,
        }
    }
}

/// Parse one `allow` entry. Grammar (same vocabulary as grants — the operator
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
/// twice. Returns the parsed triples exactly like access requests carry them.
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

    // split off /proto — only a literal /tcp or /udp suffix is a proto; any
    // other '/' (CIDR) leaves the string intact.
    let (rest, proto) = match s.rsplit_once('/') {
        Some((r, p)) => match p.to_ascii_lowercase().as_str() {
            "tcp" => (r, Proto::Tcp),
            "udp" => (r, Proto::Udp),
            _ => (s, Proto::Tcp),
        },
        None => (s, Proto::Tcp),
    };
    let rest = rest.trim();

    // Split target from port at the LAST colon — but only if it is not part
    // of a v6 address/CIDR. For literal v6 we require the bracket form.
    let (target_s, port): (String, &str) = if let Some(inner) = rest.strip_prefix('[') {
        let (host, p) = inner
            .split_once("]:")
            .ok_or_else(|| anyhow::anyhow!("allow {s:?}: bracketed target needs :port"))?;
        (host.to_string(), p) // brackets are syntax, not part of the address
    } else if !rest.contains(':') {
        // bare host/ip/CIDR => all ports
        (rest.to_string(), "")
    } else {
        match rest.rsplit_once(':') {
            // CIDR or host with explicit port: suffix is digits/dashes
            Some((t, p))
                if !p.is_empty()
                    && p.chars()
                        .all(|c| c.is_ascii_digit() || c == '-' || c == ',') =>
            {
                (t.to_string(), p)
            }
            // "fe80::1" style v6 without port: whole string is the target
            _ => (rest.to_string(), ""),
        }
    };

    let target = if let Ok(ip) = target_s.parse::<std::net::IpAddr>() {
        Target::Ip(ip)
    } else if let Ok(n) = target_s.parse::<ipnet::IpNet>() {
        Target::Net(n)
    } else {
        // hostname: same validation spirit as access requests
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

    #[test]
    fn allow_entries_parse() {
        use tethys_core::types::{Proto, Target};
        // host:port
        let (t, p, proto) = parse_allow("api.anthropic.com:443").unwrap().pop().unwrap();
        assert_eq!(t, Target::Host("api.anthropic.com".into()));
        assert_eq!((p.from, p.to), (443, 443));
        assert_eq!(proto, Proto::Tcp);
        // ip + udp
        let (t, p, proto) = parse_allow("192.168.1.5:1234/udp").unwrap().pop().unwrap();
        assert!(matches!(t, Target::Ip(_)));
        assert_eq!((p.from, p.to), (1234, 1234));
        assert_eq!(proto, Proto::Udp);
        // cidr + port range
        let (t, p, _) = parse_allow("151.101.0.0/16:80-443").unwrap().pop().unwrap();
        assert!(matches!(t, Target::Net(_)));
        assert_eq!((p.from, p.to), (80, 443));
        // bare target = all ports
        let (t, p, _) = parse_allow("198.51.100.7").unwrap().pop().unwrap();
        assert!(p.is_all());
        assert!(matches!(t, Target::Ip(_)));
        // comma list expands to one triple per port/range, sharing target+proto
        let v = parse_allow("host.example:80,443,8000-8100/tcp").unwrap();
        assert_eq!(v.len(), 3);
        assert!(v
            .iter()
            .all(|(t, _, pr)| *t == Target::Host("host.example".into()) && *pr == Proto::Tcp));
        assert_eq!((v[0].1.from, v[0].1.to), (80, 80));
        assert_eq!((v[1].1.from, v[1].1.to), (443, 443));
        assert_eq!((v[2].1.from, v[2].1.to), (8000, 8100));
        // errors: garbage, inverted range, empty
        assert!(parse_allow("").is_err());
        assert!(parse_allow("host:443-80").is_err());
        assert!(parse_allow("host:notaport").is_err());
        assert!(parse_allow("host:80,,443").is_err());
    }

    #[test]
    fn root_resolves_and_missing_user_fails() {
        assert_eq!(resolve_uid("root").unwrap(), 0);
        assert!(resolve_uid("definitely-not-a-user-xyz").is_err());
    }
}
