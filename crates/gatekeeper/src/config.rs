//! File-based configuration (TOML) with CLI overrides.
//!
//! Precedence: built-in defaults < config file < CLI flags.
//! Everything operator-tunable lives here; nothing about deployment identity
//! (user names, paths) is hard-coded in behavior beyond these defaults.

use std::path::PathBuf;

use serde::Deserialize;

fn default_mcp_socket() -> PathBuf {
    "/run/gatekeeper/mcp.sock".into()
}
fn default_admin_socket() -> PathBuf {
    "/run/gatekeeper/admin.sock".into()
}
fn default_db() -> PathBuf {
    "/var/lib/gatekeeper/ledger.db".into()
}
fn default_max_ttl() -> String {
    "4h".into()
}
fn default_approver_timeout() -> u64 {
    300
}
fn default_agent_user() -> String {
    // The uid model-run tooling executes under. Configurable on purpose:
    // different harnesses ship under different names (hermes-agent is just
    // the common default here).
    "hermes-agent".into()
}
fn default_mcp_user() -> String {
    // Service account that runs gk-mcp; the daemon only accepts MCP
    // connections from processes with this uid.
    "gk-mcp-service".into()
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
    #[serde(default = "default_max_ttl")]
    pub max_ttl: String,
    #[serde(default = "default_approver_timeout")]
    pub approver_timeout_secs: u64,
    #[serde(default = "default_agent_user")]
    pub agent_user: String,
    #[serde(default = "default_mcp_user")]
    pub mcp_user: String,
    /// Operator-declared always-allowed egress tuples (see parse_allow).
    /// Installed into the baseline carve sets at startup; reloaded wholesale
    /// on restart. No cloud providers are baked into gatekeeper — what counts
    /// as "always allowed" is the deployment's decision, spelled here.
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
            max_ttl: default_max_ttl(),
            approver_timeout_secs: default_approver_timeout(),
            agent_user: default_agent_user(),
            mcp_user: default_mcp_user(),
            allow: Vec::new(),
            dry_run: false,
        }
    }
}

/// Parse one `allow` entry. Grammar (same vocabulary as grants — the operator
/// spells *what*, gatekeeper resolves and installs):
///
///   host[:port[-port]][/(tcp|udp)]   e.g. api.anthropic.com:443
///   ip[:port[-port]][/(tcp|udp)]     e.g. 192.168.10.165:1234
///   cidr[:port[-port]][/(tcp|udp)]   e.g. 151.101.0.0/16:80-443
///   [v6]:port                        bracketed form for literal v6
///
/// Port omitted => all ports; proto omitted => tcp. Returns the parsed
/// (target, port, proto) triple exactly like an access request carries it.
pub fn parse_allow(
    s: &str,
) -> anyhow::Result<(gk_core::types::Target, gk_core::types::PortSpec, gk_core::types::Proto)> {
    use gk_core::types::{PortSpec, Proto, Target};
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
            Some((t, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit() || c == '-') => {
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
                && target_s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')),
            "allow {s:?}: bad target {target_s:?}"
        );
        Target::Host(target_s.to_ascii_lowercase())
    };

    let port = if port.is_empty() {
        PortSpec { from: 0, to: 0 }
    } else if let Some((a, b)) = port.split_once('-') {
        PortSpec { from: a.parse()?, to: b.parse()? }
    } else {
        let p = port.parse::<u16>()?;
        PortSpec { from: p, to: p }
    };
    let port = port.validate().map_err(|e| anyhow::anyhow!("allow {s:?}: {e}"))?;
    Ok((target, port, proto))
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
        assert_eq!(f.mcp_user, "gk-mcp-service");
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
        use gk_core::types::{Proto, Target};
        // host:port
        let (t, p, proto) = parse_allow("api.anthropic.com:443").unwrap();
        assert_eq!(t, Target::Host("api.anthropic.com".into()));
        assert_eq!((p.from, p.to), (443, 443));
        assert_eq!(proto, Proto::Tcp);
        // ip + udp
        let (t, p, proto) = parse_allow("192.168.10.165:1234/udp").unwrap();
        assert!(matches!(t, Target::Ip(_)));
        assert_eq!((p.from, p.to), (1234, 1234));
        assert_eq!(proto, Proto::Udp);
        // cidr + port range
        let (t, p, _) = parse_allow("151.101.0.0/16:80-443").unwrap();
        assert!(matches!(t, Target::Net(_)));
        assert_eq!((p.from, p.to), (80, 443));
        // bare target = all ports
        let (t, p, _) = parse_allow("198.51.100.7").unwrap();
        assert!(p.is_all());
        assert!(matches!(t, Target::Ip(_)));
        // errors: garbage, inverted range, empty
        assert!(parse_allow("").is_err());
        assert!(parse_allow("host:443-80").is_err());
        assert!(parse_allow("host:notaport").is_err());
    }

    #[test]
    fn root_resolves_and_missing_user_fails() {
        assert_eq!(resolve_uid("root").unwrap(), 0);
        assert!(resolve_uid("definitely-not-a-user-xyz").is_err());
    }
}
