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
            dry_run: false,
        }
    }
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
    fn root_resolves_and_missing_user_fails() {
        assert_eq!(resolve_uid("root").unwrap(), 0);
        assert!(resolve_uid("definitely-not-a-user-xyz").is_err());
    }
}
