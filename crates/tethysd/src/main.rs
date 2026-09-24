mod admin;
mod config;
mod install;
mod ledger;
mod reconcile;
mod server;

use std::path::PathBuf;

use clap::Parser;
use config::FileConfig;

#[derive(Parser, Debug)]
#[command(name = "tethysd", version, about = "pentest scope enforcement daemon")]
pub struct Cli {
    /// TOML config file (see config.example.toml)
    #[arg(long, default_value = "/etc/tethys/config.toml")]
    pub config: PathBuf,
    #[arg(long)]
    pub mcp_socket: Option<PathBuf>,
    #[arg(long)]
    pub admin_socket: Option<PathBuf>,
    #[arg(long)]
    pub db: Option<PathBuf>,
    /// nftables table to own (default: tethys)
    #[arg(long)]
    pub nft_table: Option<String>,
    #[arg(long)]
    pub max_ttl: Option<String>,
    #[arg(long)]
    pub approver_timeout_secs: Option<u64>,
    /// user of the pentest agent workload (configurable name, default hermes-agent)
    #[arg(long)]
    pub agent_user: Option<String>,
    /// operator allow-list entry (repeatable); same grammar as config `allow`
    /// (e.g. --allow api.anthropic.com:443 --allow 192.168.1.5:1234)
    #[arg(long = "allow")]
    pub allow: Vec<String>,
    /// username allowed on admin.sock (SO_PEERCRED gate; default root)
    #[arg(long)]
    pub admin_user: Option<String>,
    /// don't fail startup if configured users are missing (dev only)
    #[arg(long)]
    pub allow_missing_users: bool,
    /// dev/test: run without installing nft objects (state machine only)
    #[arg(long)]
    pub dry_run: bool,
}

/// File + CLI overrides, with resolved uids.
#[derive(Debug, Clone)]
pub struct Config {
    /// the file the operator allow list reloads from (--config value)
    pub config_path: PathBuf,
    /// true when --allow flags replaced the file's list; reload.allow refuses
    pub allow_from_cli: bool,
    pub mcp_socket: PathBuf,
    pub admin_socket: PathBuf,
    pub db: PathBuf,
    /// nftables table this daemon owns (config `nft_table`)
    pub nft_table: String,
    pub max_ttl: String,
    pub approver_timeout_secs: u64,
    pub agent_user: String,
    /// resolved uid of the pentest agent (None until the account exists)
    pub agent_uid: Option<u32>,
    pub admin_user: String,
    /// resolved uid allowed on admin.sock besides the daemon's own euid
    /// (SO_PEERCRED gate; TOCTOU-001 defense-in-depth)
    pub admin_peer_uid: Option<u32>,
    /// Some(uid) => only that uid is accepted on mcp.sock (always
    /// agent_user's, when resolvable); None => accept all (dev fallback)
    pub mcp_peer_uid: Option<u32>,
    /// group that may connect to mcp.sock (agent_user's primary gid);
    /// None => owner-only socket (dev)
    pub mcp_sock_gid: Option<u32>,
    /// Operator allow list; a bad entry aborts boot.
    pub allow: Vec<(
        tethys_core::types::Target,
        tethys_core::types::PortSpec,
        tethys_core::types::Proto,
    )>,
    pub dry_run: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();

    // A parse error in an existing config file is fatal; a missing file
    // falls back to defaults with a warning.
    let file: FileConfig = match std::fs::read_to_string(&cli.config) {
        Ok(s) => toml::from_str(&s)
            .map_err(|e| anyhow::anyhow!("parse {}: {e}", cli.config.display()))?,
        Err(_) if cli.config.exists() => {
            anyhow::bail!("cannot read {}", cli.config.display());
        }
        Err(_) => {
            tracing::warn!(path = %cli.config.display(), "no config file; using built-in defaults");
            FileConfig::default()
        }
    };

    let mut cfg = Config {
        config_path: cli.config.clone(),
        allow_from_cli: !cli.allow.is_empty(),
        mcp_socket: cli.mcp_socket.unwrap_or(file.mcp_socket),
        admin_socket: cli.admin_socket.unwrap_or(file.admin_socket),
        db: cli.db.unwrap_or(file.db),
        nft_table: cli.nft_table.unwrap_or(file.nft_table),
        max_ttl: cli.max_ttl.unwrap_or(file.max_ttl),
        approver_timeout_secs: cli
            .approver_timeout_secs
            .unwrap_or(file.approver_timeout_secs),
        agent_user: cli.agent_user.unwrap_or(file.agent_user),
        agent_uid: None,
        admin_user: cli.admin_user.unwrap_or(file.admin_user),
        admin_peer_uid: None,
        mcp_peer_uid: None,
        mcp_sock_gid: None,
        allow: Vec::new(),
        dry_run: cli.dry_run || file.dry_run,
    };

    // Allow list: CLI entries replace the file's (same precedence rule as
    // every other knob). Parse eagerly — an unparseable entry is fatal.
    // (allow_from_cli was recorded on cfg above; reload.allow reads it there.)
    let allow_src = if cli.allow.is_empty() {
        &file.allow
    } else {
        &cli.allow
    };
    for entry in allow_src {
        cfg.allow.extend(
            config::parse_allow(entry).map_err(|e| anyhow::anyhow!("config `allow`: {e}"))?,
        );
    }

    // admin user: the socket's 0600 mode is the primary gate; this uid is
    // enforced per connection as defense-in-depth (TOCTOU-001). A missing
    // admin user is fatal unless dev mode opts out; either way the daemon's
    // own euid is always admitted (it owns the socket inode).
    match config::resolve_uid(&cfg.admin_user) {
        Ok(uid) => cfg.admin_peer_uid = Some(uid),
        Err(e) if cli.allow_missing_users => {
            tracing::warn!(%e, "--allow-missing-users: admin.sock gate = daemon euid only (dev only!)");
        }
        Err(e) => return Err(e),
    }
    // agent user may legitimately not exist yet at first boot before the
    // harness provisions it — warn, don't block enforcement plumbing. The
    // same uid is what mcp.sock pins peers to: in the stdio topology the
    // harness spawns tethys-mcp itself, so the connecting process shares
    // agent_user's uid by construction. Unresolved agent => no pin (accept
    // all), mirroring the host-wide fallback on the enforcement side.
    match config::resolve_uid(&cfg.agent_user) {
        Ok(uid) => {
            cfg.agent_uid = Some(uid);
            cfg.mcp_peer_uid = Some(uid);
            cfg.mcp_sock_gid = config::resolve_gid(&cfg.agent_user).ok();
        }
        Err(e) => {
            tracing::warn!(%e, "agent_user unresolved until provisioned (mcp.sock peer pin inactive)")
        }
    }

    tracing::info!(
        agent_user = %cfg.agent_user,
        agent_uid = ?cfg.agent_uid,
        mcp_peer_uid = ?cfg.mcp_peer_uid,
        admin_user = %cfg.admin_user,
        admin_peer_uid = ?cfg.admin_peer_uid,
        "identities resolved"
    );

    if let Some(parent) = cfg.mcp_socket.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("create {}: {e}", parent.display()))?;
    }
    server::run(cfg).await
}
