mod config;
mod ledger;
mod server;

use std::path::PathBuf;

use clap::Parser;
pub use config::FileConfig;

#[derive(Parser, Debug)]
#[command(name = "gatekeeper", about = "pentest scope enforcement daemon")]
pub struct Cli {
    /// TOML config file (see config.example.toml)
    #[arg(long, default_value = "/etc/gatekeeper/config.toml")]
    pub config: PathBuf,
    #[arg(long)]
    pub mcp_socket: Option<PathBuf>,
    #[arg(long)]
    pub admin_socket: Option<PathBuf>,
    #[arg(long)]
    pub db: Option<PathBuf>,
    #[arg(long)]
    pub max_ttl: Option<String>,
    #[arg(long)]
    pub approver_timeout_secs: Option<u64>,
    /// username that runs gk-mcp; connections on mcp.sock must come from a
    /// process with this uid (resolved at startup)
    #[arg(long)]
    pub mcp_user: Option<String>,
    /// user of the pentest agent workload (configurable name, default hermes-agent)
    #[arg(long)]
    pub agent_user: Option<String>,
    /// operator allow-list entry (repeatable); same grammar as config `allow`
    /// (e.g. --allow api.anthropic.com:443 --allow 192.168.10.165:1234)
    #[arg(long = "allow")]
    pub allow: Vec<String>,
    /// don't fail startup if configured users are missing (dev only)
    #[arg(long)]
    pub allow_missing_users: bool,
    /// dev/test: run without installing nft objects (state machine only)
    #[arg(long)]
    pub dry_run: bool,
}

/// merged view: file + CLI overrides, with resolved uids where needed.
#[derive(Debug, Clone)]
pub struct Config {
    pub mcp_socket: PathBuf,
    pub admin_socket: PathBuf,
    pub db: PathBuf,
    pub max_ttl: String,
    pub approver_timeout_secs: u64,
    pub agent_user: String,
    /// resolved uid of the pentest agent (None until the account exists)
    pub agent_uid: Option<u32>,
    pub mcp_user: String,
    /// Some(uid) => only that uid is accepted on mcp.sock; None => accept all (dev)
    pub mcp_peer_uid: Option<u32>,
    /// group that may connect to mcp.sock (mcp_user's primary gid);
    /// None => owner-only socket (dev)
    pub mcp_sock_gid: Option<u32>,
    /// operator allow list, parsed at startup (a bad entry aborts boot —
    /// silently ignoring it would defeat the point of declaring it)
    pub allow: Vec<(gk_core::types::Target, gk_core::types::PortSpec, gk_core::types::Proto)>,
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
        mcp_socket: cli.mcp_socket.unwrap_or(file.mcp_socket),
        admin_socket: cli.admin_socket.unwrap_or(file.admin_socket),
        db: cli.db.unwrap_or(file.db),
        max_ttl: cli.max_ttl.unwrap_or(file.max_ttl),
        approver_timeout_secs: cli
            .approver_timeout_secs
            .unwrap_or(file.approver_timeout_secs),
        agent_user: cli.agent_user.unwrap_or(file.agent_user),
        agent_uid: None,
        mcp_user: cli.mcp_user.unwrap_or(file.mcp_user),
        mcp_peer_uid: None,
        mcp_sock_gid: None,
        allow: Vec::new(),
        dry_run: cli.dry_run || file.dry_run,
    };

    // Allow list: CLI entries replace the file's (same precedence rule as
    // every other knob). Parse eagerly — an unparseable entry is fatal.
    let allow_src = if cli.allow.is_empty() { &file.allow } else { &cli.allow };
    for entry in allow_src {
        cfg.allow.push(
            config::parse_allow(entry)
                .map_err(|e| anyhow::anyhow!("config `allow`: {e}"))?,
        );
    }

    // Identity resolution: a named-but-missing mcp user is fatal, since
    // accepting any peer would defeat the uid check on mcp.sock.
    match config::resolve_uid(&cfg.mcp_user) {
        Ok(uid) => {
            cfg.mcp_peer_uid = Some(uid);
            cfg.mcp_sock_gid = config::resolve_gid(&cfg.mcp_user).ok();
        }
        Err(e) if cli.allow_missing_users => {
            tracing::warn!(%e, "--allow-missing-users: mcp.sock peer pin DISABLED (dev only!)");
        }
        Err(e) => return Err(e),
    }
    // agent user may legitimately not exist yet at first boot before the
    // harness provisions it — warn, don't block enforcement plumbing.
    match config::resolve_uid(&cfg.agent_user) {
        Ok(uid) => cfg.agent_uid = Some(uid),
        Err(e) => tracing::warn!(%e, "agent_user unresolved until provisioned"),
    }

    tracing::info!(
        agent_user = %cfg.agent_user,
        agent_uid = ?cfg.agent_uid,
        mcp_user = %cfg.mcp_user,
        mcp_peer_uid = ?cfg.mcp_peer_uid,
        "identities resolved"
    );

    if let Some(parent) = cfg.mcp_socket.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    server::run(cfg).await
}
