//! scopeadm: human admin CLI talking NDJSON JSON-RPC to the gatekeeper
//! admin socket (the same protocol the TUI uses). Provides list / pending /
//! approve / deny / revoke / history / stop, plus scripting-friendly output.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use gk_core::protocol::{method, JsonRpcVersion, RpcRequest};

#[derive(Parser)]
#[command(name = "scopeadm", about = "gatekeeper admin client")]
struct Args {
    #[arg(long, default_value = "/run/gatekeeper/admin.sock")]
    socket: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// list approved (active) grants
    List,
    /// stream pending-approval events until a decision is made interactively
    Pending,
    /// snapshot of pending rows (with `waiting`: has a live decidable channel)
    Pendings,
    Approve {
        grant_id: String,
        #[arg(long)]
        ttl_secs: Option<u64>,
    },
    Deny {
        grant_id: String,
        #[arg(long, default_value = "")]
        note: String,
    },
    Revoke {
        grant_id: String,
    },
    /// decided rows (denied/expired/revoked/approved-past), newest first
    History {
        #[arg(long)]
        state: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// emergency stop: remove ALL active grants (baseline rules untouched)
    Stop,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let stream = UnixStream::connect(&args.socket).await?;
    let (r, mut w) = stream.into_split();
    let mut lines = BufReader::new(r).lines();

    async fn call(
        w: &mut tokio::net::unix::OwnedWriteHalf,
        req: &RpcRequest,
    ) -> anyhow::Result<()> {
        let payload = format!("{}\n", serde_json::to_string(req)?);
        w.write_all(payload.as_bytes()).await?;
        Ok(())
    }

    match args.cmd {
        Cmd::List => {
            call(
                &mut w,
                &RpcRequest { jsonrpc: JsonRpcVersion::V2_0, id: "a1".into(), method: method::LIST_GRANTS.into(), params: None },
            )
            .await?;
            // events may precede our response; match on id.
            drain_until_id(&mut lines, "a1").await?;
        }
        Cmd::Approve { grant_id, ttl_secs } => {
            let mut params = serde_json::json!({"grant_id": grant_id});
            if let Some(t) = ttl_secs {
                params["ttl_secs"] = serde_json::json!(t);
            }
            call(
                &mut w,
                &RpcRequest { jsonrpc: JsonRpcVersion::V2_0, id: "a2".into(), method: method::APPROVE.into(), params: Some(params) },
            )
            .await?;
            drain_until_id(&mut lines, "a2").await?;
        }
        Cmd::Deny { grant_id, note } => {
            call(
                &mut w,
                &RpcRequest { jsonrpc: JsonRpcVersion::V2_0, id: "a3".into(), method: method::DENY.into(),
                    params: Some(serde_json::json!({"grant_id": grant_id, "note": note})) },
            )
            .await?;
            drain_until_id(&mut lines, "a3").await?;
        }
        Cmd::Revoke { grant_id } => {
            call(
                &mut w,
                &RpcRequest { jsonrpc: JsonRpcVersion::V2_0, id: "a4".into(), method: method::REVOKE.into(),
                    params: Some(serde_json::json!({"grant_id": grant_id})) },
            )
            .await?;
            drain_until_id(&mut lines, "a4").await?;
        }
        Cmd::History { state, limit } => {
            let mut params = serde_json::json!({"limit": limit});
            if let Some(s) = state {
                params["state"] = serde_json::json!(s);
            }
            call(
                &mut w,
                &RpcRequest { jsonrpc: JsonRpcVersion::V2_0, id: "a6".into(), method: method::LIST_HISTORY.into(),
                    params: Some(params) },
            )
            .await?;
            drain_until_id(&mut lines, "a6").await?;
        }
        Cmd::Stop => {
            call(
                &mut w,
                &RpcRequest { jsonrpc: JsonRpcVersion::V2_0, id: "a5".into(), method: method::STOP_GRANTS.into(), params: None },
            )
            .await?;
            drain_until_id(&mut lines, "a5").await?;
        }
        Cmd::Pendings => {
            call(
                &mut w,
                &RpcRequest { jsonrpc: JsonRpcVersion::V2_0, id: "a7".into(), method: method::LIST_PENDING.into(), params: None },
            )
            .await?;
            drain_until_id(&mut lines, "a7").await?;
        }
        Cmd::Pending => {
            // events stream until SIGINT; approve/deny by running other subcommands
            println!("streaming requests — approve with `scopeadm approve <id>`");
            while let Some(l) = lines.next_line().await? {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&l) {
                    if v["method"] == method::EV_REQUEST_NEW {
                        println!("\n⚠ NEW REQUEST {}", serde_json::to_string_pretty(&v["params"]).unwrap());
                    }
                }
            }
        }
    }
    Ok(())
}

async fn drain_until_id(
    lines: &mut tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    id: &str,
) -> anyhow::Result<()> {
    while let Some(l) = lines.next_line().await? {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&l) {
            if v.get("id").and_then(|i| i.as_str()) == Some(id) {
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
                return Ok(());
            }
        }
    }
    anyhow::bail!("connection closed before reply")
}
