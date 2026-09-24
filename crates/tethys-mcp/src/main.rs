//! gk-mcp: model-facing MCP server (stdio transport). Exactly ONE tool.
//! It is a thin, stateless proxy: schema-validate → forward access.request to
//! the gatekeeper over the unix socket → return the verdict string. It holds
//! no approval power and no netfilter access.

use std::path::PathBuf;

use clap::Parser;
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{ServerCapabilities, ServerConfig},
    schemars,
    service::ServiceExt,
    tool, tool_handler, tool_router, ErrorData, ServerHandler,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use gk_core::protocol::{method, AccessRequestParams, JsonRpcVersion, RpcRequest};

#[derive(Parser, Debug)]
#[command(name = "gk-mcp")]
struct Args {
    #[arg(long, default_value = "/run/gatekeeper/mcp.sock")]
    gatekeeper_socket: PathBuf,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GrantRequest {
    #[schemars(description = "Target hostname; provide EXACTLY ONE of dst_host/dst_ip/dst_net")]
    #[serde(default)]
    pub dst_host: Option<String>,
    #[schemars(description = "Target IPv4/IPv6 address; exactly one target field required")]
    #[serde(default)]
    pub dst_ip: Option<String>,
    #[schemars(
        description = "Target CIDR, e.g. 203.0.113.0/24; exactly one target field required"
    )]
    #[serde(default)]
    pub dst_net: Option<String>,
    #[schemars(
        description = r#"Port spec object, e.g. {"from":443,"to":443}; all ports = {"from":0,"to":0}"#
    )]
    pub dst_port: serde_json::Value,
    #[schemars(description = "tcp or udp")]
    pub proto: String,
    #[schemars(
        description = "Why this traffic is needed for the engagement (shown verbatim to human approver)"
    )]
    pub reason: String,
    #[schemars(description = "Tool you will use (nmap, sqlmap, ...) — shown to approver")]
    pub tool: String,
    #[schemars(description = "Requested TTL: Ns/Nm/Nh grammar, e.g. 15m")]
    pub ttl: String,
}

pub struct ScopeMcp {
    sock: PathBuf,
}

#[tool_router]
impl ScopeMcp {
    fn new(sock: PathBuf) -> Self {
        Self { sock }
    }

    #[tool(
        description = "Request temporary network egress for a pentest target. BLOCKS until a human \
                       approver decides (or denies after timeout). Returns the EFFECTIVE grant \
                       (ttl/port may be reduced) — obey it, not your request."
    )]
    async fn request_traffic_grant(
        &self,
        Parameters(req): Parameters<GrantRequest>,
    ) -> Result<String, ErrorData> {
        tracing::debug!("tool call entered");
        let params = serde_json::json!({
            "dst_host": req.dst_host,
            "dst_ip": req.dst_ip,
            "dst_net": req.dst_net,
            "dst_port": req.dst_port,
            "proto": req.proto,
            "reason": req.reason,
            "tool": req.tool,
            "ttl_requested": req.ttl,
        });
        let _typed: AccessRequestParams = serde_json::from_value(params.clone())
            .map_err(|e| ErrorData::invalid_params(format!("bad request: {e}"), None))?;

        let id = format!("req-{}", next_id());
        let rpc = RpcRequest {
            jsonrpc: JsonRpcVersion::V2_0,
            id: id.clone(),
            method: method::ACCESS_REQUEST.into(),
            params: Some(params),
        };

        let resp = self.ask(&rpc).await?;
        tracing::debug!(%resp, "verdict received");
        let v: serde_json::Value = serde_json::from_str(&resp).map_err(|e| {
            ErrorData::internal_error(format!("gatekeeper reply unparseable: {e}"), None)
        })?;

        if let Some(err) = v.get("error") {
            return Err(ErrorData::internal_error(
                err.get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("gatekeeper error")
                    .to_string(),
                None,
            ));
        }
        let r = v.get("result").cloned().unwrap_or_default();
        Ok(render_verdict(&r))
    }
}

impl ScopeMcp {
    async fn ask(&self, rpc: &RpcRequest) -> Result<String, ErrorData> {
        tracing::debug!(id = %rpc.id, "connecting gatekeeper");
        let mut stream = UnixStream::connect(&self.sock)
            .await
            .map_err(|e| ErrorData::internal_error(format!("gatekeeper unavailable: {e}"), None))?;
        let payload = serde_json::to_string(rpc)
            .map(|s| format!("{s}\n"))
            .map_err(|e| ErrorData::internal_error(format!("serialize request: {e}"), None))?;
        stream
            .write_all(payload.as_bytes())
            .await
            .map_err(|e| ErrorData::internal_error(format!("write: {e}"), None))?;
        let mut line = String::new();
        let mut reader = BufReader::new(&mut stream);
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(6 * 60), // gatekeeper denies at its own timeout first
            reader.read_line(&mut line),
        )
        .await
        .map_err(|_| ErrorData::internal_error("gatekeeper response timed out", None))?
        .map_err(|e| ErrorData::internal_error(format!("read: {e}"), None))?;
        tracing::debug!(id = %rpc.id, bytes = n, "read reply line");
        if n == 0 {
            return Err(ErrorData::internal_error(
                "gatekeeper closed connection",
                None,
            ));
        }
        Ok(line)
    }
}

/// One-liner, e.g. "APPROVED: 203.0.113.7 tcp 443 granted for 15m (expires …)".
fn render_verdict(r: &serde_json::Value) -> String {
    let v: gk_core::protocol::Verdict = match serde_json::from_value(r.clone()) {
        Ok(v) => v,
        Err(e) => return format!("DENIED (malformed_verdict): gatekeeper reply unparseable: {e}"),
    };
    use gk_core::protocol::Verdict as V;
    match v {
        V::Approved {
            effective,
            ttl_granted,
            expires_at,
            ..
        } => {
            format!(
                "APPROVED: {} {} {}-{} granted for {ttl_granted} (expires {expires_at})",
                effective.dst,
                serde_json::to_value(effective.proto)
                    .ok()
                    .and_then(|p| p.as_str().map(String::from))
                    .unwrap_or_else(|| "?".into()),
                effective.dst_port.from,
                effective.dst_port.to,
            )
        }
        V::AlreadyGranted {
            grant_id,
            expires_at,
            note,
        } => {
            let mut s = format!("APPROVED (already active, grant {grant_id})");
            if let Some(e) = expires_at {
                s.push_str(&format!(" (expires {e})"));
            }
            if let Some(n) = note {
                s.push_str(&format!(" — {n}"));
            }
            s
        }
        V::Denied {
            reason_code, note, ..
        } => {
            let code = serde_json::to_value(reason_code)
                .ok()
                .and_then(|c| c.as_str().map(String::from))
                .unwrap_or_else(|| "denied".into());
            match note {
                Some(n) => format!("DENIED ({code}): {n}"),
                None => format!("DENIED ({code})"),
            }
        }
    }
}

fn next_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static C: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!("{nanos:x}{:x}", C.fetch_add(1, Ordering::Relaxed))
}

#[tool_handler]
impl ServerHandler for ScopeMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "You are sandboxed: ALL egress is blocked by the kernel unless granted. \
             Use request_traffic_grant before any network tool. One target per call; \
             waits for human approval; may be denied or reduced. Re-request when expired.",
        )
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr) // stdout is the MCP channel
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let server = ScopeMcp::new(args.gatekeeper_socket);
    let service = server.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_rendering() {
        let v = serde_json::json!({
            "decision":"approved",
            "grant_id":"7",
            "effective":{"dst":"203.0.113.7","proto":"tcp","dst_port":{"from":443,"to":443}},
            "ttl_granted":"10m","expires_at":"2026-09-15T02:41:00Z"});
        let s = render_verdict(&v);
        assert!(s.contains("APPROVED") && s.contains("203.0.113.7") && s.contains("10m"));

        let d = serde_json::json!({"decision":"denied","reason_code":"approver_offline"});
        assert_eq!(render_verdict(&d), "DENIED (approver_offline)");

        let dn = serde_json::json!({"decision":"denied","reason_code":"human_denied","note":"out of scope"});
        assert!(render_verdict(&dn).contains("out of scope"));

        let ag = serde_json::json!({"decision":"already_granted","grant_id":"9",
            "expires_at":"2026-09-15T02:41:00Z"});
        let s = render_verdict(&ag);
        assert!(s.contains("already active") && s.contains("grant 9"), "{s}");

        let bad = serde_json::json!({"decision":"approved","grant_id":"7"});
        assert!(render_verdict(&bad).starts_with("DENIED (malformed_verdict)"));
    }
}
