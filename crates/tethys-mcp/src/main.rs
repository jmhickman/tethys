//! tethys-mcp: model-facing MCP server (stdio transport). It is a thin,
//! stateless proxy over the daemon's mcp.sock: request_traffic_grant
//! forwards access.request and returns the verdict string; list_traffic_grants
//! forwards access.list and renders the live grant table. It holds no
//! approval power and no netfilter access.

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

use tethys_core::protocol::{method, AccessRequestParams, JsonRpcVersion, RpcRequest};

#[derive(Parser, Debug)]
#[command(name = "tethys-mcp", version)]
struct Args {
    #[arg(long, default_value = "/run/tethys/mcp.sock")]
    daemon_socket: PathBuf,
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
    #[schemars(description = "Tool you will use (nmap, sqlmap, ...); shown to the approver")]
    pub tool: String,
    #[schemars(description = "Requested TTL: Ns/Nm/Nh grammar, e.g. 15m")]
    pub ttl: String,
    #[schemars(
        description = r#""egress" (default) = this host connecting OUT to the target; "ingress" = allow packets IN from the target source address to the listed LOCAL ports (dst_host/dst_ip/dst_net then name the SOURCE; dst_port the local service ports). Inbound grants still need human approval, and gate only while the daemon's netns enforcement boundary is active."#
    )]
    #[serde(default)]
    pub direction: Option<String>,
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
        description = "Request temporary network access for a pentest target. Egress by default; \
                       direction=\"ingress\" opens inbound to LOCAL ports from a source address \
                       (inbound gates only exist inside the netns enforcement boundary). BLOCKS \
                       until a human approver decides (or denies after timeout). Returns the \
                       EFFECTIVE grant (ttl/port may be reduced), so obey the return value, not \
                       your request. A revoked or expired grant also DESTROYS its established TCP \
                       flows: reconnect after revoke; never assume a live socket survives it."
    )]
    async fn request_traffic_grant(
        &self,
        Parameters(req): Parameters<GrantRequest>,
    ) -> Result<String, ErrorData> {
        tracing::debug!("tool call entered");
        // Direction is validated here (not just by the daemon) so a typo
        // is an instant -32602 instead of a 5-minute popup gamble. Absent
        // means egress — the wire grammar, same as the daemon's.
        let dir = match req.direction.as_deref() {
            None | Some("") => "egress".to_string(),
            Some(d) => {
                let d = d.to_ascii_lowercase();
                if d == "egress" || d == "ingress" {
                    d
                } else {
                    return Err(ErrorData::invalid_params(
                        format!("direction must be \"egress\" or \"ingress\", got {d:?}"),
                        None,
                    ));
                }
            }
        };
        let params = serde_json::json!({
            "dst_host": req.dst_host,
            "dst_ip": req.dst_ip,
            "dst_net": req.dst_net,
            "dst_port": req.dst_port,
            "proto": req.proto,
            "dir": dir,
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
            ErrorData::internal_error(format!("tethysd reply unparseable: {e}"), None)
        })?;

        if let Some(err) = v.get("error") {
            return Err(ErrorData::internal_error(
                err.get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("tethysd error")
                    .to_string(),
                None,
            ));
        }
        let r = v.get("result").cloned().unwrap_or_default();
        let verdict = render_verdict(&r);
        // Every decision point is also a map refresh: append the other live
        // grants so the model keeps current without being told to poll.
        // Strictly best-effort — a failed digest never corrupts a verdict.
        if verdict.starts_with("APPROVED") {
            if let Some(digest) = self.digest().await {
                return Ok(format!("{verdict}\n{digest}"));
            }
        }
        Ok(verdict)
    }

    /// One-line-per-other-grant digest for the verdict footer. None on any
    /// error (the verdict stands alone). Excludes the grant just approved,
    /// which the verdict line already describes.
    async fn digest(&self) -> Option<String> {
        let rpc = RpcRequest {
            jsonrpc: JsonRpcVersion::V2_0,
            id: format!("dig-{}", next_id()),
            method: method::ACCESS_LIST.into(),
            params: None,
        };
        let resp = self.ask(&rpc).await.ok()?;
        let v: serde_json::Value = serde_json::from_str(&resp).ok()?;
        let stats: Vec<tethys_core::protocol::GrantStat> =
            serde_json::from_value(v.get("result")?.clone()).ok()?;
        if stats.is_empty() {
            return None;
        }
        let items: Vec<String> = stats
            .iter()
            .map(|g| {
                // ingress reads as an opening FROM the named source
                let arrow = if g.dir == tethys_core::types::Direction::Ingress {
                    "←"
                } else {
                    ""
                };
                format!(
                    "{arrow}{}:{} {}m left",
                    g.name,
                    g.dst_port.from,
                    g.seconds_remaining.div_ceil(60)
                )
            })
            .collect();
        Some(format!("Other live grants: {}", items.join(", ")))
    }

    #[tool(
        description = "List this host's LIVE traffic grants with kernel-truth time \
                       remaining (M:SS). Call BEFORE relying on egress, and whenever an \
                       outbound connection fails unexpectedly, to tell 'grant expired' apart \
                       from 'target is down'. No approval round-trip — returns instantly."
    )]
    async fn list_traffic_grants(&self) -> Result<String, ErrorData> {
        tracing::debug!("list tool call entered");
        let rpc = RpcRequest {
            jsonrpc: JsonRpcVersion::V2_0,
            id: format!("lst-{}", next_id()),
            method: method::ACCESS_LIST.into(),
            params: None,
        };
        let resp = self.ask(&rpc).await?;
        let v: serde_json::Value = serde_json::from_str(&resp).map_err(|e| {
            ErrorData::internal_error(format!("tethysd reply unparseable: {e}"), None)
        })?;
        if let Some(err) = v.get("error") {
            return Err(ErrorData::internal_error(
                err.get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("tethysd error")
                    .to_string(),
                None,
            ));
        }
        Ok(render_grant_list(
            &v.get("result").cloned().unwrap_or_default(),
        ))
    }
}

impl ScopeMcp {
    /// Forward one RPC over the daemon socket and read the single reply
    /// line. The read deadline (6 minutes) only backstops a wedged daemon:
    /// tethysd denies at its own approver timeout first, so a normal call
    /// returns a verdict well before this fires.
    async fn ask(&self, rpc: &RpcRequest) -> Result<String, ErrorData> {
        tracing::debug!(id = %rpc.id, "connecting tethysd");
        let mut stream = UnixStream::connect(&self.sock)
            .await
            .map_err(|e| ErrorData::internal_error(format!("tethysd unavailable: {e}"), None))?;
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
            std::time::Duration::from_secs(6 * 60),
            reader.read_line(&mut line),
        )
        .await
        .map_err(|_| ErrorData::internal_error("tethysd response timed out", None))?
        .map_err(|e| ErrorData::internal_error(format!("read: {e}"), None))?;
        tracing::debug!(id = %rpc.id, bytes = n, "read reply line");
        if n == 0 {
            return Err(ErrorData::internal_error("tethysd closed connection", None));
        }
        Ok(line)
    }
}

/// Render the agent-side grant table from an access.list reply (array of
/// GrantStat). One line per grant, kernel-truth countdown; empty table is
/// stated in words so the model never has to parse "[]".
fn render_grant_list(r: &serde_json::Value) -> String {
    let stats: Vec<tethys_core::protocol::GrantStat> = match serde_json::from_value(r.clone()) {
        Ok(s) => s,
        Err(e) => return format!("ERROR: tethysd reply unparseable: {e}"),
    };
    if stats.is_empty() {
        return "No live grants. Egress is blocked; request one with \
                request_traffic_grant."
            .into();
    }
    let mut out = format!("Live grants ({}):\n", stats.len());
    for g in &stats {
        let proto = serde_json::to_value(g.proto)
            .ok()
            .and_then(|p| p.as_str().map(String::from))
            .unwrap_or_else(|| "?".into());
        let dir_tag = if g.dir == tethys_core::types::Direction::Ingress {
            " INBOUND"
        } else {
            ""
        };
        out.push_str(&format!(
            "  #{gid} [{tool}] {name}{dir_tag} {proto} {from}-{to} · {m}:{s:02} left\n",
            gid = g.grant_id,
            tool = if g.tool.is_empty() { "?" } else { &g.tool },
            name = g.name,
            m = g.seconds_remaining / 60,
            s = g.seconds_remaining % 60,
            from = g.dst_port.from,
            to = g.dst_port.to,
        ));
    }
    out.push_str("Expiry is kernel truth; re-request before a grant lapses mid-task.");
    if stats
        .iter()
        .any(|g| g.dir == tethys_core::types::Direction::Ingress)
    {
        out.push_str(
            "\nINBOUND grants gate packets only while the daemon's netns enforcement \
             boundary is active; egress is always enforced.",
        );
    }
    out
}

/// One-liner, e.g. "APPROVED: 203.0.113.7 tcp 443 granted for 15m (expires ...)".
fn render_verdict(r: &serde_json::Value) -> String {
    let v: tethys_core::protocol::Verdict = match serde_json::from_value(r.clone()) {
        Ok(v) => v,
        Err(e) => return format!("DENIED (malformed_verdict): tethysd reply unparseable: {e}"),
    };
    use tethys_core::protocol::Verdict as V;
    match v {
        V::Approved {
            effective,
            ttl_granted,
            expires_at,
            dir,
            ..
        } => {
            let inbound = if dir == tethys_core::types::Direction::Ingress {
                " INBOUND"
            } else {
                ""
            };
            format!(
                "APPROVED{inbound}: {} {} {}-{} granted for {ttl_granted} (expires {expires_at})",
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
            // The one deny the model can misread as "try again": with the
            // boundary down, no grant can gate anything, so say what to do.
            let boundary_down = reason_code == tethys_core::protocol::DenyReason::BoundaryInactive;
            let code = serde_json::to_value(reason_code)
                .ok()
                .and_then(|c| c.as_str().map(String::from))
                .unwrap_or_else(|| "denied".into());
            if boundary_down {
                let advice = "the netns enforcement boundary is not active, so nothing can \
                              be gated right now; ask the operator to restore it \
                              (systemctl status tethysd)";
                return match note {
                    Some(n) => format!("DENIED ({code}): {n} — {advice}"),
                    None => format!("DENIED ({code}): {advice}"),
                };
            }
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
            "You are sandboxed: ALL traffic is blocked by the kernel unless granted. \
             Egress is the default; direction='ingress' opens inbound packets FROM the \
             target TO local ports (for testing services on this host) — inbound gates \
             exist only inside the netns enforcement boundary, so they are active only \
             while the daemon reports one; a deny with reason 'boundary_inactive' means \
             enforcement is down and no request can succeed until the operator restores \
             it. Use request_traffic_grant before any network tool. One target per call; \
             waits for human approval; may be denied or reduced. Revocation and expiry \
             also destroy established TCP flows of the grant: reconnect after revoke, \
             never assume a live socket survives it. Re-request when expired. \
             list_traffic_grants shows live grants with kernel-truth time remaining: \
             call it when an outbound connection fails unexpectedly to tell an expired \
             grant from a dead target.",
        )
    }
}

/// Logs go to stderr: stdout is the MCP channel.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let server = ScopeMcp::new(args.daemon_socket);
    let service = server.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_list_rendering() {
        let empty = serde_json::json!([]);
        assert!(render_grant_list(&empty).starts_with("No live grants"));

        let two = serde_json::json!([
            {"grant_id":"9","name":"host:api.jina.ai","tool":"curl",
             "dst":["ip:104.26.10.242"],"dst_port":{"from":443,"to":443},"proto":"tcp",
             "dir":"egress","seconds_remaining":598,"bytes_sent":10,"bytes_received":20},
            {"grant_id":"10","name":"ip:192.168.10.2","tool":"ssh",
             "dst":["ip:192.168.10.2"],"dst_port":{"from":22,"to":22},"proto":"tcp",
             "dir":"ingress","seconds_remaining":60,"bytes_sent":0,"bytes_received":0}
        ]);
        let s = render_grant_list(&two);
        assert!(s.contains("Live grants (2)"), "{s}");
        assert!(
            s.contains("#9 [curl] host:api.jina.ai tcp 443-443 · 9:58 left"),
            "{s}"
        );
        // ingress row is marked, and its presence adds the boundary note
        assert!(s.contains("#10 [ssh] ip:192.168.10.2 INBOUND"), "{s}");
        assert!(s.contains("netns enforcement boundary is active"), "{s}");

        // rows without `tool` still deserialize (serde default)
        let legacy = serde_json::json!([
            {"grant_id":"1","name":"host:x","dst":[],"dst_port":{"from":80,"to":80},
             "proto":"tcp","dir":"egress","seconds_remaining":5,"bytes_sent":0,"bytes_received":0}
        ]);
        assert!(
            render_grant_list(&legacy).contains("[?]"),
            "missing tool renders ?"
        );

        let junk = serde_json::json!({"not": "an array"});
        assert!(render_grant_list(&junk).starts_with("ERROR:"));
    }

    #[test]
    fn verdict_rendering() {
        let v = serde_json::json!({
            "decision":"approved",
            "grant_id":"7",
            "effective":{"dst":"203.0.113.7","proto":"tcp","dst_port":{"from":443,"to":443}},
            "ttl_granted":"10m","expires_at":"2026-09-15T02:41:00Z","dir":"egress"});
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

        // dir is REQUIRED on approved verdicts (no version shims): the
        // model must always learn which way a gate opens.
        let ing = serde_json::json!({
            "decision":"approved",
            "grant_id":"8",
            "effective":{"dst":"203.0.113.7","proto":"tcp","dst_port":{"from":4444,"to":4444}},
            "ttl_granted":"5m","expires_at":"2026-09-15T02:41:00Z",
            "dir":"ingress"});
        assert!(
            render_verdict(&ing).starts_with("APPROVED INBOUND:"),
            "{}",
            render_verdict(&ing)
        );
        let nodir = serde_json::json!({
            "decision":"approved","grant_id":"8",
            "effective":{"dst":"1.2.3.4","proto":"tcp","dst_port":{"from":80,"to":80}},
            "ttl_granted":"5m","expires_at":"x"});
        assert!(render_verdict(&nodir).starts_with("DENIED (malformed_verdict)"));

        // boundary_inactive carries operator guidance, not just a code:
        // retrying against a down boundary is futile and the model must
        // be able to say why.
        let bi = serde_json::json!({"decision":"denied","reason_code":"boundary_inactive"});
        let s = render_verdict(&bi);
        assert!(s.contains("DENIED (boundary_inactive)"), "{s}");
        assert!(s.contains("not active") && s.contains("operator"), "{s}");
    }

    #[test]
    fn direction_arg_is_optional_egress_default() {
        let r: GrantRequest = serde_json::from_value(serde_json::json!({
            "dst_ip":"1.2.3.4","dst_port":{"from":0,"to":0},"proto":"tcp",
            "reason":"","tool":"","ttl":"5m"}))
        .unwrap();
        assert_eq!(r.direction, None);
        let r: GrantRequest = serde_json::from_value(serde_json::json!({
            "dst_ip":"1.2.3.4","dst_port":{"from":0,"to":0},"proto":"tcp",
            "reason":"","tool":"","ttl":"5m","direction":"ingress"}))
        .unwrap();
        assert_eq!(r.direction.as_deref(), Some("ingress"));
    }

    // Direction validation is client-side and happens BEFORE the daemon
    // is touched: a typo is an instant -32602, not a 5-minute popup
    // gamble. A valid direction gets past validation and fails only at
    // the (deliberately nonexistent) socket.
    #[tokio::test]
    async fn bad_direction_rejected_before_touching_daemon() {
        let mcp = ScopeMcp::new(PathBuf::from("/nonexistent-tethys-test.sock"));
        let base = serde_json::json!({
            "dst_ip":"1.2.3.4","dst_port":{"from":443,"to":443},"proto":"tcp",
            "reason":"r","tool":"curl","ttl":"5m"});
        let mut req: GrantRequest = serde_json::from_value(base.clone()).unwrap();
        req.direction = Some("intress".into()); // typo
        let e = mcp
            .request_traffic_grant(Parameters(req))
            .await
            .expect_err("typo must be rejected");
        // Assert the client-side validator's own wording: the typed
        // AccessRequestParams check downstream would also reject it with
        // a serde message, so a looser assert could not tell the two
        // layers apart (mutation-tested).
        assert!(e.message.starts_with("direction must be"), "{e:?}");
        assert!(
            !e.message.contains("unavailable"),
            "must fail at validation, not the socket"
        );

        let mut req: GrantRequest = serde_json::from_value(base).unwrap();
        req.direction = Some("Ingress".into()); // case-insensitive, passes
        let e = mcp
            .request_traffic_grant(Parameters(req))
            .await
            .expect_err("no daemon behind the test socket");
        assert!(e.message.contains("unavailable"), "{e:?}");
    }
}
