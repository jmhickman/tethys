//! Wire protocol: MCP server <-> gatekeeper over NDJSON JSON-RPC 2.0.
//! Also defines the TUI-facing event/command surface (same envelope).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::types::{PortSpec, Proto};

/// JSON-RPC 2.0 request envelope (client -> server).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RpcRequest {
    pub jsonrpc: JsonRpcVersion,
    pub id: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// JSON-RPC 2.0 response envelope (server -> client). `result` carries our
/// domain payloads; denial is an outcome *inside* a result, never a protocol error.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RpcResponse {
    pub jsonrpc: JsonRpcVersion,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsonRpcVersion {
    #[serde(rename = "2.0")]
    V2_0,
}

impl Default for JsonRpcVersion {
    fn default() -> Self {
        JsonRpcVersion::V2_0
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl RpcResponse {
    pub fn ok(id: impl Into<String>, result: impl Serialize) -> Self {
        Self {
            jsonrpc: JsonRpcVersion::V2_0,
            id: id.into(),
            result: Some(serde_json::to_value(result).expect("serializable")),
            error: None,
        }
    }
    pub fn err(id: impl Into<String>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: JsonRpcVersion::V2_0,
            id: id.into(),
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
            }),
        }
    }
}

// ---------------------------------------------------------------- methods

pub mod method {
    pub const ACCESS_REQUEST: &str = "access.request";
    // TUI -> gatekeeper
    pub const APPROVE: &str = "approve";
    pub const DENY: &str = "deny";
    pub const REVOKE: &str = "revoke";
    pub const LIST_GRANTS: &str = "list.grants";
    pub const LIST_PENDING: &str = "list.pending";
    pub const LIST_HISTORY: &str = "list.history";
    pub const STOP_GRANTS: &str = "stop.grants";
    pub const SUBSCRIBE: &str = "subscribe";
    // gatekeeper -> TUI (server push notifications; id omitted per JSON-RPC)
    pub const EV_REQUEST_NEW: &str = "grant.request.new";
    pub const EV_DECIDED: &str = "grant.decided";
    pub const EV_EXPIRED: &str = "grant.expired";
    pub const EV_TRAFFIC: &str = "traffic.stat";
    pub const EV_ERROR: &str = "gk.error";
}

/// params of `access.request` (MCP -> gatekeeper). Exactly one target field.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AccessRequestParams {
    #[serde(default)]
    pub dst_host: Option<String>,
    #[serde(default)]
    pub dst_ip: Option<String>,
    #[serde(default)]
    pub dst_net: Option<String>,
    pub dst_port: PortSpec,
    pub proto: Proto,
    pub reason: String,
    pub tool: String,
    /// ttl grammar: "15m"
    pub ttl_requested: String,
}

/// The IP or CIDR actually installed (post-resolution for host targets).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EffectiveGrant {
    pub dst: String,
    pub dst_port: PortSpec,
    pub proto: Proto,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    HumanDenied,
    ApproverOffline,
    ApproverTimeout,
    /// idempotent replay whose original grant is gone (expired/revoked) —
    /// the caller must re-request under a NEW id (R: re-delivery never re-popups).
    GrantExpired,
    /// The nftables install failed; the kernel keeps its prior state.
    InstallFailed,
    /// Replay of a request whose original is still awaiting a human decision:
    /// pending is not a grant, and the replay does not create a second popup.
    AlreadyPending,
}

/// Result of `access.request`, modeled as a sum type: "approved with no
/// effective grant" or "denied with no reason" cannot be constructed, and each
/// variant carries exactly the data that outcome has. The wire shape stays
/// internally tagged on `decision` so consumers keep matching `.decision`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Verdict {
    /// New grant installed in the kernel by this very request.
    Approved {
        grant_id: String,
        effective: EffectiveGrant,
        ttl_granted: String,
        /// RFC3339 UTC expiry.
        expires_at: String,
    },
    /// Covered by an existing request/grant — NO human round-trip happened.
    /// `expires_at` absent only while the original is still pending.
    AlreadyGranted {
        grant_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    Denied {
        reason_code: DenyReason,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
}

/// Server-push payload for `traffic.stat`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GrantStat {
    pub grant_id: String,
    pub name: String,
    /// installed destinations (post-resolution), as a real array on the wire.
    pub dst: Vec<String>,
    pub dst_port: PortSpec,
    pub proto: Proto,
    pub seconds_remaining: u64,
    /// seconds since this grant's counters last moved (poll granularity).
    pub secs_since_last_packet: Option<u64>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_params_roundtrip() {
        let j = r#"{"dst_ip":"177.15.45.214","dst_port":{"from":3306,"to":3306},
            "proto":"tcp","reason":"x","tool":"sqlmap","ttl_requested":"15m"}"#;
        let p: AccessRequestParams = serde_json::from_str(j).unwrap();
        assert_eq!(p.proto, Proto::Tcp);
        assert_eq!(p.dst_port.from, 3306);
        let back = serde_json::to_string(&p).unwrap();
        assert!(back.contains("\"proto\":\"tcp\""));
    }

    #[test]
    fn verdict_serde_shape() {
        // internally tagged on `decision`: consumers keep matching .decision,
        // but malformed combinations (denied + reason-less, approved - effective)
        // combinations like this are now impossible to construct.
        let d = Verdict::Denied {
            reason_code: DenyReason::ApproverOffline,
            grant_id: None,
            note: None,
        };
        let j = serde_json::to_string(&d).unwrap();
        assert!(j.contains("\"decision\":\"denied\""));
        assert!(j.contains("\"reason_code\":\"approver_offline\""));
        assert!(!j.contains("effective"));

        let a = Verdict::Approved {
            grant_id: "7".into(),
            effective: EffectiveGrant {
                dst: "203.0.113.7".into(),
                dst_port: PortSpec { from: 443, to: 443 },
                proto: Proto::Tcp,
            },
            ttl_granted: "10m".into(),
            expires_at: "2026-09-15T02:41:00Z".into(),
        };
        let s = serde_json::to_string(&a).unwrap();
        assert!(s.contains("\"decision\":\"approved\""));
        // the round-trip must be exact on both ends
        assert_eq!(serde_json::from_str::<Verdict>(&s).unwrap(), a);

        // an "approved" blob WITHOUT effective must fail to parse — the old
        // flat struct silently accepted it.
        let bad = r#"{"decision":"approved","grant_id":"7"}"#;
        assert!(serde_json::from_str::<Verdict>(bad).is_err());
    }
}
