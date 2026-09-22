//! Wire protocol: MCP server <-> gatekeeper over NDJSON JSON-RPC 2.0.
//! Also defines the TUI-facing event/command surface (same envelope).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::types::{PortSpec, Proto};
use crate::wire::GrantState;

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

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum JsonRpcVersion {
    #[default]
    #[serde(rename = "2.0")]
    V2_0,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl RpcResponse {
    /// Success reply. A serialization failure degrades to a JSON-RPC internal
    /// error (-32603) rather than panicking — the daemon outlives any one
    /// unserializable result.
    pub fn ok(id: impl Into<String>, result: impl Serialize) -> Self {
        let id = id.into();
        match serde_json::to_value(result) {
            Ok(v) => Self {
                jsonrpc: JsonRpcVersion::V2_0,
                id,
                result: Some(v),
                error: None,
            },
            Err(e) => Self::err(id, -32603, format!("serialization failed: {e}")),
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
    /// operator allow list as parsed from config/CLI (what is installed in
    /// the baseline carve sets); read-only, no params
    pub const LIST_ALLOW: &str = "list.allow";
    pub const LIST_HISTORY: &str = "list.history";
    pub const STOP_GRANTS: &str = "stop.grants";
    pub const SUBSCRIBE: &str = "subscribe";
    // gatekeeper -> TUI (server push notifications; id omitted per JSON-RPC)
    pub const EV_REQUEST_NEW: &str = "grant.request.new";
    pub const EV_DECIDED: &str = "grant.decided";
    pub const EV_EXPIRED: &str = "grant.expired";
    /// Emergency stop swept N grants; not a per-grant decision.
    pub const EV_STOPPED: &str = "grants.stopped";
    pub const EV_TRAFFIC: &str = "traffic.stat";
    pub const EV_ERROR: &str = "gk.error";
}

// --------------------------------------------------------- admin.sock params
// Typed shapes for the commands the TUI sends. grant_id goes over the wire as
// a string; the lenient deserializer also accepts a JSON number so a
// hand-rolled `echo` on the socket works.

pub mod admin {
    use super::*;

    fn de_grant_id<'de, D>(d: D) -> Result<i64, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        match Value::deserialize(d)? {
            Value::String(s) => s.parse::<i64>().map_err(D::Error::custom),
            Value::Number(n) => n
                .as_i64()
                .ok_or_else(|| D::Error::custom("grant_id out of range")),
            _ => Err(D::Error::custom("grant_id must be a string or integer")),
        }
    }

    /// params of `approve`
    #[derive(Deserialize, Debug)]
    pub struct Approve {
        #[serde(deserialize_with = "de_grant_id")]
        pub grant_id: i64,
        #[serde(default)]
        pub ttl_secs: Option<u64>,
    }

    /// params of `deny`
    #[derive(Deserialize, Debug)]
    pub struct Deny {
        #[serde(deserialize_with = "de_grant_id")]
        pub grant_id: i64,
        #[serde(default)]
        pub note: Option<String>,
    }

    /// params of `revoke`
    #[derive(Deserialize, Debug)]
    pub struct GrantId {
        #[serde(deserialize_with = "de_grant_id")]
        pub grant_id: i64,
    }

    /// params of `list.history` (absent params = no filter, default page)
    #[derive(Deserialize, Debug, Default)]
    pub struct History {
        #[serde(default)]
        pub state: Option<GrantState>,
        #[serde(default)]
        pub limit: Option<u32>,
    }
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
    /// Replay of a request whose original grant is gone (expired/revoked).
    /// Caller must re-request under a new id.
    GrantExpired,
    /// The nftables install failed; the kernel keeps its prior state.
    InstallFailed,
    /// Replay of a request whose original is still awaiting a human decision:
    /// pending is not a grant, and the replay does not create a second popup.
    AlreadyPending,
}

/// Result of `access.request`. Internally tagged on `decision`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Verdict {
    /// New grant installed by this request.
    Approved {
        grant_id: String,
        effective: EffectiveGrant,
        ttl_granted: String,
        /// RFC3339 UTC expiry.
        expires_at: String,
    },
    /// Covered by an existing request/grant; no human round-trip.
    /// `expires_at` is absent only while the original is still pending.
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

// ------------------------------------------------------- admin event payloads
// One struct per broadcast so producer (daemon emit()) and consumer (gk-tui)
// share a compile-checked contract instead of agreeing on string keys.

/// `grant.request.new` — a request awaits human decision.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvRequestNew {
    pub grant_id: String,
    pub target: String,
    pub dst_port: PortSpec,
    pub proto: Proto,
    pub reason: String,
    pub tool: String,
    pub ttl_requested: String,
    /// lets a reconnecting TUI render honest "waiting m:ss"
    pub created_at: u64,
}

/// `grant.decided` — a row left pending/approved. Internally tagged on
/// `state`, so each decision carries exactly its own fields: no String state,
/// no nullable soup, and no `Option<Option<String>>` around `note` (that was
/// a serde artifact of sharing one struct with the stop broadcast — which is
/// now its own event, [`EvStopped`], on its own method).
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EvDecided {
    Approved {
        grant_id: String,
        ttl_granted: String,
        expires_at: String,
    },
    Denied {
        grant_id: String,
        reason_code: DenyReason,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    Revoked {
        grant_id: String,
    },
}

/// `grants.stopped` — stop.grants swept N grants. Not a per-grant decision.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvStopped {
    pub grants_removed: usize,
}

/// `grant.expired` — kernel TTL reaped the element.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvExpired {
    pub grant_id: String,
}

/// `traffic.stat` batch.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvTraffic {
    pub grants: Vec<GrantStat>,
}

/// `gk.error`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvError {
    pub message: String,
}

/// `subscribe` ack.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SubscribeAck {
    pub events: Vec<String>,
    pub approver_timeout_secs: u64,
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ev_decided_is_typed_per_state() {
        // internally tagged on `state`; each variant carries only its own fields
        let a = EvDecided::Approved {
            grant_id: "7".into(),
            ttl_granted: "10m".into(),
            expires_at: "2026-09-15T02:41:00Z".into(),
        };
        let j = serde_json::to_string(&a).unwrap();
        assert!(j.contains("\"state\":\"approved\""));
        assert!(!j.contains("reason_code") && !j.contains("grants_removed"));

        let d = EvDecided::Denied {
            grant_id: "8".into(),
            reason_code: DenyReason::HumanDenied,
            note: Some("out of scope".into()),
        };
        let j = serde_json::to_string(&d).unwrap();
        assert!(j.contains("\"state\":\"denied\"") && j.contains("\"note\":\"out of scope\""));
        // note is Option<String>: absent means absent, never a nested null
        assert!(!j.contains("null"));

        let r = EvDecided::Revoked {
            grant_id: "9".into(),
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(matches!(
            serde_json::from_str::<EvDecided>(&j),
            Ok(EvDecided::Revoked { .. })
        ));

        // stop broadcast is its own event with a required count
        let s = serde_json::to_value(EvStopped { grants_removed: 3 }).unwrap();
        assert_eq!(s["grants_removed"], 3);
        assert!(serde_json::from_value::<EvStopped>(serde_json::json!({})).is_err());
    }

    #[test]
    fn admin_params_are_typed() {
        // grant_id as string (canonical) and as number (hand-rolled echo)
        let a: admin::Approve =
            serde_json::from_value(serde_json::json!({"grant_id": "42"})).unwrap();
        assert_eq!((a.grant_id, a.ttl_secs), (42, None));
        let a: admin::Approve =
            serde_json::from_value(serde_json::json!({"grant_id": 7, "ttl_secs": 60})).unwrap();
        assert_eq!((a.grant_id, a.ttl_secs), (7, Some(60)));
        let d: admin::Deny =
            serde_json::from_value(serde_json::json!({"grant_id": "3", "note": "no"})).unwrap();
        assert_eq!((d.grant_id, d.note.as_deref()), (3, Some("no")));
        assert!(
            serde_json::from_value::<admin::GrantId>(serde_json::json!({"grant_id": "x"})).is_err()
        );
        // history: absent params default; typed state parse; bad state is an error
        let h: admin::History = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!((h.state, h.limit), (None, None));
        let h: admin::History =
            serde_json::from_value(serde_json::json!({"state": "denied", "limit": 5})).unwrap();
        assert!(matches!(h.state, Some(GrantState::Denied)));
        assert!(
            serde_json::from_value::<admin::History>(serde_json::json!({"state": "pending"}))
                .map(|h| h.state)
                .is_ok_and(|s| s == Some(GrantState::Pending))
        );
    }

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
        // internally tagged on `decision`
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
        assert_eq!(serde_json::from_str::<Verdict>(&s).unwrap(), a);

        // approved without effective must fail to parse
        let bad = r#"{"decision":"approved","grant_id":"7"}"#;
        assert!(serde_json::from_str::<Verdict>(bad).is_err());
    }
}
