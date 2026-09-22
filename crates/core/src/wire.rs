//! The shared ledger-row vocabulary. Lives here (not in the daemon) because
//! the wire contract is exactly these shapes: `list.grants`, `list.pending`
//! and `list.history` serialize them verbatim, and gk-tui deserializes them
//! back — one struct definition, no string-indexed JSON on either side.

use serde::{Deserialize, Serialize};

use crate::types::Proto;

/// Grant states. Wire/DB spelling is snake_case (serde is the single
/// spelling authority; `as_str` is an alloc-free view of it, pinned by test).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    Pending,
    Approved,
    Denied,
    /// Kernel TTL reaped the element.
    Expired,
    /// Operator kill (revoke / stop.grants).
    Revoked,
}

impl GrantState {
    pub fn as_str(self) -> &'static str {
        match self {
            GrantState::Pending => "pending",
            GrantState::Approved => "approved",
            GrantState::Denied => "denied",
            GrantState::Expired => "expired",
            GrantState::Revoked => "revoked",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        serde_json::from_value::<GrantState>(serde_json::Value::String(s.to_string())).ok()
    }
}

/// Why a grant was denied. Unknown codes load as `Unknown` rather than
/// dropping the row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyCode {
    HumanDenied,
    ApproverOffline,
    ApproverTimeout,
    InstallFailed,
    RestartOrphan,
    /// Boot reconcile found an approved row with no live attributed element.
    /// Alias keeps rows written by the pre-kebab spelling loadable.
    #[serde(alias = "restart-reconcile")]
    RestartReconcile,
    #[serde(untagged)]
    Unknown(String),
}

impl DenyCode {
    /// Wire/DB spelling comes from serde alone (snake_case); Unknown carries
    /// its original string through untouched.
    pub fn as_str(&self) -> String {
        match self {
            DenyCode::Unknown(s) => s.clone(),
            known => serde_json::to_value(known)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| "unknown".into()),
        }
    }
}

/// One ledger row, as stored and as served on admin.sock.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrantRow {
    pub id: i64,
    #[serde(default)]
    pub idem_key: Option<String>,
    pub target: String,
    /// installed destinations (post-resolution), as JSON array of strings
    pub dst_json: String,
    pub port_from: u16,
    pub port_to: u16,
    pub proto: Proto,
    pub reason: String,
    pub tool: String,
    pub ttl_secs: u64,
    #[serde(default)]
    pub granted_ttl_secs: Option<u64>,
    pub state: GrantState,
    pub created_at: u64,
    #[serde(default)]
    pub expires_at: Option<f64>, // unix seconds
    #[serde(default)]
    pub deny_code: Option<DenyCode>,
    #[serde(default)]
    pub note: Option<String>,
}

/// `list.pending` row: the ledger row plus whether a live decision channel
/// exists (only waiting rows are decidable).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingRowWire {
    #[serde(flatten)]
    pub row: GrantRow,
    pub waiting: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_spellings_match_serde() {
        for s in [
            GrantState::Pending,
            GrantState::Approved,
            GrantState::Denied,
            GrantState::Expired,
            GrantState::Revoked,
        ] {
            let ser = serde_json::to_value(s).unwrap();
            assert_eq!(serde_json::Value::String(s.as_str().into()), ser);
            assert_eq!(GrantState::parse(s.as_str()), Some(s));
        }
    }

    #[test]
    fn deny_code_roundtrip_and_alias() {
        for c in [
            DenyCode::HumanDenied,
            DenyCode::ApproverOffline,
            DenyCode::RestartReconcile,
        ] {
            let s = c.as_str();
            let back: DenyCode = serde_json::from_value(serde_json::Value::String(s)).unwrap();
            assert_eq!(back, c);
        }
        // pre-kebab spelling still loads
        let back: DenyCode =
            serde_json::from_value("restart-reconcile".into()).unwrap();
        assert_eq!(back, DenyCode::RestartReconcile);
        // unknown passes through
        let u: DenyCode = serde_json::from_value("zzz".into()).unwrap();
        assert_eq!(u, DenyCode::Unknown("zzz".into()));
    }

    #[test]
    fn pending_row_flattens() {
        let row = GrantRow {
            id: 7,
            idem_key: None,
            target: "ip:192.0.2.1".into(),
            dst_json: "[]".into(),
            port_from: 443,
            port_to: 443,
            proto: Proto::Tcp,
            reason: "r".into(),
            tool: "t".into(),
            ttl_secs: 60,
            granted_ttl_secs: None,
            state: GrantState::Pending,
            created_at: 1,
            expires_at: None,
            deny_code: None,
            note: None,
        };
        let v = serde_json::to_value(PendingRowWire { row, waiting: true }).unwrap();
        assert_eq!(v["waiting"], true);
        assert_eq!(v["id"], 7);
        assert!(!v.as_object().unwrap().contains_key("row"), "must flatten");
    }
}
