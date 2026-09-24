//! The shared ledger-row vocabulary. Lives here (not in the daemon) because
//! the wire contract is exactly these shapes: `list.grants`, `list.pending`
//! and `list.history` serialize them verbatim, and tethys deserializes them
//! back — one struct definition, no string-indexed JSON on either side.

use serde::{Deserialize, Serialize};

use crate::types::Proto;

/// Grant states. Wire/DB spelling is snake_case (serde is the authority);
/// [`GrantState::ALL`] is the alloc-free spelling table behind `as_str`/`parse`,
/// pinned against serde by test so the two cannot drift silently.
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
    /// Every state with its wire spelling. One table serves both directions.
    pub const ALL: [(GrantState, &'static str); 5] = [
        (GrantState::Pending, "pending"),
        (GrantState::Approved, "approved"),
        (GrantState::Denied, "denied"),
        (GrantState::Expired, "expired"),
        (GrantState::Revoked, "revoked"),
    ];

    pub fn as_str(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|(s, _)| *s == self)
            .map(|(_, n)| *n)
            .unwrap()
    }
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().find(|(_, n)| *n == s).map(|(s, _)| *s)
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
    /// Alloc-free DB/wire spelling: known variants are the snake_case names
    /// serde emits (pinned by test); Unknown carries its original string.
    pub fn as_str(&self) -> &str {
        match self {
            DenyCode::HumanDenied => "human_denied",
            DenyCode::ApproverOffline => "approver_offline",
            DenyCode::ApproverTimeout => "approver_timeout",
            DenyCode::InstallFailed => "install_failed",
            DenyCode::RestartOrphan => "restart_orphan",
            DenyCode::RestartReconcile => "restart_reconcile",
            DenyCode::Unknown(s) => s,
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

    /// The alloc-free spelling table and serde agree, both directions —
    /// the drift guard the reviewer asked for.
    #[test]
    fn state_spellings_match_serde() {
        for s in GrantState::ALL.iter().map(|(s, _)| *s) {
            let ser = serde_json::to_value(s).unwrap();
            assert_eq!(serde_json::Value::String(s.as_str().into()), ser);
            assert_eq!(GrantState::parse(s.as_str()), Some(s));
        }
        assert_eq!(GrantState::parse("nope"), None);
    }

    #[test]
    fn deny_code_spellings_match_serde() {
        for c in [
            DenyCode::HumanDenied,
            DenyCode::ApproverOffline,
            DenyCode::ApproverTimeout,
            DenyCode::InstallFailed,
            DenyCode::RestartOrphan,
            DenyCode::RestartReconcile,
        ] {
            assert_eq!(
                serde_json::to_value(&c).unwrap(),
                serde_json::Value::String(c.as_str().into())
            );
            let back: DenyCode =
                serde_json::from_value(serde_json::Value::String(c.as_str().into())).unwrap();
            assert_eq!(back, c);
        }
        // pre-kebab spelling still loads
        let back: DenyCode = serde_json::from_value("restart-reconcile".into()).unwrap();
        assert_eq!(back, DenyCode::RestartReconcile);
        // unknown passes through (as_str and serde both preserve it verbatim)
        let u: DenyCode = serde_json::from_value("zzz".into()).unwrap();
        assert_eq!(u, DenyCode::Unknown("zzz".into()));
        assert_eq!(u.as_str(), "zzz");
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
