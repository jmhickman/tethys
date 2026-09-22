//! Boot reconciliation: ledger follows kernel truth (see policy block on
//! `reconcile_on_boot`).

use std::collections::HashSet;
use std::sync::Arc;

use crate::ledger::{now_secs, Decide, DenyCode, GrantState};
use crate::server::State;

/// Parse a `gk:g<gid>` attribution comment.
fn grant_gid_of_comment(c: &Option<String>) -> Option<i64> {
    c.as_deref()?.strip_prefix("gk:g")?.parse().ok()
}

/// Reconcile ledger against kernel truth at startup (see policy block above).
pub(crate) async fn reconcile_on_boot(st: &Arc<State>) {
    let elements = match st.nft.poll_live(&st.cfg.nft_table).await {
        Ok(p) => p.elements,
        Err(e) => {
            // Can't read kernel: treat as no grants (fail closed).
            tracing::error!(%e, "reconcile: cannot read nft state; reaping all ledger rows");
            Vec::new()
        }
    };
    let live_gids: HashSet<i64> = elements
        .iter()
        .filter_map(|el| grant_gid_of_comment(&el.comment))
        .collect();

    // Adopt approved rows iff a live attributed element exists and expiry has not passed.
    let now = now_secs() as f64;
    let mut adopted: HashSet<i64> = HashSet::new();
    for g in st.ledger.list(GrantState::Approved).await {
        let adopt = live_gids.contains(&g.id) && g.expires_at.map(|e| e > now).unwrap_or(false);
        if adopt {
            adopted.insert(g.id);
            tracing::info!(gid = g.id, target = %g.target, "reconcile: adopted live kernel grant");
            continue;
        }
        st.ledger
            .decide(
                g.id,
                Decide::ReapRestart {
                    at: now,
                    note: Some("restart-reconcile".into()),
                },
            )
            .await;
        st.ledger.audit(
            "reconcile",
            g.id,
            format!(
                "reaped: {} -> expired (no live attributed element or lapsed)",
                g.target
            ),
        );
        tracing::info!(gid = g.id, "reconcile: reaped stale approved row");
    }

    // Pending cannot survive restart: oneshot channels died with the process.
    for g in st.ledger.list(GrantState::Pending).await {
        st.ledger
            .decide(
                g.id,
                Decide::Deny {
                    code: DenyCode::RestartOrphan,
                    note: Some("daemon restarted before decision".into()),
                },
            )
            .await;
        st.ledger
            .audit("reconcile", g.id, "pending row denied: orphaned by restart");
    }

    // Orphaned live elements (crash between nft apply and ledger flip): leave
    // for kernel TTL. Unattributed elements: warn only.
    for el in &elements {
        match grant_gid_of_comment(&el.comment) {
            Some(gid) if !adopted.contains(&gid) => {
                tracing::warn!(gid, dst = %el.dst, ttl = el.expires_secs,
                    "reconcile: orphaned grant element left for kernel TTL (no corrective action)");
            }
            None => {
                tracing::warn!(dst = %el.dst,
                    "reconcile: unattributed element in grant set (left alone; check table ownership)");
            }
            _ => {}
        }
    }

    // Accounting is derived state (counters only) — rebuild from the adopted set.
    if let Err(e) = crate::install::rebuild_acct(st).await {
        tracing::warn!(%e, "reconcile: acct rebuild failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comment_attribution_parse() {
        assert_eq!(grant_gid_of_comment(&Some("gk:g42".into())), Some(42));
        assert_eq!(grant_gid_of_comment(&Some("gk:g-1".into())), Some(-1));
        assert_eq!(grant_gid_of_comment(&Some("other".into())), None);
        assert_eq!(grant_gid_of_comment(&None), None);
    }
}
