//! nftables install/teardown for grants: element resolution, accounting
//! chains, and per-grant object sweeps. The daemon's only writer of kernel
//! grant state (reconcile reads it).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tethys_core::nft::{Batch, Dir, ElemDst, GrantElem, CHAIN_ACCT_IN, CHAIN_ACCT_OUT};
use tethys_core::protocol::EffectiveGrant;
use tethys_core::types::{PortSpec, Proto, Target};

use crate::ledger::{GrantRow, GrantState};
use crate::server::State;

/// Install kernel elements. Hosts are resolved here; the kernel gets IPs only.
/// Returns (effective view, installed dsts) for dst_json.
pub(crate) async fn install_grant(
    st: &Arc<State>,
    target: &Target,
    port_spec: PortSpec,
    gid: i64,
    proto: Proto,
    ttl: Duration,
) -> Result<(EffectiveGrant, Vec<ElemDst>), String> {
    let port = PortSpec {
        from: port_spec.from,
        to: port_spec.to,
    };
    let dsts = target_elems(target).await?;

    let mut b = Batch::with_table(&st.cfg.nft_table);
    for d in &dsts {
        b.add_grant(
            &GrantElem {
                dst: d.clone(),
                proto,
                port,
            },
            ttl,
            gid,
        );
    }
    if !st.cfg.dry_run {
        st.nft.apply(&b).await.map_err(|e| e.to_string())?;
    }
    let eff_dst = match &dsts[0] {
        ElemDst::Ip(ip) => ip.to_string(),
        ElemDst::Net(n) => n.to_string(),
    };
    Ok((
        EffectiveGrant {
            dst: eff_dst,
            dst_port: port,
            proto,
        },
        dsts,
    ))
}

/// Remove installed elements for a grant whose approval could not be pinned
/// (RESDISC-002 rollback). Best-effort: an uninstall failure is logged; the
/// kernel element still dies with its TTL.
pub(crate) async fn uninstall_grant(
    st: &Arc<State>,
    dsts: &[ElemDst],
    proto: Proto,
    port: PortSpec,
) {
    if st.cfg.dry_run {
        return;
    }
    let mut b = Batch::with_table(&st.cfg.nft_table);
    for d in dsts {
        b.delete_grant(&GrantElem {
            dst: d.clone(),
            proto,
            port,
        });
    }
    if let Err(e) = st.nft.apply(&b).await {
        tracing::error!(%e, "uninstall_grant rollback failed (TTL will reap)");
    }
}

/// Scope egress to `agent_user`. Unresolved uid => empty list => host-wide.
pub(crate) async fn install_scope(st: &Arc<State>) -> anyhow::Result<()> {
    let mut b = Batch::with_table(&st.cfg.nft_table);
    match st.cfg.agent_uid {
        Some(uid) => {
            b.rebuild_scope(&[uid]);
            tracing::info!(uid, user = %st.cfg.agent_user, "egress enforcement scoped to agent uid");
        }
        None => {
            b.rebuild_scope(&[]);
            tracing::warn!(
                user = %st.cfg.agent_user,
                "agent_user unresolved — enforcing host-wide (all uids policed)"
            );
        }
    }
    st.nft
        .apply(&b)
        .await
        .map_err(|e| anyhow::anyhow!("scope install failed: {e}"))
}

/// Flush carve sets, resolve hostnames, install the operator allow list.
pub(crate) async fn install_carves(st: &Arc<State>) -> anyhow::Result<()> {
    let mut b = Batch::with_table(&st.cfg.nft_table);
    b.ensure_carve_sets();
    b.flush_carves();
    let mut n = 0usize;
    // add-of-existing-element aborts an nft batch: dedupe resolved tuples
    let mut seen: HashSet<(String, u8, u16, u16)> = Default::default();
    // snapshot the in-force list: a concurrent reload must not mutate the
    // vec mid-loop (leaves kernel state matching one coherent snapshot)
    let allow = st.allow.read().await.clone();
    for (target, port, proto) in &allow {
        let dsts = target_elems(target)
            .await
            .map_err(|e| anyhow::anyhow!("allow {}: {e}", target.canonical()))?;
        anyhow::ensure!(
            !dsts.is_empty(),
            "allow {}: resolved to zero addresses",
            target.canonical()
        );
        for d in &dsts {
            let key = (
                d.canonical(),
                if *proto == Proto::Tcp { 0 } else { 1 },
                port.from,
                port.to,
            );
            if !seen.insert(key) {
                tracing::warn!(target = %target.canonical(), "allow: duplicate tuple skipped");
                continue;
            }
            b.add_carve(&GrantElem {
                dst: d.clone(),
                proto: *proto,
                port: *port,
            });
            n += 1;
        }
        tracing::info!(target = %target.canonical(), %proto, ports = %format!("{}-{}", port.from, port.to), addrs = dsts.len(), "allow entry installed");
    }
    if !st.cfg.dry_run {
        st.nft
            .apply(&b)
            .await
            .map_err(|e| anyhow::anyhow!("carve install failed: {e}"))?;
    }
    tracing::info!(
        entries = allow.len(),
        elements = n,
        "operator allow list installed"
    );
    Ok(())
}

pub(crate) async fn target_elems(t: &Target) -> Result<Vec<ElemDst>, String> {
    match t {
        Target::Ip(ip) => Ok(vec![ElemDst::Ip(*ip)]),
        Target::Net(n) => Ok(vec![ElemDst::Net(*n)]),
        Target::Host(h) => resolve_host(h).await,
    }
}

async fn resolve_host(h: &str) -> Result<Vec<ElemDst>, String> {
    let addrs = tokio::net::lookup_host((h, 0))
        .await
        .map_err(|e| format!("resolve {h}: {e}"))?;
    let mut out: Vec<ElemDst> = addrs.map(|a| ElemDst::Ip(a.ip())).collect();
    out.sort_by_key(|e| match e {
        ElemDst::Ip(ip) => ip.to_string(),
        _ => String::new(),
    });
    out.dedup();
    if out.is_empty() {
        return Err(format!("no addresses for host {h}"));
    }
    Ok(out)
}

/// Dsts for a ledger row: persisted dst_json when present, not a fresh lookup.
pub(crate) async fn row_elems(row: &GrantRow) -> Result<Vec<ElemDst>, String> {
    let stored: Vec<String> = serde_json::from_str(&row.dst_json).unwrap_or_default();
    if !stored.is_empty() {
        let out: Vec<ElemDst> = stored
            .iter()
            .filter_map(|s| ElemDst::from_canonical(s))
            .collect();
        if out.is_empty() {
            return Err(format!("dst_json unparseable: {}", row.dst_json));
        }
        return Ok(out);
    }
    target_elems(&parse_canonical_target(&row.target)?).await
}

/// Rebuild accounting chains from approved rows. Count-only; no verdicts.
pub(crate) async fn rebuild_acct(st: &Arc<State>) -> Result<(), String> {
    if st.cfg.dry_run {
        return Ok(());
    }
    let rows = st.ledger.list(GrantState::Approved).await;
    let mut b = Batch::with_table(&st.cfg.nft_table);
    b.flush_chain(CHAIN_ACCT_OUT);
    b.flush_chain(CHAIN_ACCT_IN);
    for g in &rows {
        let dsts = match row_elems(g).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(id = g.id, %e, "acct: dst resolution failed (stats only)");
                continue;
            }
        };
        let proto = g.proto;
        let port = PortSpec {
            from: g.port_from,
            to: g.port_to,
        };
        for dir in [Dir::Out, Dir::In] {
            for v6 in [false, true] {
                let fam: Vec<&ElemDst> = dsts.iter().filter(|d| d.is_v6() == v6).collect();
                if fam.is_empty() {
                    continue;
                }
                b.add_counter(&dir.counter(g.id));
                b.add_acct_set(g.id, dir, v6);
                for d in fam {
                    b.add_acct_elem(
                        g.id,
                        dir,
                        &GrantElem {
                            dst: d.clone(),
                            proto,
                            port,
                        },
                    );
                }
                b.add_acct_rule(g.id, dir, proto, v6);
            }
        }
    }
    st.nft.apply(&b).await.map_err(|e| e.to_string())
}

/// Sweep per-grant objects after a grant leaves approved.
/// Run after rebuild_acct so objects are unreferenced. One batch per object
/// (deletes are not idempotent).
pub(crate) async fn sweep_grant_objs(st: &Arc<State>, gid: i64) {
    use tethys_core::nft::acct_set;
    if st.cfg.dry_run {
        return;
    }
    let mut names: Vec<(bool, String)> = Vec::new(); // (is_counter, name)
    for dir in [Dir::Out, Dir::In] {
        for v6 in [false, true] {
            names.push((false, acct_set(gid, dir, v6)));
        }
        names.push((true, dir.counter(gid)));
    }
    for (is_counter, name) in names {
        let mut b = Batch::with_table(&st.cfg.nft_table);
        if is_counter {
            b.delete_counter(&name);
        } else {
            b.delete_set(&name);
        }
        // ENOENT/EBUSY: a dead object may linger until the next wipe.
        if let Err(e) = st.nft.apply(&b).await {
            tracing::debug!(gid, %e, obj = %name, "acct sweep delete (ignored)");
        }
    }
}

fn parse_canonical_target(t: &str) -> Result<Target, String> {
    if let Some(h) = t.strip_prefix("host:") {
        Ok(Target::Host(h.into()))
    } else if let Some(i) = t.strip_prefix("ip:") {
        i.parse().map(Target::Ip).map_err(|e| e.to_string())
    } else if let Some(n) = t.strip_prefix("net:") {
        n.parse().map(Target::Net).map_err(|e| e.to_string())
    } else {
        Err(format!("bad canonical target: {t}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_target_roundtrip() {
        for t in [
            Target::Host("example.com".into()),
            Target::Ip("10.0.0.1".parse().unwrap()),
            Target::Net("172.16.0.0/12".parse().unwrap()),
        ] {
            assert_eq!(parse_canonical_target(&t.canonical()).unwrap(), t);
        }
        assert!(parse_canonical_target("mac:aa:bb").is_err());
    }
}
