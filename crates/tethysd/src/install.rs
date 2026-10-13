//! nftables install/teardown for grants: element resolution, accounting
//! chains, and per-grant object sweeps. The daemon's only writer of kernel
//! grant state (reconcile reads it).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use std::collections::BTreeSet;

use tethys_core::nft::{Batch, Dir, ElemDst, GrantElem, CHAIN_ACCT_IN, CHAIN_ACCT_OUT};
use tethys_core::protocol::EffectiveGrant;
use tethys_core::types::{Direction, PortSpec, Proto, Target};

use crate::ledger::{GrantRow, GrantState};
use crate::provision::{Mode, SET_DELEGATED_V4, SET_DELEGATED_V6};
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
    dir: Direction,
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
            dir,
        );
    }
    if !st.cfg.dry_run {
        st.nft.apply(&b).await.map_err(|e| e.to_string())?;
    }

    // Ingress in routed mode additionally delegates the port on the host.
    // Ordering is load-bearing: the ns-side element lands FIRST (delegation
    // never precedes its rule), and a delegation failure rolls the ns
    // elements back rather than reporting APPROVED with no inbound path.
    if dir.is_ingress() {
        if let Err(e) = delegated_add(st, &dsts, port).await {
            let mut rb = Batch::with_table(&st.cfg.nft_table);
            for d in &dsts {
                rb.delete_grant(
                    &GrantElem {
                        dst: d.clone(),
                        proto,
                        port,
                    },
                    dir,
                );
            }
            if !st.cfg.dry_run {
                if let Err(e2) = st.nft.apply(&rb).await {
                    tracing::error!(gid, %e2, "install rollback after delegation failure failed (TTL will reap)");
                }
            }
            return Err(e);
        }
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
    dir: Direction,
) {
    if st.cfg.dry_run {
        return;
    }
    // Delegation must never outlive the ns-side rule: drop the host port
    // FIRST, then the elements.
    if dir.is_ingress() {
        delegated_remove(st, dsts, port).await;
    }
    let mut b = Batch::with_table(&st.cfg.nft_table);
    for d in dsts {
        b.delete_grant(
            &GrantElem {
                dst: d.clone(),
                proto,
                port,
            },
            dir,
        );
    }
    if let Err(e) = st.nft.apply(&b).await {
        tracing::error!(%e, "uninstall_grant rollback failed (TTL will reap)");
    }
}

/// Flush all four carve sets (egress + ingress), resolve hostnames, install
/// both operator allow lists (`allow` -> carve_*, `allow_in` -> carve_in_*).
/// Adding an existing element aborts an nft batch, so resolved tuples are
/// deduped first; the in-force lists are snapshotted under the read lock
/// so a concurrent reload cannot mutate them mid-loop (kernel state then
/// matches one coherent snapshot). An entry that resolves to zero addresses
/// is an error, not a silent skip.
pub(crate) async fn install_carves(st: &Arc<State>) -> anyhow::Result<()> {
    let mut b = Batch::with_table(&st.cfg.nft_table);
    b.ensure_carve_sets();
    b.flush_carves();
    let mut n = 0usize;
    let mut seen: HashSet<(String, u8, u16, u16)> = Default::default();
    let allow = st.allow.read().await.clone();
    let allow_in = st.allow_in.read().await.clone();
    let entries = allow
        .iter()
        .map(|e| (e, Direction::Egress))
        .chain(allow_in.iter().map(|e| (e, Direction::Ingress)));
    for ((target, port, proto), dir) in entries {
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
                if dir.is_ingress() {
                    2
                } else if *proto == Proto::Tcp {
                    0
                } else {
                    1
                },
                port.from,
                port.to,
            );
            if !seen.insert(key) {
                tracing::warn!(target = %target.canonical(), "allow: duplicate tuple skipped");
                continue;
            }
            b.add_carve(
                &GrantElem {
                    dst: d.clone(),
                    proto: *proto,
                    port: *port,
                },
                dir,
            );
            n += 1;
        }
        tracing::info!(target = %target.canonical(), %proto, dir = dir.as_str(), ports = %format!("{}-{}", port.from, port.to), addrs = dsts.len(), "allow entry installed");
    }
    if !st.cfg.dry_run {
        st.nft
            .apply(&b)
            .await
            .map_err(|e| anyhow::anyhow!("carve install failed: {e}"))?;
    }
    tracing::info!(
        entries = allow.len() + allow_in.len(),
        elements = n,
        "operator allow lists installed"
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
/// (deletes are not idempotent); an ENOENT/EBUSY delete is ignored, so a
/// dead object may linger until the next wipe.
pub(crate) async fn sweep_grant_objs(st: &Arc<State>, gid: i64) {
    use tethys_core::nft::acct_set;
    if st.cfg.dry_run {
        return;
    }
    let mut names: Vec<(bool, String)> = Vec::new();
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

// ------------------------------------------------- delegated-port projection
//
// Routed mode carries inbound to the namespace through a host prerouting
// DNAT rule keyed on `delegated_v4`/`delegated_v6` (created by
// `tethysd provision`). Every live ingress grant — and every allow_in port —
// must have its port delegated on the host for exactly as long as its
// ns-side rule exists: installs add the ns element first, then delegate;
// teardowns undelegate first, then remove. Uniqueness is enforced per
// family at install time: a port already delegated (by another grant or by
// allow_in) is refused rather than silently shared — the holder cannot tell
// the kernel who else is relying on its element.

/// True when this deployment maintains host-side delegated-port sets
/// (routed mode, real kernel). Bridge mode has real inbound addressing and
/// no DNAT chain; dry-run touches nothing.
pub(crate) fn projection_active(st: &State) -> bool {
    !st.cfg.dry_run
        && st
            .cfg
            .netns
            .as_ref()
            .is_some_and(|s| matches!(s.mode, Mode::Routed(_)))
}

/// The delegated sets the given destination families require.
fn delegation_sets(dsts: &[ElemDst]) -> Vec<&'static str> {
    let mut v = Vec::new();
    if dsts.iter().any(|d| !d.is_v6()) {
        v.push(SET_DELEGATED_V4);
    }
    if dsts.iter().any(|d| d.is_v6()) {
        v.push(SET_DELEGATED_V6);
    }
    v
}

/// One inet_service interval element.
type PortRange = (u16, u16);

/// First live interval overlapping `want` (inclusive interval overlap).
fn first_overlap(want: PortRange, live: &[PortRange]) -> Option<PortRange> {
    live.iter()
        .copied()
        .find(|(lo, hi)| *lo <= want.1 && want.0 <= *hi)
}

/// Exact-tuple diff of desired vs observed port intervals: (to_add,
/// to_delete). Intervals are compared verbatim — nft element ops are not
/// idempotent, so only exactly-present elements are deleted and only
/// exactly-absent ones added.
fn diff_ports(desired: &[PortRange], observed: &[PortRange]) -> (Vec<PortRange>, Vec<PortRange>) {
    let d: BTreeSet<PortRange> = desired.iter().copied().collect();
    let o: BTreeSet<PortRange> = observed.iter().copied().collect();
    (
        d.difference(&o).copied().collect(),
        o.difference(&d).copied().collect(),
    )
}

/// Check uniqueness, then add the port to each family's delegated set
/// (one host batch). Errors: collision (naming the holder set) or apply
/// failure. No-op when the projection is inactive.
async fn delegated_add(st: &Arc<State>, dsts: &[ElemDst], port: PortSpec) -> Result<(), String> {
    if !projection_active(st) {
        return Ok(());
    }
    let want = port.nft_range();
    let mut b = Batch::with_table(&st.cfg.nft_table);
    for set in delegation_sets(dsts) {
        let live = st
            .host_nft
            .set_ports(&st.cfg.nft_table, set)
            .await
            .map_err(|e| format!("read {set}: {e}"))?;
        if let Some((lo, hi)) = first_overlap(want, &live) {
            return Err(format!(
                "delegated port {lo}-{hi} in {set} is already held (one holder per port per family)"
            ));
        }
        b.add_port(set, &port);
    }
    st.host_nft
        .apply(&b)
        .await
        .map_err(|e| format!("delegation add: {e}"))
}

/// Best-effort teardown mirror of [`delegated_add`]: poll each family's set
/// and delete only exactly-present matching intervals (element deletes
/// abort a batch on ENOENT).
pub(crate) async fn delegated_remove(st: &Arc<State>, dsts: &[ElemDst], port: PortSpec) {
    if !projection_active(st) {
        return;
    }
    let want = port.nft_range();
    let mut b = Batch::with_table(&st.cfg.nft_table);
    let mut any = false;
    for set in delegation_sets(dsts) {
        match st.host_nft.set_ports(&st.cfg.nft_table, set).await {
            Ok(live) => {
                if live.contains(&want) {
                    b.delete_port(set, &port);
                    any = true;
                }
            }
            Err(e) => tracing::warn!(%e, set, "delegated_remove: poll failed (skipping delete)"),
        }
    }
    if any {
        if let Err(e) = st.host_nft.apply(&b).await {
            tracing::error!(%e, "delegation delete failed (stale delegation is safe: ns policy still gates)");
        }
    }
}

/// Rebuild both delegated sets to exactly mirror
/// live ingress grants ∪ allow_in ports. Called at boot (after reconcile,
/// so adopted rows are in the mirror), after reload.allow, and after
/// stop.grants. Deletes and adds go in separate batches so one failed
/// batch cannot block the other; a concurrent install racing this diff may
/// abort one batch (element exists / ENOENT) — logged, self-heals on the
/// next rebuild, and every failure mode drops toward "under-delegated",
/// which fails closed.
pub(crate) async fn project_delegated(st: &Arc<State>) -> anyhow::Result<()> {
    if !projection_active(st) {
        return Ok(());
    }
    let mut desired: std::collections::BTreeMap<&'static str, Vec<PortRange>> = Default::default();
    let mut want = |dsts: &[ElemDst], port: PortSpec| {
        let r = port.nft_range();
        for set in delegation_sets(dsts) {
            desired.entry(set).or_default().push(r);
        }
    };
    for (target, port, _) in st.allow_in.read().await.iter() {
        let dsts = target_elems(target)
            .await
            .map_err(|e| anyhow::anyhow!("allow_in {}: {e}", target.canonical()))?;
        want(&dsts, *port);
    }
    for row in st.ledger.list(GrantState::Approved).await {
        if !row.dir.is_ingress() {
            continue;
        }
        let dsts = row_elems(&row)
            .await
            .map_err(|e| anyhow::anyhow!("grant {}: {e}", row.id))?;
        want(
            &dsts,
            PortSpec {
                from: row.port_from,
                to: row.port_to,
            },
        );
    }
    for set in [SET_DELEGATED_V4, SET_DELEGATED_V6] {
        let observed = st
            .host_nft
            .set_ports(&st.cfg.nft_table, set)
            .await
            .map_err(|e| anyhow::anyhow!("read {set}: {e}"))?;
        let (add, del) = diff_ports(&desired.get(set).cloned().unwrap_or_default(), &observed);
        if !del.is_empty() {
            let mut b = Batch::with_table(&st.cfg.nft_table);
            for (lo, hi) in &del {
                b.delete_port(set, &PortSpec { from: *lo, to: *hi });
            }
            st.host_nft
                .apply(&b)
                .await
                .map_err(|e| anyhow::anyhow!("projection delete {set}: {e}"))?;
        }
        if !add.is_empty() {
            let mut b = Batch::with_table(&st.cfg.nft_table);
            for (lo, hi) in &add {
                b.add_port(set, &PortSpec { from: *lo, to: *hi });
            }
            st.host_nft
                .apply(&b)
                .await
                .map_err(|e| anyhow::anyhow!("projection add {set}: {e}"))?;
        }
        if !add.is_empty() || !del.is_empty() {
            tracing::info!(
                set,
                added = add.len(),
                removed = del.len(),
                "delegated-port projection updated"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Projection diff is exact-tuple (nft element ops are not idempotent),
    // overlap detection is inclusive on both ends, and family selection
    // mirrors the dst families exactly.
    #[test]
    fn delegation_diff_overlap_and_families() {
        assert_eq!(
            diff_ports(&[(80, 80), (443, 443)], &[(443, 443), (993, 993)]),
            (vec![(80, 80)], vec![(993, 993)])
        );
        assert_eq!(diff_ports(&[], &[]), (vec![], vec![]));
        assert_eq!(diff_ports(&[(1, 5)], &[(1, 5)]), (vec![], vec![]));

        assert_eq!(first_overlap((80, 90), &[(1, 79), (91, 100)]), None);
        assert_eq!(first_overlap((80, 90), &[(90, 95)]), Some((90, 95)));
        assert_eq!(first_overlap((80, 90), &[(70, 80)]), Some((70, 80)));
        assert_eq!(first_overlap((0, 65535), &[(443, 443)]), Some((443, 443)));
        assert_eq!(first_overlap((443, 443), &[(0, 65535)]), Some((0, 65535)));

        let v4 = ElemDst::Ip("1.2.3.4".parse().unwrap());
        let v6 = ElemDst::Ip("fe80::1".parse().unwrap());
        assert_eq!(
            delegation_sets(std::slice::from_ref(&v4)),
            vec![SET_DELEGATED_V4]
        );
        assert_eq!(
            delegation_sets(std::slice::from_ref(&v6)),
            vec![SET_DELEGATED_V6]
        );
        assert_eq!(
            delegation_sets(&[v4, v6]),
            vec![SET_DELEGATED_V4, SET_DELEGATED_V6]
        );
    }

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
