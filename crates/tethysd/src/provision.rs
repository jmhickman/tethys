//! `tethysd provision` — successor to `tethys-baseline.service`.
//!
//! Creates (idempotently) the agent account's dedicated network namespace,
//! wires it per mode ([`Mode::Routed`] by default), loads the base policy
//! INSIDE it through core's namespaced executor, and builds the minimal
//! host-stack projection: forward-accept for the veth pair, MASQUERADE for
//! ns egress in both families, and an empty delegated-port DNAT chain whose
//! elements tethysd maintains at runtime (step 3). Runs as `ExecStartPre=`;
//! if it fails the netns path is absent, systemd refuses to instantiate the
//! user manager, and agent login fails closed — the operator (root, outside
//! the namespace) is unaffected. Log loudly, exit non-zero.
//!
//! All subprocess work shells out to `ip`/`mount` with idempotent verbs
//! (`replace`, up-on-up); namespace-side commands funnel through one helper
//! that installs core's [`setns_pre_exec`] on the child — no netlink
//! dependency is added for this boot-time path.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde_json::{json, Value};

use tethys_core::nft::{setns_pre_exec, Batch, Netns, NftCli};

use crate::config::{FileConfig, NetnsFile};

/// Fixed ULA pair used for the veth when `[netns].prefix6` is unset. No
/// site routing required; NAT66 masquerade gives remotes the container's
/// GUA (step 9 docs). Enforcement guarantees are identical either way —
/// only the address remote peers see changes.
pub const DEFAULT_V6_ULA: &str = "fc9a:5445:5448::/64";

/// IFNAMSIZ minus NUL; a longer name makes every `ip link` call fail with a
/// cryptic EINVAL, so config validation catches it here instead.
const IFNAMSIZ: usize = 15;

pub const HOST_CHAIN_FWD: &str = "host_fwd";
pub const HOST_CHAIN_DNAT: &str = "delegated";
pub const HOST_CHAIN_MASQ: &str = "host_masq";
pub const SET_DELEGATED_V4: &str = "delegated_v4";
pub const SET_DELEGATED_V6: &str = "delegated_v6";

#[derive(Debug, Clone)]
pub struct Routed {
    pub prefix4: Ipv4Net,
    /// Host-side veth address (first usable of `prefix4`).
    pub gw4: Ipv4Addr,
    /// Namespace-side veth address (second).
    pub ns4: Ipv4Addr,
    /// IPv6 pair from `prefix6` when set, else the fixed ULA pair.
    pub prefix6: Ipv6Net,
    pub gw6: Ipv6Addr,
    pub ns6: Ipv6Addr,
    /// Fixed masquerade source for v6 egress (several container GUAs).
    pub masq_src6: Option<Ipv6Addr>,
}

#[derive(Debug, Clone)]
pub struct Bridge {
    pub bridge: String,
    /// Operator-assigned namespace addresses (LAN), as given in config.
    pub addrs: Vec<IpNet>,
    pub gw4: Option<IpAddr>,
    pub gw6: Option<IpAddr>,
}

#[derive(Debug, Clone)]
pub enum Mode {
    Routed(Routed),
    Bridge(Bridge),
}

/// Fully validated provisioning input: everything `provision` needs, with
/// derived addresses resolved. Construction is the validation surface —
/// bad config aborts before any process spawn.
#[derive(Debug, Clone)]
pub struct Spec {
    pub path: PathBuf,
    pub host_veth: String,
    pub ns_veth: String,
    pub table: String,
    pub mode: Mode,
}

impl Spec {
    /// Strict parse of `[netns]` for the provision path. Missing section is
    /// an error here; the daemon's run-mode boot applies the same strict
    /// validation through `Spec::from_netns` (main.rs).
    pub fn from_config(file: &FileConfig, table_override: Option<&str>) -> anyhow::Result<Spec> {
        let nf = file
            .netns
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("[netns] section is required for provision"))?;
        Spec::from_netns(nf, table_override.unwrap_or(&file.nft_table))
    }

    pub fn from_netns(nf: &NetnsFile, table: &str) -> anyhow::Result<Spec> {
        anyhow::ensure!(
            !nf.name.is_empty()
                && nf
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')),
            "[netns].name {name:?}: use [A-Za-z0-9._-]",
            name = nf.name
        );
        let dir = nf.dir.clone().unwrap_or_else(|| "/run/netns".into());
        let path = dir.join(&nf.name);

        fn ifname(n: &str, what: &str) -> anyhow::Result<String> {
            anyhow::ensure!(
                !n.is_empty() && n.len() <= IFNAMSIZ && !n.contains(char::is_whitespace),
                "[netns].{what} {n:?}: must be 1..={IFNAMSIZ} chars, no spaces"
            );
            Ok(n.to_string())
        }
        let host_veth = match &nf.host_veth {
            Some(h) => ifname(h, "host_veth")?,
            // ASCII name (validated above), so byte-slicing is safe.
            None => format!("vh-{}", nf.name)[..IFNAMSIZ.min(3 + nf.name.len())].to_string(),
        };
        let ns_veth = match &nf.ns_veth {
            Some(v) => ifname(v, "ns_veth")?,
            None => "veth0".into(),
        };

        let mode = match nf.mode.as_str() {
            "routed" => Mode::Routed(routed_spec(nf)?),
            "bridge" => Mode::Bridge(bridge_spec(nf)?),
            other => anyhow::bail!("[netns].mode {other:?}: expected routed|bridge"),
        };
        Ok(Spec {
            path,
            host_veth,
            ns_veth,
            table: table.to_string(),
            mode,
        })
    }

    /// Addresses the forward-accept must admit toward the namespace (the
    /// DNAT/masq chains are routed-mode-only).
    fn ns_ips(&self) -> Vec<IpAddr> {
        match &self.mode {
            Mode::Routed(r) => vec![r.ns4.into(), r.ns6.into()],
            // The ASSIGNED address of each operator CIDR, not its network.
            Mode::Bridge(b) => b.addrs.iter().map(|a| a.addr()).collect(),
        }
    }

    /// Chains whose rule bodies this batch owns (flush-and-rebuild).
    fn owned_host_chains(&self) -> Vec<&'static str> {
        match self.mode {
            Mode::Routed(_) => vec![HOST_CHAIN_FWD, HOST_CHAIN_DNAT, HOST_CHAIN_MASQ],
            Mode::Bridge(_) => vec![HOST_CHAIN_FWD],
        }
    }
}

fn routed_spec(nf: &NetnsFile) -> anyhow::Result<Routed> {
    let p4: Ipv4Net = nf
        .prefix4
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("[netns].prefix4 is required in routed mode"))?
        .parse()
        .map_err(|e| anyhow::anyhow!("[netns].prefix4 {:?}: {e}", nf.prefix4))?;
    anyhow::ensure!(
        p4.prefix_len() <= 30,
        "[netns].prefix4 {p4}: need at least a /30 (host + namespace addresses)"
    );
    let off4 = |base: Ipv4Addr, k: u8| -> Ipv4Addr {
        let mut o = base.octets();
        o[3] += k; // <= /30 guarantees room in the last octet
        Ipv4Addr::from(o)
    };
    let (gw4, ns4) = (off4(p4.network(), 1), off4(p4.network(), 2));

    let p6: Ipv6Net = match nf.prefix6.as_deref() {
        Some(s) => s
            .parse()
            .map_err(|e| anyhow::anyhow!("[netns].prefix6 {s:?}: {e}"))?,
        None => DEFAULT_V6_ULA
            .parse()
            .expect("built-in ULA constant is valid"),
    };
    anyhow::ensure!(
        p6.prefix_len() <= 126,
        "[netns].prefix6 {p6}: need room for the veth pair"
    );
    let off6 = |k: u128| Ipv6Addr::from(u128::from(p6.network()) + k);
    let (gw6, ns6) = (off6(1), off6(2));

    let masq_src6 = match &nf.masq_src6 {
        Some(s) => Some(
            s.parse::<Ipv6Addr>()
                .map_err(|e| anyhow::anyhow!("[netns].masq_src6 {s:?}: {e}"))?,
        ),
        None => None,
    };
    Ok(Routed {
        prefix4: p4,
        gw4,
        ns4,
        prefix6: p6,
        gw6,
        ns6,
        masq_src6,
    })
}

fn bridge_spec(nf: &NetnsFile) -> anyhow::Result<Bridge> {
    let bridge = nf
        .bridge
        .as_deref()
        .filter(|b| !b.is_empty())
        .ok_or_else(|| anyhow::anyhow!("[netns].bridge is required in bridge mode"))?
        .to_string();
    anyhow::ensure!(
        !nf.addrs.is_empty(),
        "[netns].addrs must hold at least one CIDR in bridge mode"
    );
    let mut addrs = Vec::new();
    for a in &nf.addrs {
        addrs.push(
            a.parse::<IpNet>()
                .map_err(|e| anyhow::anyhow!("[netns].addrs {a:?}: {e}"))?,
        );
    }
    Ok(Bridge {
        bridge,
        addrs,
        gw4: nf
            .gw4
            .as_deref()
            .map(|s| parse_family(s, false, "gw4"))
            .transpose()?,
        gw6: nf
            .gw6
            .as_deref()
            .map(|s| parse_family(s, true, "gw6"))
            .transpose()?,
    })
}

fn parse_family(s: &str, v6: bool, what: &str) -> anyhow::Result<IpAddr> {
    let a: IpAddr = s
        .parse()
        .map_err(|e| anyhow::anyhow!("[netns].{what} {s:?}: {e}"))?;
    anyhow::ensure!(
        a.is_ipv6() == v6,
        "[netns].{what} {s:?}: expected {}",
        if v6 { "IPv6" } else { "IPv4" }
    );
    Ok(a)
}

/// One idempotent `ip` invocation. `in_ns` routes it through the setns
/// pre_exec helper; otherwise it runs on the host stack.
#[derive(Debug, PartialEq, Eq)]
pub struct Step {
    pub what: String,
    pub args: Vec<String>,
    pub in_ns: bool,
}

fn step(what: &str, args: &[&str], in_ns: bool) -> Step {
    Step {
        what: what.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        in_ns,
    }
}

/// Host-side link steps (unconditional, idempotent). Pair creation and the
/// peer move are conditional on link presence — those live with the runner.
pub fn host_steps(spec: &Spec) -> Vec<Step> {
    let mut v = Vec::new();
    if let Mode::Bridge(b) = &spec.mode {
        v.push(step(
            "enslave veth into bridge",
            &["link", "set", &spec.host_veth, "master", &b.bridge],
            false,
        ));
    }
    v.push(step(
        "bring up host veth",
        &["link", "set", &spec.host_veth, "up"],
        false,
    ));
    if let Mode::Routed(r) = &spec.mode {
        // The gateway end of the pair lives on the HOST side.
        v.push(step(
            "host gw address (v4)",
            &[
                "addr",
                "replace",
                &format!("{}/{}", r.gw4, r.prefix4.prefix_len()),
                "dev",
                &spec.host_veth,
            ],
            false,
        ));
        v.push(step(
            "host gw address (v6)",
            &[
                "-6",
                "addr",
                "replace",
                &format!("{}/{}", r.gw6, r.prefix6.prefix_len()),
                "dev",
                &spec.host_veth,
            ],
            false,
        ));
    }
    v
}

/// Namespace-side link steps. `lo` must be up (the base chains accept on
/// it) before any addressing; everything uses replace/up so reruns
/// converge.
pub fn ns_steps(spec: &Spec) -> Vec<Step> {
    let mut v = vec![
        step("bring up loopback", &["link", "set", "lo", "up"], true),
        step(
            "bring up namespace veth",
            &["link", "set", &spec.ns_veth, "up"],
            true,
        ),
    ];
    match &spec.mode {
        Mode::Routed(r) => {
            v.push(step(
                "namespace address (v4)",
                &[
                    "addr",
                    "replace",
                    &format!("{}/{}", r.ns4, r.prefix4.prefix_len()),
                    "dev",
                    &spec.ns_veth,
                ],
                true,
            ));
            v.push(step(
                "namespace address (v6)",
                &[
                    "-6",
                    "addr",
                    "replace",
                    &format!("{}/{}", r.ns6, r.prefix6.prefix_len()),
                    "dev",
                    &spec.ns_veth,
                ],
                true,
            ));
            v.push(step(
                "default route (v4)",
                &[
                    "route",
                    "replace",
                    "default",
                    "via",
                    &r.gw4.to_string(),
                    "dev",
                    &spec.ns_veth,
                ],
                true,
            ));
            v.push(step(
                "default route (v6)",
                &[
                    "-6",
                    "route",
                    "replace",
                    "default",
                    "via",
                    &r.gw6.to_string(),
                    "dev",
                    &spec.ns_veth,
                ],
                true,
            ));
        }
        Mode::Bridge(b) => {
            for a in &b.addrs {
                let v6 = a.network().is_ipv6();
                let mut args: Vec<&str> = Vec::new();
                if v6 {
                    args.push("-6");
                }
                let cidr = a.to_string();
                args.extend(["addr", "replace", &cidr, "dev", &spec.ns_veth]);
                v.push(step(
                    if v6 {
                        "namespace address (v6)"
                    } else {
                        "namespace address (v4)"
                    },
                    &args,
                    true,
                ));
            }
            if let Some(g) = &b.gw4 {
                v.push(step(
                    "default route (v4)",
                    &[
                        "route",
                        "replace",
                        "default",
                        "via",
                        &g.to_string(),
                        "dev",
                        &spec.ns_veth,
                    ],
                    true,
                ));
            }
            if let Some(g) = &b.gw6 {
                v.push(step(
                    "default route (v6)",
                    &[
                        "-6",
                        "route",
                        "replace",
                        "default",
                        "via",
                        &g.to_string(),
                        "dev",
                        &spec.ns_veth,
                    ],
                    true,
                ));
            }
        }
    }
    v
}

/// The host-stack projection: forward-accept for the pair (both modes),
/// and — routed mode only — MASQUERADE in both families plus an empty
/// delegated-port DNAT chain hooked in prerouting. `delegated_*` elements
/// are maintained by tethysd at runtime (step 3); the rules referencing
/// them here make provisioning self-contained. Emit order is objects →
/// flushes → rules so a rerun converges instead of duplicating, same
/// discipline as core's ensure_base. No drop verdict anywhere: host paths
/// keep zero Tethys policy beyond these accepts (firewalld coexistence).
pub fn host_batch(spec: &Spec) -> Batch {
    let t = spec.table.clone();
    let hv = spec.host_veth.as_str();
    let mut b = Batch::with_table(&t);
    let rule = |chain: &str, exprs: Vec<Value>| json!({"add":{"rule":{"family":"inet","table":&t,"chain":chain,"expr":exprs}}});

    // --- objects -----------------------------------------------------------
    b.ensure_table();
    if matches!(spec.mode, Mode::Routed(_)) {
        for name in [SET_DELEGATED_V4, SET_DELEGATED_V6] {
            b.push_cmd(json!({"add":{"set":{
                "family":"inet","table":&t,"name":name,
                "type":"inet_service","flags":["interval"]
            }}}));
        }
    }
    for (chain, hook, ty, prio) in [
        (HOST_CHAIN_FWD, "forward", "filter", 0),
        (HOST_CHAIN_DNAT, "prerouting", "nat", -100),
        (HOST_CHAIN_MASQ, "postrouting", "nat", 100),
    ] {
        if !spec.owned_host_chains().contains(&chain) {
            continue;
        }
        b.push_cmd(json!({"add":{"chain":{
            "family":"inet","table":&t,"name":chain,
            "hook":hook,"type":ty,"prio":prio,"policy":"accept"
        }}}));
    }
    for chain in spec.owned_host_chains() {
        b.push_cmd(json!({"flush":{"chain":{
            "family":"inet","table":&t,"name":chain
        }}}));
    }

    // --- forward-accept ------------------------------------------------------
    // ns egress out any interface, plus inbound toward the namespace
    // (post-DNAT in routed mode, LAN-local in bridge mode).
    b.push_cmd(rule(
        HOST_CHAIN_FWD,
        vec![
            json!({"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":hv}}),
            json!({"accept":null}),
        ],
    ));
    for ip in spec.ns_ips() {
        let af = if ip.is_ipv6() { "ip6" } else { "ip" };
        b.push_cmd(rule(
            HOST_CHAIN_FWD,
            vec![
                json!({"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":hv}}),
                json!({"match":{"op":"==","left":{"payload":{"protocol":af,"field":"daddr"}},
                                 "right":ip.to_string()}}),
                json!({"accept":null}),
            ],
        ));
    }

    if let Mode::Routed(r) = &spec.mode {
        // Delegated-port DNAT: packets destined for THIS host (fib local),
        // arriving from anywhere but our own veth (so ns egress is never
        // hairpinned), tcp/udp on a delegated port, go to the namespace
        // address. DNAT keeps true client sources — what igrants_* keying
        // consumes. Empty sets => nothing matches until step 3 maintains.
        for (set, daddr) in [
            (SET_DELEGATED_V4, r.ns4.to_string()),
            (SET_DELEGATED_V6, r.ns6.to_string()),
        ] {
            b.push_cmd(rule(
                HOST_CHAIN_DNAT,
                vec![
                    // nft JSON fib schema: `flags` selects the lookup key,
                    // `result` the result to return — `fib daddr type
                    // == local` ("destined for this host"). Member names
                    // are exact; a wrong one fails the parser (caught live
                    // on the first root run, and by batches_parse_under_local_nft).
                    json!({"match":{"op":"==","left":{
                        "fib":{"flags":"daddr","result":"type"}},"right":"local"}}),
                    json!({"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":hv}}),
                    json!({"match":{"op":"in","left":{"meta":{"key":"l4proto"}},
                                     "right":{"set":["tcp","udp"]}}}),
                    json!({"match":{"op":"in","left":{
                        "payload":{"protocol":"th","field":"dport"}},
                        "right":format!("@{set}")}}),
                    // inet tables require the address family alongside
                    // the DNAT target (libnftables-json: "Required in inet
                    // table family").
                    json!({"dnat":{"addr":daddr,
                                   "family": if set == SET_DELEGATED_V6 { "ip6" } else { "ip" }}}),
                ],
            ));
        }

        // MASQUERADE for ns-ORIGINATED egress in both families (remotes
        // see one address per family — unchanged from host-mode today).
        // Matching ct ORIGINAL saddr rather than the packet's saddr is
        // load-bearing: replies to DNAT'd ingress flows leave postrouting
        // with ns-prefix source but their conntrack origin is the remote —
        // masquerading those would SNAT SYN-ACKs away from the address the
        // client connected to, and the client socket would discard them.
        // A pinned masq_src6 turns the v6 rule into a deterministic snat.
        let prefix = |addr: String, len: u8| json!({"prefix":{"addr":addr,"len":len}});
        // libnftables-json(5) CT object: key + family + dir. The `family`
        // member is not decoration — in an inet table a family-less ct
        // saddr fails EVALUATION ("cannot determine ip protocol version",
        // live-verified), which parsing alone does not catch. `dir` (not
        // "direction": unknown members are silently ignored) pins the
        // original direction explicitly.
        let ct_origin_saddr =
            |fam: &str| json!({"ct":{"key":"saddr","family":fam,"dir":"original"}});
        b.push_cmd(rule(
            HOST_CHAIN_MASQ,
            vec![
                json!({"match":{"op":"!=","left":{"meta":{"key":"oifname"}},"right":hv}}),
                json!({"match":{"op":"==","left":ct_origin_saddr("ip"),
                                 "right":prefix(r.prefix4.network().to_string(), r.prefix4.prefix_len())}}),
                json!({"masquerade":null}),
            ],
        ));
        let mut v6 = vec![
            json!({"match":{"op":"!=","left":{"meta":{"key":"oifname"}},"right":hv}}),
            json!({"match":{"op":"==","left":ct_origin_saddr("ip6"),
                             "right":prefix(r.prefix6.network().to_string(), r.prefix6.prefix_len())}}),
        ];
        match r.masq_src6 {
            Some(src) => v6.push(json!({"snat":{"addr":src.to_string()}})),
            None => v6.push(json!({"masquerade":null})),
        }
        b.push_cmd(rule(HOST_CHAIN_MASQ, v6));
    }

    b
}

// ---------------------------------------------------------------------------
// execution (root-only effects)
// ---------------------------------------------------------------------------

fn run(mut cmd: Command, what: &str) -> anyhow::Result<String> {
    tracing::debug!(%what, args = ?cmd.get_args().collect::<Vec<_>>(), "provision: running");
    let out = cmd
        .output()
        .map_err(|e| anyhow::anyhow!("{what}: spawn: {e}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "{what}: {} exited {}: {}",
            cmd.get_program().to_string_lossy(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn ip<I, S>(args: I) -> Command
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let mut c = Command::new("ip");
    c.env_clear();
    c.arg("-o");
    c.args(args);
    c
}

/// The single helper funnelling namespace-side subprocesses through core's
/// setns pre_exec (same audited syscall pair the nft executor uses).
fn ip_in_ns<I, S>(ns: &Netns, args: I) -> Command
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let mut c = ip(args);
    // SAFETY: post-fork/pre-exec fcntl+setns only; see core::nft::setns_pre_exec.
    #[allow(unsafe_code)]
    unsafe {
        c.pre_exec(setns_pre_exec(ns.fd()))
    };
    c
}

fn link_exists(name: &str) -> bool {
    ip(["link", "show", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Create the nsfs file if absent: bind-mount a netns created by
/// `unshare(CLONE_NEWNET)` — what `ip netns add` does, but at a configurable
/// path (tests use a scratch dir; production `/run/netns`). Returns whether
/// this call created it.
fn ensure_netns(path: &std::path::Path) -> anyhow::Result<bool> {
    if path.exists() {
        // A plain file where a namespace should be means a crash landed
        // between creating the file and mounting onto it. Fail loudly —
        // opening a bare file for setns would die later with a confusing
        // EINVAL from deep inside the daemon.
        anyhow::ensure!(
            is_mountpoint(path),
            "{} exists but is not a mounted namespace (leftover from a crashed \
             provision?); umount and remove it, then retry",
            path.display()
        );
        return Ok(false);
    }
    let dir = path.parent().unwrap_or_else(|| "/".as_ref());
    std::fs::create_dir_all(dir).map_err(|e| anyhow::anyhow!("create {}: {e}", dir.display()))?;
    // The bind needs the target file to exist — the touch `ip netns add`
    // does. If the mount fails, remove the file again so a bare empty file
    // never masquerades as a namespace on the next run.
    std::fs::File::create(path).map_err(|e| anyhow::anyhow!("create {}: {e}", path.display()))?;
    if let Err(e) = create_netns(path) {
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(true)
}

/// Create a pinned netns at `path` (the file must already exist): fork,
/// `unshare(CLONE_NEWNET)`, legacy `mount("/proc/self/ns/net", path, "nsfs",
/// MS_BIND)` — exactly what `ip netns add` does, and the bind itself pins
/// the namespace (no holder process). Deliberately NOT `mount --bind`:
/// util-linux routes binds through open_tree(OPEN_TREE_CLONE)+move_mount,
/// which AppArmor denies inside LXC containers (EACCES) while allowing the
/// legacy syscall — provisioning must not depend on which mount API a
/// distro's mount(8) happens to use.
#[allow(unsafe_code)] // fork/unshare/mount/waitpid: raw syscalls by design
fn create_netns(path: &std::path::Path) -> anyhow::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid netns path {}", path.display()))?;
    // Child exit codes: 0 ok; 1..127 = errno of the failed unshare;
    // 129..255 = 128 + errno of the failed mount. (The child runs after a
    // fork in a multithreaded process, so it touches nothing but syscalls.)
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(anyhow::anyhow!("fork: {}", std::io::Error::last_os_error())),
        0 => {
            if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(1);
                unsafe { libc::_exit(e.clamp(1, 127)) };
            }
            let rc = unsafe {
                libc::mount(
                    c"/proc/self/ns/net".as_ptr(),
                    c_path.as_ptr(),
                    c"nsfs".as_ptr(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            };
            let code = if rc == 0 {
                0
            } else {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(1);
                128 + e.clamp(1, 127)
            };
            unsafe { libc::_exit(code) };
        }
        _ => {
            let mut status = 0;
            loop {
                if unsafe { libc::waitpid(pid, &mut status, 0) } >= 0 {
                    break;
                }
                if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    return Err(anyhow::anyhow!(
                        "waitpid: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
            let code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                return Err(anyhow::anyhow!("create netns: child killed by signal"));
            };
            match code {
                0 => Ok(()),
                c @ 1..=127 => Err(anyhow::anyhow!(
                    "unshare(CLONE_NEWNET): {}",
                    std::io::Error::from_raw_os_error(c)
                )),
                c => Err(anyhow::anyhow!(
                    "bind-mounting nsfs onto {}: {}",
                    path.display(),
                    std::io::Error::from_raw_os_error(c - 128)
                )),
            }
        }
    }
}

/// True when `path` is a mount point per /proc/self/mountinfo (mount-point
/// fields are octal-escaped there; our paths rarely need it, decode anyway).
fn is_mountpoint(path: &std::path::Path) -> bool {
    let want = path.display().to_string();
    std::fs::read_to_string("/proc/self/mountinfo")
        .map(|mi| {
            mi.lines().any(|l| {
                l.split_whitespace().nth(4).map(|mp| {
                    mp.replace("\\040", " ")
                        .replace("\\011", "\t")
                        .replace("\\012", "\n")
                }) == Some(want.clone())
            })
        })
        .unwrap_or(false)
}

fn write_sysctl(path: &str, want: &str) -> anyhow::Result<()> {
    if let Ok(cur) = std::fs::read_to_string(path) {
        if cur.trim() == want {
            return Ok(());
        }
    }
    std::fs::write(path, want).map_err(|e| {
        anyhow::anyhow!("sysctl {path} := {want}: {e} (routed mode cannot forward without it)")
    })
}

/// Run the full provisioning pass. Idempotent: safe as `ExecStartPre=` on
/// every boot and safe to rerun by hand. All operator-relevant facts are
/// logged; any failure aborts with context so systemd fails the unit closed
/// (agent login fail-closed, operator outside the namespace unaffected).
pub async fn run_spec(spec: &Spec) -> anyhow::Result<()> {
    tracing::info!(path = %spec.path.display(), table = %spec.table, "provision: start");

    let created = ensure_netns(&spec.path)?;
    tracing::info!(created, path = %spec.path.display(), "netns present");

    // The handle pins the inode up front; core revalidates it per batch and
    // the setns helper below inherits exactly this fd.
    let ns = Netns::open(&spec.path)
        .map_err(|e| anyhow::anyhow!("open netns {}: {e}", spec.path.display()))?;

    // Link plumbing: create the pair only when absent, move the peer while
    // it is still on the host. A half-torn pair (host end gone, ns name
    // shadowing on host) gets recreated so reruns converge to one shape.
    if !link_exists(&spec.host_veth) {
        if link_exists(&spec.ns_veth) {
            run(ip(["link", "del", &spec.ns_veth]), "delete orphan veth end")?;
        }
        run(
            ip([
                "link",
                "add",
                &spec.host_veth,
                "type",
                "veth",
                "peer",
                "name",
                &spec.ns_veth,
            ]),
            "create veth pair",
        )?;
    }
    if link_exists(&spec.ns_veth) {
        // Hand the peer end to the namespace by nsfs fd path — works with a
        // custom dir where `ip netns exec <name>` would not resolve.
        let fd_path = format!("/proc/{}/fd/{}", std::process::id(), ns.fd());
        run(
            ip(["link", "set", &spec.ns_veth, "netns", &fd_path]),
            "move veth into netns",
        )?;
    }

    for s in host_steps(spec) {
        run(ip(&s.args), &s.what)?;
    }
    for s in ns_steps(spec) {
        run(ip_in_ns(&ns, &s.args), &s.what)?;
    }

    if let Mode::Routed(_) = spec.mode {
        write_sysctl("/proc/sys/net/ipv4/ip_forward", "1")?;
        write_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1")?;
        tracing::info!("routing sysctls set (ip_forward, forwarding)");
    }

    // Host projection + the namespace's own policy table, one batch each.
    let host = NftCli::default();
    host.apply(&host_batch(spec))
        .await
        .map_err(|e| anyhow::anyhow!("host projection apply failed: {e}"))?;

    let inside = NftCli::in_netns(&spec.path).map_err(|e| anyhow::anyhow!("nft on netns: {e}"))?;
    let mut base = Batch::with_table(&spec.table);
    base.ensure_base();
    inside
        .apply(&base)
        .await
        .map_err(|e| anyhow::anyhow!("namespace policy apply failed: {e}"))?;

    // Fail loudly NOW if the loaded table is not actually wired — the
    // review's Medium finding caught at boot instead of per-verdict.
    let status = inside
        .enforcement_status(&spec.table)
        .await
        .map_err(|e| anyhow::anyhow!("enforcement probe failed: {e}"))?;
    anyhow::ensure!(
        status.active(),
        "policy loaded in {} but enforcement probe inactive: {status:?}",
        spec.path.display()
    );
    tracing::info!(path = %spec.path.display(), table = %spec.table, "provision: enforcement active");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a `[netns]` fragment through the real FileConfig path.
    fn spec_of(body: &str, table: &str) -> anyhow::Result<Spec> {
        let file: FileConfig = toml::from_str(&format!("[netns]\n{body}")).unwrap();
        Spec::from_config(&file, Some(table))
    }

    fn routed() -> Spec {
        spec_of("name = 'agent'\nprefix4 = '10.91.0.0/24'", "tethys").unwrap()
    }

    #[test]
    fn routed_derives_addresses_and_defaults() {
        let s = routed();
        assert_eq!(s.path, PathBuf::from("/run/netns/agent"));
        assert_eq!(
            (s.host_veth.as_str(), s.ns_veth.as_str()),
            ("vh-agent", "veth0")
        );
        let Mode::Routed(r) = &s.mode else {
            panic!("default mode is routed")
        };
        assert_eq!(r.gw4, Ipv4Addr::new(10, 91, 0, 1));
        assert_eq!(r.ns4, Ipv4Addr::new(10, 91, 0, 2));
        // No prefix6 => fixed ULA pair; guarantees unchanged, address differs.
        assert_eq!(r.prefix6.to_string(), DEFAULT_V6_ULA);
        assert_eq!(r.gw6, Ipv6Addr::new(0xfc9a, 0x5445, 0x5448, 0, 0, 0, 0, 1));
        // forward-accept admits the NS addresses only, never the gw ends.
        let ips = s.ns_ips();
        assert!(ips.contains(&IpAddr::from(Ipv4Addr::new(10, 91, 0, 2))));
        assert!(!ips.iter().any(|i| i.to_string() == "10.91.0.1"));
    }

    #[test]
    fn prefix6_gua_pair_and_masq_pin() {
        let s = spec_of(
            "name='agent'\nprefix4='10.91.0.0/30'\nprefix6='2001:db8:7::/64'\nmasq_src6='2001:db8:7::5'",
            "t",
        )
        .unwrap();
        let Mode::Routed(r) = &s.mode else {
            panic!("routed")
        };
        assert_eq!(r.ns6.to_string(), "2001:db8:7::2");
        assert_eq!(
            r.masq_src6,
            Some(Ipv6Addr::new(0x2001, 0xdb8, 7, 0, 0, 0, 0, 5))
        );
    }

    #[test]
    fn missing_netns_section_is_an_error() {
        let file: FileConfig = toml::from_str("db = '/tmp/x.db'").unwrap();
        assert!(Spec::from_config(&file, None).is_err());
    }

    #[test]
    fn masq_src6_pins_v6_egress_to_snat() {
        let s = spec_of(
            "name='agent'\nprefix4='10.91.0.0/24'\nprefix6='2001:db8:7::/64'\nmasq_src6='2001:db8:7::5'",
            "t",
        )
        .unwrap();
        let c = cmds(&host_batch(&s));
        let masq: Vec<_> = c
            .iter()
            .filter(|x| x["add"]["rule"]["chain"].as_str() == Some(HOST_CHAIN_MASQ))
            .collect();
        assert_eq!(masq.len(), 2);
        let is_v6 = |x: &&Value| -> bool {
            x["add"]["rule"]["expr"]
                .as_array()
                .map(|e| {
                    e.iter().any(|m| {
                        m["match"]["left"]["ct"]["dir"].as_str() == Some("original")
                            && m["match"]["left"]["ct"]["family"].as_str() == Some("ip6")
                            && m["match"]["right"]["prefix"]["addr"].as_str()
                                == Some("2001:db8:7::")
                    })
                })
                .unwrap_or(false)
        };
        let v6 = masq.iter().find(|x| is_v6(x)).expect("v6 masq rule");
        assert_eq!(
            v6["add"]["rule"]["expr"]
                .as_array()
                .unwrap()
                .last()
                .unwrap()["snat"]["addr"],
            json!("2001:db8:7::5"),
            "pinned source => deterministic snat, not interface-address masquerade"
        );
        let v4 = masq.iter().find(|x| !is_v6(x)).expect("v4 masq rule");
        assert!(
            v4["add"]["rule"]["expr"]
                .as_array()
                .unwrap()
                .last()
                .unwrap()
                .get("masquerade")
                .is_some(),
            "pinning is v6-only"
        );
    }

    #[test]
    fn validation_rejects_bad_configs() {
        // routed without prefix4 / unknown mode / too-small v4 net / long ifname
        assert!(spec_of("name='a'", "t").is_err());
        assert!(spec_of("name='a'\nmode='macvlan'\nprefix4='10.0.0.0/24'", "t").is_err());
        assert!(spec_of("name='a'\nprefix4='10.0.0.0/31'", "t").is_err());
        assert!(spec_of(
            "name='a'\nprefix4='10.0.0.0/24'\nhost_veth='this-name-is-way-too-long'",
            "t"
        )
        .is_err());
        // bridge without bridge/addrs; gw family mismatch
        assert!(spec_of("name='a'\nmode='bridge'", "t").is_err());
        assert!(spec_of(
            "name='a'\nmode='bridge'\nbridge='vmbr0'\naddrs=['192.168.5.30/24']\ngw4='fe80::1'",
            "t"
        )
        .is_err());
    }

    #[test]
    fn bridge_spec_keeps_operator_addresses() {
        let s = spec_of(
            "name='agent'\nmode='bridge'\nbridge='vmbr0'\naddrs=['192.168.5.30/24','2001:db8::30/64']\ngw6='fe80::1'",
            "t",
        )
        .unwrap();
        let Mode::Bridge(b) = &s.mode else {
            panic!("bridge")
        };
        assert_eq!(b.addrs.len(), 2);
        assert_eq!(b.gw6.map(|g| g.to_string()), Some("fe80::1".into()));
        // forward-accept must target the ASSIGNED addresses, not networks.
        let ips = s.ns_ips();
        assert!(ips.contains(&"192.168.5.30".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"2001:db8::30".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn ns_plan_is_idempotent_and_ordered() {
        let s = routed();
        let p = ns_steps(&s);
        // lo up FIRST (base chains accept on loopback), then veth addressing,
        // and every mutating verb is `replace`/`up` — never `add`.
        assert_eq!(p[0].args, vec!["link", "set", "lo", "up"]);
        for st in &p {
            let joined = st.args.join(" ");
            assert!(st.in_ns);
            assert!(
                joined.starts_with("link set")
                    || joined.contains("addr replace")
                    || joined.contains("route replace"),
                "non-idempotent step: {joined}"
            );
        }
        let v4 = p
            .iter()
            .find(|st| st.what == "namespace address (v4)")
            .unwrap();
        assert_eq!(
            v4.args,
            vec!["addr", "replace", "10.91.0.2/24", "dev", "veth0"]
        );
        let r6 = p.iter().find(|st| st.what == "default route (v6)").unwrap();
        assert_eq!(r6.args[0], "-6");

        // routed host side carries BOTH gateway ends; nothing inside the ns.
        let h = host_steps(&s);
        assert!(h.iter().all(|st| !st.in_ns));
        let Mode::Routed(r) = &s.mode else { panic!() };
        assert!(h.iter().any(|st| st.args.join(" ")
            == format!(
                "addr replace {}/{} dev vh-agent",
                r.gw4,
                r.prefix4.prefix_len()
            )));
        assert!(
            h.iter().any(|st| st.args.join(" ")
                == format!(
                    "-6 addr replace {}/{} dev vh-agent",
                    r.gw6,
                    r.prefix6.prefix_len()
                )),
            "host v6 gateway end must be addressed or the ns has no v6 next hop"
        );
    }

    #[test]
    fn bridge_plan_uses_given_cidrs_and_gateways() {
        let s = spec_of(
            "name='agent'\nmode='bridge'\nbridge='vmbr0'\naddrs=['192.168.5.30/24','2001:db8::30/64']\ngw4='192.168.5.1'",
            "t",
        )
        .unwrap();
        let p = ns_steps(&s);
        assert!(p
            .iter()
            .any(|st| st.args.join(" ").contains("addr replace 192.168.5.30/24")));
        let v6 = p
            .iter()
            .find(|st| st.what == "namespace address (v6)")
            .unwrap();
        assert_eq!(v6.args[0], "-6");
        assert!(
            !p.iter().any(|st| st.what.contains("route (v6)")),
            "no gw6 => no route step"
        );

        let h = host_steps(&s);
        assert_eq!(h[0].args.join(" "), "link set vh-agent master vmbr0");
    }

    fn cmds(b: &Batch) -> Vec<Value> {
        serde_json::from_str::<Value>(&b.to_json()).unwrap()["nftables"]
            .as_array()
            .unwrap()
            .clone()
    }

    #[test]
    fn host_batch_routed_wires_all_three_chains() {
        let s = routed();
        let c = cmds(&host_batch(&s));
        for (name, hook, ty, prio) in [
            (HOST_CHAIN_FWD, "forward", "filter", 0i64),
            (HOST_CHAIN_DNAT, "prerouting", "nat", -100),
            (HOST_CHAIN_MASQ, "postrouting", "nat", 100),
        ] {
            assert!(
                c.iter()
                    .any(|x| x["add"]["chain"]["name"].as_str() == Some(name)
                        && x["add"]["chain"]["hook"].as_str() == Some(hook)
                        && x["add"]["chain"]["type"].as_str() == Some(ty)
                        && x["add"]["chain"]["prio"].as_i64() == Some(prio)),
                "missing hooked chain {name}"
            );
            // No verdicts on host paths beyond explicit accepts: policy is
            // accept everywhere (firewalld coexistence).
            assert!(c
                .iter()
                .any(|x| x["add"]["chain"]["policy"].as_str() == Some("accept")
                    && x["add"]["chain"]["name"].as_str() == Some(name)));
        }

        // Delegated-port sets exist (empty; tethysd maintains elements),
        // as interval sets so port-range elements are legal in step 3.
        for set in [SET_DELEGATED_V4, SET_DELEGATED_V6] {
            assert!(c
                .iter()
                .any(|x| x["add"]["set"]["name"].as_str() == Some(set)
                    && x["add"]["set"]["type"].as_str() == Some("inet_service")
                    && x["add"]["set"]["flags"] == json!(["interval"])));
        }

        // DNAT: one rule per family, guarded (fib local; not from our own
        // veth), referencing its set, dnat'ing to the derived ns address.
        let Mode::Routed(r) = &s.mode else { panic!() };
        for (set, target) in [
            ("@delegated_v4", r.ns4.to_string()),
            ("@delegated_v6", r.ns6.to_string()),
        ] {
            let rule = c.iter().find(|x| {
                x["add"]["rule"]["chain"].as_str() == Some(HOST_CHAIN_DNAT)
                    && x["add"]["rule"]["expr"]
                        .as_array()
                        .map(|e| e.iter().any(|m| m["match"]["right"].as_str() == Some(set)))
                        .unwrap_or(false)
            });
            let rule = rule.unwrap_or_else(|| panic!("no DNAT rule for {set}"));
            let exprs = rule["add"]["rule"]["expr"].as_array().unwrap();
            assert!(
                exprs.iter().any(|e| e["match"]["left"]["fib"].is_object()),
                "fib local guard"
            );
            assert!(
                exprs
                    .iter()
                    .any(|e| e["match"]["op"] == json!("!=")
                        && e["match"]["right"] == json!("vh-agent")),
                "iifname hairpin guard"
            );
            assert_eq!(
                exprs.last().unwrap()["dnat"]["addr"].as_str(),
                Some(target.as_str())
            );
        }

        // MASQ: one rule per family; each guards `oifname != host_veth`
        // (never masquerade toward the ns itself), matches saddr against
        // EXACTLY its namespace prefix, and ends in a plain masquerade.
        let masq_rules: Vec<_> = c
            .iter()
            .filter(|x| x["add"]["rule"]["chain"].as_str() == Some(HOST_CHAIN_MASQ))
            .collect();
        assert_eq!(masq_rules.len(), 2, "one masquerade rule per family");
        for (af, net, len) in [
            (
                "ip",
                r.prefix4.network().to_string(),
                r.prefix4.prefix_len(),
            ),
            (
                "ip6",
                r.prefix6.network().to_string(),
                r.prefix6.prefix_len(),
            ),
        ] {
            // ct original-direction saddr, never the post-NAT packet
            // saddr: DNAT'd ingress replies must not be masqueraded.
            // The RHS prefix pins which family's rule this is.
            let found = masq_rules.iter().find(|x| {
                x["add"]["rule"]["expr"]
                    .as_array()
                    .map(|e| {
                        e.iter().any(|m| {
                            m["match"]["left"]["ct"]["dir"].as_str() == Some("original")
                                && m["match"]["left"]["ct"]["key"].as_str() == Some("saddr")
                                && m["match"]["right"]["prefix"]["addr"].as_str()
                                    == Some(net.as_str())
                        })
                    })
                    .unwrap_or(false)
            });
            let found = found.unwrap_or_else(|| panic!("no masq rule for {af}"));
            let exprs = found["add"]["rule"]["expr"].as_array().unwrap();
            assert_eq!(exprs[0]["match"]["op"], json!("!="), "{af}: oifname guard");
            assert_eq!(
                exprs[0]["match"]["right"],
                json!("vh-agent"),
                "{af}: guard targets host veth"
            );
            assert_eq!(
                exprs[1]["match"]["right"]["prefix"]["addr"].as_str(),
                Some(net.as_str()),
                "{af}: masquerade must scope to the ns prefix, not everything"
            );
            assert_eq!(
                exprs[1]["match"]["right"]["prefix"]["len"],
                json!(len as u64)
            );
            assert!(
                exprs.last().unwrap().get("masquerade").is_some(),
                "{af}: default is unpinned masquerade"
            );
        }

        // Owned chains are flushed between declare and rules (converge).
        for name in [HOST_CHAIN_FWD, HOST_CHAIN_DNAT, HOST_CHAIN_MASQ] {
            let add = c
                .iter()
                .position(|x| x["add"]["chain"]["name"].as_str() == Some(name))
                .unwrap();
            let flush = c
                .iter()
                .position(|x| x["flush"]["chain"]["name"].as_str() == Some(name))
                .unwrap();
            let first_rule = c
                .iter()
                .position(|x| x["add"]["rule"]["chain"].as_str() == Some(name))
                .unwrap();
            assert!(
                add < flush && flush < first_rule,
                "{name}: add < flush < rules"
            );
        }

        // Forward-accept: ns egress + inbound toward each derived address.
        let fwd: Vec<_> = c
            .iter()
            .filter(|x| x["add"]["rule"]["chain"].as_str() == Some(HOST_CHAIN_FWD))
            .collect();
        assert_eq!(fwd.len(), 3, "egress accept + v4 inbound + v6 inbound");
        for ip in s.ns_ips() {
            let hit = fwd.iter().any(|x| {
                x["add"]["rule"]["expr"]
                    .as_array()
                    .map(|e| {
                        e.iter()
                            .any(|m| m["match"]["right"] == json!(ip.to_string()))
                    })
                    .unwrap_or(false)
            });
            assert!(hit, "forward-accept must admit {ip}");
        }
    }

    #[test]
    fn host_batch_bridge_has_no_nat() {
        let s = spec_of(
            "name='agent'\nmode='bridge'\nbridge='vmbr0'\naddrs=['192.168.5.30/24']",
            "t",
        )
        .unwrap();
        let c = cmds(&host_batch(&s));
        assert!(c
            .iter()
            .any(|x| x["add"]["chain"]["name"].as_str() == Some(HOST_CHAIN_FWD)));
        for absent in [HOST_CHAIN_DNAT, HOST_CHAIN_MASQ] {
            assert!(
                !c.iter()
                    .any(|x| x["add"]["chain"]["name"].as_str() == Some(absent)),
                "{absent} must not exist in bridge mode"
            );
            assert!(!c
                .iter()
                .any(|x| x["flush"]["chain"]["name"].as_str() == Some(absent)));
        }
        // But the assigned LAN address is still forward-accepted.
        assert!(c.iter().any(|x| {
            x["add"]["rule"]["chain"].as_str() == Some(HOST_CHAIN_FWD)
                && x["add"]["rule"]["expr"]
                    .as_array()
                    .map(|e| {
                        e.iter()
                            .any(|m| m["match"]["right"] == json!("192.168.5.30"))
                    })
                    .unwrap_or(false)
        }));
    }

    #[test]
    fn mountpoint_detection() {
        // needs neither root nor nftables: mountinfo is world-readable
        assert!(is_mountpoint(std::path::Path::new("/")));
        assert!(!is_mountpoint(std::path::Path::new("/etc/hostname")));
        // a file we just made cannot be a mount point
        let p = std::env::temp_dir().join(format!("tethys-mp-{}", std::process::id()));
        std::fs::File::create(&p).unwrap();
        assert!(!is_mountpoint(&p));
        std::fs::remove_file(&p).unwrap();
    }

    // Root-gated smoke: real unshare/mount/ip/nft round trip, skipped when
    // unprivileged (this box cannot even open a userns). Scratch dir +
    // private names; cleans up best-effort regardless of outcome.
    #[test]
    fn provision_routed_smoke_root_only() {
        if nix::unistd::geteuid().as_raw() != 0 {
            eprintln!("SKIP provision_routed_smoke_root_only: requires root");
            return;
        }
        let tag = std::process::id();
        let dir = std::env::temp_dir().join(format!("tethys-prov-{tag}"));
        let table = format!("tph{tag}"); // <16 chars, nft-friendly
        let hv = format!("vh-s{tag}");
        let toml_body = format!(
            "nft_table='{table}'\n[netns]\nname='smoke{tag}'\ndir='{d}'\nprefix4='10.231.77.0/29'\nhost_veth='{hv}'",
            d = dir.display(),
        );
        let file: FileConfig = toml::from_str(&toml_body).unwrap();
        let spec = Spec::from_config(&file, None).unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let outcome = rt.block_on(async {
            let res = run_spec(&spec).await;
            // Drop both private tables (host stack + inside the ns) while
            // the runtime and namespace still exist.
            let mut b = Batch::with_table(&spec.table);
            b.push_cmd(json!({"delete":{"table":{"family":"inet","name":spec.table}}}));
            let _ = NftCli::default().apply(&b).await;
            if let Ok(inside) = NftCli::in_netns(&spec.path) {
                let mut b2 = Batch::with_table(&spec.table);
                b2.push_cmd(json!({"delete":{"table":{"family":"inet","name":spec.table}}}));
                let _ = inside.apply(&b2).await;
            }
            res
        });

        let _ = ip(["link", "del", &hv]).output();
        drop(rt);
        let _ = std::process::Command::new("umount")
            .arg(&spec.path)
            .output();
        let _ = std::fs::remove_file(&spec.path);
        let _ = std::fs::remove_dir_all(dir);

        outcome.expect("provision round trip");
    }

    // Parser gate: nft validates the whole batch before it ever opens
    // netlink, so an UNPRIVILEGED run still catches JSON grammar errors —
    // apply only fails with EPERM after parsing succeeded. This test
    // exists because the first root run found a wrong `fib` member name
    // that every hand-written JSON assertion missed: they asserted my
    // assumptions about the schema, not the schema.
    #[test]
    fn batches_parse_under_local_nft() {
        use std::io::Write;
        if Command::new("nft").arg("--version").output().is_err() {
            eprintln!("SKIP batches_parse_under_local_nft: no nft binary");
            return;
        }
        let tag = std::process::id();
        let table = format!("pchk{tag}"); // <16 chars, nft-friendly
        let toml_body = format!(
            "nft_table='{t}'\n[netns]\nname='pc{tag}'\ndir='/tmp'\nprefix4='10.231.77.0/29'",
            t = table
        );
        let file: FileConfig = toml::from_str(&toml_body).unwrap();
        let spec = Spec::from_config(&file, None).unwrap();
        let mut ns_batch = Batch::with_table(&table);
        ns_batch.ensure_base();
        let check = |name: &str, body: String| {
            // Validation ladder, strongest first:
            //  1. `unshare -n nft` (root): a throwaway netns with full
            //     privileges — the batch is APPLIED there, so semantic
            //     errors ("Basetype ... is not bitmask") surface too, and
            //     the netns dies with the process: zero cleanup.
            //  2. `unshare -Umrn nft` (unprivileged boxes that allow
            //     userns): same strength via a user namespace.
            //  3. plain `nft`: parse-only — parsing precedes netlink init,
            //     so grammar errors still surface; semantics do not.
            // A wrapper that cannot even run (seccomp, containers) or
            // leaves only permission errors falls through to the next rung.
            let wrappers: [&[&str]; 3] = [&["unshare", "-n"], &["unshare", "-Umrn"], &[]];
            let mut parse_only_ok = false;
            for wrapper in wrappers {
                let mut cmd = match wrapper.first() {
                    Some(prog) => {
                        let mut c = Command::new(prog);
                        c.args(&wrapper[1..]).arg("nft");
                        c
                    }
                    None => Command::new("nft"),
                };
                cmd.args(["--json", "-f", "-"]);
                let mut child = match cmd
                    .stdin(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                {
                    Ok(c) => c,
                    Err(_) => continue, // wrapper binary absent
                };
                let mut stdin = child.stdin.take().unwrap();
                let _ = stdin.write_all(body.as_bytes());
                drop(stdin);
                let out = child.wait_with_output().unwrap();
                let err = String::from_utf8_lossy(&out.stderr).to_string();
                if out.status.success() {
                    return; // fully validated (applied in a throwaway netns)
                }
                if err.contains("unshare:") {
                    continue; // wrapper itself failed; next rung
                }
                let unexplained: Vec<&str> = err
                    .lines()
                    .map(str::trim)
                    .filter(|l| l.contains("Error:") || l.contains("syntax error"))
                    .filter(|l| !l.starts_with("netlink: Error: cache initialization failed"))
                    .filter(|l| {
                        !l.contains("Operation not permitted") && !l.contains("Permission denied")
                    })
                    .collect();
                assert!(
                    unexplained.is_empty(),
                    "{name} batch rejected by nft ({wrapper:?}): {unexplained:?}\nfull: {err}"
                );
                parse_only_ok = true; // permission-limited pass; try stronger
            }
            assert!(parse_only_ok, "{name}: no nft validation rung ran");
        };
        check("host_batch", host_batch(&spec).to_json());
        check("ensure_base", ns_batch.to_json());
    }
}
