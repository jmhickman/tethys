//! Socket kill (step 4): destroying live TCP flows when their grant leaves,
//! so a granted session can no longer outlive its kernel element.
//!
//! Mechanism: the same netlink calls `ss -K` makes, made directly — a
//! `NETLINK_SOCK_DIAG` dump (`SOCK_DIAG_BY_FAMILY`) of TCP sockets in the
//! killable states (established, handshake, half-closed — see
//! [`TCPF_KILL`]), userspace filtering against the grant tuple, then one
//! `SOCK_DESTROY` request per match (uapi `linux/sock_diag.h`). No external
//! binary: minimal LXC images — a first-class deployment target — may ship
//! no iproute2 at all, and ss's filter grammar has no uid term anyway. The
//! netns boundary IS the account boundary here (everything inside belongs
//! to the policed account by construction), yet the dump's `idi_uid` is
//! still checked when `agent_uid` resolves — belt-and-braces, and it is
//! what makes the plan's "+ agent uid" real.
//!
//! Netns mechanics: `setns(CLONE_NEWNET)` is THREAD-scoped, so the whole
//! dump+destroy runs on a dedicated thread that joins and exits — tokio's
//! reusable blocking-pool threads must never stay pinned inside the agent
//! netns (a later `getaddrinfo` on a recycled worker would resolve there).
//! The netlink socket is created after the setns, binding it to the target
//! namespace.
//!
//! Ordering contract (shared with install.rs): kill AFTER the grant element
//! is gone. A killed process reconnecting must hit the (already removed)
//! element's drop, not slip back through a still-live rule.
//!
//! UDP gap: `SOCK_DESTROY` covers TCP only. Destroying a UDP socket would
//! not age out the conntrack entries carrying its assumed flow anyway, so
//! UDP flows fade with conntrack timeouts instead of being cut; documented
//! for operators in DEPLOYMENT.md (step 9).

// The sock_diag syscalls are this module's audited unsafe surface: plain
// libc calls on private fds and live buffers, same posture as core's
// setns/nft spawn helpers.
#![allow(unsafe_code)]

use std::io;
use std::mem;
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::sync::Arc;

use tethys_core::nft::ElemDst;
use tethys_core::types::{Direction, PortSpec, Proto};

use crate::server::State;

// ------------------------------------------------------------- sock_diag wire

/// uapi linux/netlink.h
const NETLINK_SOCK_DIAG: i32 = 4;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04; // uapi netlink.h: "Reply with ack, with zero or error code"
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_NOOP: u16 = 0x1;
const NLMSG_ERROR: u16 = 0x2;
const NLMSG_DONE: u16 = 0x3;
const NLMSG_HDRLEN: usize = 16;
/// uapi linux/sock_diag.h
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const SOCK_DESTROY: u16 = 21;
/// uapi linux/inet_diag.h states
const TCP_ESTABLISHED: u8 = 1;
const TCP_SYN_SENT: u8 = 2;
const TCP_SYN_RECV: u8 = 3;
const TCP_FIN_WAIT1: u8 = 4;
const TCP_FIN_WAIT2: u8 = 5;
const TCP_CLOSE_WAIT: u8 = 8;
const TCP_NEW_SYN_RECV: u8 = 12;
const IPPROTO_TCP: u8 = 6;
/// Kernel tcp_states.h convention: the bitmask bit is `1 << state`, NOT
/// `1 << (state - 1)` — off by one here silently requests TCP_CLOSE and
/// every dump comes back empty (verified live).
///
/// Kill-pass mask: every state that can still complete a handshake or
/// carry bytes. SYN-SENT/SYN-RECV/NEW-SYN-RECV close the "handshake
/// completes after the kill" race: conntrack's established/reply accepts
/// let the final ACK through without consulting any grant set, so an
/// in-flight handshake must be destroyed by the pass, not trusted to the
/// rules it already outran. FIN-WAIT/CLOSE-WAIT cut leftover bytes on
/// half-closed flows. TIME_WAIT/CLOSE/LAST_ACK/CLOSING carry nothing
/// killable and LISTEN is not a flow (and never matches the tuple) — all
/// excluded. A kernel that refuses SOCK_DESTROY on request sockets logs
/// the per-socket failure and moves on; the pass degrades to
/// established+half-closed there.
const TCPF_KILL: u32 = (1 << TCP_ESTABLISHED)
    | (1 << TCP_SYN_SENT)
    | (1 << TCP_SYN_RECV)
    | (1 << TCP_FIN_WAIT1)
    | (1 << TCP_FIN_WAIT2)
    | (1 << TCP_CLOSE_WAIT)
    | (1 << TCP_NEW_SYN_RECV);
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
/// CLONE_NEWNET for setns(2)
const NEWNET: i32 = 0x4000_0000;

/// `struct nlmsghdr` (16 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

/// `struct inet_diag_req_v2` (56 bytes). Ports are big-endian on the wire;
/// zero means wildcard. Byte 1 is the IPPROTO_* selector (NOT a state —
/// states are the bitmask); getting it wrong silently queries another
/// protocol's diag table.
#[repr(C)]
#[derive(Clone, Copy)]
struct InetDiagReqV2 {
    sdiag_family: u8,
    sdiag_protocol: u8,
    idiag_ext: u8,
    pad: u8,
    idiag_states: u32,
    idiag_sport: [u8; 2],
    idiag_dport: [u8; 2],
    idiag_src: [u8; 16],
    idiag_dst: [u8; 16],
    idiag_if: u32,
    idiag_cookie: [u32; 2],
}

// The kernel validates request length exactly; layout drift must fail the
// build, not the (root-only) runtime path.
const _: () = assert!(mem::size_of::<InetDiagReqV2>() == 56);
const _: () = assert!(mem::size_of::<NlMsgHdr>() == 16);

impl InetDiagReqV2 {
    fn wildcard(family: u8) -> Self {
        Self {
            sdiag_family: family,
            sdiag_protocol: IPPROTO_TCP,
            idiag_ext: 0,
            pad: 0,
            idiag_states: TCPF_KILL,
            idiag_sport: [0; 2],
            idiag_dport: [0; 2],
            idiag_src: [0; 16],
            idiag_dst: [0; 16],
            idiag_if: 0,
            idiag_cookie: [0; 2],
        }
    }

    /// A destroy request pinned to one dumped socket (5-tuple + cookie),
    /// exactly what `ss -K` sends per match.
    fn for_sock(s: &SockInfo) -> Self {
        Self {
            sdiag_family: s.family,
            sdiag_protocol: IPPROTO_TCP,
            idiag_ext: 0,
            pad: 0,
            idiag_states: TCPF_KILL,
            idiag_sport: s.sport.to_be_bytes(),
            idiag_dport: s.dport.to_be_bytes(),
            idiag_src: s.src,
            idiag_dst: s.dst,
            idiag_if: s.ifidx,
            idiag_cookie: s.cookie,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe {
            // SAFETY: repr(C) POD of fixed size; every field laid out
            // explicitly above, no padding-sensitive semantics.
            std::slice::from_raw_parts(self as *const Self as *const u8, mem::size_of::<Self>())
        }
    }
}

/// One established TCP socket as read from a `SOCK_DIAG_BY_FAMILY` dump
/// (`inet_diag_msg`: family/state/timer/retrans, then inet_diag_sockid
/// {sport, dport, src[4]u32, dst[4]u32, if, cookie[2]} ending at offset
/// 52, then expires/rqueue/wqueue/uid/inode as host-order u32s — uid at
/// 64, sizeof 72; uapi linux/inet_diag.h).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SockInfo {
    family: u8,
    sport: u16,
    dport: u16,
    src: [u8; 16],
    dst: [u8; 16],
    uid: u32,
    ifidx: u32,
    cookie: [u32; 2],
}

impl SockInfo {
    fn ip_of(&self, b: [u8; 16]) -> IpAddr {
        if self.family == AF_INET {
            IpAddr::from(<[u8; 4]>::try_from(&b[..4]).unwrap())
        } else {
            let v6 = IpAddr::from(b);
            // A v4 client on a dual-stack listener shows as ::ffff:a.b.c.d;
            // normalize so v4 grant elements match those sockets.
            match v6 {
                IpAddr::V6(v) if v.to_ipv4_mapped().is_some() => {
                    IpAddr::V4(v.to_ipv4_mapped().unwrap())
                }
                other => other,
            }
        }
    }
    /// Local endpoint — used by the live tests to identify each side of
    /// a loopback pair; production filtering only ever needs the remote
    /// side (see `peer`).
    #[cfg(test)]
    fn src_ip(&self) -> IpAddr {
        self.ip_of(self.src)
    }
    fn dst_ip(&self) -> IpAddr {
        self.ip_of(self.dst)
    }
    /// The socket's peer from the namespace's point of view: egress
    /// sockets peer at dst, ingress sockets peer at src (the client).
    /// The remote endpoint of the socket. inet_diag is PER-SOCKET, not
    /// packet-oriented: net/ipv4/inet_diag.c fills idiag_src from
    /// sk_rcv_saddr and idiag_dst from sk_daddr — src is LOCAL, dst is
    /// REMOTE on every socket, in both directions. The peer is therefore
    /// dst_ip() for either grant direction; what direction selects is the
    /// PORT (granted_port below), not the address side. (An earlier
    /// "ingress peer = src" reading — packet-sense — compared ingress
    /// grants against the socket's local address and silently killed
    /// nothing; live e2e caught what loopback tests could not.)
    fn peer(&self, _dir: Direction) -> IpAddr {
        self.dst_ip()
    }
    /// The granted port from the namespace's point of view: egress is
    /// constrained by peer port (dport), ingress by LOCAL port (sport).
    fn granted_port(&self, dir: Direction) -> u16 {
        if dir.is_ingress() {
            self.sport
        } else {
            self.dport
        }
    }
}

/// Parse one `inet_diag_msg` payload. Short messages and states outside
/// the kill-pass mask yield None.
fn parse_sock(msg: &[u8]) -> Option<SockInfo> {
    // sizeof(inet_diag_msg) = 4 + sockid(48) + expires/rqueue/wqueue/uid/
    // inode(20) = 72.
    if msg.len() < 72
        || !matches!(
            msg[1],
            TCP_ESTABLISHED
                | TCP_SYN_SENT
                | TCP_SYN_RECV
                | TCP_FIN_WAIT1
                | TCP_FIN_WAIT2
                | TCP_CLOSE_WAIT
                | TCP_NEW_SYN_RECV
        )
    {
        return None;
    }
    // Only the sockid's ports and addresses are network order; if, cookie,
    // uid and inode are plain host-order __u32s.
    let u16b = |o: usize| u16::from_be_bytes([msg[o], msg[o + 1]]);
    let u32n = |o: usize| u32::from_ne_bytes([msg[o], msg[o + 1], msg[o + 2], msg[o + 3]]);
    let family = msg[0];
    let n = if family == AF_INET { 4 } else { 16 };
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src[..n].copy_from_slice(&msg[8..8 + n]);
    dst[..n].copy_from_slice(&msg[24..24 + n]);
    Some(SockInfo {
        family,
        sport: u16b(4),
        dport: u16b(6),
        src,
        dst,
        ifidx: u32n(40),
        cookie: [u32n(44), u32n(48)],
        uid: u32n(64),
    })
}

/// Walk a netlink datagram buffer, invoking `f` per payload message.
/// Returns Ok(true) on NLMSG_DONE, Ok(false) when the buffer ended
/// naturally, Err with the kernel's negative errno on NLMSG_ERROR.
fn for_each_msg(buf: &[u8], mut f: impl FnMut(&[u8]) -> bool) -> Result<bool, i32> {
    let mut off = 0usize;
    while off + NLMSG_HDRLEN <= buf.len() {
        let hdr = unsafe {
            // SAFETY: bounds checked by the loop condition; nlmsghdr is
            // repr(C, align 4) and netlink buffers are aligned.
            &*(buf.as_ptr().add(off) as *const NlMsgHdr)
        };
        let len = hdr.nlmsg_len as usize;
        if len < NLMSG_HDRLEN || off + len > buf.len() {
            break;
        }
        let payload = &buf[off + NLMSG_HDRLEN..off + len];
        match hdr.nlmsg_type {
            NLMSG_NOOP => {}
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => {
                if payload.len() < 4 {
                    return Err(libc::EPROTO);
                }
                let code = i32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
                if code != 0 {
                    return Err(code); // negative errno
                }
            }
            _ => {
                if !f(payload) {
                    return Ok(false);
                }
            }
        }
        off += (len + 3) & !3; // NLMSG_ALIGN
    }
    Ok(false)
}

// ------------------------------------------------------------------ syscalls

/// setns + netlink socket creation must share a thread: CLONE_NEWNET via
/// setns(2) is thread-scoped, and the socket binds to the creating
/// thread's namespace. The dedicated thread exits when done, so no pooled
/// runtime thread is ever left inside the agent netns.
fn open_diag(ns_fd: Option<RawFd>) -> io::Result<RawFd> {
    unsafe {
        if let Some(fd) = ns_fd {
            if libc::setns(fd, NEWNET) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_SOCK_DIAG,
        );
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_nl = mem::zeroed();
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = 0;
        addr.nl_groups = 0;
        let rc = libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as u32,
        );
        if rc != 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        // No recv on this fd may ever block unboundedly: a protocol
        // break (e.g. a reply shape we misread) must surface as a
        // bounded EAGAIN through kill_flows' error path, not hang the
        // admin RPC behind this thread.
        let tv = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            mem::size_of::<libc::timeval>() as libc::socklen_t,
        ) != 0
        {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        Ok(fd)
    }
}

fn send_msg(fd: RawFd, msg_type: u16, flags: u16, seq: u32, body: &[u8]) -> io::Result<()> {
    let hdr = NlMsgHdr {
        nlmsg_len: (NLMSG_HDRLEN + body.len()) as u32,
        nlmsg_type: msg_type,
        nlmsg_flags: flags,
        nlmsg_seq: seq,
        nlmsg_pid: 0,
    };
    let iov = [
        libc::iovec {
            iov_base: &hdr as *const _ as *mut libc::c_void,
            iov_len: NLMSG_HDRLEN,
        },
        libc::iovec {
            iov_base: body.as_ptr() as *mut libc::c_void,
            iov_len: body.len(),
        },
    ];
    let rc = unsafe {
        // SAFETY: both iovecs point into locals that outlive the sendmsg.
        let msg = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: iov.as_ptr() as *mut libc::iovec,
            msg_iovlen: 2,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        libc::sendmsg(fd, &msg, 0)
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Dump every established TCP socket of one family.
fn dump_family(fd: RawFd, family: u8, seq: u32, out: &mut Vec<SockInfo>) -> io::Result<()> {
    let req = InetDiagReqV2::wildcard(family);
    send_msg(
        fd,
        SOCK_DIAG_BY_FAMILY,
        NLM_F_REQUEST | NLM_F_DUMP,
        seq,
        req.as_bytes(),
    )?;
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let done = for_each_msg(&buf[..n as usize], |payload| {
            if let Some(s) = parse_sock(payload) {
                out.push(s);
            }
            true
        })
        .map_err(|code| io::Error::from_raw_os_error(-code))?;
        if done {
            return Ok(());
        }
    }
}

/// Read the terminal NLMSG_ERROR reply of an NLM_F_ACK'd unicast request:
/// 0 on success, negative errno otherwise. Skips NOOP and foreign-seq
/// messages (a private, unbound diag socket should see neither, but a
/// mismatch must never be mistaken for our ACK).
fn recv_ack(fd: RawFd, seq: u32) -> io::Result<i32> {
    let mut buf = [0u8; 2048];
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let buf = &buf[..n as usize];
    let mut off = 0usize;
    while off + NLMSG_HDRLEN <= buf.len() {
        let hdr = unsafe {
            // SAFETY: bounds checked by the loop condition; repr(C, align 4)
            // header over an aligned netlink buffer.
            &*(buf.as_ptr().add(off) as *const NlMsgHdr)
        };
        let len = hdr.nlmsg_len as usize;
        if len < NLMSG_HDRLEN || off + len > buf.len() {
            break;
        }
        match hdr.nlmsg_type {
            NLMSG_NOOP => {}
            NLMSG_ERROR if hdr.nlmsg_seq == seq => {
                let payload = &buf[off + NLMSG_HDRLEN..off + len];
                if payload.len() < 4 {
                    return Err(io::Error::from_raw_os_error(libc::EPROTO));
                }
                return Ok(i32::from_ne_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                ]));
            }
            _ => {}
        }
        off += (len + 3) & !3;
    }
    Err(io::Error::from_raw_os_error(libc::EPROTO))
}

/// Destroy one socket; returns how many were destroyed (1 normally, 0 if
/// the tuple raced to nothing). Kernel truth
/// (net/ipv4/inet_diag.c::inet_diag_handler_cmd): the NLM_F_DUMP branch
/// is SOCK_DIAG_BY_FAMILY ONLY — SOCK_DESTROY is an EXACT command
/// (find one socket, `sock_diag_destroy` it), and its success is SILENT
/// unless NLM_F_ACK is set. An un-ACKed successful destroy sends no reply
/// at all, so a dump-style recv loop hangs forever on the FIRST socket
/// actually killed (live-bitten: revoke timed out behind a blocked
/// sock_pass thread; the probe never hit this because its impossible
/// tuple always answered -ENOENT).
fn destroy_sock(fd: RawFd, s: &SockInfo, seq: u32) -> io::Result<usize> {
    let req = InetDiagReqV2::for_sock(s);
    send_msg(
        fd,
        SOCK_DESTROY,
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        req.as_bytes(),
    )?;
    match recv_ack(fd, seq)? {
        0 => Ok(1),
        code if code < 0 => match -code {
            libc::ENOENT => Ok(0),
            e => Err(io::Error::from_raw_os_error(e)),
        },
        _ => Err(io::Error::from_raw_os_error(libc::EPROTO)),
    }
}

/// Run `work` on a dedicated thread that first setns'es into the
/// enforcement netns (None = host stack, dev/dry-run fallback).
async fn sock_pass<T: Send + 'static>(
    st: &State,
    work: impl FnOnce(RawFd) -> io::Result<T> + Send + 'static,
) -> Result<T, String> {
    let ns_fd = st.nft.netns_fd().map_err(|e| format!("netns fd: {e}"))?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = open_diag(ns_fd).and_then(|fd| {
            let out = work(fd);
            unsafe { libc::close(fd) };
            out
        });
        let _ = tx.send(r);
    });
    rx.recv()
        .map_err(|_| "sock_diag thread died".to_string())?
        .map_err(|e| e.to_string())
}

// ----------------------------------------------------------------- filtering

/// Does this dumped socket belong to the grant tuple? Peer is the remote
/// endpoint for both directions (see SockInfo::peer); the DIRECTION picks
/// which port is the granted one (local sport for ingress, remote dport
/// for egress), range-checked against the nft-normalized spec; uid is
/// checked when resolvable.
fn sock_matches(
    s: &SockInfo,
    dir: Direction,
    dsts: &[ElemDst],
    port: &PortSpec,
    agent_uid: Option<u32>,
) -> bool {
    let peer = s.peer(dir);
    let in_dsts = dsts.iter().any(|d| match d {
        ElemDst::Ip(ip) => peer == *ip,
        ElemDst::Net(n) => n.contains(&peer),
    });
    if !in_dsts {
        return false;
    }
    let (lo, hi) = port.nft_range();
    if !(lo <= s.granted_port(dir) && s.granted_port(dir) <= hi) {
        return false;
    }
    match agent_uid {
        Some(uid) => s.uid == uid,
        None => true,
    }
}

/// One full kill pass on an open diag socket: dump both families, filter
/// against the grant tuple, destroy the matches. Sync and fd-parameterized
/// so the live-kernel tests can drive it directly on the host stack.
fn kill_work(
    fd: RawFd,
    dir: Direction,
    dsts: &[ElemDst],
    port: &PortSpec,
    uid: Option<u32>,
) -> io::Result<usize> {
    let mut socks = Vec::new();
    dump_family(fd, AF_INET, 1, &mut socks)?;
    dump_family(fd, AF_INET6, 2, &mut socks)?;
    let mut killed = 0usize;
    for s in socks
        .iter()
        .filter(|s| sock_matches(s, dir, dsts, port, uid))
    {
        match destroy_sock(fd, s, 3) {
            Ok(n) => killed += n,
            Err(e) => tracing::warn!(%e, "SOCK_DESTROY failed for one socket"),
        }
    }
    Ok(killed)
}

// ---------------------------------------------------------------- public API

/// Destroy TCP flows matching one grant in any killable state (see
/// [`TCPF_KILL`]: established, in-flight handshake, half-closed); returns
/// how many sockets were killed. Silent no-ops (returning 0): dry-run, UDP
/// (see module docs), or capability absent — the condition was logged once
/// at boot by [`probe`].
pub(crate) async fn kill_flows(
    st: &Arc<State>,
    dir: Direction,
    proto: Proto,
    dsts: &[ElemDst],
    port: PortSpec,
) -> usize {
    if st.cfg.dry_run || proto != Proto::Tcp || dsts.is_empty() {
        return 0;
    }
    if !st.sock_destroy.load(std::sync::atomic::Ordering::Relaxed) {
        return 0;
    }
    let uid = st.cfg.agent_uid;
    let dsts = dsts.to_vec();
    let result = sock_pass(st, move |fd| kill_work(fd, dir, &dsts, &port, uid)).await;
    match result {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(%e, "socket kill pass failed (element teardown already done)");
            0
        }
    }
}

/// Sync probe body on an open diag socket (live-testable on the host
/// stack). A SOCK_DESTROY request whose tuple cannot
/// exist (reserved 240.0.0.1 peer, ports 65535/65534) still separates
/// kernels: sock_diag answers an unregistered message type with
/// EOPNOTSUPP *before* matching any socket, so an unsupporting kernel
/// (CONFIG_INET_DIAG_DESTROY=n) errors on the probe itself, while a
/// supporting one completes the (empty) destroy-dump. Any other failure
/// (EPERM without CAP_NET_ADMIN, netns gone) degrades identically:
/// element-deletion-only, logged loudly once.
fn probe_diag(fd: RawFd) -> io::Result<bool> {
    let req = InetDiagReqV2 {
        sdiag_family: AF_INET,
        sdiag_protocol: IPPROTO_TCP,
        idiag_ext: 0,
        pad: 0,
        idiag_states: TCPF_KILL,
        idiag_sport: 65534u16.to_be_bytes(),
        idiag_dport: 65535u16.to_be_bytes(),
        idiag_src: [0; 16],
        // 240.0.0.1: reserved; nothing lives there.
        idiag_dst: [240, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        idiag_if: 0,
        idiag_cookie: [0; 2],
    };
    send_msg(
        fd,
        SOCK_DESTROY,
        NLM_F_REQUEST | NLM_F_ACK,
        9,
        req.as_bytes(),
    )?;
    // ACK'd unicast: exactly one NLMSG_ERROR answers every outcome —
    // EOPNOTSUPP (handler absent) vs ENOENT/success (handler ran) is the
    // separation being probed. ACK also guarantees a reply even in the
    // impossible case the probe tuple matches something real.
    match recv_ack(fd, 9)? {
        0 => Ok(true),
        code if code < 0 => match -code {
            libc::EOPNOTSUPP => Ok(false),
            // Zero sockets matched: the destroy handler RAN, which is
            // exactly the capability being probed.
            libc::ENOENT => Ok(true),
            e => Err(io::Error::from_raw_os_error(e)),
        },
        _ => Err(io::Error::from_raw_os_error(libc::EPROTO)),
    }
}

/// Boot-time capability probe: runs [`probe_diag`] on the enforcement
/// netns thread and maps the outcome onto `State.sock_destroy`, logging
/// the degraded mode loudly exactly once.
pub(crate) async fn probe(st: &Arc<State>) -> bool {
    let result = sock_pass(st, probe_diag).await;
    match result {
        Ok(true) => {
            tracing::info!("socket-kill capability confirmed (SOCK_DESTROY)");
            true
        }
        Ok(false) => {
            tracing::error!(
                "kernel lacks CONFIG_INET_DIAG_DESTROY (sock_diag answered EOPNOTSUPP): \
                 revoke/expiry/stop.grants delete elements only — established TCP flows \
                 outlive their grants until they close on their own"
            );
            false
        }
        Err(e) => {
            tracing::error!(%e, "socket-kill probe failed; degrading to element-deletion-only");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn v4() -> ElemDst {
        ElemDst::Ip("104.26.10.242".parse::<IpAddr>().unwrap())
    }
    fn net6() -> ElemDst {
        ElemDst::Net("2001:db8::/32".parse().unwrap())
    }
    fn port(from: u16, to: u16) -> PortSpec {
        PortSpec { from, to }
    }

    /// An egress socket: ns -> 104.26.10.242:443.
    fn egress_sock() -> SockInfo {
        let mut src = [0u8; 16];
        src[..4].copy_from_slice(&[10, 91, 0, 2]);
        let mut dst = [0u8; 16];
        dst[..4].copy_from_slice(&[104, 26, 10, 242]);
        SockInfo {
            family: AF_INET,
            sport: 51111,
            dport: 443,
            src,
            dst,
            uid: 999,
            ifidx: 7,
            cookie: [1, 2],
        }
    }

    /// The accepted socket an ingress grant must kill, exactly as the
    /// kernel reports it: LOCAL side [2001:db8::42]:22 (idiag_src/
    /// idiag_sport = sk_rcv_saddr/inet_sport), REMOTE side the v4 client
    /// ::ffff:203.0.113.7:33333 on a dual-stack listener (idiag_dst).
    /// The earlier fixture put the client in `src` — packet-sense — and
    /// thereby asserted the inverted peer rule.
    fn ingress_sock() -> SockInfo {
        let mut src = [0u8; 16];
        src[0] = 0x20;
        src[1] = 0x01;
        src[2] = 0x0d;
        src[3] = 0xb8;
        src[15] = 0x42;
        let mut dst = [0u8; 16];
        dst[10] = 0xff;
        dst[11] = 0xff;
        dst[12..16].copy_from_slice(&[203, 0, 113, 7]);
        SockInfo {
            family: AF_INET6,
            sport: 22,
            dport: 33333,
            src,
            dst,
            uid: 999,
            ifidx: 7,
            cookie: [3, 4],
        }
    }

    #[test]
    fn egress_matches_peer_dst_and_dport() {
        let s = egress_sock();
        assert!(sock_matches(
            &s,
            Direction::Egress,
            &[v4()],
            &port(443, 443),
            Some(999)
        ));
        // Wrong direction sense must not match: this socket's LOCAL port
        // is ephemeral, its peer port is 443.
        assert!(!sock_matches(
            &s,
            Direction::Ingress,
            &[v4()],
            &port(443, 443),
            Some(999)
        ));
    }

    #[test]
    fn ingress_matches_client_dst_and_local_sport() {
        let s = ingress_sock();
        let client = ElemDst::Ip("203.0.113.7".parse().unwrap());
        assert!(sock_matches(
            &s,
            Direction::Ingress,
            std::slice::from_ref(&client),
            &port(22, 22),
            None
        ));
        assert!(!sock_matches(
            &s,
            Direction::Egress,
            std::slice::from_ref(&client),
            &port(22, 22),
            None
        ));
    }

    #[test]
    fn cidr_membership_and_v4_mapped() {
        let s = ingress_sock();
        // Ingress elems are CLIENT sources: the v4-mapped src must match a
        // plain v4 element (dual-stack listeners report ::ffff:a.b.c.d).
        let client = ElemDst::Ip("203.0.113.7".parse().unwrap());
        assert!(sock_matches(
            &s,
            Direction::Ingress,
            &[client],
            &port(22, 22),
            None
        ));
        // Per-socket sense: the peer is the REMOTE side for BOTH
        // directions; direction picks the port. Egress on this socket
        // means "agent dialed 203.0.113.7:33333" — dport side.
        let wrong = ElemDst::Net("203.0.113.0/24".parse().unwrap());
        assert!(sock_matches(
            &s,
            Direction::Egress,
            &[wrong],
            &port(33333, 33333),
            None
        ));
        // The LOCAL net is never an egress peer, and never an ingress
        // one either: an ingress grant keyed on the local address must
        // not match (this assertion kills the src-as-peer inversion).
        assert!(!sock_matches(
            &s,
            Direction::Egress,
            &[net6()],
            &port(33333, 33333),
            None
        ));
        assert!(!sock_matches(
            &s,
            Direction::Ingress,
            &[net6()],
            &port(22, 22),
            None
        ));
    }

    #[test]
    fn ranges_all_ports_and_uid_gating() {
        let s = egress_sock();
        assert!(sock_matches(
            &s,
            Direction::Egress,
            &[v4()],
            &port(400, 500),
            None
        ));
        assert!(!sock_matches(
            &s,
            Direction::Egress,
            &[v4()],
            &port(80, 90),
            None
        ));
        assert!(sock_matches(
            &s,
            Direction::Egress,
            &[v4()],
            &port(0, 0),
            None
        )); // all-ports
        assert!(!sock_matches(
            &s,
            Direction::Egress,
            &[v4()],
            &port(443, 443),
            Some(1000)
        ));
        assert!(sock_matches(
            &s,
            Direction::Egress,
            &[v4()],
            &port(443, 443),
            Some(999)
        ));
    }

    #[test]
    fn request_is_56_bytes_selecting_tcp() {
        // The kernel validates request length exactly and dispatches on
        // sdiag_protocol; a layout drift here fails silently at runtime
        // (empty dumps), so pin the contract in bytes.
        let req = InetDiagReqV2::wildcard(AF_INET);
        let b = req.as_bytes();
        assert_eq!(b.len(), 56);
        assert_eq!(b[0], AF_INET);
        assert_eq!(b[1], IPPROTO_TCP, "byte 1 is the protocol, not a state");
        assert_eq!(u32::from_ne_bytes([b[4], b[5], b[6], b[7]]), TCPF_KILL);
    }

    #[test]
    fn parses_inet_diag_msg_bytes() {
        // Hand-built inet_diag_msg (uapi layout, 72 bytes): v4
        // established, sport :7, dport :9, src 127.0.0.1, dst 10.0.0.1,
        // cookie [1111,2222] (host-order), uid 5 at offset 64.
        let mut m = vec![0u8; 72];
        m[0] = AF_INET;
        m[1] = TCP_ESTABLISHED;
        m[4..6].copy_from_slice(&7u16.to_be_bytes());
        m[6..8].copy_from_slice(&9u16.to_be_bytes());
        m[8..12].copy_from_slice(&[127, 0, 0, 1]);
        m[24..28].copy_from_slice(&[10, 0, 0, 1]);
        m[44..48].copy_from_slice(&1111u32.to_ne_bytes());
        m[48..52].copy_from_slice(&2222u32.to_ne_bytes());
        m[64..68].copy_from_slice(&5u32.to_ne_bytes());
        let s = parse_sock(&m).unwrap();
        assert_eq!(s.sport, 7);
        assert_eq!(s.dport, 9);
        assert_eq!(s.src_ip().to_string(), "127.0.0.1");
        assert_eq!(s.dst_ip().to_string(), "10.0.0.1");
        assert_eq!(s.uid, 5);
        assert_eq!(s.cookie, [1111, 2222]);
        // A message that stops before the uid field is not parsed: the
        // uid offset (64) must not silently read padding as uid.
        m[64..68].copy_from_slice(&0u32.to_ne_bytes());
        m[52..56].copy_from_slice(&999u32.to_ne_bytes()); // idiag_expires
        assert!(parse_sock(&m[..71]).is_none());
        assert_eq!(parse_sock(&m).unwrap().uid, 0, "expires(999) is not uid");
        // Non-killable states are skipped; killable handshake states are not.
        m[1] = 2; // SYN_SENT
        assert!(parse_sock(&m).is_some());
        m[1] = 3; // SYN_RECV
        assert!(parse_sock(&m).is_some());
        m[1] = 6; // TIME_WAIT: carries nothing
        assert!(parse_sock(&m).is_none());
        m[1] = 10; // LISTEN: not a flow
        assert!(parse_sock(&m).is_none());
    }

    #[test]
    fn netlink_walk_noop_done_and_error() {
        let msg = |ty: u16, body: &[u8]| -> Vec<u8> {
            let hdr = NlMsgHdr {
                nlmsg_len: (NLMSG_HDRLEN + body.len()) as u32,
                nlmsg_type: ty,
                nlmsg_flags: 0,
                nlmsg_seq: 1,
                nlmsg_pid: 0,
            };
            let mut v =
                unsafe { std::slice::from_raw_parts(&hdr as *const _ as *const u8, NLMSG_HDRLEN) }
                    .to_vec();
            v.extend_from_slice(body);
            while v.len() % 4 != 0 {
                v.push(0);
            }
            v
        };
        let mut buf = msg(NLMSG_NOOP, &[]);
        buf.extend_from_slice(&msg(SOCK_DIAG_BY_FAMILY, &[AF_INET, TCP_ESTABLISHED, 0, 0]));
        buf.extend_from_slice(&msg(NLMSG_DONE, &[0; 4]));
        let mut seen = 0;
        let done = for_each_msg(&buf, |_p| {
            seen += 1;
            true
        })
        .unwrap();
        assert!(done);
        assert_eq!(seen, 1, "NOOP skipped, DONE ends the walk");

        let mut err = vec![0u8; 4];
        err[..4].copy_from_slice(&(-96i32).to_ne_bytes()); // -EOPNOTSUPP
        let ebuf = msg(NLMSG_ERROR, &err);
        assert!(matches!(for_each_msg(&ebuf, |_| true), Err(-96)));
    }

    #[test]
    fn netlink_walk_edge_shapes() {
        let msg = |ty: u16, body: &[u8]| -> Vec<u8> {
            let hdr = NlMsgHdr {
                nlmsg_len: (NLMSG_HDRLEN + body.len()) as u32,
                nlmsg_type: ty,
                nlmsg_flags: 0,
                nlmsg_seq: 1,
                nlmsg_pid: 0,
            };
            let mut v =
                unsafe { std::slice::from_raw_parts(&hdr as *const _ as *const u8, NLMSG_HDRLEN) }
                    .to_vec();
            v.extend_from_slice(body);
            // Netlink pads payloads to 4-byte alignment.
            while v.len() % 4 != 0 {
                v.push(0);
            }
            v
        };
        // Truncated header: walked as nothing, not a panic.
        assert_eq!(for_each_msg(&[0u8; 10], |_| true), Ok(false));
        // Unaligned payloads still visit every message (NLMSG_ALIGN).
        let mut buf = msg(SOCK_DIAG_BY_FAMILY, &[1; 1]);
        buf.extend_from_slice(&msg(SOCK_DIAG_BY_FAMILY, &[2; 5]));
        let mut seen = 0;
        assert_eq!(
            for_each_msg(&buf, |_| {
                seen += 1;
                true
            }),
            Ok(false)
        );
        assert_eq!(seen, 2);
        // A closure returning false stops the walk.
        let mut buf2 = msg(SOCK_DIAG_BY_FAMILY, &[1; 4]);
        buf2.extend_from_slice(&msg(SOCK_DIAG_BY_FAMILY, &[2; 4]));
        let mut seen2 = 0;
        assert_eq!(
            for_each_msg(&buf2, |_| {
                seen2 += 1;
                seen2 < 1
            }),
            Ok(false)
        );
        assert_eq!(seen2, 1);
        // NLMSG_ERROR with a truncated payload is EPROTO, not UB.
        let ebuf = msg(NLMSG_ERROR, &[0, 0]);
        assert!(matches!(for_each_msg(&ebuf, |_| true), Err(libc::EPROTO)));
    }

    // ---------------------------------------------------------- live kernel
    //
    // These drive the real syscall path on the HOST netns (open_diag with
    // no setns): the request/response ABI is exactly what unit byte-tests
    // cannot prove. Dumps need no privilege. The suite is portable by
    // construction: it never asserts distro kernel CONFIG — kernels
    // without CONFIG_INET_DIAG_DESTROY (production degrades on those)
    // must answer coherently, and the strict assertions (destroy of an
    // impossible tuple completes 0) engage exactly when the kernel says
    // it supports destroy. EINVAL/E2BIG anywhere means our request shape
    // drifted from the uapi; that is a regression on every kernel.

    fn with_host_diag<T>(f: impl FnOnce(RawFd) -> io::Result<T>) -> io::Result<T> {
        let fd = open_diag(None)?;
        let out = f(fd);
        unsafe { libc::close(fd) };
        out
    }

    #[test]
    fn live_dump_finds_a_loopback_pair_and_matches_grant_tuples() {
        use std::net::{TcpListener, TcpStream};
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let _c = TcpStream::connect(addr).unwrap();
        let (_srv, _) = l.accept().unwrap();

        let socks = with_host_diag(|fd| {
            let mut v = Vec::new();
            dump_family(fd, AF_INET, 1, &mut v)?;
            io::Result::Ok(v)
        })
        .expect("host dump must succeed (EINVAL here = request layout drift)");

        // The kernel answered with our sockets: the protocol byte and
        // struct size are accepted, and parsing found real entries.
        let cli = socks
            .iter()
            .find(|s| s.dport == addr.port() && s.dst_ip().to_string() == "127.0.0.1")
            .expect("client side of loopback pair must be dumped");
        let srv = socks
            .iter()
            .find(|s| s.sport == addr.port() && s.src_ip().to_string() == "127.0.0.1")
            .expect("server side of loopback pair must be dumped");

        // uid is read from the real kernel: offset 64, host order. A
        // regression to the old offset reads idiag_expires and fails here.
        let me = unsafe { libc::getuid() };
        assert_eq!(cli.uid, me, "idiag_uid offset must be 64");

        // Grant-tuple matching against live sockets, both senses:
        // an egress grant to 127.0.0.1:PORT kills the client socket...
        let dst = ElemDst::Ip("127.0.0.1".parse().unwrap());
        let p = PortSpec {
            from: addr.port(),
            to: addr.port(),
        };
        assert!(sock_matches(
            cli,
            Direction::Egress,
            std::slice::from_ref(&dst),
            &p,
            Some(me)
        ));
        assert!(!sock_matches(
            srv,
            Direction::Egress,
            std::slice::from_ref(&dst),
            &p,
            Some(me)
        ));
        // ...and an ingress grant on PORT from 127.0.0.1 kills the server
        // socket. (On loopback both sides share the peer ADDRESS, so this
        // live pair only exercises the port sense — the address sense is
        // pinned by the ingress_sock fixture; don't read a stronger
        // guarantee into this assertion than loopback can give.)
        assert!(sock_matches(
            srv,
            Direction::Ingress,
            std::slice::from_ref(&dst),
            &p,
            Some(me)
        ));
        assert!(!sock_matches(
            cli,
            Direction::Ingress,
            std::slice::from_ref(&dst),
            &p,
            Some(me)
        ));
    }

    /// Probe and destroy must tell a coherent story on ANY kernel — this
    /// is what makes the live suite portable across kernels with and
    /// without CONFIG_INET_DIAG_DESTROY (production degrades on the
    /// latter, so a test demanding support would fail correct code):
    ///
    /// ```text
    /// probe supported    -> destroy of an impossible tuple completes 0
    ///                       (strict: we demonstrably have the capability)
    /// probe unsupported  -> destroy must answer EOPNOTSUPP too;
    ///                       disagreement means our request shape broke
    /// probe EPERM        -> unprivileged: destroy may legitimately answer
    ///                       Ok(0), EPERM, or EOPNOTSUPP
    /// ```
    ///
    /// Any other outcome (EINVAL = struct-size drift, destroyed sockets
    /// for a tuple that cannot exist) fails the test.
    #[test]
    fn probe_and_destroy_are_coherent_on_the_live_kernel() {
        let mut ghost = ingress_sock();
        // Tuple that cannot exist locally: documentation-prefix dst,
        // NOCOOKIE cookie. (The ports are inside some hosts' ephemeral
        // ranges; the address is the real guard.)
        ghost.cookie = [u32::MAX, u32::MAX]; // INET_DIAG_NOCOOKIE
        ghost.dport = 65535;
        ghost.sport = 65534;
        let probe = with_host_diag(probe_diag);
        let destroy = with_host_diag(|fd| destroy_sock(fd, &ghost, 7));
        match (&probe, &destroy) {
            // Supported kernel: handler ran, matched nothing.
            (Ok(true), Ok(0)) => {}
            // Config-off kernel: both paths coherently say unsupported.
            (Ok(false), Err(e)) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => {}
            // Unprivileged: capability unknown; destroy's three
            // legitimate answers all pass, ABI drift never does.
            (Err(_), _)
                if probe.as_ref().err().and_then(|e| e.raw_os_error()) == Some(libc::EPERM) =>
            {
                if let Ok(n) = &destroy {
                    assert_eq!(*n, 0, "ghost tuple must destroy nothing");
                } else if let Err(d) = &destroy {
                    assert!(
                        matches!(d.raw_os_error(), Some(libc::EPERM) | Some(libc::EOPNOTSUPP)),
                        "unexpected destroy outcome: {d}"
                    );
                }
            }
            (Ok(true), Ok(n)) => panic!("ghost tuple must destroy nothing, destroyed {n}"),
            (Ok(true), Err(e)) => panic!("probe says supported but destroy failed: {e}"),
            (Ok(false), Ok(n)) => panic!("probe unsupported but destroy returned {n}"),
            (Ok(false), Err(e)) => {
                panic!("probe unsupported but destroy errored differently: {e}")
            }
            (Err(e), _) => panic!("probe errored: {e}"),
        }
    }

    /// Destroying a REAL socket must report exactly one and RETURN.
    /// Ghost-tuple tests cannot catch a silent-success protocol break:
    /// an un-ACKed SOCK_DESTROY destroys the socket and sends no reply
    /// at all, so a dump-style recv loop hangs forever on the first
    /// real kill (live-bitten: revoke timed out behind a blocked
    /// sock_pass thread while the flow sat destroyed). Skips cleanly
    /// when unprivileged or CONFIG_INET_DIAG_DESTROY=n.
    #[test]
    fn destroying_a_real_socket_reports_one_and_returns() {
        use std::net::{TcpListener, TcpStream};
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let c = TcpStream::connect(addr).unwrap();
        let (_srv, _) = l.accept().unwrap();
        let cport = c.local_addr().unwrap().port();

        let out = with_host_diag(|fd| {
            match probe_diag(fd) {
                Ok(true) => {}
                // Unsupported or unpermitted host: nothing to assert.
                _ => return Ok(None),
            }
            let mut socks = Vec::new();
            dump_family(fd, AF_INET, 1, &mut socks)?;
            let client = socks
                .iter()
                .find(|s| s.sport == cport && s.dport == addr.port())
                .expect("client side of the loopback pair must be dumped");
            match destroy_sock(fd, client, 11) {
                Ok(n) => Ok(Some(n)),
                Err(e) if e.raw_os_error() == Some(libc::EPERM) => Ok(None),
                Err(e) => Err(e),
            }
        })
        .expect("destroy pass must not error");
        if let Some(n) = out {
            assert_eq!(n, 1, "exact-tuple destroy must report exactly one socket");
            let socks = with_host_diag(|fd| {
                let mut v = Vec::new();
                dump_family(fd, AF_INET, 1, &mut v)?;
                io::Result::Ok(v)
            })
            .unwrap();
            assert!(
                !socks
                    .iter()
                    .any(|s| s.sport == cport && s.dport == addr.port()),
                "destroyed socket must vanish from dumps"
            );
        }
    }

    /// The probe must not error on any healthy host, and when it reports
    /// unsupported it must be the kernel's config talking, not our request
    /// shape: the plain dump path (independent of destroy support) has to
    /// keep working on the same socket.
    #[test]
    fn live_probe_answers_without_erroring() {
        with_host_diag(|fd| match probe_diag(fd) {
            Ok(true) => Ok(()),
            Ok(false) => {
                let mut v = Vec::new();
                dump_family(fd, AF_INET, 1, &mut v)?;
                Ok(())
            }
            Err(e) => Err(e),
        })
        .expect("probe must answer (EPERM tolerated below, anything else = ABI drift)");
    }
}
