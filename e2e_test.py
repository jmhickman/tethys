#!/usr/bin/env python3
"""E2E for tethysd in netns mode: real namespaces, real packets, real nft.

Run from workspace root as a privileged account — the harness starts its own
PRIVATE network namespace (fresh name per run, under /run/tethys-e2e,
never /run/netns), provisions it through `tethysd provision`, runs the daemon
against it, and sends real TCP packets through the host projection. The
production kernel state is untouched: everything lives in a private netns + a
private table (tethys_e2e) in both the host stack (delegated/DNAT chains) and
the namespace (enforcement table).

  sudo python3 e2e_test.py
  # dev fallback without host privileges: -n matters as much as -Ur — the
  # userns owns the netns it creates, and veth/nft in the "host" projection
  # need that ownership too:
  unshare -Umrn python3 e2e_test.py

Topology (routed mode, addresses randomized per run from the pid):
  client-netns --vc-c/vc-h-- HOST STACK ==[DNAT delegated ports]== vh-X/veth0-- agent-netns
  The client plays the remote: its SYNs ENTER the host over vc-h, so they
  traverse the prerouting DNAT chain exactly like real WAN traffic, and the
  true client source is what `igrants_*` must key on.

Scenarios (all must pass):
  S0  provision idempotent; subscribe ack reports the boundary ACTIVE,
      the exact netns path, and the SOCK_DESTROY capability
  S1  request -> admin event -> approve -> verdict + kernel element w/ expiry
  S2  identical request while active -> instant already_granted, NO popup
  S3  human deny propagates note to the model side
  S4  no admin connected -> immediate denied/approver_offline
  S5  revoke deletes the live kernel element (inside the namespace)
  S6  stop.grants kills live+pending grants, table survives, killed field
  S7  idempotent replay: no re-popup, original verdict; grant_expired after
  S8  list.history: decided-only, newest-first, state filter, limit
  S9  TUI contract: subscribe ack shape, created_at, list.pending, deny event
  S10 ingress, no grant: SYN to a DELEGATED port on the host address times
      out (dropped in the namespace, tethys_drops_in climbs) for v4 AND v6;
      a non-delegated port is REFUSED at the host and the drop counter does
      not move — the packet never reached the namespace
  S11 ingress, granted: approve -> handshake completes and the listener
      sees the TRUE client source (DNAT preserved it) for v4 AND v6;
      revoke mid-session -> the live flow dies within the kill pass
      (skipped-with-warning on kernels without SOCK_DESTROY); reconnect
      is gated again
  S12 no operator lockout: a host-stack listener is reachable while the
      daemon runs and after it is stopped; the namespace table stays loaded
      and keeps dropping without any daemon (kernel persistence)
"""
import json, os, re, signal, socket, subprocess, sys, threading, time

ROOT = os.path.dirname(os.path.abspath(__file__))
DIR = "/tmp/tethys-e2e"
ADMIN = f"{DIR}/admin.sock"
MCP = f"{DIR}/mcp.sock"
CFG = f"{DIR}/config.toml"
NS = f"t-e2e-{os.getpid()}"          # fresh name per run
# nsfs bind-mounts live under /run (tmpfs), mirroring production's
# /run/netns — a private sibling dir, never the real one. Binding nsfs
# onto files of other filesystem classes (ZFS et al.) can EINVAL;
# first root run proved exactly that on /tmp.
NSDIR = "/run/tethys-e2e"
NSPATH = f"{NSDIR}/{NS}"
HOSTVETH = ("vh-" + NS)[:15]          # provision's default host_veth name
CLIENT_NSFILE = f"{NSDIR}/c-{NS}"     # bind-mount of the client netns
VC_H, VC_C = "vc-h", "vc-c"
TETHYSD_BIN = os.environ.get("TETHYSD_BIN", os.path.join(ROOT, "target/debug/tethysd"))
TABLE = os.environ.get("TETHYS_E2E_TABLE", "tethys_e2e")

R = os.getpid()
PREFIX4 = f"172.{16 + R % 16}.{(R * 7) % 60 * 4}.0/30"          # gw=.1 ns=.2
PREFIX6 = f"fd00:e2e:{R & 0xFFFF:x}::/64"                        # gw=::1 ns=::2
CL_PREFIX4 = f"198.51.{1 + R % 250}.0/30"                        # host=.1 client=.2
CL_PREFIX6 = f"fd00:c1e:{R & 0xFFFF:x}::/64"                     # host=::1 client=::2
GW4, NS4 = re.sub(r"\.0/30$", "", PREFIX4) + ".1", re.sub(r"\.0/30$", "", PREFIX4) + ".2"
GW6, NS6 = PREFIX6.replace("::/64", "::1"), PREFIX6.replace("::/64", "::2")
HOSTVC4, CLIENT4 = re.sub(r"\.0/30$", "", CL_PREFIX4) + ".1", re.sub(r"\.0/30$", "", CL_PREFIX4) + ".2"
HOSTVC6, CLIENT6 = CL_PREFIX6.replace("::/64", "::1"), CL_PREFIX6.replace("::/64", "::2")
P_IN = 45300 + R % 700        # delegated ingress test port
P_NO = P_IN + 1               # never delegated
P_HOST = P_IN + 2             # host-stack listener (lockout probe)

CLONE_NEWNET = 0x40000000
import ctypes
_LIBC = ctypes.CDLL("libc.so.6", use_errno=True)


def make_netns(target):
    """Pin a fresh netns at `target` (file must exist): fork, unshare,
    legacy mount(2) bind of /proc/self/ns/net — iproute2's spelling. NOT
    `mount --bind`: util-linux uses open_tree(OPEN_TREE_CLONE)+move_mount,
    which AppArmor denies inside LXC containers (EACCES) while the legacy
    syscall is allowed. The bind itself pins the namespace; no holder."""
    touch(target)
    pid = os.fork()
    if pid == 0:
        try:
            if _LIBC.unshare(CLONE_NEWNET) != 0:
                os._exit(ctypes.get_errno() or 1)
            rc = _LIBC.mount(b"/proc/self/ns/net", os.fsencode(target),
                             b"nsfs", 4096, None)   # MS_BIND
            os._exit(0 if rc == 0 else (ctypes.get_errno() or 1))
        except OSError:
            os._exit(127)
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    if code != 0:
        raise RuntimeError(f"make_netns {target}: {os.strerror(code)}")


def run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, timeout=60, **kw)


def need(cmd):
    r = run(cmd)
    if r.returncode != 0:
        raise RuntimeError(f"{cmd}: rc={r.returncode} {r.stderr.strip()[:300]}")
    return r.stdout


def in_ns(argv, input=None, timeout=30, nsfile=NSPATH):
    """Run argv with the calling thread setns'd into the given netns file."""
    def _pre():
        fd = os.open(nsfile, os.O_RDONLY)
        os.setns(fd, CLONE_NEWNET)
        os.close(fd)
    return subprocess.run(argv, input=input, capture_output=True, text=True,
                          preexec_fn=_pre, timeout=timeout)


def ns_text(argv, **kw):
    r = in_ns(argv, **kw)
    return r.stdout if r.returncode == 0 else ""


def drops():
    """tethys_drops_in packet count inside the enforcement namespace."""
    out = ns_text(["nft", "list", "counter", "inet", TABLE, "tethys_drops_in"])
    m = re.search(r"packets\s+(\d+)", out)
    if not m:
        raise RuntimeError(f"no tethys_drops_in counter in namespace: {out[:200]!r}")
    return int(m.group(1))


def delegate(port, family=4):
    run(["nft", "add", "element", "inet", TABLE, f"delegated_v{family}", "{", str(port), "}"])


def undelegate(port, family=4):
    run(["nft", "delete", "element", "inet", TABLE, f"delegated_v{family}", "{", str(port), "}"])


def nft_grants():
    return ns_text(["nft", "list", "set", "inet", TABLE, "grants_v4"])


LISTENER = r"""
import json, socket, sys, threading
port, log = int(sys.argv[1]), sys.argv[2]
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.bind(("::", port)); s.listen(8)
def serve(c):
    peer = c.getpeername()
    peer = peer[0].removeprefix("::ffff:")
    with open(log, "a") as f:
        f.write(json.dumps({"accept": peer}) + "\n")
    try:
        while data := c.recv(1024):
            c.sendall(data)
    except OSError:
        pass
    finally:
        with open(log, "a") as f:
            f.write(json.dumps({"close": peer}) + "\n")
        c.close()
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
"""

PROBE = r"""
import socket, sys, time
dst, port, to, hold = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4])
payload = sys.argv[5] if len(sys.argv) > 5 else None
fam = socket.AF_INET6 if ":" in dst else socket.AF_INET
s = socket.socket(fam, socket.SOCK_STREAM)
s.settimeout(to)
try:
    s.connect((dst, port))
except socket.timeout:
    print("timeout"); sys.exit(2)      # SYN went nowhere: dropped
except ConnectionRefusedError:
    print("refused"); sys.exit(3)      # RST: host answered, ns never saw it
except OSError as e:
    # Any other ICMP/errno answer is still "the host answered and the ns
    # never saw it"; classifying it beats an rc1 traceback that hides the
    # real errno (seen live).
    print({113: "unreach", 101: "unreach-net", 1: "permdenied",
           13: "permdenied"}.get(e.errno, f"err:{e.errno}")); sys.exit(3)
print("ok", flush=True)
if payload:
    s.sendall(payload.encode()); s.settimeout(to)
    try:
        got = s.recv(64)
    except OSError:
        print("readerr"); sys.exit(4)
    if got.decode(errors="replace") != payload:
        print("echo-mismatch", got); sys.exit(4)
    print("echo", got.decode(), flush=True)
if hold > 0:
    s.settimeout(hold)
    try:
        d = s.recv(1)
        print("closed" if not d else "data"); sys.exit(5)   # flow died
    except socket.timeout:
        print("held"); sys.exit(0)                          # survived hold
    except ConnectionResetError:
        print("reset"); sys.exit(5)                         # flow died
sys.exit(0)
"""


def main():
    if os.geteuid() != 0:
        print("e2e must run as root (netns + nftables):\n"
              "  sudo python3 e2e_test.py\n"
              "or in a dev user+net namespace:\n"
              "  unshare -Umrn python3 e2e_test.py")
        sys.exit(2)

    # build first — stale-binary trap bit twice (cargo test does NOT refresh
    # target/debug/<bin>; e2e runs must compile the binaries they execute)
    b = subprocess.run(["cargo", "build", "--workspace"], cwd=ROOT, capture_output=True, text=True)
    if b.returncode != 0:
        print("BUILD FAILED:\n", b.stderr[-2000:]); sys.exit(1)
    # kill a leftover TEST daemon from a previous run only — never a
    # production tethysd (match on this harness's distinctive cmdline)
    subprocess.run(["pkill", "-f", "--", f"{TETHYSD_BIN} .*{DIR}/"])
    time.sleep(0.3)

    # sweep leftovers from a crashed previous run (recorded in state.json)
    try:
        old = json.load(open(f"{DIR}/state.json"))
        for p in old.get("umounts", []):
            run(["umount", p])
        for link in old.get("links", []):
            run(["ip", "link", "del", link])
    except Exception:
        pass
    os.system(f"rm -rf {DIR} && mkdir -p {DIR} {NSDIR}")
    open(f"{DIR}/listener.py", "w").write(LISTENER)
    open(f"{DIR}/probe.py", "w").write(PROBE)
    state = {"umounts": [], "links": []}

    # ---- config: netns mode is the only mode, so the file carries [netns] --
    with open(CFG, "w") as f:
        f.write(f"""
mcp_socket = "{MCP}"
admin_socket = "{ADMIN}"
db = "{DIR}/ledger.db"
nft_table = "{TABLE}"

[netns]
name = "{NS}"
dir = "{NSDIR}"
mode = "routed"
prefix4 = "{PREFIX4}"
prefix6 = "{PREFIX6}"
""")

    daemon = listener = hostl = None
    fails, skips = [], []
    try:
        # ---- S0a: provisioning (and it must be idempotent) -----------------
        # journal the mount/link targets BEFORE provisioning: a mid-run
        # failure still leaves a mounted nsfs + veth to clean up, and a
        # later crash (or exit) must not orphan them (seen live).
        state["umounts"].append(NSPATH)
        state["links"].append(HOSTVETH)
        json.dump(state, open(f"{DIR}/state.json", "w"))
        for attempt in (1, 2):
            p = run([TETHYSD_BIN, "provision", "--config", CFG])
            if p.returncode != 0:
                raise RuntimeError(f"provision attempt {attempt}: {p.stdout[-500:]} {p.stderr[-500:]}")

        # ---- client netns: the "remote" whose SYNs enter the host ----------
        make_netns(CLIENT_NSFILE)
        state["umounts"].append(CLIENT_NSFILE)
        state["links"].append(VC_H)
        json.dump(state, open(f"{DIR}/state.json", "w"))
        need(["ip", "link", "add", VC_H, "type", "veth", "peer", "name", VC_C])
        # iproute2 accepts an nsfs file path (anything containing '/'),
        # and make_netns's fork has already exited — the mount is the ns.
        need(["ip", "link", "set", VC_C, "netns", str(CLIENT_NSFILE)])
        need(["ip", "addr", "add", f"{HOSTVC4}/30", "dev", VC_H])
        need(["ip", "-6", "addr", "add", f"{HOSTVC6}/64", "dev", VC_H])
        need(["ip", "link", "set", VC_H, "up"])
        CN = dict(nsfile=CLIENT_NSFILE)
        need_in_ns(["ip", "link", "set", "lo", "up"], **CN)
        need_in_ns(["ip", "link", "set", VC_C, "up"], **CN)
        need_in_ns(["ip", "addr", "add", f"{CLIENT4}/30", "dev", VC_C], **CN)
        need_in_ns(["ip", "-6", "addr", "add", f"{CLIENT6}/64", "dev", VC_C], **CN)

        # ---- daemon in netns mode ------------------------------------------
        # agent user deliberately unresolved: the harness (root) speaks mcp.sock
        # itself; kill filtering then matches any uid inside the namespace.
        daemon = subprocess.Popen(
            [TETHYSD_BIN, "--config", CFG,
             "--approver-timeout-secs", "8",
             "--agent-user", "tethys-e2e-absent", "--allow-missing-users"],
            stdout=open(f"{DIR}/tethysd.log", "w"), stderr=subprocess.STDOUT)
        time.sleep(0.8)

        adm = socket.socket(socket.AF_UNIX); adm.connect(ADMIN)
        adm.sendall(b'{"jsonrpc":"2.0","id":"s","method":"subscribe"}\n')
        events, buf = [], b""
        adm.settimeout(0.3)

        def pump():
            nonlocal buf
            while True:
                try:
                    d = adm.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not d:
                    break
                buf += d
                while b"\n" in buf:
                    l, buf = buf.split(b"\n", 1)
                    if l.strip():
                        events.append(json.loads(l))

        threading.Thread(target=pump, daemon=True).start()
        time.sleep(0.3)

        def request(rid, params):
            a = socket.socket(socket.AF_UNIX); a.connect(MCP)
            a.sendall((json.dumps({"jsonrpc": "2.0", "id": rid, "method": "access.request", "params": params}) + "\n").encode())
            return a

        def admin_rpc(method, params=None):
            s = socket.socket(socket.AF_UNIX); s.connect(ADMIN)
            s.settimeout(5)
            req = {"jsonrpc": "2.0", "id": "cli", "method": method}
            if params is not None:
                req["params"] = params
            s.sendall((json.dumps(req) + "\n").encode())
            buf = b""
            while b"\n" not in buf:
                d = s.recv(65536)
                if not d:
                    break
                buf += d
            s.close()
            line = buf.split(b"\n", 1)[0]
            return json.loads(line) if line.strip() else {}

        def ack_of(eid, timeout=5):
            t0 = time.time()
            while time.time() - t0 < timeout:
                for e in events:
                    if e.get("id") == eid:
                        return e.get("result") or {}
                time.sleep(0.1)
            return {}

        def probe(dst, port, to=2.5, hold=0.0, payload=None):
            """TCP handshake probe from the CLIENT netns. Returns
            ('timeout'|'refused'|'ok', process)."""
            argv = ["python3", f"{DIR}/probe.py", dst, str(port), str(to), str(hold)]
            if payload:
                argv.append(payload)
            p = in_ns(argv, timeout=to + hold + 15, nsfile=CLIENT_NSFILE)
            out = (p.stdout or "").strip().splitlines()
            kind = out[0].split()[0] if out else f"rc{p.returncode}:{(p.stderr or '').strip()[-160:]}"
            return kind, p

        # ---- S0b: the ack must tell the truth about the boundary -----------
        res = ack_of("s")
        sock_destroy = bool(res.get("sock_destroy"))
        enf = res.get("enforcement") or {}
        if enf.get("boundary") != f"netns:{NSPATH}" or enf.get("active") is not True:
            fails.append(f"S0 enforcement ack: {enf} (want active boundary {NSPATH})")
        if len(res.get("events", [])) != 6 or res.get("approver_timeout_secs") != 8:
            fails.append(f"S0 ack shape: {res}")
        print(f"S0 provision+boundary: {'ok' if 'S0' not in str(fails) else fails[-1]}"
              f" (sock_destroy={sock_destroy})")

        # S1: approve flow
        a1 = request("r1", {"dst_ip": "192.0.2.77", "dst_port": {"from": 443, "to": 443}, "proto": "tcp",
                            "reason": "s1", "tool": "t", "ttl_requested": "60s"})
        gid = None
        t0 = time.time()
        while time.time() - t0 < 5 and gid is None:
            for e in events:
                if e.get("method") == "grant.request.new":
                    gid = e["params"]["grant_id"]
            time.sleep(0.1)
        if not gid:
            fails.append("S1 no popup event")
        admin_rpc("approve", {"grant_id": str(gid)})
        a1.settimeout(5)
        d1 = json.loads(a1.recv(65536).decode())["result"]
        if d1.get("decision") != "approved" or "192.0.2.77" not in nft_grants():
            fails.append(f"S1 {d1}")
        print("S1 approve:", "ok" if "S1" not in str(fails) else fails)

        # S2: dedup (sum-type verdict: already_granted carries grant_id + expiry)
        a2 = request("r2", {"dst_ip": "192.0.2.77", "dst_port": {"from": 443, "to": 443}, "proto": "tcp",
                            "reason": "again", "tool": "t", "ttl_requested": "60s"})
        a2.settimeout(5)
        d2 = json.loads(a2.recv(65536).decode())["result"]
        popups = len([e for e in events if e.get("method") == "grant.request.new"])
        if d2.get("decision") != "already_granted" or not d2.get("expires_at") or popups != 1:
            fails.append(f"S2 {d2} popups={popups}")
        print("S2 dedup:", "ok" if "S2" not in str(fails) else fails[-1])

        # S3: deny with note
        a3 = request("r3", {"dst_net": "198.51.100.0/24", "dst_port": {"from": 20, "to": 22}, "proto": "tcp",
                            "reason": "nope", "tool": "t", "ttl_requested": "60s"})
        t0 = time.time()
        gid3 = None
        while time.time() - t0 < 5:
            g = [e["params"]["grant_id"] for e in events if e.get("method") == "grant.request.new" and e["params"]["grant_id"] != gid]
            if g:
                gid3 = g[-1]; break
            time.sleep(0.1)
        admin_rpc("deny", {"grant_id": str(gid3), "note": "out of scope"})
        a3.settimeout(5)
        d3 = json.loads(a3.recv(65536).decode())["result"]
        if d3.get("decision") != "denied" or d3.get("note") != "out of scope":
            fails.append(f"S3 {d3}")
        print("S3 deny+note:", "ok" if "S3" not in str(fails) else fails[-1])

        # S4: approver offline -> instant deny
        adm.close()
        time.sleep(0.3)
        a4 = request("r4", {"dst_ip": "203.0.113.5", "dst_port": {"from": 80, "to": 80}, "proto": "tcp",
                            "reason": "offline", "tool": "t", "ttl_requested": "60s"})
        a4.settimeout(5)
        d4 = json.loads(a4.recv(65536).decode())["result"]
        if d4.get("decision") != "denied" or d4.get("reason_code") != "approver_offline":
            fails.append(f"S4 {d4}")
        print("S4 offline-deny:", "ok" if "S4" not in str(fails) else fails[-1])

        # S5: revoke removes kernel element (inside the namespace)
        adm2 = socket.socket(socket.AF_UNIX); adm2.connect(ADMIN)
        adm2.settimeout(0.3)
        buf2 = b""

        def pump2():
            nonlocal buf2
            while True:
                try:
                    d = adm2.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not d:
                    break
                buf2 += d
                while b"\n" in buf2:
                    l, buf2 = buf2.split(b"\n", 1)
                    if l.strip():
                        events.append(json.loads(l))

        threading.Thread(target=pump2, daemon=True).start()
        time.sleep(0.3)
        admin_rpc("revoke", {"grant_id": str(gid)})
        if "192.0.2.77" in nft_grants():
            fails.append("S5 element still present after revoke")
        print("S5 revoke:", "ok" if "S5" not in str(fails) else fails[-1])

        # S6: stop.grants — several grants + one pending all terminate; the
        # table survives; EvStopped carries the required killed field.
        def popup_gids():
            return [e["params"]["grant_id"] for e in events
                    if e.get("method") == "grant.request.new"]

        def new_gid(base):
            # `base` MUST be captured before the request is sent: a shared
            # counter went stale once S7/S9 made popups outside this helper,
            # and the next caller approved a dead gid (live-run failure).
            t0 = time.time()
            while time.time() - t0 < 5:
                gg = popup_gids()
                if len(gg) > base:
                    return gg[-1]
                time.sleep(0.1)
            return None

        def wait_decided(gid, state="approved", timeout=5):
            t0 = time.time()
            while time.time() - t0 < timeout:
                for e in events:
                    if (e.get("method") == "grant.decided"
                            and e["params"].get("grant_id") == gid
                            and e["params"].get("state") == state):
                        return True
                time.sleep(0.1)
            return False

        approved_gids = []
        for ip in ["192.0.2.10", "192.0.2.11"]:
            b6 = len(popup_gids())
            a = request("r6-" + ip, {"dst_ip": ip, "dst_port": {"from": 80, "to": 80}, "proto": "tcp",
                                     "reason": "batch", "tool": "t", "ttl_requested": "300s"})
            g = new_gid(b6)
            if g:
                admin_rpc("approve", {"grant_id": str(g)})
                if wait_decided(g):
                    approved_gids.append(g)
        b6p = len(popup_gids())
        a_pend = request("r6-pending", {"dst_ip": "192.0.2.12", "dst_port": {"from": 80, "to": 80},
                                        "proto": "tcp", "reason": "left pending", "tool": "t", "ttl_requested": "300s"})
        g = new_gid(b6p)
        r = admin_rpc("stop.grants")
        try:
            d_pend = json.loads(a_pend.recv(65536).decode())["result"]
        except Exception:
            d_pend = {}
        out = nft_grants()
        table_exists = in_ns(["nft", "list", "table", "inet", TABLE]).returncode == 0
        if ("192.0.2.10" in out or "192.0.2.11" in out) or not table_exists or "error" in r:
            fails.append(f"S6 stop.grants: leftover={out[:80]} table={table_exists} resp={r}")
        stopped = [e["params"] for e in events if e.get("method") == "grants.stopped"]
        if not stopped or stopped[-1].get("grants_removed") != 2:
            fails.append(f"S6 grants.stopped broadcast missing/wrong: {stopped}")
        if "killed" not in (stopped[-1] if stopped else {}):
            fails.append(f"S6 grants.stopped missing required killed field: {stopped}")
        if len(approved_gids) != 2:
            fails.append(f"S6 only {len(approved_gids)} grants confirmed approved before stop")
        if d_pend.get("reason_code") != "human_denied" or "stopped" not in (d_pend.get("note") or ""):
            fails.append(f"S6 pending not denied by stop: {d_pend}")
        print("S6 stop.grants:", "ok" if "S6" not in str(fails) else fails[-1])

        # S7: idempotency re-delivery
        base7 = len(popup_gids())
        a7 = request("r7", {"dst_ip": "192.0.2.33", "dst_port": {"from": 443, "to": 443}, "proto": "tcp",
                            "reason": "idempotency", "tool": "t", "ttl_requested": "300s"})
        g7 = new_gid(base7)
        admin_rpc("approve", {"grant_id": str(g7)})
        a7.settimeout(5)
        d7 = json.loads(a7.recv(65536).decode())["result"]

        a7b = request("r7", {"dst_ip": "192.0.2.33", "dst_port": {"from": 443, "to": 443}, "proto": "tcp",
                             "reason": "retry", "tool": "t", "ttl_requested": "300s"})
        a7b.settimeout(5)
        r7b = json.loads(a7b.recv(65536).decode())
        pops7 = len([e for e in events if e.get("method") == "grant.request.new"])
        if (r7b.get("result", {}).get("decision") != "already_granted"
                or r7b.get("id") != "r7"
                or pops7 != base7 + 1):
            fails.append(f"S7 replay-active: {r7b} pops={pops7 - base7}")

        admin_rpc("revoke", {"grant_id": str(d7["grant_id"])})
        time.sleep(0.3)
        a7c = request("r7", {"dst_ip": "192.0.2.33", "dst_port": {"from": 443, "to": 443}, "proto": "tcp",
                             "reason": "retry after revoke", "tool": "t", "ttl_requested": "300s"})
        a7c.settimeout(5)
        d7raw = a7c.recv(65536).decode()
        d7c = json.loads(d7raw).get("result", {})
        if "error" in d7raw:
            fails.append(f"S7 replay-revoked got error envelope: {d7raw[:160]}")
        if d7c.get("decision") != "denied" or d7c.get("reason_code") != "grant_expired":
            fails.append(f"S7 replay-revoked: {d7c}")
        pops7b = len([e for e in events if e.get("method") == "grant.request.new"])
        if pops7b != base7 + 1:
            fails.append(f"S7 replay re-popuped ({pops7b - base7} popups)")
        print("S7 idempotent-replay:", "ok" if "S7" not in str(fails) else fails[-1])

        # S8: list.history
        hist = admin_rpc("list.history", {"limit": 100})
        rows = hist.get("result") or []
        states = [x["state"] for x in rows]
        ids = [int(x["id"]) for x in rows]
        if "error" in hist or not rows:
            fails.append(f"S8 history empty/error: {json.dumps(hist)[:200]}")
        if "pending" in states:
            fails.append("S8 history contains pending rows")
        if ids != sorted(ids, reverse=True):
            fails.append(f"S8 not newest-first: {ids}")
        if "denied" not in states or "revoked" not in states:
            fails.append(f"S8 missing terminal states: {sorted(set(states))}")
        rows2 = admin_rpc("list.history", {"state": "denied"}).get("result") or []
        if not rows2 or any(x["state"] != "denied" for x in rows2):
            fails.append(f"S8 state filter broken: {[x.get('state') for x in rows2]}")
        rows3 = admin_rpc("list.history", {"limit": 1}).get("result") or []
        if len(rows3) != 1 or int(rows3[0]["id"]) != ids[0]:
            fails.append(f"S8 limit keeps wrong end: {rows3}")
        print("S8 history:", "ok" if "S8" not in str(fails) else fails[-1])

        # S9: TUI contract
        adm2.sendall((json.dumps({"jsonrpc": "2.0", "id": "s9sub", "method": "subscribe"}) + "\n").encode())
        res9 = ack_of("s9sub")
        if res9.get("approver_timeout_secs") != 8 or len(res9.get("events", [])) != 6:
            fails.append(f"S9 subscribe ack: {res9}")

        a9 = request("r9", {"dst_ip": "192.0.2.99", "dst_port": {"from": 8080, "to": 8080}, "proto": "tcp",
                            "reason": "contract", "tool": "t", "ttl_requested": "60s"})
        g9 = None
        t0 = time.time()
        while time.time() - t0 < 5 and g9 is None:
            for e in events:
                if (e.get("method") == "grant.request.new" and e["params"].get("created_at")
                        and e["params"].get("target") == "ip:192.0.2.99"):
                    g9 = e["params"]["grant_id"]
            time.sleep(0.1)
        if not g9:
            fails.append("S9 popup missing created_at (or no popup)")

        pends = admin_rpc("list.pending").get("result") or []
        mine = [p for p in pends if p["id"] == int(g9)] if g9 else []
        if len(mine) != 1 or mine[0].get("waiting") is not True:
            fails.append(f"S9 list.pending snapshot wrong: {mine}")

        admin_rpc("deny", {"grant_id": str(g9), "note": "contract test"})
        try:
            a9.settimeout(5); a9.recv(65536)
        except Exception:
            pass
        dec = None
        t0 = time.time()
        while time.time() - t0 < 5 and dec is None:
            for e in events:
                if (e.get("method") == "grant.decided" and e["params"].get("grant_id") == g9
                        and e["params"].get("state") == "denied"):
                    dec = e["params"]
            time.sleep(0.1)
        if not dec or dec.get("reason_code") != "human_denied" or dec.get("note") != "contract test":
            fails.append(f"S9 deny event missing/wrong: {dec}")
        print("S9 tui-contract:", "ok" if "S9" not in str(fails) else fails[-1])

        # ---- packet scenarios ----------------------------------------------
        LOG = f"{DIR}/listener.log"
        listener = in_ns_popen(["python3", f"{DIR}/listener.py", str(P_IN), LOG])
        hostl = subprocess.Popen(
            ["python3", "-c",
             "import socket,sys; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
             f"s.bind(('{HOSTVC4}',{P_HOST})); s.listen(16);"
             "open(sys.argv[1],'a').close()\n"
             "while True:\n c,_=s.accept(); c.close()",
             f"{DIR}/hostlistener.log"])
        time.sleep(0.5)

        # S10: delegated port, no grant -> dropped IN the namespace (v4 + v6);
        # non-delegated port -> refused at the host, namespace never sees it.
        delegate(P_IN, 4); delegate(P_IN, 6)
        d0 = drops()
        k4, _ = probe(GW4, P_IN)
        d1c = drops()
        if k4 != "timeout":
            fails.append(f"S10 v4 ungranted SYN to delegated port: {k4} (want timeout)")
        if d1c <= d0:
            fails.append(f"S10 v4 tethys_drops_in did not climb: {d0} -> {d1c}")
        k6, _ = probe(GW6, P_IN)
        d2c = drops()
        if k6 != "timeout":
            fails.append(f"S10 v6 ungranted SYN to delegated port: {k6} (want timeout)")
        if d2c <= d1c:
            fails.append(f"S10 v6 tethys_drops_in did not climb: {d1c} -> {d2c}")
        kn, _ = probe(GW4, P_NO)
        d3c = drops()
        if kn not in ("refused", "unreach", "unreach-net", "permdenied"):
            fails.append(f"S10 non-delegated port: {kn} (want host to answer, ns to never see it)")
        if d3c != d2c:
            fails.append(f"S10 non-delegated SYN reached the namespace: {d2c} -> {d3c}")
        print("S10 ingress-drop:", "ok" if "S10" not in str(fails) else fails[-1])

        # S11: grant -> completes with TRUE source (DNAT preserved it) both
        # families; revoke kills the live flow; reconnect is gated again.
        def approve_ingress(src, port):
            base = len(popup_gids())
            a = request(f"r11-{src}", {"dst_ip": src, "dst_port": {"from": port, "to": port},
                                       "proto": "tcp", "dir": "ingress",
                                       "reason": "s11", "tool": "t", "ttl_requested": "300s"})
            gg = new_gid(base)
            admin_rpc("approve", {"grant_id": str(gg)})
            a.settimeout(5)
            d = json.loads(a.recv(65536).decode())["result"]
            if d.get("decision") != "approved" or d.get("dir") != "ingress":
                fails.append(f"S11 ingress verdict wrong: {d}")
            return d.get("grant_id")

        gid11 = approve_ingress(CLIENT4, P_IN)
        ig = ns_text(["nft", "list", "set", "inet", TABLE, "igrants_v4"])
        if CLIENT4 not in ig or str(P_IN) not in ig:
            fails.append(f"S11 igrants_v4 missing grant element: {ig[:200]}")
        k, p = probe(GW4, P_IN, to=4.0, payload="s11")
        if k != "ok":
            fails.append(f"S11 granted v4 flow did not complete: {k}")
        else:
            if "echo s11" not in p.stdout:
                fails.append(f"S11 v4 echo failed: {p.stdout!r}")
            time.sleep(0.2)
            accs = [json.loads(l)["accept"] for l in open(LOG) if '"accept"' in l] if os.path.exists(LOG) else []
            if CLIENT4 not in accs:
                fails.append(f"S11 listener saw {accs}, want true source {CLIENT4} (DNAT rewrote it)")

        gid11b = approve_ingress(CLIENT6, P_IN)
        ig6 = ns_text(["nft", "list", "set", "inet", TABLE, "igrants_v6"])
        if CLIENT6 not in ig6:
            fails.append(f"S11 igrants_v6 missing grant element: {ig6[:200]}")
        k6g, p6 = probe(GW6, P_IN, to=4.0, payload="s11v6")
        if k6g != "ok" or "echo s11v6" not in p6.stdout:
            fails.append(f"S11 granted v6 flow failed: {k6g} {p6.stdout!r}")
        else:
            time.sleep(0.2)
            accs = [json.loads(l)["accept"] for l in open(LOG) if '"accept"' in l]
            if CLIENT6 not in accs:
                fails.append(f"S11 listener saw {accs}, want true source {CLIENT6}")

        # revoke mid-session: a background client holds the v4 flow open
        # across the revoke; the kill pass (step 4) must end it immediately.
        held = in_ns_popen(["python3", f"{DIR}/probe.py", GW4, str(P_IN), "4.0", "8.0", "held"],
                           stdout=subprocess.PIPE)
        time.sleep(1.2)
        if '"accept"' not in open(LOG).read():
            fails.append("S11 held flow never reached the listener")
        admin_rpc("revoke", {"grant_id": str(gid11)})
        try:
            held.wait(timeout=10)
        except subprocess.TimeoutExpired:
            held.kill()
            fails.append("S11 held flow outlived revoke+kill window")
        held_out = (held.stdout.read().decode() if held.stdout else "").strip()
        if sock_destroy:
            if held.returncode != 5:
                fails.append(f"S11 revoke did not kill live flow: rc={held.returncode} out={held_out!r}")
        else:
            skips.append("S11 kill check skipped: kernel reports no SOCK_DESTROY")
        # the v6 grant's element must be gone on its own revoke too
        admin_rpc("revoke", {"grant_id": str(gid11b)})
        if CLIENT6 in ns_text(["nft", "list", "set", "inet", TABLE, "igrants_v6"]):
            fails.append("S11 igrants_v6 element survived revoke")
        # reconnect gated again: daemon undelegated on revoke; re-delegate so
        # the SYN can reach the namespace, where the removed element drops it.
        delegate(P_IN, 4)
        kr, _ = probe(GW4, P_IN)
        if kr != "timeout":
            fails.append(f"S11 reconnect after revoke: {kr} (want timeout — gated again)")
        print("S11 ingress-grant-kill:", "ok" if "S11" not in str(fails) else fails[-1])

        # S12: host-stack listener reachable while the daemon runs AND after
        # it dies; the namespace keeps enforcing with no daemon at all.
        kh, _ = probe(HOSTVC4, P_HOST, to=2.0)
        if kh != "ok":
            fails.append(f"S12 host listener while daemon runs: {kh} (host stack must be untouched)")
        daemon.send_signal(signal.SIGTERM)
        daemon.wait(timeout=5)
        daemon = None
        kh2, _ = probe(HOSTVC4, P_HOST, to=2.0)
        if kh2 != "ok":
            fails.append(f"S12 host listener after daemon stop: {kh2} (operator lockout!)")
        if in_ns(["nft", "list", "table", "inet", TABLE]).returncode != 0:
            fails.append("S12 namespace table vanished with the daemon (kernel persistence broken)")
        delegate(P_IN, 4)
        d0 = drops()
        kd, _ = probe(GW4, P_IN)
        d1c = drops()
        if kd != "timeout" or d1c <= d0:
            fails.append(f"S12 enforcement without daemon: {kd}, drops {d0}->{d1c}")
        print("S12 no-lockout+persistence:", "ok" if "S12" not in str(fails) else fails[-1])
    finally:
        for p in [daemon, listener, hostl]:
            if p is None:
                continue
            try:
                p.terminate(); p.wait(timeout=3)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        for p in state["umounts"]:
            run(["umount", p])
        for link in state["links"]:
            run(["ip", "link", "del", link])
        run(["nft", "delete", "table", "inet", TABLE])   # host stack only
        os.system(f"rm -rf {DIR}; rm -f {NSPATH} {CLIENT_NSFILE}; rmdir {NSDIR} 2>/dev/null")
        # the harness's cargo build ran as root under sudo; hand target/ back
        # so the developer's next unprivileged build isn't locked out
        if os.environ.get("SUDO_UID"):
            os.system(f"chown -R {os.environ['SUDO_UID']}:{os.environ.get('SUDO_GID', '')} "
                      f"{os.path.join(ROOT, 'target')} 2>/dev/null")

    for s in skips:
        print("SKIP:", s)
    if fails:
        print("FAILURES:", *fails, sep="\n  ")
        sys.exit(1)
    print("ALL E2E SCENARIOS PASSED")


def touch(path):
    with open(path, "a"):
        os.utime(path, None)
    return path


def need_in_ns(argv, nsfile):
    r = in_ns(argv, nsfile=nsfile)
    if r.returncode != 0:
        raise RuntimeError(f"in-ns {argv}: rc={r.returncode} {r.stderr.strip()[:300]}")
    return r.stdout


def in_ns_popen(argv, nsfile=NSPATH, stdout=None):
    def _pre():
        fd = os.open(nsfile, os.O_RDONLY)
        os.setns(fd, CLONE_NEWNET)
        os.close(fd)
    return subprocess.Popen(argv, stdout=stdout or subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, preexec_fn=_pre)


if __name__ == "__main__":
    main()
