#!/usr/bin/env python3
"""E2E for tethysd over real unix sockets + live nftables.

Run from workspace root as a privileged account (nftables changes + nft
required); the harness starts its own daemon on /tmp/tethys-e2e/* and points
it at a private nftables table (TETHYS_E2E_TABLE, default tethys_e2e) — production
kernel state is untouched.

Scenarios (all must pass):
  S1 request -> admin event -> approve -> verdict + kernel element w/ expiry
  S2 identical request while active -> instant already_granted, NO popup
  S3 human deny propagates note to the model side
  S4 no admin connected -> immediate denied/approver_offline
  S5 revoke deletes the live kernel element
"""
import json, os, signal, socket, subprocess, sys, threading, time

ROOT = os.path.dirname(os.path.abspath(__file__))
DIR = "/tmp/tethys-e2e"
ADMIN = f"{DIR}/admin.sock"
MCP = f"{DIR}/mcp.sock"
TETHYSD_BIN = os.environ.get("TETHYSD_BIN", os.path.join(ROOT, "target/debug/tethysd"))
# private table: the kernel is shared with any production tethysd, so the
# harness owns its own table end-to-end (daemon flag + every verification query)
TABLE = os.environ.get("TETHYS_E2E_TABLE", "tethys_e2e")


def nft_grants():
    return subprocess.run(
        ["nft", "--json", "-f", "-"], input=json.dumps({"nftables":[{"list":{"set":{"family":"inet","table":TABLE,"name":"grants_v4"}}}]}),
        capture_output=True, text=True).stdout


def main():
    # build first — stale-binary trap bit twice (cargo test does NOT refresh
    # target/debug/<bin>; e2e runs must compile the binaries they execute)
    b = subprocess.run(["cargo", "build", "--workspace"], cwd=ROOT, capture_output=True, text=True)
    if b.returncode != 0:
        print("BUILD FAILED:\n", b.stderr[-2000:]); sys.exit(1)
    # kill a leftover TEST daemon from a previous run only — never a
    # production tethysd (match on this harness's distinctive cmdline)
    subprocess.run(["pkill", "-f", "--", f"{TETHYSD_BIN} .*{DIR}/"])
    time.sleep(0.3)
    os.system(f"rm -rf {DIR} && mkdir -p {DIR}")
    # start from a clean private table (idempotent; needs nft privileges)
    subprocess.run(["nft", "delete", "table", "inet", TABLE], capture_output=True)
    daemon = subprocess.Popen(
        [TETHYSD_BIN, "--db", f"{DIR}/ledger.db", "--mcp-socket", MCP, "--admin-socket", ADMIN,
         "--nft-table", TABLE,
         "--approver-timeout-secs", "8",
         # dev mode: no peer pin
         "--mcp-user", "tethys-e2e-absent", "--allow-missing-users"],
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
        """One-shot JSON-RPC call over admin.sock (the approver surface)."""
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

    fails = []

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
    print("S1 approve:", "ok" if not fails else fails)

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

    # S5: revoke removes kernel element
    adm2 = socket.socket(socket.AF_UNIX); adm2.connect(ADMIN)  # reopen admin for stop
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

    # S6: stop.grants emergency stop — several grants + one pending, all
    # terminate, while the baseline nftables table survives (grants die,
    # baseline rules do not). Reopen the admin stream for popups first.
    ev_base = len([e for e in events if e.get("method") == "grant.request.new"])

    def new_gid():
        t0 = time.time()
        while time.time() - t0 < 5:
            gg = [e["params"]["grant_id"] for e in events if e.get("method") == "grant.request.new"]
            nonlocal_ev = len(gg)
            if nonlocal_ev > S6_STATE["n"]:
                S6_STATE["n"] = nonlocal_ev
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

    S6_STATE = {"n": ev_base}
    approved_gids = []
    for ip in ["192.0.2.10", "192.0.2.11"]:
        a = request("r6-" + ip, {"dst_ip": ip, "dst_port": {"from": 80, "to": 80}, "proto": "tcp",
                                 "reason": "batch", "tool": "t", "ttl_requested": "300s"})
        g = new_gid()
        if g:
            admin_rpc("approve", {"grant_id": str(g)})
            if wait_decided(g):
                approved_gids.append(g)
    # one pending left undecided — stop must deny it too
    a_pend = request("r6-pending", {"dst_ip": "192.0.2.12", "dst_port": {"from": 80, "to": 80},
                                    "proto": "tcp", "reason": "left pending", "tool": "t", "ttl_requested": "300s"})
    g = new_gid()
    r = admin_rpc("stop.grants")
    try:
        d_pend = json.loads(a_pend.recv(65536).decode())["result"]
    except Exception:
        d_pend = {}
    out = nft_grants()
    table_exists = subprocess.run(["nft", "list", "table", "inet", TABLE],
                                  capture_output=True, text=True).returncode == 0
    if ("192.0.2.10" in out or "192.0.2.11" in out) or not table_exists or "error" in r:
        fails.append(f"S6 stop.grants: leftover={out[:80]} table={table_exists} resp={r}")
    stopped = [e["params"] for e in events if e.get("method") == "grants.stopped"]
    if not stopped or stopped[-1].get("grants_removed") != 2:
        fails.append(f"S6 grants.stopped broadcast missing/wrong: {stopped}")
    if len(approved_gids) != 2:
        fails.append(f"S6 only {len(approved_gids)} grants confirmed approved before stop")
    if d_pend.get("reason_code") != "human_denied" or "stopped" not in (d_pend.get("note") or ""):
        fails.append(f"S6 pending not denied by stop: {d_pend}")
    print("S6 stop.grants:", "ok" if "S6" not in str(fails) else fails[-1])

    # S7: idempotency re-delivery — replaying a request id must NOT re-popup and
    # must return the ORIGINAL verdict; after revoke, replay says grant_expired.
    base7 = len([e for e in events if e.get("method") == "grant.request.new"])
    a7 = request("r7", {"dst_ip": "192.0.2.33", "dst_port": {"from": 443, "to": 443}, "proto": "tcp",
                        "reason": "idempotency", "tool": "t", "ttl_requested": "300s"})
    g7 = new_gid()
    admin_rpc("approve", {"grant_id": str(g7)})
    a7.settimeout(5)
    d7 = json.loads(a7.recv(65536).decode())["result"]

    # replay while ACTIVE -> already_granted, no second popup
    a7b = request("r7", {"dst_ip": "192.0.2.33", "dst_port": {"from": 443, "to": 443}, "proto": "tcp",
                         "reason": "retry", "tool": "t", "ttl_requested": "300s"})
    a7b.settimeout(5)
    r7b = json.loads(a7b.recv(65536).decode())
    pops7 = len([e for e in events if e.get("method") == "grant.request.new"])
    if (r7b.get("result", {}).get("decision") != "already_granted"
            or r7b.get("id") != "r7"
            or pops7 != base7 + 1):  # exactly ONE popup for both sends
        fails.append(f"S7 replay-active: {r7b} pops={pops7 - base7}")

    # revoke, then replay -> denied/grant_expired with guidance to use a new id
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

    # S8: list.history — decided rows only, newest first; state filter + limit
    # + client-error validation all ride the admin socket.
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
    # this run produced denies (S3/S4/S6), a revoke (S5/S7) and expirables;
    # at least the deny+revoke terminals must be represented
    if "denied" not in states or "revoked" not in states:
        fails.append(f"S8 missing terminal states: {sorted(set(states))}")
    rows2 = admin_rpc("list.history", {"state": "denied"}).get("result") or []
    if not rows2 or any(x["state"] != "denied" for x in rows2):
        fails.append(f"S8 state filter broken: {[x.get('state') for x in rows2]}")
    rows3 = admin_rpc("list.history", {"limit": 1}).get("result") or []
    if len(rows3) != 1 or int(rows3[0]["id"]) != ids[0]:
        fails.append(f"S8 limit keeps wrong end: {rows3}")
    print("S8 history:", "ok" if "S8" not in str(fails) else fails[-1])

    # S9: TUI daemon-contract — subscribe ack carries timeout+full event list;
    # grant.request.new carries created_at; list.pending snapshots live pendings
    # with a `waiting` flag; human deny emits grant.decided(state=denied).
    adm2.sendall((json.dumps({"jsonrpc": "2.0", "id": "s9sub", "method": "subscribe"}) + "\n").encode())
    ack = None
    t0 = time.time()
    while time.time() - t0 < 5 and ack is None:
        for e in events:
            if e.get("id") == "s9sub":
                ack = e
        time.sleep(0.1)
    res = (ack or {}).get("result") or {}
    if res.get("approver_timeout_secs") != 8 or len(res.get("events", [])) != 6:
        fails.append(f"S9 subscribe ack: {res}")

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

    daemon.send_signal(signal.SIGTERM)
    daemon.wait(timeout=5)
    # leave no kernel residue: the private table is ours, drop it whole
    subprocess.run(["nft", "delete", "table", "inet", TABLE], capture_output=True)
    if fails:
        print("FAILURES:", *fails, sep="\n  ")
        sys.exit(1)
    print("ALL E2E SCENARIOS PASSED")


if __name__ == "__main__":
    main()
