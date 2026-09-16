#!/usr/bin/env bash
# enforcement_e2e: kernel-truth proof of the WHOLE chain —
#   static baseline default-deny  +  gatekeeper grants (approve/revoke/expiry)
#   actually admit/block real TCP traffic.
# Everything runs inside throwaway netns `gk-enf`; the host namespace is never
# touched. MCP transport is covered by mcp_e2e.sh; pinning by pin_e2e.sh —
# this script isolates the data-plane verdict path (dev mode: no peer pin).
set -u
NS=gk-enf
SRV=gk-srv
cd /root/gatekeeper

ip netns del $NS 2>/dev/null || true
ip netns del $SRV 2>/dev/null || true
cleanup(){ ip netns del $NS 2>/dev/null || true; ip netns del $SRV 2>/dev/null || true; pkill -f 'gk-enf/config.toml' 2>/dev/null; }
trap cleanup EXIT
ip netns add $NS
ip netns add $SRV
# `ip netns exec` insists on remounting /sys (blocked in this LXC); nsenter skips it.
N="nsenter --net=/run/netns/$NS"
S="nsenter --net=/run/netns/$SRV"

# veth pair across TWO namespaces — dst 10.99.0.2 must be non-local in the
# client ns or packets never traverse the OUTPUT hook (local delivery bypasses it).
$N ip link set lo up
$S ip link set lo up
ip link add v0 type veth peer name v1 2>/dev/null || { echo "veth create failed"; exit 1; }
ip link set v0 netns $NS; ip link set v1 netns $SRV
$N ip addr add 10.99.0.1/24 dev v0
$S ip addr add 10.99.0.2/24 dev v1
$N ip link set v0 up; $S ip link set v1 up

# static baseline loads cleanly...
$N nft -f deploy/gatekeeper-baseline.nft || { echo "FAIL: baseline load"; exit 1; }
echo "baseline loaded in $NS"

# two listeners in the SERVER ns so each scenario gets a fresh conntrack tuple
$S python3 -m http.server --bind 10.99.0.2 8877 >/dev/null 2>&1 &
$S python3 -m http.server --bind 10.99.0.2 8878 >/dev/null 2>&1 &
sleep 0.6

curl_try(){ $N curl -s -o /dev/null -w '%{http_code}' -m 3 "http://10.99.0.2:$1/" ; }
expect_blocked(){ local p=$1 out rc; out=$(curl_try $p); rc=$?
  if [ $rc -eq 0 ]; then echo "FAIL: port $p allowed without grant (code=$out)"; exit 1; fi
  echo "port $p blocked as expected (curl rc=$rc)"; }
expect_allowed(){ local p=$1 out; out=$(curl_try $p); if [ "$out" != "200" ]; then echo "FAIL: port $p not served (code=$out)"; exit 1; fi
  echo "port $p served 200 under grant"; }

DROPS(){ printf '{"nftables":[{"list":{"counter":{"family":"inet","table":"gatekeeper","name":"gk_drops"}}}]}' | $N nft --json -f - \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([c["counter"]["packets"] for c in d["nftables"] if "counter" in c][0])'; }
D0=$(DROPS)

# 1. baseline default-deny BEFORE any daemon exists (self-healing floor)
expect_blocked 8877
D1=$(DROPS); [ "$D1" -gt "$D0" ] && echo "gk_drops counter moved $D0->$D1 ✓" || { echo "FAIL: drop counter idle ($D0->$D1)"; exit 1; }

# 2. daemon on top of the static table (cross-owner idempotency of ensure_base)
rm -rf /tmp/gk-enf && mkdir -p /tmp/gk-enf && chmod 755 /tmp/gk-enf
printf 'mcp_socket="/tmp/gk-enf/mcp.sock"\nadmin_socket="/tmp/gk-enf/admin.sock"\ndb="/tmp/gk-enf/ledger.db"\nmax_ttl="1h"\napprover_timeout_secs=60\nmcp_user="gk-e2e-absent"\n' > /tmp/gk-enf/config.toml
$N env RUST_LOG=info ./target/debug/gatekeeper --config /tmp/gk-enf/config.toml --allow-missing-users >/tmp/gk-enf/gk.log 2>&1 &
sleep 0.8
grep -q "nft base table ready" /tmp/gk-enf/gk.log || { echo "FAIL: daemon vs static table"; cat /tmp/gk-enf/gk.log; exit 1; }
echo "gatekeeper ensure_base coexists with static baseline ✓"

# approve helper: listen on admin sock, approve first popup, print grant id
cat > /tmp/gk-enf/appr.py <<'PY'
import json,socket,subprocess,sys,time
port=sys.argv[1]; ttl=sys.argv[2]
adm=socket.socket(socket.AF_UNIX); adm.connect("/tmp/gk-enf/admin.sock"); adm.settimeout(20)
c=socket.socket(socket.AF_UNIX); c.connect("/tmp/gk-enf/mcp.sock")
c.sendall((json.dumps({"jsonrpc":"2.0","id":f"enf-{port}","method":"access.request","params":{
 "dst_ip":"10.99.0.2","dst_port":{"from":int(port),"to":int(port)},"proto":"tcp",
 "reason":"enforcement e2e","tool":"curl","ttl_requested":ttl}})+"\n").encode())
gid=None; t0=time.time()
while not gid and time.time()-t0<15:
    for l in adm.recv(65536).decode().splitlines():
        d=json.loads(l)
        if d.get("method")=="grant.request.new": gid=d["params"]["grant_id"]
r=subprocess.run(["./target/debug/scopeadm","--socket","/tmp/gk-enf/admin.sock","approve",gid],capture_output=True,text=True)
assert r.returncode==0, r.stderr
c.settimeout(20); rep=json.loads(c.recv(65536).decode())
assert rep["result"]["decision"]=="approved", rep
print(gid)
PY

GID=$(python3 /tmp/gk-enf/appr.py 8877 30s) || { echo FAIL approve; tail -5 /tmp/gk-enf/gk.log; exit 1; }
echo "grant $GID approved for tcp/8877"

# 3. THE flip: same destination, now served (grant in kernel set)
expect_allowed 8877

# 4. revoke -> blocked again (element removed from live kernel set)
./target/debug/scopeadm --socket /tmp/gk-enf/admin.sock revoke $GID >/dev/null
sleep 0.3
expect_blocked 8877
echo "revoke -> re-blocked ✓"

# 5. D3 self-healing: short TTL expires IN KERNEL with no further userspace action
GID2=$(python3 /tmp/gk-enf/appr.py 8878 10s) || { echo FAIL approve2; exit 1; }
expect_allowed 8878
echo "grant $GID2 live on tcp/8878"

# 5b. traffic accounting (R4): admin subscriber must see bytes moving for this
# grant via pushed traffic.stat events. The subscriber itself is what enables
# the poller (admins_online gating) — so this asserts both halves.
cat > /tmp/gk-enf/stats.py <<'PY'
import json,socket,sys,time
adm=socket.socket(socket.AF_UNIX); adm.connect("/tmp/gk-enf/admin.sock"); adm.settimeout(15)
want=sys.argv[1]; t0=time.time(); seen=(0,0)
while time.time()-t0<14:
    try: data=adm.recv(65536).decode()
    except Exception: break
    if not data: break
    for l in data.splitlines():
        d=json.loads(l)
        if d.get("method")=="traffic.stat":
            for g in d["params"]["grants"]:
                if g["grant_id"]==want:
                    seen=(max(seen[0],g["bytes_sent"]), max(seen[1],g["bytes_received"]))
    if seen[0]>0 and seen[1]>0:
        print(f"traffic.stat ok: grant {want} out={seen[0]}B in={seen[1]}B"); sys.exit(0)
print(f"FAIL traffic.stat for {want}: out={seen[0]} in={seen[1]}"); sys.exit(1)
PY
( for i in 1 2 3; do curl_try 8878 >/dev/null; sleep 1; done ) &
python3 /tmp/gk-enf/stats.py "$GID2" || { echo "FAIL: traffic accounting"; exit 1; }

echo "waiting out kernel TTL..."
sleep 12
# count LIVE elements (the set-definition also contains typeof concat — parse, don't grep)
ELEMS=$(printf '{"nftables":[{"list":{"table":{"family":"inet","name":"gatekeeper"}}}]}' | $N nft --json -f - \
  | python3 -c 'import json,sys
d=json.load(sys.stdin)
print(sum(len(s.get("elem",[])) for it in d["nftables"] for s in [it.get("set") or {}] if s.get("name")=="grants_v4"))')
[ "$ELEMS" = "0" ] || { echo "FAIL: $ELEMS element(s) survived TTL"; exit 1; }
echo "kernel reaped element ✓"
expect_blocked 8878
./target/debug/scopeadm --socket /tmp/gk-enf/admin.sock list | grep -q "\"id\": $GID2" && { echo "FAIL: ledger still lists expired grant"; exit 1; } || echo "reconciler flipped row to expired ✓"

echo "ENFORCEMENT E2E PASSED"
