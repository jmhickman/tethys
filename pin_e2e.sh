#!/usr/bin/env bash
# pin_e2e: real peer-uid enforcement via config-file-driven mcp_user.
#  1) a peer that is NOT the configured mcp_user is REJECTED on mcp.sock
#     (this harness runs as root; no reply, daemon survives)
#  2) a peer running as gk-mcp-service on mcp.sock gets the full approve flow
#     (approvals go over admin.sock, which is 0600 root-only)
set -u
cd /root/gatekeeper
pgrep -x gatekeeper | xargs -r kill 2>/dev/null; sleep 0.3
rm -rf /tmp/gk-pin && mkdir -p /tmp/gk-pin && chmod 755 /tmp/gk-pin

cat > /tmp/gk-pin/config.toml <<'CFG'
mcp_socket   = "/tmp/gk-pin/mcp.sock"
admin_socket = "/tmp/gk-pin/admin.sock"
db = "/tmp/gk-pin/ledger.db"
max_ttl = "1h"
approver_timeout_secs = 60
agent_user = "hermes-agent"
mcp_user   = "gk-mcp-service"      # peer check: only this uid is accepted on mcp.sock
CFG

./target/debug/gatekeeper --config /tmp/gk-pin/config.toml > /tmp/gk-pin/gk.log 2>&1 &
GK=$!
sleep 0.8
grep -q "identities resolved" /tmp/gk-pin/gk.log || { echo "startup failed"; cat /tmp/gk-pin/gk.log; exit 1; }

# --- negative: this shell's user is not gk-mcp-service -> request is ignored.
python3 - <<'PY'
import json, socket, sys
s = socket.socket(socket.AF_UNIX); s.connect("/tmp/gk-pin/mcp.sock")
s.sendall((json.dumps({"jsonrpc":"2.0","id":"pin-1","method":"access.request","params":{
 "dst_ip":"192.0.2.1","dst_port":{"from":80,"to":80},"proto":"tcp",
 "reason":"should never reach","tool":"t","ttl_requested":"60s"}})+"\n").encode())
s.settimeout(2.0)
try:
    data = s.recv(4096)
except Exception:
    data = b""
if data:
    print("UNEXPECTED reply to pinned-out peer:", data[:120]); sys.exit(1)
print("non-mcp-user peer on mcp.sock: correctly ignored (no reply)")
PY
NEG=$?

# --- positive: MCP connection as gk-mcp-service (connector helper); approvals
#     come from the admin socket, which this harness opens as its own user.
cat > /tmp/gk-pin/connector.py <<'PY'
import json, socket, sys
try:
    a = socket.socket(socket.AF_UNIX); a.connect("/tmp/gk-pin/mcp.sock")
    a.sendall((json.dumps({"jsonrpc":"2.0","id":"pin-2","method":"access.request","params":{
     "dst_ip":"192.0.2.2","dst_port":{"from":80,"to":80},"proto":"tcp",
     "reason":"scoped peer test","tool":"t","ttl_requested":"60s"}})+"\n").encode())
    a.settimeout(30)  # blocks until the approval arrives on admin.sock
    rep = a.recv(65536).decode()
    assert '"approved"' in rep, rep[:200]
    print("gk-mcp-service verdict:", json.loads(rep)["result"]["decision"])
except Exception as e:
    print("connector FAIL:", type(e).__name__, str(e)[:120]); sys.exit(1)
PY
# the connector runs as gk-mcp-service; this shell's umask (077) would make
# the script unreadable to that account, hence the chmod
chmod 644 /tmp/gk-pin/connector.py

python3 - <<'PY'
import json, socket, subprocess, sys, threading, time
adm = socket.socket(socket.AF_UNIX); adm.connect("/tmp/gk-pin/admin.sock")  # daemon owner may connect
conn = subprocess.Popen(["runuser","-u","gk-mcp-service","--","python3","/tmp/gk-pin/connector.py"],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
adm.settimeout(25)
t0=time.time(); gid=None
while time.time()-t0<20 and not gid:
    try:
        for line in adm.recv(65536).decode().splitlines():
            d=json.loads(line)
            if d.get("method")=="grant.request.new": gid=d["params"]["grant_id"]
    except Exception as e:
        print("admin read:", e); break
    time.sleep(0.1)
if not gid:
    print("no popup for gk-mcp-service request")
    try:
        out,_ = conn.communicate(timeout=5)
        print("connector said:", out.strip()[:300])
    except Exception:
        conn.kill()
    sys.exit(1)
r = subprocess.run(["./target/debug/scopeadm","--socket","/tmp/gk-pin/admin.sock","approve",gid],
                   capture_output=True, text=True)
assert r.returncode==0, r.stderr
out,_ = conn.communicate(timeout=30)
print(out.strip())
assert "approved" in out and conn.returncode==0, (out, conn.returncode)
PY
POSRC=$?

# daemon must still be alive after the rejected connection
kill -0 $GK 2>/dev/null || { echo "daemon died on rejected conn"; NEG=9; }
kill $GK 2>/dev/null
nft delete table inet gatekeeper 2>/dev/null

echo "negative(non-mcp-user rejected)=$NEG positive(gk-mcp-service ok)=$POSRC"
[ $NEG -eq 0 ] && [ $POSRC -eq 0 ] && echo "PIN E2E PASSED" || { echo PIN_FAIL; cat /tmp/gk-pin/gk.log; exit 1; }
