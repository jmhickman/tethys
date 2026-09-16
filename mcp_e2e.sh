#!/usr/bin/env bash
# MCP stdio E2E: real JSON-RPC client -> scope-mcp -> gatekeeper -> live kernel.
set -u
cd /root/gatekeeper
pgrep -x gatekeeper | xargs -r kill 2>/dev/null
pkill -f 'target/debug/scope-mcp' 2>/dev/null
rm -rf /tmp/gk-test && mkdir -p /tmp/gk-test
# exercise the real config-file path (TOML parse + defaults + strict users)
cat > /tmp/gk-test/config.toml <<'CFG'
mcp_socket  = "/tmp/gk-test/mcp.sock"
admin_socket = "/tmp/gk-test/admin.sock"
db = "/tmp/gk-test/ledger.db"
max_ttl = "4h"
approver_timeout_secs = 8
agent_user = "hermes-agent"
mcp_user = "gk-e2e-absent"   # dev pin disabled via --allow-missing-users below
dry_run = false
CFG
./target/debug/gatekeeper --config /tmp/gk-test/config.toml \
  --allow-missing-users > /tmp/gk-test/gk.log 2>&1 &
GK=$!
sleep 0.8

python3 -u - <<'PY'
import json, subprocess, threading, time, socket, sys

ADMIN="/tmp/gk-test/admin.sock"
adm=socket.socket(socket.AF_UNIX); adm.connect(ADMIN)
events=[]; buf=b""; adm.settimeout(0.3)
def pump():
    global buf
    while True:
        try: d=adm.recv(4096)
        except socket.timeout: continue
        except OSError: break
        if not d: break
        buf+=d
        while b"\n" in buf:
            l,buf=buf.split(b"\n",1)
            if l.strip(): events.append(json.loads(l))
threading.Thread(target=pump,daemon=True).start()

p = subprocess.Popen(["./target/debug/scope-mcp","--gatekeeper-socket","/tmp/gk-test/mcp.sock"],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

def send(o): p.stdin.write(json.dumps(o)+"\n"); p.stdin.flush()

def recv(timeout=25):
    import select
    r,_,_ = select.select([p.stdout],[],[],timeout)
    if not r: raise TimeoutError("no response from scope-mcp")
    l=p.stdout.readline()
    if not l.strip(): raise EOFError("scope-mcp closed stdout")
    return json.loads(l)

send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}})
init=recv(); print("INIT ok:", init["result"]["serverInfo"])
send({"jsonrpc":"2.0","method":"notifications/initialized"})
send({"jsonrpc":"2.0","id":2,"method":"tools/list"})
tl=recv(); tools=tl["result"]["tools"]
print("TOOLS:", [t["name"] for t in tools])
assert len(tools)==1 and tools[0]["name"]=="request_traffic_grant", tools

def approver():
    t0=time.time(); gid=None
    while time.time()-t0<20:
        for e in events:
            if e.get("method")=="grant.request.new": gid=e["params"]["grant_id"]
        if gid: break
        time.sleep(0.1)
    assert gid,"no popup event arrived"
    ev=[e for e in events if e.get("method")=="grant.request.new"][-1]["params"]
    print(f"POPUP: {ev['target']} {ev['ttl_requested']} reason={ev['reason']!r} tool={ev['tool']}")
    r=subprocess.run(["./target/debug/scopeadm","--socket",ADMIN,"approve",gid],capture_output=True,text=True)
    assert r.returncode==0, r.stderr

t=threading.Thread(target=approver); t.start()
send({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"request_traffic_grant",
  "arguments":{"dst_ip":"198.51.100.32","dst_port":{"from":443,"to":443},"proto":"tcp",
  "reason":"mcp e2e test — recon on engagement host","tool":"nmap","ttl":"10m"}}})
res=recv()
txt=res["result"]["content"][0]["text"]
print("TOOL RESULT:", txt)
assert not res["result"].get("isError") and "APPROVED" in txt, res
t.join(10)

# kernel truth
out=subprocess.run(["nft","list","set","inet","gatekeeper","grants_v4"],capture_output=True,text=True).stdout
assert "198.51.100.32" in out and "expires" in out, out
print("kernel element present with expiry ✓")

# invalid args surface as an error (JSON-RPC error object or isError result)
send({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"request_traffic_grant",
  "arguments":{"dst_ip":"198.51.100.32","dst_net":"10.0.0.0/8","dst_port":{"from":80,"to":80},
  "proto":"tcp","reason":"two targets","tool":"t","ttl":"5m"}}})
r4=recv()
msg = (r4.get("error") or {}).get("message") or (r4.get("result",{}).get("content") or [{}])[0].get("text","")
assert ("exactly one" in msg), r4
print("validation error surfaced:", msg[:80])
p.terminate()
print("MCP STDIO E2E PASSED")
PY
RC=$?
kill $GK 2>/dev/null
nft delete table inet gatekeeper 2>/dev/null
exit $RC
