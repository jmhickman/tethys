#!/usr/bin/env bash
set -u
cd /root/gatekeeper
pgrep -x gatekeeper | xargs -r kill; sleep 0.3
rm -rf /tmp/gk-pin && mkdir -p /tmp/gk-pin && chmod 755 /tmp/gk-pin
cat > /tmp/gk-pin/config.toml <<'CFG'
mcp_socket   = "/tmp/gk-pin/mcp.sock"
admin_socket = "/tmp/gk-pin/admin.sock"
db = "/tmp/gk-pin/ledger.db"
agent_user = "hermes-agent"
mcp_user   = "gk-mcp-service"
CFG
./target/debug/gatekeeper --config /tmp/gk-pin/config.toml > /tmp/gk-pin/gk.log 2>&1 &
GK=$!
sleep 0.8
ls -l /tmp/gk-pin/*.sock | awk '{print $1, $3, $4, $NF}'
runuser -u gk-mcp-service -- python3 -c "
import socket
try:
    s=socket.socket(socket.AF_UNIX); s.connect('/tmp/gk-pin/mcp.sock'); print('gk-mcp-service CONNECT OK')
except Exception as e: print('gk-mcp-service CONNECT FAIL:', type(e).__name__, e)
"
kill $GK 2>/dev/null
tail -3 /tmp/gk-pin/gk.log
