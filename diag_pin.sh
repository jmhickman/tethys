#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
pgrep -x tethysd | xargs -r kill; sleep 0.3
rm -rf /tmp/tethys-pin && mkdir -p /tmp/tethys-pin && chmod 755 /tmp/tethys-pin
cat > /tmp/tethys-pin/config.toml <<'CFG'
mcp_socket   = "/tmp/tethys-pin/mcp.sock"
admin_socket = "/tmp/tethys-pin/admin.sock"
db = "/tmp/tethys-pin/ledger.db"
agent_user = "hermes-agent"
CFG
./target/debug/tethysd --config /tmp/tethys-pin/config.toml > /tmp/tethys-pin/tethysd.log 2>&1 &
DAEMON=$!
sleep 0.8
ls -l /tmp/tethys-pin/*.sock | awk '{print $1, $3, $4, $NF}'
runuser -u hermes-agent -- python3 -c "
import socket
try:
    s=socket.socket(socket.AF_UNIX); s.connect('/tmp/tethys-pin/mcp.sock'); print('hermes-agent CONNECT OK')
except Exception as e: print('hermes-agent CONNECT FAIL:', type(e).__name__, e)
"
kill $DAEMON 2>/dev/null
tail -3 /tmp/tethys-pin/tethysd.log
