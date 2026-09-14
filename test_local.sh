#!/usr/bin/env bash
set -u
cd ~/ai-bridge
TOKEN=$(python3 -c "import json;print(json.load(open('config/config.json'))['token'])")
BASE="http://127.0.0.1:8765/$TOKEN"

python3 bridge.py < /dev/null > logs/server.log 2>&1 &
echo $! > run/test.pid
sleep 1.2

pass=0; fail=0

echo "== health (no token should 404) =="
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8765/health

echo "== health (with token) =="
curl -s -w "\ncode:%{http_code}\n" "$BASE/health"

echo "== execute: whoami =="
curl -s -X POST "$BASE/execute" -H "Content-Type: application/json" \
  -d '{"command":"whoami && pwd","working_directory":"/data/data/com.termux/files/home"}' \
  | python3 -m json.tool

echo "== execute async + status + cancel =="
PID=$(curl -s -X POST "$BASE/execute" -H "Content-Type: application/json" \
  -d '{"command":"sleep 60","working_directory":"/data/data/com.termux/files/home","async":true}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['process_id'])")
echo "pid=$PID"
curl -s -X POST "$BASE/process/status" -H "Content-Type: application/json" -d "{\"process_id\":$PID}" | python3 -m json.tool
curl -s -X POST "$BASE/process/cancel" -H "Content-Type: application/json" -d "{\"process_id\":$PID}" | python3 -m json.tool
curl -s -X POST "$BASE/process/status" -H "Content-Type: application/json" -d "{\"process_id\":$PID}" | python3 -m json.tool

echo "== files: write/list/read/search =="
curl -s -X POST "$BASE/files/write" -H "Content-Type: application/json" \
  -d '{"path":"/data/data/com.termux/files/home/ai-bridge/run/test.txt","content":"hello ai-bridge\nline2\n"}' | python3 -m json.tool
curl -s -X POST "$BASE/files/list" -H "Content-Type: application/json" \
  -d '{"path":"/data/data/com.termux/files/home/ai-bridge/run"}' | python3 -m json.tool
curl -s -X POST "$BASE/files/read" -H "Content-Type: application/json" \
  -d '{"path":"/data/data/com.termux/files/home/ai-bridge/run/test.txt"}' | python3 -m json.tool
curl -s -X POST "$BASE/files/search" -H "Content-Type: application/json" \
  -d '{"path":"/data/data/com.termux/files/home/ai-bridge","pattern":"*.txt"}' | python3 -m json.tool

echo "== path escape should be blocked =="
curl -s -X POST "$BASE/files/read" -H "Content-Type: application/json" \
  -d '{"path":"/../../etc/hosts"}' | python3 -m json.tool

echo "== destructive command blocked in DEVELOPMENT =="
curl -s -X POST "$BASE/execute" -H "Content-Type: application/json" \
  -d '{"command":"rm -rf /somewhere","working_directory":"/data/data/com.termux/files/home"}' | python3 -m json.tool

echo "== git status (home likely not a repo - expect graceful error) =="
curl -s -X POST "$BASE/git" -H "Content-Type: application/json" \
  -d '{"path":"/data/data/com.termux/files/home/ai-bridge","op":"status"}' | python3 -c "import sys,json;d=json.load(sys.stdin);print('success:',d['success']);print((d.get('result',{}).get('stdout') or d.get('error'))[:200])"

echo "== system info =="
curl -s -X POST "$BASE/system/info" -H "Content-Type: application/json" -d '{}' | python3 -c "import sys,json;d=json.load(sys.stdin);print(json.dumps(d['result']['info'],indent=1))"

echo "== workflows list + run =="
curl -s "$BASE/workflows" | python3 -m json.tool
curl -s -X POST "$BASE/workflows" -H "Content-Type: application/json" \
  -d '{"name":"welcome","args":["x","y"]}' | python3 -c "import sys,json;d=json.load(sys.stdin);r=d['result'];print('exit:',r['exit_code']);print(r['stdout'])"

echo "== openapi sanity =="
curl -s "$BASE/openapi.json" | python3 -c "import sys,json;d=json.load(sys.stdin);print('openapi',d['openapi']);print('servers',d['servers']);print('paths',len(d['paths']))"

echo "== cleanup test file =="
curl -s -X POST "$BASE/files/delete" -H "Content-Type: application/json" \
  -d '{"path":"/data/data/com.termux/files/home/ai-bridge/run/test.txt"}' | python3 -m json.tool

echo "== stopping server =="
kill "$(cat run/test.pid)" 2>/dev/null
sleep 0.5
echo "done"