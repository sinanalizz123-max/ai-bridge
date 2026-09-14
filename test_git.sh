#!/usr/bin/env bash
set -u
cd ~/ai-bridge
TOKEN=$(python3 -c "import json;print(json.load(open('config/config.json'))['token'])")
B="http://127.0.0.1:8765/$TOKEN"
rm -rf run/testrepo run/aib_*
mkdir -p run/testrepo
cd run/testrepo && git init -q . && echo "file1" > a.txt && git add a.txt && git -c user.email=t@t -c user.name=t commit -qm init
cd ~/ai-bridge
python3 bridge.py < /dev/null > logs/server.log 2>&1 &
SRV=$!
sleep 1.2

show() { python3 -c "import sys,json
d=json.load(sys.stdin)
r=d.get('result')
if r is None:
    print('NO RESULT:', d)
else:
    print('exit', r.get('exit_code'), '|', (r.get('stdout') or '')[:150].strip(), '|', (r.get('stderr') or '')[:200].strip())"; }

echo "== git status =="; curl -s -X POST "$B/git" -H "Content-Type: application/json" -d '{"path":"/data/data/com.termux/files/home/ai-bridge/run/testrepo","op":"status"}' | show
echo "== git log =="; curl -s -X POST "$B/git" -H "Content-Type: application/json" -d '{"path":"/data/data/com.termux/files/home/ai-bridge/run/testrepo","op":"log"}' | show
echo "== diff after edit =="
curl -s -X POST "$B/files/write" -H "Content-Type: application/json" -d '{"path":"/data/data/com.termux/files/home/ai-bridge/run/testrepo/a.txt","content":"file1 v2\n"}' > /dev/null
curl -s -X POST "$B/git" -H "Content-Type: application/json" -d '{"path":"/data/data/com.termux/files/home/ai-bridge/run/testrepo","op":"diff"}' | show
echo "== commit =="; curl -s -X POST "$B/git" -H "Content-Type: application/json" -d '{"path":"/data/data/com.termux/files/home/ai-bridge/run/testrepo","op":"commit","message":"update a.txt"}' | show
echo "== add backwards-compat add =="; curl -s -X POST "$B/git" -H "Content-Type: application/json" -d '{"path":"/data/data/com.termux/files/home/ai-bridge/run/testrepo","op":"add","files":["a.txt"]}' | show
echo "== git status clean =="; curl -s -X POST "$B/git" -H "Content-Type: application/json" -d '{"path":"/data/data/com.termux/files/home/ai-bridge/run/testrepo","op":"status"}' | show
echo "== push (no remote, expect git error) =="; curl -s -X POST "$B/git" -H "Content-Type: application/json" -d '{"path":"/data/data/com.termux/files/home/ai-bridge/run/testrepo","op":"push"}' | show

kill -9 $SRV 2>/dev/null
sleep 0.5
rm -rf run/testrepo run/aib_*
echo "TEST-COMPLETE"