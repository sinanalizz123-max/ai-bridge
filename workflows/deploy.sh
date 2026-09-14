#!/data/data/com.termux/files/usr/bin/bash
# Deploy a project: pull latest then rebuild. Usage: deploy.sh <project-dir>
set -e
PROJECT="${1?usage: deploy.sh <project-dir>}"
echo "=== Deploy workflow for $PROJECT ==="
cd "$PROJECT" || exit 1
echo "[1/3] git pull"
git pull --ff-only || echo "note: nothing to pull or branch has no remote"
echo "[2/3] gradle build"
if [ -x ./gradlew ]; then ./gradlew build; else gradle build; fi
echo "[3/3] done"
echo "=== Deploy finished ==="