#!/data/data/com.termux/files/usr/bin/bash
# ai-bridge installer (Termux)

set -e

BRIDGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"

echo "[*] Checking required packages..."
for pkg in python openssh; do
    if ! command -v "$pkg" >/dev/null 2>&1; then
        echo "[*] Installing $pkg ..."
        pkg install -y "$pkg"
    fi
done

chmod +x "$BRIDGE_DIR/ai-bridge"
ln -sf "$BRIDGE_DIR/ai-bridge" "$PREFIX/bin/ai-bridge"

echo "[*] Preparing config..."
if [ ! -f "$BRIDGE_DIR/config/config.json" ]; then
    python3 "$BRIDGE_DIR/bridge.py" --init >/dev/null 2>&1 || true
fi

echo "[*] Done."
echo
echo "  Run:   ai-bridge start"
echo "  Then:  import the printed OpenAPI URL into your Custom GPT's Actions"
echo "         (Authentication: No authentication)"
echo