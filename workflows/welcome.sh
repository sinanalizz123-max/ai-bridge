#!/data/data/com.termux/files/usr/bin/bash
# Check the health of the Termux build environment and print useful info.
echo "=== ai-bridge welcome workflow ==="
echo "Host:          $(hostname)"
echo "Kernel:        $(uname -r)"
echo "Node (arch):   $(node -v 2>/dev/null || echo n/a)"
echo "Python:        $(python --version 2>&1)"
echo "Git:           $(git --version 2>&1)"
echo "Storage free:  $(df -h /data 2>/dev/null | tail -1 | awk '{print $4}')"
echo "ARGS: $*"