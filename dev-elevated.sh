#!/bin/bash
# dev-elevated.sh
# Run NetSentinel with elevated privileges (required for ARP/ICMP raw socket scans).
# The project uses pure Rust + Iced (no Tauri/Vite/React).
set -e

# ── Build the Rust binary from the project root ──────────────────────────
echo "[*] Building NetSentinel (debug)..."
cargo build

BINARY="target/debug/netsentinel"

if [ ! -f "$BINARY" ]; then
    echo "[!] Build succeeded but binary not found at $BINARY" >&2
    exit 1
fi

# ── Prepare environment for GUI under sudo ───────────────────────────────
# Iced needs access to the display server (Wayland or X11/XWayland).
# sudo -E preserves env vars, but we also need filesystem access to the
# user's runtime directory and X server authorization.

# Allow root to connect to the X server (XWayland / X11)
if [ -n "$DISPLAY" ]; then
    xhost +local:root >/dev/null 2>&1 || true
fi

# Export all variables that sudo -E will forward to the root session
export DISPLAY="${DISPLAY:-:0}"
export WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-wayland-0}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=${XDG_RUNTIME_DIR}/bus}"

# ── Run with elevated privileges ─────────────────────────────────────────
echo "[*] Launching NetSentinel as root (raw socket privileges)..."
echo "    DISPLAY=$DISPLAY"
echo "    WAYLAND_DISPLAY=$WAYLAND_DISPLAY"

sudo -E "$BINARY"

# ── Cleanup ──────────────────────────────────────────────────────────────
# Revoke X server access for root
if [ -n "$DISPLAY" ]; then
    xhost -local:root >/dev/null 2>&1 || true
fi

echo "[*] NetSentinel exited."
