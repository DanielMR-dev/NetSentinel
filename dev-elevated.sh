# dev-elevated.sh
#!/bin/bash
set -e 

# Build the Rust binary
cd src-tauri
cargo build
cd ..

# Start Vite Dev server in background
pnpm dev &
VITE_PID=$!

# Wait of Vite to be ready
sleep 3

# Run the Tauri binary as root, preserving environment variables (DISPLAY, WAYLAND_DISPLAY, etc.)
sudo -E src-tauri/target/debug/app 

# Cleanup
kill $VITE_PID 2>/dev/null
