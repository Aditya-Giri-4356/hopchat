#!/bin/sh
# ==============================================================================
# HOPCHAT KILLSWITCH
# ==============================================================================
# This script completely purges HopChat from your system.
# It uninstalls the binary from the Cargo package manager and deletes the 
# repository source code from the disk.

echo "⚠️  INITIATING HOPCHAT KILLSWITCH..."

# 1. Remove from Cargo package manager
if command -v cargo >/dev/null 2>&1; then
    echo "[-] Uninstalling from Cargo..."
    cargo uninstall hopchat 2>/dev/null
fi

# 2. Force remove the binary if it was copied manually
if [ -f "$HOME/.cargo/bin/hopchat" ]; then
    rm -f "$HOME/.cargo/bin/hopchat"
fi

# 3. Retrieve current directory to delete the source repo
REPO_DIR=$(pwd)

echo "[-] Wiping source repository at $REPO_DIR..."
cd ..

# 4. Self-destruct the folder recursively
rm -rf "$REPO_DIR"

echo "✅ HOPCHAT HAS BEEN COMPLETELY PURGED FROM THIS SYSTEM."
