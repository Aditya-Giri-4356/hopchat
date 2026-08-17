#!/bin/sh
# ==============================================================================
# HOPCHAT KILLSWITCH
# ==============================================================================
# This script completely purges HopChat from your system.
# It uninstalls the binary from the Cargo package manager and deletes the
# repository source code from the disk.

set -eu

# Safety: Verify we are in a HopChat repository
REPO_DIR=$(cd "$(dirname "$0")" && pwd)
if [ ! -f "$REPO_DIR/Cargo.toml" ]; then
    echo "❌ Safety check failed: No Cargo.toml found in $REPO_DIR. Aborting."
    exit 1
fi

if ! grep -q 'name = "hopchat"' "$REPO_DIR/Cargo.toml" 2>/dev/null; then
    echo "❌ Safety check failed: Cargo.toml does not belong to HopChat. Aborting."
    exit 1
fi

printf "⚠️  This will permanently delete HopChat from: %s\n" "$REPO_DIR"
printf "   It will also remove your identity keys and trust database.\n"
printf "   Are you sure? [y/N] "
read -r confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "Aborted."
    exit 0
fi

echo "⚠️  INITIATING HOPCHAT KILLSWITCH..."

# 1. Remove from Cargo package manager
if command -v cargo >/dev/null 2>&1; then
    echo "[-] Uninstalling from Cargo..."
    cargo uninstall hopchat 2>/dev/null || true
fi

# 2. Force remove the binary if it was copied manually
if [ -f "$HOME/.cargo/bin/hopchat" ]; then
    rm -f "$HOME/.cargo/bin/hopchat"
fi

# 3. Remove from common manual install paths
for path in /usr/local/bin/hopchat /usr/bin/hopchat; do
    if [ -f "$path" ]; then
        echo "[-] Removing $path..."
        rm -f "$path" 2>/dev/null || true
    fi
done

# 4. Remove persistent identity keys (both legacy and per-user formats)
echo "[-] Removing persistent identity keys..."
rm -f "$HOME/.hopchat_id" 2>/dev/null || true
rm -f "$HOME"/.hopchat_id_* 2>/dev/null || true

# 5. Remove TOFU trust database
echo "[-] Removing trust database..."
rm -f "$HOME/.hopchat_trust_db" 2>/dev/null || true

# 6. Self-destruct the source repository
echo "[-] Wiping source repository at $REPO_DIR..."
rm -rf "$REPO_DIR"

echo "✅ HOPCHAT HAS BEEN COMPLETELY PURGED FROM THIS SYSTEM."
