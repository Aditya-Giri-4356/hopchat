#!/bin/sh
# ==============================================================================
# HOPCHAT AUTOMATIC INSTALLER
# ==============================================================================
# Installs HopChat globally on the system (runs like neofetch).
# Supports iSH (Alpine), Android Termux, and standard macOS/Linux.

set -e

echo "------------------------------------------------"
echo "🌀 INITIATING HOPCHAT ONE-TIME GLOBAL INSTALLER..."
echo "------------------------------------------------"

# Helper to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Case 1: Termux (Android)
if [ -n "$TERMUX_VERSION" ] || [ -d "/data/data/com.termux" ]; then
    echo "[+] Android Termux environment detected."
    echo "[+] Updating package index..."
    pkg update -y
    
    echo "[+] Installing system dependencies (rust, clang, git)..."
    pkg install -y rust clang git

    echo "[+] Building HopChat from source and installing to Termux path..."
    cargo install --git https://github.com/Aditya-Giri-4356/hopchat.git --root "$PREFIX" --force

    echo "------------------------------------------------"
    echo "✅ HOPCHAT INSTALLED SUCCESSFULLY!"
    echo "   Simply run: hopchat"
    echo "------------------------------------------------"

# Case 2: Alpine Linux / iSH (iPhone)
elif [ -f /etc/alpine-release ] || grep -q "Alpine" /etc/issue 2>/dev/null; then
    echo "[+] Alpine Linux / iSH environment detected."
    
    if ! command_exists curl; then
        echo "[+] Installing curl..."
        apk update
        apk add curl
    fi

    echo "[+] Fetching latest release version tag..."
    LATEST_TAG=$(curl -s https://api.github.com/repos/Aditya-Giri-4356/hopchat/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    
    # Fallback to current version if API limit is hit or resolution fails
    if [ -z "$LATEST_TAG" ] || [ "$LATEST_TAG" = "null" ]; then
        LATEST_TAG="v2.1.1"
    fi
    echo "[+] Target release: $LATEST_TAG"

    INSTALL_DIR="/usr/local/bin"
    if [ ! -d "$INSTALL_DIR" ]; then
        INSTALL_DIR="/usr/bin"
    fi

    echo "[+] Downloading pre-built iSH binary to $INSTALL_DIR/hopchat..."
    curl -L "https://github.com/Aditya-Giri-4356/hopchat/releases/download/${LATEST_TAG}/hopchat-ish" -o "${INSTALL_DIR}/hopchat"
    
    echo "[+] Making binary executable..."
    chmod +x "${INSTALL_DIR}/hopchat"

    echo "------------------------------------------------"
    echo "✅ HOPCHAT INSTALLED SUCCESSFULLY!"
    echo "   Simply run: hopchat"
    echo "------------------------------------------------"

# Case 3: macOS / standard Linux
else
    OS_TYPE=$(uname -s)
    echo "[+] Standard system detected: $OS_TYPE"
    
    if command_exists cargo; then
        echo "[+] Compiling and installing HopChat via Cargo..."
        cargo install --git https://github.com/Aditya-Giri-4356/hopchat.git --force
        
        echo "------------------------------------------------"
        echo "✅ HOPCHAT INSTALLED SUCCESSFULLY!"
        echo "   Simply run: hopchat"
        echo "   (Make sure '\$HOME/.cargo/bin' is added to your PATH)"
        echo "------------------------------------------------"
    else
        echo "❌ Cargo/Rust not found."
        echo "Please install Rust (https://rustup.rs) first, then run this installer."
        exit 1
    fi
fi
