# HOPCHAT

**Status: Production-Hardened (v2.0.0)**


HOPCHAT is a lightweight, decentralized, deeply encrypted terminal messenger written in Rust. It enables real-time peer-to-peer texting across local networks, isolated WiFi environments, and phone hotspots—no internet access required.

Inspired by the [permissionlesstech/bitchat](https://github.com/permissionlesstech/bitchat) project, HOPCHAT focuses on ultra-fast, offline-first LAN communication, utilizing pure UDP, dynamic X25519 Key Exchange, and XChaCha20-Poly1305 authenticated encryption.

Tactical Deployment: Read about the viability of HOPCHAT in contested Military and DDIL environments here: [MILITARY_USE_CASE.md](MILITARY_USE_CASE.md)

---

## Repository Structure & Versions

This repository contains two versions of HopChat to preserve development history and allow comparison:

*   **HopChat v2 (Root Directory)**: The primary, production-hardened codebase featuring TOFU security identity, optimized Tokio runtime, low stack allocations, unified socket networking, and O(1) decryption caching.
*   **[HopChat v1 (Legacy)](hopchat-v1/)**: The original proof-of-concept codebase. It remains accessible in the `hopchat-v1/` directory for historical reference, research, or testing.
*   **[CHANGELOG.md](CHANGELOG.md)**: A deeply detailed technical walkthrough of all changes, optimizations, and bug fixes made between version 1.0.0 and version 2.0.0.

---

## Architecture Diagram

```ascii
┌──────────────────┐               ┌──────────────────┐
│   Linux Laptop   │               │   iPhone (iSH)   │
│   (HOPCHAT UI)   ├─────┐   ┌─────┤   (HOPCHAT UI)   │
└────────▲─────────┘     │   │     └────────▲─────────┘
         │               │   │              │
     Multicast           ▼   ▼      Direct Unicast Fallback
    Discovery        ┌───────────┐      (/connect IP)
      (UDP)          │   Phone   │          (UDP)
                     │  Hotspot  │
                     │ (Offline) │
                     └───────────┘
```

---

## Features

- **Offline-First Networking**: Communicates purely via LAN IP tables. Works on phone hotspots, disconnected routers, and isolated local ad-hoc networks.
- **Identity-Anchored Security**: Every node generates a persistent Ed25519 long-term identity to prevent username spoofing.
- **Metadata Masking**: All routing headers (sender, receiver, id, timestamp) are encrypted inside the XChaCha20 payload. Observers only see raw hex bytes.
- **Dynamic End-to-End Encryption**: Every session is uniquely secured using x25519-dalek Diffie-Hellman key derivation and hashed via sha2::Sha256 to create 256-bit symmetric session keys.
- **DoS Mitigation**: Built-in Token-Bucket rate limiting on the UDP listener to prevent network floods from crashing your node.
- **Robust UDP Protocol**: Replaces TCP handshakes with custom UDP structs. Includes deduplication caching, automatic ACKs, and a 3-strike 500ms jittered retransmission loop to guarantee delivery over spotty WiFi.
- **High Fallback Redundancy**: Sends discovery broadcasts parallel via IPV4 Multicast (239.255.255.250) and Broadcast Fallbacks (255.255.255.255).
- **iSH Terminal Support**: Works flawlessly inside iOS Alpine shells using the manual direct-IP bypass (/connect <ip>).
- **Sub-2% Resource Usage**: Powered by tokio asynchronous lightweight tasks spanning under 30MB of RAM.
- **The Killswitch**: Includes a one-click killswitch.sh script to instantly purge the application and source binaries from your environment.

---

## Installation

### The Quick Way (Recommended)

Run the following command in your terminal (works on macOS, Linux, iPhone iSH, and Android Termux):

```bash
curl -fsSL https://raw.githubusercontent.com/Aditya-Giri-4356/hopchat/master/install.sh | sh
```

This script automatically detects your platform, installs any missing dependencies (like Rust/Clang on Termux, or curl on iSH), downloads the correct pre-built binary (or compiles it from source), and places it in your system's `$PATH`. 

Once installed, you can launch HopChat from **any directory** simply by typing:
```bash
hopchat
```

---

### Manual Installation (Alternative)

#### 1. iOS / iSH Terminal (Alpine Linux — 32-bit x86)

iSH emulates a basic i586-class x86 CPU — it does **not** support SSE/SSE2 instructions. Instead of compiling directly on iSH, you can manually download the pre-compiled binary:

```bash
apk update && apk add curl
curl -LO https://github.com/Aditya-Giri-4356/hopchat/releases/latest/download/hopchat-ish
chmod +x hopchat-ish
mv hopchat-ish /usr/local/bin/hopchat
hopchat
```

#### 2. Android Termux
If you want to manually install it via Cargo on Termux:
```bash
pkg update
pkg install -y rust clang git
cargo install --git https://github.com/Aditya-Giri-4356/hopchat.git --root "$PREFIX"
hopchat
```

#### 3. Linux / macOS (From Source)
```bash
# Clone and Build
git clone https://github.com/Aditya-Giri-4356/hopchat.git
cd hopchat
cargo install --path . # Safely compiles and places binary in ~/.cargo/bin without requiring sudo
```

#### 4. Package Manager (Global Cargo Install)
```bash
cargo install --git https://github.com/Aditya-Giri-4356/hopchat.git
```
*Note: Ensure `~/.cargo/bin` is in your environment PATH.*

---

## Running HOPCHAT

HOPCHAT is a single-binary application. Just run it from your terminal:

```bash
cargo run --release
# OR
./target/release/hopchat
```

You'll be prompted to enter a username. Once supplied, the terminal UI (TUI) will launch and HOPCHAT will automatically discover peers on your network.

### Running the Legacy v1 Version

To run the legacy version 1 of HopChat, navigate to the `hopchat-v1` directory and use Cargo:

```bash
cd hopchat-v1
cargo run --release
```

### Commands

Inside the chat buffer, you can execute special slash commands:

- /help - Show the contextual help menu.
- /peers - List all currently active peers, along with their resolved local IP addresses.
- /connect <ip> - Manually fire a handshake to a specific IP Address. This bypasses UDP multicast drops and establishes a direct P2P link (Critical for iOS / iSH / restrictive routers).
- /quit - Safely exit the application. Alternatively, press CTRL-C or ESC.

---

## Security Model

1. **Identity:** At first boot, HOPCHAT generates a persistent Ed25519 identity key saved to ~/.hopchat_id.
2. **Key Agreement:** Sessions use ephemeral X25519 DH exchange. Handshakes are signed with the Ed25519 identity to prevent spoofing and MITM.
3. **Verification:** Users can verify out-of-band using the 16-character TOFU (Trust On First Use) Security Codes displayed in the UI.
4. **Encryption:** Payloads are XChaCha20-Poly1305 encrypted. Unlike previous versions, all metadata is now hidden inside the cipher.
5. **Resilience:** Built-in IP rate limiting prevents DoS flood attacks.

---

## The Killswitch

HOPCHAT ships with a privacy-preserving uninstaller script. If you need to completely erase the program, the binaries, your cargo package definitions, and the source code from your computer simultaneously, run:

```bash
./killswitch.sh
```
This will forcefully uninstall hopchat from the Cargo package manager and then permanently delete the $REPO_DIR containing the project code.

---

## Roadmap

- **Hybrid Bluetooth Low Energy (BLE) Transport**: We plan to implement concurrent BLE and UDP P2P networking using the `blew` crate. This will allow true zero-net connectivity by acting as both a BLE Central and Peripheral, leveraging opportunistic L2CAP CoC for high-speed socket-like P2P communication when WiFi is entirely absent.
- **File Transfers**: Base64 binary chunking to allow for direct encrypted file transfer over UDP and BLE. 
- **Mesh Relay**: Decentralized packet hopping. If A can see B, and B can see C, A can message C purely through the HOPCHAT physical geometry.

---

## Acknowledgements

HOPCHAT is heavily inspired by the paradigm experiments over at Bitchat. We wanted to take the philosophy of permissionless LAN text strings and apply military-grade encryption payloads utilizing modern Rust architectures.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
