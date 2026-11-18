# HOPCHAT

**Status: Production-Hardened (v2.5.0)**


HOPCHAT is a lightweight, decentralized, deeply encrypted terminal messenger written in Rust. It enables real-time peer-to-peer texting across local networks, isolated WiFi environments, phone hotspots, and direct Bluetooth LE links—no internet access required.

Inspired by the [permissionlesstech/bitchat](https://github.com/permissionlesstech/bitchat) project, HOPCHAT focuses on ultra-fast, offline-first LAN communication, utilizing pure UDP, dynamic X25519 Key Exchange, and XChaCha20-Poly1305 authenticated encryption.

Tactical Deployment: Read about the viability of HOPCHAT in contested Military and DDIL environments here: [MILITARY_USE_CASE.md](MILITARY_USE_CASE.md)

---

## Demo

![HOPCHAT v2.5.0 Terminal Demo](assets/hopchat-demo.gif)

---

## Repository Structure & Versions

This repository contains two versions of HopChat to preserve development history and allow comparison:

*   **HopChat v2 (Root Directory)**: The primary, production-hardened codebase featuring persistent TOFU identity pinning, sliding-window replay protection, signed discovery broadcasts, constant-time verification, optimized Tokio runtime, low stack allocations, unified socket networking, and O(1) decryption caching.
*   **[HopChat v1 (Legacy)](hopchat-v1/)**: The original proof-of-concept codebase. It remains accessible in the `hopchat-v1/` directory for historical reference, research, or testing.
*   **[CHANGELOG.md](CHANGELOG.md)**: A deeply detailed technical walkthrough of all changes, optimizations, and bug fixes made between version 1.0.0 and version 2.0.0.
*   **[TRANSPORT_PLAN.md](TRANSPORT_PLAN.md)**: Where the networking layer is headed — BLE, mesh relay, LoRa, and the rest of the transport work.

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
- **Signed Discovery Broadcasts**: Discovery packets are signed with the sender's Ed25519 key and validated against a 30-second timestamp freshness window to eliminate discovery spoofing and broadcast replays.
- **Persistent TOFU Trust Database**: Pinned peer identities are stored in `~/.hopchat_trust_db` (with `0600` permissions on Unix). If a peer's public key changes across restarts, HOPCHAT detects and flags the potential MITM attack.
- **Sliding-Window Replay Protection**: Each active peer session maintains a 64-message sequence sliding bitmask ($O(1)$ memory & CPU), immediately dropping replayed or out-of-order packets.
- **Constant-Time Verification**: Prevents timing side-channel attacks on identity signatures, TOFU security codes, and session material using constant-time byte comparisons (`ct_eq`).
- **Metadata Masking**: All routing headers (sender, receiver, id, timestamp) are encrypted inside the XChaCha20 payload. Observers only see raw hex bytes.
- **Dynamic End-to-End Encryption**: Every session is uniquely secured using x25519-dalek Diffie-Hellman key derivation and hashed via sha2::Sha256 to create 256-bit symmetric session keys.
- **DoS Mitigation**: Built-in Token-Bucket rate limiting on the UDP listener to prevent network floods from crashing your node.
- **Robust UDP Protocol**: Replaces TCP handshakes with custom UDP structs. Includes automatic ACKs, deduplication, and a 3-strike 500ms jittered retransmission loop to guarantee delivery over spotty WiFi.
- **O(1) Memory Pruning**: Uses `VecDeque` ring buffers for chat history so message pruning executes in constant time with zero array shifts.
- **High Fallback Redundancy**: Sends discovery broadcasts parallel via IPV4 Multicast (239.255.255.250), Broadcast Fallbacks (255.255.255.255), and directed sweeps across every active interface.
- **Bluetooth LE Transport**: On macOS and Linux, every node advertises a GATT service and scans for peers, so two devices can chat with no router or hotspot at all. Bluetooth is preferred when a link exists and UDP is used as the fallback; both carry the same signed handshake, TOFU pins, and encrypted envelope.
- **Visible Transports**: `/wifi` and `/bluetooth` report the real interface/radio state, and can pause either radio without restarting the app.
- **iSH Terminal Support**: Works flawlessly inside iOS Alpine shells using the manual direct-IP bypass (/connect <ip>) and subnet sweep. iSH cannot access Bluetooth hardware, so the BLE transport is compiled out there and the UI reports it as unavailable; Wi-Fi chat is unchanged.
- **Sub-2% Resource Usage**: Powered by tokio asynchronous lightweight tasks spanning under 30MB of RAM and a 1.3MB stripped binary.
- **The Hardened Killswitch**: Includes a verified `killswitch.sh` script with safety checks and confirmation prompts to cleanly purge the application, trust database, identity keys, and source code.

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

## Updating an Existing Installation

To update your existing HopChat installation to the latest version:

### Option 1: Re-run the Quick Installer (All Platforms)
The installer script automatically detects your platform, downloads or compiles the latest release, and updates your binary:
```bash
curl -fsSL https://raw.githubusercontent.com/Aditya-Giri-4356/hopchat/master/install.sh | sh
```

### Option 2: Cargo Update (macOS, Linux, Android Termux)
If you installed via Cargo, pass the `--force` flag to overwrite your existing binary with the latest code from `master`:
```bash
# macOS & Linux
cargo install --git https://github.com/Aditya-Giri-4356/hopchat.git --force

# Android Termux
cargo install --git https://github.com/Aditya-Giri-4356/hopchat.git --root "$PREFIX" --force
```

### Option 3: From a Local Git Clone
If you previously cloned the repository:
```bash
cd hopchat
git pull origin master
cargo install --path . --force
```

### Option 4: iOS / iSH Terminal (Pre-built i586 Binary)
Download and replace the binary with the latest release asset:
```bash
curl -LO https://github.com/Aditya-Giri-4356/hopchat/releases/latest/download/hopchat-ish
chmod +x hopchat-ish
mv -f hopchat-ish /usr/local/bin/hopchat
```

### Verify Update
Confirm you are running the latest version:
```bash
hopchat --version
# Expected: hopchat v2.5.0
```

> [!NOTE]
> **Data & Identity Persistence:** Updating HopChat preserves your long-term Ed25519 identity keys (`~/.hopchat_id_<username>`) and your pinned peer database (`~/.hopchat_trust_db`). They are never deleted or modified during an update.
>
> *Handshake Note:* Version 2.4.0+ hardened the cryptographic handshake signature format by binding the username and X25519 key together. Ensure all communicating peers update to v2.4.0+ so sessions establish properly.

---

## Running HOPCHAT

HOPCHAT is a single-binary application. Just run it from your terminal:

```bash
hopchat
# OR from source:
cargo run --release
```

### Command-Line Arguments

HopChat v2.5.0 supports zero-dependency CLI arguments:

```bash
Usage: hopchat [OPTIONS]

Options:
  -p, --port <PORT>        Chat UDP port (default: 9878)
  -u, --username <NAME>    Username (skips the interactive prompt)
      --no-wifi            Start with LAN/Wi-Fi announcements off
      --no-bluetooth       Start with the Bluetooth transport off
  -h, --help               Show help message
      --version            Show version information
```

**Examples:**
```bash
# Start with username pre-set
hopchat -u alice

# Bind to a custom port
hopchat -p 9900 -u bob
```

---

### Running the Legacy v1 Version

To run the legacy version 1 of HopChat, navigate to the `hopchat-v1` directory and use Cargo:

```bash
cd hopchat-v1
cargo run --release
```

### Interactive Subnet Scanner & Mobile Detection

Want to see who is online before connecting? HopChat comes with a built-in subnet scanner overlay that works natively on all devices.

Because iOS (iSH) and Android (Termux) use emulated or restrictive network stacks, standard `255.255.255.255` UDP broadcasts often fail silently. To guarantee peer discovery, HopChat implements a **Robust UDP Subnet Sweep**:
1. It creates a dummy UDP socket to `8.8.8.8` to query the operating system's routing table, exposing the true local WiFi IP (e.g., `192.168.1.7`) even when emulators try to default to `127.0.0.1`.
2. It automatically calculates your active `/24` subnet.
3. It rapidly blasts directed UDP Unicast packets to all 254 possible IP addresses on the network on both discovery and chat ports.

**How to use the scanner:**
- **Desktop (macOS / Linux):** Press the **`Tab`** key while inside HopChat.
- **Mobile (iSH / Termux):** Virtual keyboards often lack a physical Tab key. Simply type the **`/scan`** command in the chat box and press `Enter`.

This will instantly pop open an interactive overlay displaying active HopChat peers.

**Navigation:** 
- Use the **Left** and **Right** arrow keys to move the cursor while typing, **Up** and **Down** to highlight a user in the scanner. 
- Press **Enter** to instantly connect to them and initiate a Diffie-Hellman key exchange.
- Press `Ctrl-C` or `ESC` to close the scanner.

### Mobile UI Differences & Touch Support
HopChat automatically scales to fit mobile screen resolutions. It also includes full terminal mouse/touch support!
- **Desktop**: Close the app via `Ctrl+C` or `ESC`.
- **Mobile**: A dedicated, touchable **`[ QUIT ]`** button is rendered directly in the Terminal UI. Simply tap the button on your touchscreen to safely exit the app without needing to open your virtual keyboard's control ribbon.

### Commands

Inside the chat buffer, you can execute special slash commands:

- `/help` - Show the contextual help menu.
- `/scan` - Launch the Interactive Subnet Scanner (especially useful on mobile).
- `/nearby` - Open the Nearby window, the same list the scanner gives you.
- `/peers` - List all currently active peers, along with their resolved local IP addresses and whether each is linked over Wi-Fi, Bluetooth, or both.
- `/wifi [on|off|status|scan]` - Show the active IPv4 interfaces and the subnets being swept, pause/resume LAN announcements, or open the scanner. Receiving from peers who already know your address still works while announcements are paused.
- `/bluetooth [on|off|status|scan]` - Show the radio state and authenticated links, or pause/resume BLE advertising and scanning. On iSH this reports that Bluetooth is unavailable instead of pretending.
- `/connect <ip> [port]` - Manually fire a handshake to a specific address. The port is optional and defaults to the peer's advertised one. (The Subnet Scanner is highly recommended over this).
- `/trust` - Show the identity keys pinned for your peers so far.
- `/unpin <username>` - Forget a pinned key. Use this when a peer reinstalls and comes back with a new identity; otherwise the old pin rejects them.
- `/clear` - Clear the conversation you are currently looking at.
- `/quit` - Safely exit the application. Alternatively, tap the **`[ QUIT ]`** button on mobile.

---

## Transports

HopChat has two independent ways to reach a peer. Nothing above the transport layer
changes between them: same identity, same X25519 session, same TOFU trust database, same
replay window, same encrypted envelope.

### Wi-Fi / LAN (UDP, all platforms)

The original transport. Discovery uses multicast, limited broadcast, and a directed sweep
of the local /24 on every active IPv4 interface, so a laptop on Wi-Fi and Ethernet is
reachable on both, and a hotspot behind a VPN is still covered. `hopchat --no-wifi` starts
with announcements paused; `/wifi off` pauses them at runtime and leaves the listener up.
There is no portable terminal API for Wi-Fi Direct/IBSS, so HopChat does not claim to join
ad-hoc Wi-Fi networks — it uses the IP network the device is already on.

### Bluetooth LE (macOS and Linux)

Every node runs both GATT roles at once:

* **Peripheral** — advertises the HopChat service and accepts encrypted chat frames.
* **Central** — scans for the same service and connects when it finds a peer.

To avoid two devices connecting to each other twice, the advertisement carries `HC` plus
the first 8 hex characters of SHA-256(Ed25519 public key), and only the lexicographically
smaller name initiates the connection. Large packets are split into 160-byte fragments
with a 7-byte header and paced at 6 ms to survive phone ATT queues. The BLE handshake is
signed with the same Ed25519 identity and bound to the advertised address, port, and a
300-second timestamp; chat itself is the normal XChaCha20-Poly1305 envelope.

Practical range is roughly 10–30 m, line of sight. Links persist while the app runs, and
an idle link is kept fresh with a signed heartbeat every 20 s. If a peer has a BLE link it
is tried first; if that link is busy or gone, HopChat falls back to UDP automatically.

On iSH there is no Bluetooth hardware exposed to the Linux userland, so the BLE backend is
not compiled into the `i586` build. `/bluetooth` and the mobile status bar report `n/a`, and
Wi-Fi chat works exactly as before. macOS may ask for Bluetooth permission the first time
the transport starts.

---

## Security Model

1. **Identity:** At first boot, HOPCHAT generates a persistent Ed25519 identity key saved to `~/.hopchat_id_<username>` (`0600` permissions on Unix).
2. **Key Agreement:** Sessions use ephemeral X25519 DH exchange. Handshakes are signed with the Ed25519 identity over the username and the X25519 key together, so a captured handshake cannot be replayed under another name, and low-order peer keys that would force an all-zero shared secret are rejected. The signature format changed in v2.4.0 — all devices must be updated together to complete a handshake.
3. **Persistent TOFU Trust DB:** Discovered peer public key fingerprints are pinned in `~/.hopchat_trust_db`. If an existing peer's key changes on subsequent launches, the connection is rejected and flagged as a potential MITM attack.
4. **Signed Discovery:** Discovery packets contain an Ed25519 signature, a timestamp, and the sender's address. An announcement claiming a username you already trust must carry that peer's pinned key, and only a packet whose signed address matches its source can move a peer you already know, which stops a replayed broadcast from redirecting a conversation.
5. **Replay Protection:** Incoming messages are verified against a per-peer 64-message sliding sequence bitmask, discarding duplicates and expired packets.
6. **Constant-Time Verification:** All cryptographic fingerprint comparisons use constant-time algorithms (`ct_eq`) to eliminate timing side-channels.
7. **Encryption:** Payloads are XChaCha20-Poly1305 encrypted. All routing metadata is hidden inside the cipher.
8. **Resilience:** Built-in per-IP rate limiting covers both the chat port and the discovery port, so a flood cannot turn into unbounded signature checks, peer-table entries or DNS lookups.

---

## The Killswitch

HOPCHAT ships with a privacy-preserving uninstaller script. If you need to completely erase the program, the binaries, your cargo package definitions, identity keys, trust DB, and the source code from your computer simultaneously, run:

```bash
./killswitch.sh
```
This performs a safety verification check against `Cargo.toml`, requests interactive confirmation `[y/N]`, forcefully uninstalls hopchat from Cargo, wipes identity keys (`~/.hopchat_id*`) & trust databases (`~/.hopchat_trust_db`), and then permanently deletes the `$REPO_DIR` containing the project code.

---

## Roadmap

BLE GATT is now a working second transport on macOS and Linux, alongside the UDP LAN path. The next big step is still decoupling the envelope from hex so the narrowest pipes are cheap: BLE L2CAP CoC for speed, a mesh relay layer so A can reach C through B, a LoRa bridge via cheap Meshtastic radios for kilometre-range hops, and file transfer once the envelope is binary rather than hex.

That plan got long enough to deserve its own page. **→ [TRANSPORT_PLAN.md](TRANSPORT_PLAN.md)**

---

## Acknowledgements

HOPCHAT is heavily inspired by the paradigm experiments over at Bitchat. We wanted to take the philosophy of permissionless LAN text strings and apply military-grade encryption payloads utilizing modern Rust architectures.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
