# Changelog

---

## v2.1.1 — iSH Illegal Instruction Fix (SSE2 Removal)

HopChat v2.1.0 binaries crashed immediately on iSH with `Illegal instruction`. This patch completely eliminates SSE/SSE2 instructions from the compiled binary.

### 🐛 Bug Fix

#### Illegal Instruction Crash on iSH
* **Problem:** The v2.1.0 binary was compiled for the `i686-unknown-linux-musl` target, which enables **SSE2 floating-point** by default. iSH emulates a basic i586-class x86 CPU and does **not** support SSE or SSE2 instructions. Any SSE2 opcode triggers an immediate `Illegal instruction` signal and crash.
* **Root Cause:** Rust's `i686` target assumes Pentium 4-class features (SSE2). iSH's CPU emulator only supports Pentium-class (i586) instructions — integer x87 FPU only, no SIMD.
* **Solution:** Switched the CI cross-compilation target from `i686-unknown-linux-musl` to `i586-unknown-linux-musl` and added `RUSTFLAGS="-C target-cpu=pentium"` to force all codegen (including dependencies like `curve25519-dalek` and `chacha20poly1305`) to use only Pentium-compatible instructions.

### 🏗️ Build & Deployment

#### Updated CI Workflow
* Target changed: `i686-unknown-linux-musl` → `i586-unknown-linux-musl`
* Added `RUSTFLAGS="-C target-cpu=pentium"` environment variable
* Binary renamed from `hopchat-i686-linux-musl` to `hopchat-ish` for clarity
* Release body now includes inline download instructions

#### Updated README & Cross.toml
* All iSH installation instructions reference the new `hopchat-ish` binary name
* Cross-compilation docs updated to target `i586-unknown-linux-musl`

---

## v2.1.0 — iSH / i686 32-bit Alpine Compatibility

HopChat v2.1.0 focuses on **portability**: making the application compile and run on 32-bit i686 Alpine Linux environments like the iSH terminal emulator on iOS.

### 🔧 Compatibility Fixes

#### Replaced `std::sync::LazyLock` with `once_cell::sync::Lazy`
* **Problem:** `std::sync::LazyLock` was introduced in Rust 1.80.0. Alpine Linux's `apk` package manager ships Rust 1.72 (Alpine 3.19) or older. Attempting to compile HopChat on iSH or any system with Rust < 1.80 resulted in a compilation error.
* **Solution:** Replaced `LazyLock` with `once_cell::sync::Lazy`, which is functionally identical but works on Rust 1.56+.

#### Replaced `AtomicU64` with `AtomicUsize`
* **Problem:** On 32-bit i686 targets, `AtomicU64` requires hardware support for 64-bit atomic compare-and-swap (CAS) instructions. While most i686 CPUs support `cmpxchg8b`, the emulation layer in iSH may not reliably provide it, leading to potential `Illegal Instruction` crashes or linker failures.
* **Solution:** Switched the message ID counter from `AtomicU64` to `AtomicUsize`, which is natively 32-bit on i686 targets. The counter value is cast to `u64` for wire-protocol compatibility, preserving the serialized message format.

#### Pinned `ratatui` to v0.26.1 and `crossterm` to v0.27
* **Problem:** `ratatui` 0.29 requires Rust 1.74+ (MSRV). Additionally, newer versions introduced API changes (`frame.area()` → `frame.size()`, `set_cursor_position` → `set_cursor`) that don't exist in earlier versions.
* **Solution:** Pinned `ratatui = "0.26.1"` (MSRV 1.70) and `crossterm = "0.27"`. Updated all API call sites to match the 0.26 interface:
  - `frame.area()` → `frame.size()`
  - `frame.set_cursor_position((x, y))` → `frame.set_cursor(x, y)`

#### Set Explicit MSRV (Minimum Supported Rust Version)
* Added `rust-version = "1.70.0"` to `Cargo.toml` so that `cargo` will produce a clear, actionable error if a user attempts to compile with an incompatible toolchain.

### 🏗️ Build & Deployment

#### GitHub Actions CI for i686 Cross-Compilation
* Added `.github/workflows/build-ish.yml` — a GitHub Actions workflow that automatically cross-compiles a static `i686-unknown-linux-musl` binary on every tagged release.
* The binary is published as a GitHub Release artifact, allowing iSH users to download and run it directly without needing to compile Rust on their phone.

#### Updated README with iSH Instructions
* Replaced the "compile on iSH" instructions with practical steps: download a pre-built i686 static binary from GitHub Releases.
* Added developer documentation for cross-compiling locally using `cross` + Docker.

---

## v2.0.0 — Hardening, Optimization & Bug Fixes

HopChat v2.0.0 represents a comprehensive hardening, optimization, and bug-fixing release of the terminal-based peer-to-peer encrypted chat application. While maintaining the core ephemeral promise of HopChat (zero disk persistence of chat history, self-destructing data on exit), version 2.0.0 resolves security risks, performance overheads, and packet routing bugs present in the original v1.0.0 codebase.

---

## 1. Security & Integrity Hardening

### Persistent Ed25519 Identity for TOFU Verification
* **Problem in v1.0.0**: Key exchange relied on ephemeral, unsigned X25519 keys generated at startup. While messages were encrypted, there was no cryptographic persistence of identities between restarts. An attacker in the middle could intercept the initial key exchange, present their own keys, and hijack the conversation without warning.
* **Solution in v2.0.0**: 
  - Integrated a persistent Ed25519 identity keypair generated once and saved in `~/.hopchat_id`. 
  - During the X25519 key exchange, each node signs its ephemeral X25519 public key using its Ed25519 private key.
  - Peers verify the signature against the sender's Ed25519 public key and register the public key fingerprint using a Trust-On-First-Use (TOFU) architecture.
  - If a peer attempts to reconnect in a subsequent run with the same username but a different Ed25519 fingerprint, HopChat flags a security mismatch, warning the user of a potential Man-in-the-Middle (MITM) hijacking.
  - The Ed25519 key is stored securely locally; message histories themselves remain completely ephemeral.

### Username Sanitization (UDP Payload Injection Prevention)
* **Problem in v1.0.0**: Usernames were taken directly from standard input without validation. Since discovery payloads are serialized as pipe-delimited strings (e.g., `HOPCHAT|username|ip|port|...`), a user could input a username containing pipe characters (such as `attacker|192.168.1.100|9999`). This injected fake columns into the parsed packet, allowing arbitrary peer injection.
* **Solution in v2.0.0**: 
  - Usernames are now rigorously sanitized at startup.
  - All pipe (`|`) characters and spaces are stripped out.
  - A maximum limit of 32 characters is strictly enforced to prevent buffer overrun or UI truncation.

### Randomized Message IDs (Anti-Metadata Leak)
* **Problem in v1.0.0**: Message IDs were initialized to `1` and incremented sequentially. Eavesdroppers observing the traffic could read packet headers and count acknowledgement payloads (e.g., `HOPCHAT_ACK|3`, `HOPCHAT_ACK|4`) to determine precisely how many messages a particular node had sent.
* **Solution in v2.0.0**:
  - The `NEXT_MESSAGE_ID` atomic counter is now initialized to a randomized 64-bit unsigned integer (`u64`) at startup, seeded using `rand::thread_rng().gen::<u64>()`.
  - While incrementing remains sequential to ensure proper packet order and deduplication, the starting point is completely randomized, hiding the absolute volume of messages sent by any node.

### Safe & Thorough Killswitch Execution
* **Problem in v1.0.0**: The `killswitch.sh` script used basic relative pathing, failing if executed from a different working directory. It also left behind the persistent `~/.hopchat_id` key, violating the "clean exit" promise.
* **Solution in v2.0.0**:
  - Re-written to dynamically determine its own source path using `dirname "$0"` so it executes reliably from any folder.
  - Hardened to delete `~/.hopchat_id` as part of the teardown process, ensuring that once a user runs the killswitch or exits the application, no cryptographic identity traces or key files remain on the disk.

---

## 2. Performance & Resource Optimizations

### Lightweight Tokio Runtime
* **Problem in v1.0.0**: The project imported `tokio` using the `features = ["full"]` directive. This dragged in heavy components (file system, process execution, signals, and multi-threaded timers) that HopChat does not use, bloating binary sizes and adding run-time overhead.
* **Solution in v2.0.0**:
  - Pruned Tokio features to a minimal set: `["rt-multi-thread", "net", "sync", "macros", "time"]`.
  - Removed the unused direct dependency `rand_core` (pulled transitively by `rand`).
  - Reduces compilation time, slims down the final release binary to under 2MB, and decreases RAM footprint — vital when running HopChat on resource-constrained devices like iPhones using the iSH terminal.

### Stack Memory Optimization
* **Problem in v1.0.0**: The UDP messaging listener allocated a `[0u8; 65535]` buffer on the stack for every loop iteration. While 65,535 bytes is the absolute theoretical maximum size of a UDP packet, HopChat's encrypted messages are well under 1–2KB. This wasted stack space and caused unnecessary memory cycling.
* **Solution in v2.0.0**:
  - Reduced the receive buffer size to a sane maximum of `[0u8; 4096]` (4KB). 
  - This easily accommodates the encrypted X25519 exchanges and text messages while saving over 60KB of stack allocations per frame in the listener loop.

### Outbound Connection/Socket Reuse
* **Problem in v1.0.0**: Sending messages or issuing `/connect` created a new throwaway ephemeral `UdpSocket` every time. Spawning temporary sockets under high volume risks file descriptor/port exhaustion.
* **Solution in v2.0.0**:
  - Extracted the primary bound socket into an `Arc<UdpSocket>` in the shared `AppState`.
  - Commands and messaging tasks now reuse this outbound socket instead of binding new ones, preventing OS port depletion.

### O(1) Decryption Routing Cache
* **Problem in v1.0.0**: When an encrypted packet arrived, HopChat iterated sequentially through all active cryptographic sessions, attempting to decrypt the message until one succeeded. As the number of peers (N) grew, this resulted in an O(N) CPU load.
* **Solution in v2.0.0**:
  - Introduced an IP-to-session routing cache. 
  - Once key exchange completes with a peer, their IP/Port is mapped to their session key.
  - Incoming packets look up the session key by source IP in O(1) time, avoiding repetitive decryption attempts and saving CPU cycles during active multi-user group chats.

---

## 3. Architecture & Critical Bug Fixes

### Unified Listening & Outbound Socket (Key Exchange Bug)
* **Problem in v1.0.0**: HopChat bound one socket for the inbound listener (port `9878`) and spawned a separate, ephemeral outbound socket for sending data. When a local user sent a key exchange packet to a peer, the peer received the packet from the sender's ephemeral port, not port `9878`. The peer replied to the source address (the ephemeral port), which was no longer listening, causing all key exchange responses to be silently dropped by the OS.
* **Solution in v2.0.0**:
  - Fully unified the network model. The application binds a single `UdpSocket` at startup (falling back dynamically if the preferred port is taken).
  - This single socket is cloned via `Arc` and shared for both listening to incoming broadcasts and sending outbound packets.
  - This guarantees that all key exchange packets leave from the listener port and return to the listener port, fixing a critical bug that blocked chat handshakes.

### Discovery Loop Ghost Self-Registration
* **Problem in v1.0.0**: The local host tried to filter out its own discovery broadcasts by matching the packet's source IP with its own local IP. If local IP detection resolved to `127.0.0.1` or if the network adapter IP changed, the filter failed, causing the user to register *themselves* in their own peer directory.
* **Solution in v2.0.0**:
  - Added a secondary check that filters out discovery packets matching the host's own username.
  - Removed outdated debug printing comments that polluted the TUI standard output and corrupted rendering.

### TUI Input Buffer Restoration
* **Problem in v1.0.0**: When a key exchange handshake occurred in the background, it interrupted the terminal event loop, sometimes wiping out the user's half-typed input text in the chat input bar.
* **Solution in v2.0.0**:
  - Decoupled key exchange state transitions from the TUI renderer loop.
  - Half-typed messages are preserved in the input state buffer throughout key exchange events.

### General Code Quality & Documentation
* **Problem in v1.0.0**: Source code comments in `main.rs` referenced "TCP Server" setups despite HopChat being a UDP-only application. Version indicators in the code and renderer were frozen at `v1.0.0`.
* **Solution in v2.0.0**:
  - Corrected network protocol descriptions.
  - Updated all version numbers across `Cargo.toml`, `src/main.rs`, and `src/tui/renderer.rs` to reflect `v2.0.0`.
