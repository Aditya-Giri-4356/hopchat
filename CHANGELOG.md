# Changelog — HopChat v2.0.0

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
