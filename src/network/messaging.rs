// =============================================================================
// HOPCHAT — Network Module: Reliable UDP Messaging
// =============================================================================
//
// Sends and receives structured chat messages over UDP.
// Packets are formatted as: HOPCHAT_MSG|id|sender|receiver|timestamp|content
// Acknowledgements are: HOPCHAT_ACK|id
// Key Exchanges are: HOPCHAT_KEY|username|public_key_hex

use crate::chat::messages::ChatMessage;
use crate::crypto::key_exchange::X25519KeyPair;
use crate::network::peer_registry::{Peer, PeerRegistry};
use crate::network::discovery::sanitize_network_username;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex};
use tokio::time::timeout;
use crate::user::identity::LocalIdentity;

/// A thread-safe, shared history of chat messages, keyed by peer username.
pub type ChatHistory = Arc<Mutex<HashMap<String, Vec<ChatMessage>>>>;
/// A thread-safe registry mapping message IDs to their success notifiers.
pub type AckRegistry = Arc<Mutex<HashMap<u64, oneshot::Sender<()>>>>;
/// [CONN-7] A HashSet-based dedup cache. HashSet::contains is O(1) vs VecDeque's O(n).
/// When the set reaches capacity (500), it is cleared entirely. This trade-off is
/// acceptable because the 500-entry window is large enough that clearing at capacity
/// does not cause duplicate delivery in normal usage — the only risk is a brief
/// window where a retransmitted packet from the exact moment of clearing could be
/// accepted twice, which is harmless for chat messages.
pub type DedupCache = Arc<Mutex<HashSet<u64>>>;
/// A thread-safe registry mapping peer username to their negotiated 32-byte symmetric key.
pub type PeerKeyRegistry = Arc<Mutex<HashMap<String, [u8; 32]>>>;
/// [CONN-4] TOFU registry: maps peer username to their pinned Ed25519 public key hex.
/// Stored on AppState so it persists for the entire process lifetime.
pub type TofuRegistry = Arc<Mutex<HashMap<String, String>>>;

/// [SEC-5] Integer-based token bucket for rate limiting.
/// Uses millitokens (×1000) to allow sub-token accumulation without floating-point
/// imprecision. All arithmetic is exact integer math.
pub struct TokenBucket {
    tokens_milli: u64,      // current tokens × 1000
    capacity_milli: u64,    // max tokens × 1000
    refill_per_us: u64,     // millitokens added per microsecond
    last_update: Instant,
}

impl TokenBucket {
    fn new(max_tokens: u64, refill_per_second: u64) -> Self {
        Self {
            tokens_milli: max_tokens * 1000,
            capacity_milli: max_tokens * 1000,
            // refill_per_second tokens/sec = refill_per_second * 1000 millitokens/sec
            // = refill_per_second * 1000 / 1_000_000 millitokens/us
            // To avoid rounding to zero, we use: (refill_per_second * 1000) / 1_000_000
            // which simplifies to refill_per_second / 1000. But that rounds to 0 for
            // small values. Instead, store as millitokens_per_second and compute in try_consume.
            refill_per_us: (refill_per_second * 1000).max(1),
            last_update: Instant::now(),
        }
    }

    fn try_consume(&mut self, now: Instant) -> bool {
        let elapsed_us = now.duration_since(self.last_update).as_micros() as u64;
        self.last_update = now;
        // refill_per_us is actually millitokens per second, so:
        // added = elapsed_us * refill_per_us / 1_000_000
        let added = elapsed_us.saturating_mul(self.refill_per_us) / 1_000_000;
        self.tokens_milli = self.tokens_milli.saturating_add(added).min(self.capacity_milli);
        if self.tokens_milli >= 1000 {
            self.tokens_milli -= 1000;
            true
        } else {
            false
        }
    }
}

/// Sends a raw UDP packet (fire-and-forget).
pub async fn send_raw_packet(
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    packet_str: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    socket.send_to(packet_str.as_bytes(), &peer_addr).await?;
    Ok(())
}

/// [CONN-8] Sends a structured chat message and retries up to 3 times if no ACK is received.
/// On each retry iteration, the stale sender is removed from the registry before inserting
/// a fresh one, preventing orphaned senders from resolving the wrong rx.
pub async fn send_message_with_retry(
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    message: &ChatMessage,
    ack_registry: AckRegistry,
    key: [u8; 32],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let packet_str = message.to_packet_string(&key)?;

    let retry_limit = 3;
    let mut attempt = 0;

    loop {
        attempt += 1;
        
        let (tx, rx) = oneshot::channel();
        {
            let mut reg = ack_registry.lock().await;
            // [CONN-8] Remove any stale sender from a previous retry before inserting fresh
            reg.remove(&message.id);
            reg.insert(message.id, tx);
        }

        // Send the raw packet
        if let Err(e) = send_raw_packet(&socket, peer_addr, &packet_str).await {
            eprintln!("Failed to send UDP packet: {}", e);
            // [CONN-8] On send failure, remove the just-inserted sender immediately
            // so the registry is never left with a sender whose packet was never sent
            {
                let mut reg = ack_registry.lock().await;
                reg.remove(&message.id);
            }
            if attempt >= retry_limit {
                return Err("Failed to deliver message: send_raw_packet failed after 3 attempts.".into());
            }
            continue;
        }

        // Wait up to 500ms for the ACK signal
        match timeout(Duration::from_millis(500), rx).await {
            Ok(Ok(_)) => {
                // ACK received successfully
                return Ok(());
            }
            _ => {
                // Timeout or channel dropped, meaning no ACK was received.
                // We need to clean up the unused channel sender if it timed out.
                {
                    let mut reg = ack_registry.lock().await;
                    reg.remove(&message.id);
                }

                if attempt >= retry_limit {
                    // Maximum retries reached
                    return Err("Failed to deliver message: No ACK received after 3 attempts.".into());
                }
            }
        }
    }
}

/// Listens for incoming UDP chat messages, ACKs, Key exchanges, and discovery packets.
/// Uses the shared socket for both receiving and sending (ACKs, key exchange responses).
/// Also handles HOPCHAT discovery packets that arrive on the chat port (from /connect).
pub async fn listen_for_messages(
    socket: Arc<UdpSocket>,
    our_username: String,
    history: ChatHistory,
    ack_registry: AckRegistry,
    dedup_cache: DedupCache,
    peer_keys: PeerKeyRegistry,
    local_keypair: Arc<X25519KeyPair>,
    local_identity: Arc<LocalIdentity>,
    peer_registry: PeerRegistry,
    tofu_registry: TofuRegistry,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // [SEC-5] DoS Mitigation: Integer-based token bucket (20 packets/sec burst, 5/sec refill)
    let mut rate_limits: HashMap<IpAddr, TokenBucket> = HashMap::new();
    // [CONN-6] Bounded eviction queue for rate_limits — cap at 4096 entries
    let mut rate_limit_order: VecDeque<IpAddr> = VecDeque::new();
    const RATE_LIMIT_CAP: usize = 4096;

    // [CONN-5] IP-to-username routing cache with bounded LRU eviction — cap at 1024 entries
    let mut ip_to_username: HashMap<IpAddr, String> = HashMap::new();
    let mut ip_cache_order: VecDeque<IpAddr> = VecDeque::new();
    const IP_CACHE_CAP: usize = 1024;
    
    // Compute our own discovery info for echo responses
    // MUST use get_local_ip() — local_ip_address::local_ip() returns 127.0.0.1 on iSH
    let our_ip = crate::get_local_ip();
    let our_chat_port = socket.local_addr().map(|a| a.port()).unwrap_or(crate::PREFERRED_CHAT_PORT);

    let mut buf = [0u8; 4096]; // HopChat packets are well under 4KB
    loop {
        if let Ok((len, src_addr)) = socket.recv_from(&mut buf).await {
            let now = Instant::now();
            let ip = src_addr.ip();

            // --- [SEC-5] INTEGER TOKEN BUCKET RATE LIMITER ---
            // [CONN-6] Bounded rate_limits map with LRU eviction
            if !rate_limits.contains_key(&ip) {
                // New IP — enforce capacity before inserting
                while rate_limit_order.len() >= RATE_LIMIT_CAP {
                    if let Some(evict_ip) = rate_limit_order.pop_front() {
                        rate_limits.remove(&evict_ip);
                    }
                }
                rate_limits.insert(ip, TokenBucket::new(200, 100));
                rate_limit_order.push_back(ip);
            }

            let bucket = rate_limits.get_mut(&ip).unwrap();
            if !bucket.try_consume(now) {
                // Drop packet: Rate limit exceeded
                continue;
            }
            // ---------------------------------

            if let Ok(text) = std::str::from_utf8(&buf[..len]) {
                let packet_str = text.trim();

                // Handle discovery packets that arrive on the chat socket
                if packet_str.starts_with("HOPCHAT|") && !packet_str.starts_with("HOPCHAT_") {
                    let parts: Vec<&str> = packet_str.split('|').collect();
                    if parts.len() == 4 && parts[0] == "HOPCHAT" {
                        let peer_username = match sanitize_network_username(parts[1]) {
                            Some(u) => u,
                            None => continue,
                        };
                        
                        // Trust actual packet source, not payload IP
                        let peer_ip = src_addr.ip().to_string();
                        if let Ok(peer_port) = parts[3].parse::<u16>() {
                            if peer_username != our_username {
                                let mut reg = peer_registry.lock().await;
                                
                                if reg.len() >= 1000 && !reg.contains_key(&peer_username) {
                                    continue;
                                }

                                let is_new = !reg.contains_key(&peer_username);

                                if let Some(existing_peer) = reg.get_mut(&peer_username) {
                                    existing_peer.last_seen = tokio::time::Instant::now();
                                    existing_peer.ip = peer_ip.clone();
                                    existing_peer.port = peer_port;
                                } else {
                                    let peer = Peer {
                                        username: peer_username.clone(),
                                        ip: peer_ip.clone(),
                                        port: peer_port,
                                        hostname: None,
                                        last_seen: tokio::time::Instant::now(),
                                    };
                                    reg.insert(peer_username.clone(), peer);
                                }
                                drop(reg);

                                if is_new {
                                    crate::network::peer_registry::resolve_hostname(
                                        peer_registry.clone(), peer_username.clone(), peer_ip.clone(),
                                    );
                                }

                                // ============================================================
                                // DISCOVERY ECHO — the critical missing piece.
                                // When we receive a discovery packet from a peer, echo
                                // back our own discovery AND key exchange payloads. Without
                                // this, the sender has no way to know WE exist (especially
                                // on iSH where broadcast is broken).
                                // ============================================================
                                {
                                    // Echo our discovery payload
                                    let echo_discovery = format!(
                                        "HOPCHAT|{}|{}|{}",
                                        our_username, our_ip, our_chat_port
                                    );
                                    // Send to the actual src_addr (covers ephemeral ports)
                                    let _ = socket.send_to(echo_discovery.as_bytes(), &src_addr).await;
                                    // Also send to the peer's CHAT port (the canonical listener)
                                    let peer_chat_addr = format!("{}:{}", peer_ip, crate::PREFERRED_CHAT_PORT);
                                    let _ = socket.send_to(echo_discovery.as_bytes(), &peer_chat_addr).await;

                                    // Initiate key exchange immediately
                                    let pub_x25519 = local_keypair.public_key_hex();
                                    let pub_ed25519 = local_identity.public_key_hex();
                                    let sig = local_identity.sign_payload(pub_x25519.as_bytes());
                                    let key_payload = format!(
                                        "HOPCHAT_KEY|{}|{}|{}|{}",
                                        our_username, pub_x25519, pub_ed25519, sig
                                    );
                                    let _ = socket.send_to(key_payload.as_bytes(), &src_addr).await;
                                    let _ = socket.send_to(key_payload.as_bytes(), &peer_chat_addr).await;
                                }
                            }
                        }
                    }
                } else if packet_str.starts_with("HOPCHAT_ACK|") {
                    // Handle ACK receipt
                    let parts: Vec<&str> = packet_str.split('|').collect();
                    if parts.len() == 2 {
                        if let Ok(ack_id) = parts[1].parse::<u64>() {
                            let mut reg = ack_registry.lock().await;
                            if let Some(tx) = reg.remove(&ack_id) {
                                // Trigger the oneshot to inform `send_message_with_retry`
                                let _ = tx.send(());
                            }
                        }
                    }
                } else if packet_str.starts_with("HOPCHAT_KEY|") {
                    // Handle Key Exchange receipt + Identity Signature
                    // Format: HOPCHAT_KEY|username|x25519_pub|ed25519_pub|signature
                    let parts: Vec<&str> = packet_str.split('|').collect();
                    if parts.len() == 5 {
                        // [SEC-4] Sanitize network-provided username
                        let sender_username = match sanitize_network_username(parts[1]) {
                            Some(u) => u,
                            None => continue,
                        };
                        let sender_x25519_hex = parts[2];
                        let sender_ed25519_hex = parts[3];
                        let sender_signature = parts[4];

                        if sender_username != our_username {
                            // [CONN-4] Check TOFU registry (process-lifetime, not task-local)
                            {
                                let pinned = tofu_registry.lock().await;
                                if let Some(pinned_ed25519) = pinned.get(&sender_username) {
                                    if pinned_ed25519 != sender_ed25519_hex {
                                        eprintln!("CRITICAL SECURITY ALERT: Peer '{}' presented a different identity key! Possible MITM attack. Packet dropped.", sender_username);
                                        continue; // Drop out prematurely, do not derive key
                                    }
                                }
                            }
                            // Pin if first time (outside the lock scope above to avoid double-lock)
                            {
                                let mut pinned = tofu_registry.lock().await;
                                if !pinned.contains_key(&sender_username) {
                                    pinned.insert(sender_username.clone(), sender_ed25519_hex.to_string());
                                }
                            }

                            // Verify the identity signature to prevent spoofing
                            if LocalIdentity::verify_signature(
                                sender_ed25519_hex,
                                sender_x25519_hex.as_bytes(),
                                sender_signature,
                            ) {
                                if let Ok(derived_key) = local_keypair.derive_session_key(sender_x25519_hex) {
                                    // Save the derived 32-byte session key for XChaCha20Poly1305
                                    let mut keys_lock = peer_keys.lock().await;
                                    let already_had_key = keys_lock.contains_key(&sender_username);
                                    keys_lock.insert(sender_username.clone(), derived_key);

                                    // [CONN-5] Update IP-to-username cache with bounded eviction
                                    if !ip_to_username.contains_key(&ip) {
                                        while ip_cache_order.len() >= IP_CACHE_CAP {
                                            if let Some(evict_ip) = ip_cache_order.pop_front() {
                                                ip_to_username.remove(&evict_ip);
                                            }
                                        }
                                        ip_cache_order.push_back(ip);
                                    }
                                    ip_to_username.insert(ip, sender_username.clone());

                                    // Register/refresh peer in the registry so they appear in FRIENDS.
                                    // This is critical for /connect on iSH where discovery broadcasts
                                    // don't work — the key exchange is the only signal we get.
                                    {
                                        let mut reg = peer_registry.lock().await;
                                        let is_new = !reg.contains_key(&sender_username);
                                        let peer_ip = src_addr.ip().to_string();
                                        // Use the PREFERRED_CHAT_PORT, NOT src_addr.port().
                                        // src_addr.port() is the sender's ephemeral outbound port
                                        // (e.g. 49123) which will be dead by the time we try to
                                        // send a message. The chat listener is on PREFERRED_CHAT_PORT.
                                        let peer_port = crate::PREFERRED_CHAT_PORT;
                                        reg.insert(sender_username.clone(), Peer {
                                            username: sender_username.clone(),
                                            ip: peer_ip.clone(),
                                            port: peer_port,
                                            hostname: None,
                                            last_seen: tokio::time::Instant::now(),
                                        });
                                        drop(reg);
                                        if is_new {
                                            crate::network::peer_registry::resolve_hostname(peer_registry.clone(), sender_username.clone(), peer_ip);
                                        }
                                    }

                                    // Send our key back to complete the handshake if we didn't have theirs
                                    if !already_had_key {
                                        let pub_x25519 = local_keypair.public_key_hex();
                                        let pub_ed25519 = local_identity.public_key_hex();
                                        let sig = local_identity.sign_payload(pub_x25519.as_bytes());

                                        let handshake_packet = format!(
                                            "HOPCHAT_KEY|{}|{}|{}|{}",
                                            our_username, pub_x25519, pub_ed25519, sig
                                        );
                                        let _ = socket.send_to(handshake_packet.as_bytes(), &src_addr).await;
                                    }
                                }
                            } else {
                                // Invalid Identity Signature - Spoofing Attempt!
                                eprintln!("WARNING: Rejected invalid Ed25519 identity signature from {}", src_addr);
                            }
                        }
                    }
                } else if packet_str.starts_with("HOPCHAT_MSG|") {
                    // Handle Encrypted Message receipt (Masked Metadata)
                    // The payload format is just HOPCHAT_MSG|<hex_ciphertext>
                    let ciphertext_hex = &packet_str["HOPCHAT_MSG|".len()..];
                    
                    // Strict Length Bounds Validation (Cryptographic Downgrade Fix)
                    // A valid hex payload must be even in length, and realistically 
                    // at least 32 bytes long (nonce + tag + minimal ciphertext)
                    if ciphertext_hex.len() % 2 != 0 || ciphertext_hex.len() < 32 || ciphertext_hex.len() > 8192 {
                        eprintln!("SECURITY: Rejected malformed HOPCHAT_MSG payload (invalid length).");
                        continue;
                    }
                    
                    // We must determine WHO sent this since the sender is encrypted inside the payload.
                    // Use IP-to-Session Cache first for O(1) decryption
                    let mut decrypted_msg = None;
                    let mut matched_username = None;

                    // Scope the lock tightly to avoid cloning the massive HashMap on every packet
                    {
                        let keys_lock = peer_keys.lock().await;
                        
                        // 1. O(1) Fast Path: Try the IP-to-Username cache first
                        if let Some(username) = ip_to_username.get(&ip) {
                            if let Some(key) = keys_lock.get(username) {
                                if let Some(msg) = ChatMessage::from_packet_string(packet_str, key) {
                                    decrypted_msg = Some(msg);
                                    matched_username = Some(username.clone());
                                }
                            }
                        }

                        // 2. O(N) Slow Path: Trial Decryption (with yield to prevent CPU lockup)
                        if decrypted_msg.is_none() {
                            for (peer_username, key) in keys_lock.iter() {
                                if let Some(msg) = ChatMessage::from_packet_string(packet_str, key) {
                                    decrypted_msg = Some(msg);
                                    matched_username = Some(peer_username.clone());
                                    break;
                                }
                                // Yield control back to Tokio to prevent a malicious UDP flood from starving the event loop
                                tokio::task::yield_now().await; 
                            }
                        }
                    }

                    // 3. [CONN-5] Update the IP cache outside the lock if we found a match (bounded)
                    if let Some(ref username) = matched_username {
                        if !ip_to_username.contains_key(&ip) {
                            while ip_cache_order.len() >= IP_CACHE_CAP {
                                if let Some(evict_ip) = ip_cache_order.pop_front() {
                                    ip_to_username.remove(&evict_ip);
                                }
                            }
                            ip_cache_order.push_back(ip);
                        }
                        ip_to_username.insert(ip, username.clone());
                    }

                    if let (Some(msg), Some(peer_username)) = (decrypted_msg, matched_username) {
                        let msg_id = msg.id;
                        
                        // Send an ACK back to the sender
                        let ack_packet = format!("HOPCHAT_ACK|{}", msg_id);
                        let _ = socket.send_to(ack_packet.as_bytes(), &src_addr).await;

                        // Refresh last_seen so /connect peers don't get evicted
                        // by the 15-second cleanup task
                        {
                            let mut reg = peer_registry.lock().await;
                            if let Some(peer) = reg.get_mut(&peer_username) {
                                peer.last_seen = tokio::time::Instant::now();
                            }
                        }

                        // [CONN-7] Check deduplication cache (O(1) HashSet lookup)
                        let mut cache = dedup_cache.lock().await;
                        if !cache.contains(&msg_id) {
                            // [CONN-7] Clear at capacity instead of pop_front (HashSet has no ordering)
                            if cache.len() >= 500 {
                                cache.clear();
                            }
                            cache.insert(msg_id);

                            // Safe to add to chat history now
                            let mut history_lock = history.lock().await;
                            let list = history_lock
                                .entry(peer_username)
                                .or_insert_with(Vec::new);
                            list.push(msg);
                            if list.len() > 1000 {
                                list.remove(0);
                            }
                        }
                    }
                }
            }
        }
    }
}

// CHANGES:
// [CONN-4] pinned_identities moved out of this function into AppState as TofuRegistry.
//          Passed in as a parameter. Persists for process lifetime.
// [CONN-5] ip_to_username capped at 1024 entries with VecDeque-based LRU eviction.
// [CONN-6] rate_limits capped at 4096 entries with VecDeque-based LRU eviction.
//          Existing IPs update in-place without re-queuing.
// [CONN-7] DedupCache changed from VecDeque<u64> to HashSet<u64> for O(1) contains().
//          cache.clear() at capacity instead of pop_front.
// [CONN-8] send_message_with_retry: Remove stale sender before inserting fresh on each
//          retry. On send failure, immediately remove the just-inserted sender.
// [SEC-4] All network-provided usernames sanitized via sanitize_network_username().
// [SEC-5] TokenBucket replaced with integer microsecond accounting (millitokens).
//         No floating-point arithmetic in the rate limiter.
