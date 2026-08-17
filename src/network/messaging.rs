// =============================================================================
// HOPCHAT — Network Module: Reliable UDP Messaging
// =============================================================================
//
// Sends and receives structured chat messages over UDP.
// Packets are formatted as: HOPCHAT_MSG|<hex_ciphertext>
// Acknowledgements are: HOPCHAT_ACK|id
// Key Exchanges are: HOPCHAT_KEY|username|x25519_pub|ed25519_pub|signature
// Discovery echoes: HOPCHAT|username|ip|port|timestamp|ed25519_pub|signature

use crate::chat::messages::ChatMessage;
use crate::crypto::key_exchange::X25519KeyPair;
use crate::network::peer_registry::{Peer, PeerRegistry};
use crate::network::discovery::sanitize_network_username;
use crate::user::identity::LocalIdentity;
use crate::user::trust_db::TrustDb;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex};
use tokio::time::timeout;

/// Chat history: maps peer username to a ring buffer of messages.
/// VecDeque gives O(1) pop_front for history pruning (vs Vec's O(N) remove(0)).
pub type ChatHistory = Arc<Mutex<HashMap<String, VecDeque<ChatMessage>>>>;

/// Maps message IDs to their ACK notifier channels.
pub type AckRegistry = Arc<Mutex<HashMap<u64, oneshot::Sender<()>>>>;

/// Per-peer session state: symmetric key + replay protection window.
pub struct PeerSession {
    pub key: [u8; 32],
    pub replay: ReplayWindow,
}

/// Maps peer username to their negotiated session (key + replay state).
pub type PeerKeyRegistry = Arc<Mutex<HashMap<String, PeerSession>>>;

/// Persistent TOFU trust database (loaded from disk).
pub type TrustRegistry = Arc<Mutex<TrustDb>>;

// =============================================================================
// Sliding Window Replay Protection
// =============================================================================

/// 64-bit sliding window for per-peer replay detection.
///
/// Tracks the highest seen message ID and a 64-bit bitmap of the preceding
/// 64 IDs. O(1) check, O(1) memory per peer, no unbounded growth.
pub struct ReplayWindow {
    max_id: u64,
    bitmap: u64,
    initialized: bool,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self { max_id: 0, bitmap: 0, initialized: false }
    }

    /// Returns true if this ID is new (not a replay). Updates state on accept.
    pub fn check_and_accept(&mut self, id: u64) -> bool {
        if !self.initialized {
            self.max_id = id;
            self.initialized = true;
            return true;
        }

        if id == self.max_id {
            return false; // Exact duplicate
        }

        if id > self.max_id {
            // New highest ID — shift window forward
            let shift = id - self.max_id;
            if shift < 64 {
                self.bitmap = self.bitmap.checked_shl(shift as u32).unwrap_or(0);
                // Mark the old max_id's position in the bitmap
                self.bitmap |= 1u64 << (shift - 1);
            } else {
                self.bitmap = 0; // Window fully shifted out
            }
            self.max_id = id;
            true
        } else {
            // id < max_id — check if within the 64-entry window
            let age = self.max_id - id;
            if age > 64 {
                return false; // Too old — outside window
            }
            let bit = 1u64 << (age - 1);
            if self.bitmap & bit != 0 {
                return false; // Already seen
            }
            self.bitmap |= bit;
            true
        }
    }
}

// =============================================================================
// Rate Limiting
// =============================================================================

/// Integer-based token bucket for DoS mitigation.
/// Uses millitokens (×1000) for sub-token accumulation without floating-point.
struct TokenBucket {
    tokens_milli: u64,
    capacity_milli: u64,
    refill_per_us: u64,
    last_update: Instant,
}

impl TokenBucket {
    fn new(max_tokens: u64, refill_per_second: u64) -> Self {
        Self {
            tokens_milli: max_tokens * 1000,
            capacity_milli: max_tokens * 1000,
            refill_per_us: (refill_per_second * 1000).max(1),
            last_update: Instant::now(),
        }
    }

    fn try_consume(&mut self, now: Instant) -> bool {
        let elapsed_us = now.duration_since(self.last_update).as_micros() as u64;
        self.last_update = now;
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

// =============================================================================
// Packet Sending
// =============================================================================

/// Sends a raw UDP packet (fire-and-forget).
pub async fn send_raw_packet(
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    packet_str: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    socket.send_to(packet_str.as_bytes(), &peer_addr).await?;
    Ok(())
}

/// Sends a structured chat message with up to 3 retries waiting for ACK.
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
            reg.remove(&message.id);
            reg.insert(message.id, tx);
        }

        if let Err(e) = send_raw_packet(&socket, peer_addr, &packet_str).await {
            eprintln!("[ERROR] Failed to send UDP packet: {}", e);
            {
                let mut reg = ack_registry.lock().await;
                reg.remove(&message.id);
            }
            if attempt >= retry_limit {
                return Err("Failed to deliver message: send_raw_packet failed after 3 attempts.".into());
            }
            continue;
        }

        match timeout(Duration::from_millis(500), rx).await {
            Ok(Ok(_)) => return Ok(()),
            _ => {
                {
                    let mut reg = ack_registry.lock().await;
                    reg.remove(&message.id);
                }
                if attempt >= retry_limit {
                    return Err("Failed to deliver message: No ACK received after 3 attempts.".into());
                }
            }
        }
    }
}

// =============================================================================
// Discovery Packet Helpers
// =============================================================================

/// Returns the current Unix timestamp in seconds.
fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Creates a signed discovery packet.
/// Format: HOPCHAT|username|ip|port|timestamp|ed25519_pub|signature
pub fn create_signed_discovery(
    username: &str,
    ip: &str,
    port: u16,
    identity: &LocalIdentity,
) -> String {
    let timestamp = unix_timestamp();
    let payload = format!("HOPCHAT|{}|{}|{}|{}", username, ip, port, timestamp);
    let sig = identity.sign_payload(payload.as_bytes());
    let ed_pub = identity.public_key_hex();
    format!("{}|{}|{}", payload, ed_pub, sig)
}

/// Parses and optionally verifies a discovery packet. Accepts both:
/// - Old format (4 fields): HOPCHAT|username|ip|port (no verification)
/// - New format (7 fields): HOPCHAT|username|ip|port|timestamp|ed25519_pub|sig
///
/// Returns (username, source_ip, port) on success.
pub fn parse_discovery_packet(
    packet_str: &str,
    src_ip: &str,
) -> Option<(String, String, u16)> {
    let parts: Vec<&str> = packet_str.split('|').collect();

    if parts.len() == 7 && parts[0] == "HOPCHAT" {
        // New signed format
        let username = sanitize_network_username(parts[1])?;
        let port: u16 = parts[3].parse().ok()?;
        let timestamp: u64 = parts[4].parse().ok()?;
        let ed25519_pub = parts[5];
        let sig_hex = parts[6];

        // Reject packets older than 30 seconds (replay protection)
        let now = unix_timestamp();
        let age = if now >= timestamp { now - timestamp } else { timestamp - now };
        if age > 30 {
            return None;
        }

        // Verify signature over the unsigned portion
        let payload = format!("HOPCHAT|{}|{}|{}|{}", parts[1], parts[2], parts[3], parts[4]);
        if !LocalIdentity::verify_signature(ed25519_pub, payload.as_bytes(), sig_hex) {
            return None;
        }

        // Trust source IP, not payload IP
        Some((username, src_ip.to_string(), port))
    } else if parts.len() == 4 && parts[0] == "HOPCHAT" {
        // Legacy unsigned format — accept for backward compatibility
        let username = sanitize_network_username(parts[1])?;
        let port: u16 = parts[3].parse().ok()?;
        Some((username, src_ip.to_string(), port))
    } else {
        None
    }
}

// =============================================================================
// Main Listener
// =============================================================================

/// Listens for incoming UDP packets: chat messages, ACKs, key exchanges,
/// and discovery echoes. Uses the shared socket for both receive and send.
pub async fn listen_for_messages(
    socket: Arc<UdpSocket>,
    our_username: String,
    history: ChatHistory,
    ack_registry: AckRegistry,
    peer_keys: PeerKeyRegistry,
    local_keypair: Arc<X25519KeyPair>,
    local_identity: Arc<LocalIdentity>,
    peer_registry: PeerRegistry,
    trust_db: TrustRegistry,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Rate limiting state
    let mut rate_limits: HashMap<IpAddr, TokenBucket> = HashMap::new();
    let mut rate_limit_order: VecDeque<IpAddr> = VecDeque::new();
    const RATE_LIMIT_CAP: usize = 4096;

    // IP-to-username routing cache for O(1) message decryption
    let mut ip_to_username: HashMap<IpAddr, String> = HashMap::new();
    let mut ip_cache_order: VecDeque<IpAddr> = VecDeque::new();
    const IP_CACHE_CAP: usize = 1024;

    // Our own discovery info for echo responses
    let our_ip = crate::get_local_ip();
    let our_chat_port = socket.local_addr().map(|a| a.port()).unwrap_or(crate::PREFERRED_CHAT_PORT);

    let mut buf = [0u8; 4096];
    loop {
        if let Ok((len, src_addr)) = socket.recv_from(&mut buf).await {
            let now = Instant::now();
            let ip = src_addr.ip();

            // --- Rate Limiting ---
            if !rate_limits.contains_key(&ip) {
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
                continue; // Drop: rate limit exceeded
            }

            if let Ok(text) = std::str::from_utf8(&buf[..len]) {
                let packet_str = text.trim();

                // ==========================================================
                // HOPCHAT Discovery Packets (on chat port)
                // ==========================================================
                if packet_str.starts_with("HOPCHAT|") && !packet_str.starts_with("HOPCHAT_") {
                    let src_ip_str = src_addr.ip().to_string();
                    if let Some((peer_username, peer_ip, peer_port)) =
                        parse_discovery_packet(packet_str, &src_ip_str)
                    {
                        if peer_username != our_username {
                            // Register/update peer
                            {
                                let mut reg = peer_registry.lock().await;
                                if reg.len() >= 1000 && !reg.contains_key(&peer_username) {
                                    continue;
                                }
                                let is_new = !reg.contains_key(&peer_username);
                                if let Some(existing) = reg.get_mut(&peer_username) {
                                    existing.last_seen = tokio::time::Instant::now();
                                    existing.ip = peer_ip.clone();
                                    existing.port = peer_port;
                                } else {
                                    reg.insert(peer_username.clone(), Peer {
                                        username: peer_username.clone(),
                                        ip: peer_ip.clone(),
                                        port: peer_port,
                                        hostname: None,
                                        last_seen: tokio::time::Instant::now(),
                                    });
                                }
                                drop(reg);
                                if is_new {
                                    crate::network::peer_registry::resolve_hostname(
                                        peer_registry.clone(), peer_username.clone(), peer_ip.clone(),
                                    );
                                }
                            }

                            // Echo back our signed discovery + key exchange
                            {
                                let echo = create_signed_discovery(
                                    &our_username, &our_ip, our_chat_port, &local_identity,
                                );
                                let _ = socket.send_to(echo.as_bytes(), &src_addr).await;
                                let peer_chat = format!("{}:{}", peer_ip, crate::PREFERRED_CHAT_PORT);
                                let _ = socket.send_to(echo.as_bytes(), &peer_chat).await;

                                // Key exchange
                                let pub_x25519 = local_keypair.public_key_hex();
                                let pub_ed25519 = local_identity.public_key_hex();
                                let sig = local_identity.sign_payload(pub_x25519.as_bytes());
                                let key_payload = format!(
                                    "HOPCHAT_KEY|{}|{}|{}|{}",
                                    our_username, pub_x25519, pub_ed25519, sig
                                );
                                let _ = socket.send_to(key_payload.as_bytes(), &src_addr).await;
                                let _ = socket.send_to(key_payload.as_bytes(), &peer_chat).await;
                            }
                        }
                    }

                // ==========================================================
                // HOPCHAT_ACK
                // ==========================================================
                } else if packet_str.starts_with("HOPCHAT_ACK|") {
                    let parts: Vec<&str> = packet_str.split('|').collect();
                    if parts.len() == 2 {
                        if let Ok(ack_id) = parts[1].parse::<u64>() {
                            let mut reg = ack_registry.lock().await;
                            if let Some(tx) = reg.remove(&ack_id) {
                                let _ = tx.send(());
                            }
                        }
                    }

                // ==========================================================
                // HOPCHAT_KEY — Key Exchange
                // ==========================================================
                } else if packet_str.starts_with("HOPCHAT_KEY|") {
                    let parts: Vec<&str> = packet_str.split('|').collect();
                    if parts.len() == 5 {
                        let sender_username = match sanitize_network_username(parts[1]) {
                            Some(u) => u,
                            None => continue,
                        };
                        let sender_x25519_hex = parts[2];
                        let sender_ed25519_hex = parts[3];
                        let sender_signature = parts[4];

                        if sender_username != our_username {
                            // TOFU check via persistent trust database
                            {
                                let mut db = trust_db.lock().await;
                                if !db.verify_or_pin(&sender_username, sender_ed25519_hex) {
                                    continue; // Identity mismatch — drop
                                }
                            }

                            // Verify Ed25519 signature over the X25519 public key
                            if LocalIdentity::verify_signature(
                                sender_ed25519_hex,
                                sender_x25519_hex.as_bytes(),
                                sender_signature,
                            ) {
                                if let Ok(derived_key) = local_keypair.derive_session_key(sender_x25519_hex) {
                                    let mut keys_lock = peer_keys.lock().await;
                                    let already_had_key = keys_lock.contains_key(&sender_username);
                                    keys_lock.insert(sender_username.clone(), PeerSession {
                                        key: derived_key,
                                        replay: ReplayWindow::new(),
                                    });

                                    // Update IP cache
                                    if !ip_to_username.contains_key(&ip) {
                                        while ip_cache_order.len() >= IP_CACHE_CAP {
                                            if let Some(evict) = ip_cache_order.pop_front() {
                                                ip_to_username.remove(&evict);
                                            }
                                        }
                                        ip_cache_order.push_back(ip);
                                    }
                                    ip_to_username.insert(ip, sender_username.clone());

                                    drop(keys_lock);

                                    // Register peer
                                    {
                                        let mut reg = peer_registry.lock().await;
                                        let is_new = !reg.contains_key(&sender_username);
                                        let peer_ip = src_addr.ip().to_string();
                                        reg.insert(sender_username.clone(), Peer {
                                            username: sender_username.clone(),
                                            ip: peer_ip.clone(),
                                            port: crate::PREFERRED_CHAT_PORT,
                                            hostname: None,
                                            last_seen: tokio::time::Instant::now(),
                                        });
                                        drop(reg);
                                        if is_new {
                                            crate::network::peer_registry::resolve_hostname(
                                                peer_registry.clone(), sender_username.clone(), peer_ip,
                                            );
                                        }
                                    }

                                    // Send our key back to complete the handshake
                                    if !already_had_key {
                                        let pub_x25519 = local_keypair.public_key_hex();
                                        let pub_ed25519 = local_identity.public_key_hex();
                                        let sig = local_identity.sign_payload(pub_x25519.as_bytes());
                                        let handshake = format!(
                                            "HOPCHAT_KEY|{}|{}|{}|{}",
                                            our_username, pub_x25519, pub_ed25519, sig
                                        );
                                        let _ = socket.send_to(handshake.as_bytes(), &src_addr).await;
                                    }
                                }
                            } else {
                                eprintln!("[SECURITY] Rejected invalid Ed25519 signature from {}", src_addr);
                            }
                        }
                    }

                // ==========================================================
                // HOPCHAT_MSG — Encrypted Chat Message
                // ==========================================================
                } else if packet_str.starts_with("HOPCHAT_MSG|") {
                    let ciphertext_hex = &packet_str["HOPCHAT_MSG|".len()..];

                    // Length validation
                    if ciphertext_hex.len() % 2 != 0 || ciphertext_hex.len() < 32 || ciphertext_hex.len() > 8192 {
                        continue;
                    }

                    let mut decrypted_msg = None;
                    let mut matched_username = None;

                    {
                        let keys_lock = peer_keys.lock().await;

                        // O(1) fast path: IP cache
                        if let Some(username) = ip_to_username.get(&ip) {
                            if let Some(session) = keys_lock.get(username) {
                                if let Some(msg) = ChatMessage::from_packet_string(packet_str, &session.key) {
                                    decrypted_msg = Some(msg);
                                    matched_username = Some(username.clone());
                                }
                            }
                        }

                        // O(N) slow path: trial decryption
                        if decrypted_msg.is_none() {
                            for (peer_username, session) in keys_lock.iter() {
                                if let Some(msg) = ChatMessage::from_packet_string(packet_str, &session.key) {
                                    decrypted_msg = Some(msg);
                                    matched_username = Some(peer_username.clone());
                                    break;
                                }
                                tokio::task::yield_now().await;
                            }
                        }
                    }

                    // Update IP cache
                    if let Some(ref username) = matched_username {
                        if !ip_to_username.contains_key(&ip) {
                            while ip_cache_order.len() >= IP_CACHE_CAP {
                                if let Some(evict) = ip_cache_order.pop_front() {
                                    ip_to_username.remove(&evict);
                                }
                            }
                            ip_cache_order.push_back(ip);
                        }
                        ip_to_username.insert(ip, username.clone());
                    }

                    if let (Some(msg), Some(peer_username)) = (decrypted_msg, matched_username) {
                        let msg_id = msg.id;

                        // Send ACK
                        let ack = format!("HOPCHAT_ACK|{}", msg_id);
                        let _ = socket.send_to(ack.as_bytes(), &src_addr).await;

                        // Refresh peer last_seen
                        {
                            let mut reg = peer_registry.lock().await;
                            if let Some(peer) = reg.get_mut(&peer_username) {
                                peer.last_seen = tokio::time::Instant::now();
                            }
                        }

                        // Sliding window replay check (per-peer)
                        let is_new = {
                            let mut keys_lock = peer_keys.lock().await;
                            if let Some(session) = keys_lock.get_mut(&peer_username) {
                                session.replay.check_and_accept(msg_id)
                            } else {
                                false
                            }
                        };

                        if is_new {
                            let mut history_lock = history.lock().await;
                            let list = history_lock
                                .entry(peer_username)
                                .or_insert_with(VecDeque::new);
                            list.push_back(msg);
                            if list.len() > 1000 {
                                list.pop_front();
                            }
                        }
                    }
                }
            }
        }
    }
}
