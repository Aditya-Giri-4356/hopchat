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
use std::collections::{HashMap, VecDeque};
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
/// A simple rolling cache to detect and drop duplicate arriving messages.
pub type DedupCache = Arc<Mutex<VecDeque<u64>>>;
/// A thread-safe registry mapping peer username to their negotiated 32-byte symmetric key.
pub type PeerKeyRegistry = Arc<Mutex<HashMap<String, [u8; 32]>>>;

/// A simple struct for tracking IP UDP burst rate limits
pub struct TokenBucket {
    pub tokens: f32,
    pub last_update: Instant,
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

/// Sends a structured chat message and retries up to 3 times if no ACK is received.
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
            reg.insert(message.id, tx);
        }

        // Send the raw packet
        if let Err(e) = send_raw_packet(&socket, peer_addr, &packet_str).await {
            eprintln!("Failed to send UDP packet: {}", e);
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // DoS Mitigation: Map of IP to TokenBucket (Allows 20 packets/sec burst)
    let mut rate_limits: HashMap<IpAddr, TokenBucket> = HashMap::new();
    let mut ip_to_username: HashMap<IpAddr, String> = HashMap::new();
    let mut pinned_identities: HashMap<String, String> = HashMap::new();
    let max_tokens = 20.0;
    let refill_rate = 5.0; // Tokens per second
    
    let mut buf = [0u8; 4096]; // HopChat packets are well under 4KB
    loop {
        if let Ok((len, src_addr)) = socket.recv_from(&mut buf).await {
            let now = Instant::now();
            let ip = src_addr.ip();

            // --- TOKEN BUCKET RATE LIMITER ---
            let bucket = rate_limits.entry(ip).or_insert(TokenBucket {
                tokens: max_tokens,
                last_update: now,
            });

            let elapsed = now.duration_since(bucket.last_update).as_secs_f32();
            bucket.tokens = f32::min(max_tokens, bucket.tokens + elapsed * refill_rate);
            bucket.last_update = now;

            if bucket.tokens < 1.0 {
                // Drop packet: Rate limit exceeded
                continue;
            }
            bucket.tokens -= 1.0;
            // ---------------------------------

            if let Ok(text) = std::str::from_utf8(&buf[..len]) {
                let packet_str = text.trim();

                // Handle discovery packets that arrive on the chat socket
                // (sent by /connect which targets both ports)
                if packet_str.starts_with("HOPCHAT|") && !packet_str.starts_with("HOPCHAT_") {
                    let parts: Vec<&str> = packet_str.split('|').collect();
                    if parts.len() == 4 && parts[0] == "HOPCHAT" {
                        let peer_username = parts[1].to_string();
                        let peer_ip = parts[2].to_string();
                        if let Ok(peer_port) = parts[3].parse::<u16>() {
                            if peer_username != our_username {
                                let mut reg = peer_registry.lock().await;
                                
                                // DoS Protection: Cap the maximum number of tracked peers
                                if reg.len() >= 1000 && !reg.contains_key(&peer_username) {
                                    continue; // Drop new peer discovery if registry is full
                                }

                                // MITM/Hijack Protection: Do not allow unauthenticated UDP 
                                // discovery packets to hijack the routing of a known, pinned peer.
                                // The IP/Port should only be updated if a cryptographically signed 
                                // Key Exchange (HOPCHAT_KEY) validates the new IP.
                                if let Some(existing_peer) = reg.get_mut(&peer_username) {
                                    // Only update last_seen, DO NOT update IP/Port from unauthenticated broadcast
                                    existing_peer.last_seen = tokio::time::Instant::now();
                                } else {
                                    // New peer, add to registry temporarily
                                    let peer = Peer {
                                        username: peer_username.clone(),
                                        ip: peer_ip,
                                        port: peer_port,
                                        last_seen: tokio::time::Instant::now(),
                                    };
                                    reg.insert(peer_username, peer);
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
                        let sender_username = parts[1].to_string();
                        let sender_x25519_hex = parts[2];
                        let sender_ed25519_hex = parts[3];
                        let sender_signature = parts[4];

                        if sender_username != our_username {
                            // Check if the identity is pinned, and if it matches
                            if let Some(pinned_ed25519) = pinned_identities.get(&sender_username) {
                                if pinned_ed25519 != sender_ed25519_hex {
                                    eprintln!("CRITICAL SECURITY ALERT: Peer '{}' presented a different identity key! Possible MITM attack. Packet dropped.", sender_username);
                                    continue; // Drop out prematurely, do not derive key
                                }
                            } else {
                                // First time seeing this peer, pin their identity (TOFU)
                                pinned_identities.insert(sender_username.clone(), sender_ed25519_hex.to_string());
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
                                    ip_to_username.insert(ip, sender_username.clone());

                                    // Register/refresh peer in the registry so they appear in FRIENDS.
                                    // This is critical for /connect on iSH where discovery broadcasts
                                    // don't work — the key exchange is the only signal we get.
                                    {
                                        let mut reg = peer_registry.lock().await;
                                        reg.insert(sender_username.clone(), Peer {
                                            username: sender_username.clone(),
                                            ip: src_addr.ip().to_string(),
                                            port: src_addr.port(),
                                            last_seen: tokio::time::Instant::now(),
                                        });
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

                    // 3. Update the IP cache outside the lock if we found a match
                    if let Some(ref username) = matched_username {
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

                        // Check deduplication cache
                        let mut cache = dedup_cache.lock().await;
                        if !cache.contains(&msg_id) {
                            // Add to cache
                            if cache.len() >= 500 {
                                cache.pop_front();
                            }
                            cache.push_back(msg_id);

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
