// =============================================================================
// HOPCHAT — Network Module: UDP Peer Discovery
// =============================================================================
//
// Uses UDP broadcast to discover peers on the local network.
// Each device broadcasts its username, IP, and TCP port every 2 seconds.
// Discovered peers are added to a shared peer list.

use crate::network::peer_registry::{Peer, PeerRegistry};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use tokio::net::UdpSocket;
use tokio::time::{interval, Duration, Instant};

/// The UDP port used for peer discovery broadcasts.
pub const DISCOVERY_PORT: u16 = 9877;

/// Creates a UdpSocket configured for broadcast and port reuse.
/// [SEC-6] Uses proper error propagation instead of unwrap() on SocketAddr parse.
fn create_reuse_socket() -> Result<UdpSocket, std::io::Error> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    
    // Allow multiple instances on the same machine to bind to this port
    socket.set_reuse_address(true)?;
    
    #[cfg(not(target_os = "windows"))]
    socket.set_reuse_port(true)?;

    socket.set_broadcast(true)?;
    
    // Bind to all interfaces on the discovery port
    // [SEC-6] Proper error propagation instead of .unwrap()
    let addr: SocketAddr = format!("0.0.0.0:{}", DISCOVERY_PORT)
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    socket.bind(&addr.into())?;
    
    // Join the multicast group for LAN environments where broadcast is disabled
    let multicast_addr = Ipv4Addr::new(239, 255, 255, 250);
    let any_addr = Ipv4Addr::UNSPECIFIED;
    if let Err(e) = socket.join_multicast_v4(&multicast_addr, &any_addr) {
        // Some systems/iSH might not fail gracefully or support it, just log it.
        eprintln!("Warning: Could not join multicast group: {}", e);
    }

    // Set non-blocking before converting to Tokio
    socket.set_nonblocking(true)?;
    
    let std_socket: StdUdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
}

/// Broadcasts this device's presence on the network every 3 seconds.
///
/// Sends a custom pipe-delimited string format via UDP broadcast:
/// HOPCHAT|username|ip|port
pub async fn broadcast_presence(
    username: String,
    ip: String,
    chat_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket = create_reuse_socket()?;

    // Format: HOPCHAT|username|ip|port
    let payload = format!("HOPCHAT|{}|{}|{}", username, ip, chat_port);
    let data = payload.as_bytes();

    let broadcast_addr = format!("255.255.255.255:{}", DISCOVERY_PORT);
    let multicast_addr = format!("239.255.255.250:{}", DISCOVERY_PORT);

    let mut tick = interval(Duration::from_secs(3));
    loop {
        tick.tick().await;
        // Send discovery broadcast — try multicast first
        let _ = socket.send_to(data, &multicast_addr).await;
        // Broadcast fallback constraint for restrictive iOS/iSH environments
        let _ = socket.send_to(data, &broadcast_addr).await;

        // MESH ROUTING PLACEHOLDER:
        // In a mesh network, discovery packets could also be relayed
        // through intermediate nodes.
    }
}

/// Listens for UDP discovery broadcasts from other peers.
///
/// Parses packets ending with `HOPCHAT|username|ip|port` and 
/// updates the shared peer registry.
pub async fn listen_for_peers(
    _own_ip: String,
    own_username: String,
    registry: PeerRegistry,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket = create_reuse_socket()?;

    let mut buf = [0u8; 1024];
    loop {
        if let Ok((len, _src)) = socket.recv_from(&mut buf).await {
            if let Ok(text) = std::str::from_utf8(&buf[..len]) {
                let packet_str = text.trim();
                let parts: Vec<&str> = packet_str.split('|').collect();

                // Validate packet structure: HOPCHAT|username|ip|port
                if parts.len() == 4 && parts[0] == "HOPCHAT" {
                    // [SEC-4] Sanitize network-provided username before any use
                    let packet_username = match sanitize_network_username(parts[1]) {
                        Some(u) => u,
                        None => continue, // Drop packet with invalid username
                    };
                    let packet_ip = parts[2].to_string();
                    
                    if let Ok(packet_port) = parts[3].parse::<u16>() {
                        // Ignore our own broadcasts.
                        // Primary: match IP + username. Secondary: username-only guard
                        // in case local IP detection returned a different address.
                        if packet_username == own_username {
                            continue;
                        }

                        let mut registry_lock = registry.lock().await;
                        let is_new = !registry_lock.contains_key(&packet_username);

                        // [CONN-3] IP/port updates for existing peers must only occur via
                        // authenticated HOPCHAT_KEY packets (handled in messaging.rs).
                        // Do not update routing from unauthenticated UDP discovery.
                        if is_new {
                            let peer = Peer {
                                username: packet_username.clone(),
                                ip: packet_ip.clone(),
                                port: packet_port,
                                hostname: None,
                                last_seen: Instant::now(),
                            };
                            registry_lock.insert(packet_username.clone(), peer);
                            drop(registry_lock);
                            crate::network::peer_registry::resolve_hostname(registry.clone(), packet_username, packet_ip);
                        } else {
                            // Known peer: only refresh last_seen timestamp
                            if let Some(existing) = registry_lock.get_mut(&packet_username) {
                                existing.last_seen = Instant::now();
                            }
                        }
                    }
                }
            }
        }
    }
}

/// [SEC-4] Sanitizes a network-provided username by stripping non-alphanumeric
/// characters (except underscore) and capping length at 32.
/// Returns None if the sanitized result is empty.
pub fn sanitize_network_username(raw: &str) -> Option<String> {
    let sanitized: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(32)
        .collect();
    if sanitized.is_empty() {
        None
    } else {
        Some(sanitized)
    }
}

// CHANGES:
// [CONN-3] listen_for_peers: For known peers (!is_new), only update last_seen —
//          never update ip or port from unauthenticated UDP discovery packets.
// [SEC-4] Added sanitize_network_username() helper. Applied to all network-provided
//         usernames in listen_for_peers before any HashMap insertion.
// [SEC-6] create_reuse_socket: Replaced .parse().unwrap() with .parse().map_err()
//         for proper error propagation instead of panic on misconfiguration.
