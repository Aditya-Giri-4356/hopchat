// =============================================================================
// HOPCHAT — Network Module: UDP Peer Discovery
// =============================================================================
//
// Uses UDP broadcast/multicast/directed-unicast to discover peers on the LAN.
// Each device broadcasts its username, IP, and chat port every 3 seconds.
// Discovered peers are added to a shared peer list.
//
// Architecture:
//   broadcast_presence() — creates its OWN lightweight outbound-only socket
//                          (binds to port 0 / any ephemeral port). Sends to
//                          broadcast + multicast + directed subnet sweep.
//   listen_for_peers()   — creates a socket bound to DISCOVERY_PORT (9877).
//                          Only ONE socket ever binds to 9877.
//
// This split eliminates the double-bind conflict that caused EINVAL (os error 22)
// on iSH and any platform lacking SO_REUSEPORT.

use crate::network::peer_registry::{Peer, PeerRegistry};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use tokio::net::UdpSocket;
use tokio::time::{interval, Duration, Instant};

/// The UDP port used for peer discovery broadcasts.
pub const DISCOVERY_PORT: u16 = 9877;

/// Creates a lightweight SEND-ONLY socket for broadcasting.
/// Binds to 0.0.0.0:0 (ephemeral port) — never competes with the listener.
/// Failures in optional setsockopt calls are silently ignored for iSH compat.
fn create_broadcast_socket() -> Result<UdpSocket, std::io::Error> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    
    // These are optional — iSH may reject them with EINVAL
    let _ = socket.set_broadcast(true);
    let _ = socket.set_reuse_address(true);
    
    // Bind to ANY port (not DISCOVERY_PORT) — no conflict with listener
    let addr: SocketAddr = "0.0.0.0:0".parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    socket.bind(&addr.into())?;
    
    socket.set_nonblocking(true)?;
    let std_socket: StdUdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
}

/// Creates a RECEIVE socket bound to DISCOVERY_PORT for listening.
/// Only ONE task should call this — listen_for_peers().
fn create_listener_socket() -> Result<UdpSocket, std::io::Error> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    
    // Allow reuse so we can restart without waiting for TIME_WAIT
    let _ = socket.set_reuse_address(true);
    #[cfg(not(target_os = "windows"))]
    let _ = socket.set_reuse_port(true);
    let _ = socket.set_broadcast(true);
    
    let addr: SocketAddr = format!("0.0.0.0:{}", DISCOVERY_PORT)
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    socket.bind(&addr.into())?;
    
    // Multicast join — best-effort (fails on iSH, works on macOS/Linux)
    let multicast_addr = Ipv4Addr::new(239, 255, 255, 250);
    let any_addr = Ipv4Addr::UNSPECIFIED;
    let _ = socket.join_multicast_v4(&multicast_addr, &any_addr);

    socket.set_nonblocking(true)?;
    let std_socket: StdUdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
}

/// Broadcasts this device's presence on the network every 3 seconds.
///
/// Uses THREE delivery methods for maximum compatibility:
///   1. Multicast to 239.255.255.250 (works on enterprise WiFi that blocks broadcast)
///   2. Broadcast to 255.255.255.255 (works on home/SOHO WiFi)
///   3. Directed subnet sweep to x.x.x.1-254 (works on iSH and restrictive networks)
///
/// The subnet sweep runs once every 3rd tick (~9 seconds) to avoid flooding.
pub async fn broadcast_presence(
    username: String,
    ip: String,
    chat_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket = create_broadcast_socket()?;

    let payload = format!("HOPCHAT|{}|{}|{}", username, ip, chat_port);
    let data = payload.as_bytes();

    let broadcast_addr = format!("255.255.255.255:{}", DISCOVERY_PORT);
    let multicast_addr = format!("239.255.255.250:{}", DISCOVERY_PORT);

    // Compute the subnet prefix for directed sweep
    let parts: Vec<&str> = ip.split('.').collect();
    let subnet_prefix = if parts.len() == 4 {
        Some(format!("{}.{}.{}", parts[0], parts[1], parts[2]))
    } else {
        None
    };

    let mut tick = interval(Duration::from_secs(3));
    let mut tick_count: u64 = 0;
    loop {
        tick.tick().await;
        tick_count += 1;

        // Method 1: Multicast (enterprise WiFi)
        let _ = socket.send_to(data, &multicast_addr).await;
        // Method 2: Broadcast (home WiFi)
        let _ = socket.send_to(data, &broadcast_addr).await;

        // Method 3: Directed subnet sweep every 3rd tick (~9 seconds)
        // This is the critical fallback for iSH/Termux where broadcast/multicast
        // may not work. Sending to all 254 host addresses is reliable but produces
        // traffic, so we do it less frequently.
        if tick_count % 3 == 1 {
            if let Some(ref prefix) = subnet_prefix {
                for i in 1..=254u8 {
                    let target = format!("{}.{}:{}", prefix, i, DISCOVERY_PORT);
                    let _ = socket.send_to(data, &target).await;
                    // Also send to the chat port in case the peer's discovery
                    // listener failed (the chat listener also handles discovery)
                    let target_chat = format!("{}.{}:{}", prefix, i, crate::PREFERRED_CHAT_PORT);
                    let _ = socket.send_to(data, &target_chat).await;
                }
            }
        }
    }
}

/// Listens for UDP discovery broadcasts from other peers.
///
/// Parses packets matching `HOPCHAT|username|ip|port` and
/// updates the shared peer registry.
pub async fn listen_for_peers(
    _own_ip: String,
    own_username: String,
    registry: PeerRegistry,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket = create_listener_socket()?;

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
                        // Ignore our own broadcasts
                        if packet_username == own_username {
                            continue;
                        }

                        let mut registry_lock = registry.lock().await;
                        let is_new = !registry_lock.contains_key(&packet_username);

                        if is_new {
                            // Cap peer registry to prevent DoS
                            if registry_lock.len() >= 1000 {
                                continue;
                            }
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
                            // Known peer: refresh last_seen and UPDATE ip/port.
                            // On iSH, the discovery listener may be the only working
                            // path, so we need to accept IP/port updates here.
                            // TOFU protection in messaging.rs guards against key theft.
                            if let Some(existing) = registry_lock.get_mut(&packet_username) {
                                existing.last_seen = Instant::now();
                                existing.ip = packet_ip;
                                existing.port = packet_port;
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
