// =============================================================================
// HOPCHAT — Network Module: UDP Peer Discovery
// =============================================================================
//
// Uses directed UDP unicast to discover peers on the LAN.
// Each device broadcasts its username, IP, and chat port every 3 seconds.
// Discovered peers are added to a shared peer list.
//
// Architecture:
//   broadcast_presence() — uses a plain tokio UDP socket (port 0) to send
//                          discovery packets. Tries broadcast/multicast first,
//                          falls back to directed subnet sweep for iSH/Termux.
//   listen_for_peers()   — binds to DISCOVERY_PORT (9877) to receive broadcasts.
//                          Falls back gracefully if bind fails (iSH).
//
// On iSH/Termux where socket2 fails and broadcast is unsupported,
// discovery relies on:
//   1. The directed subnet sweep in broadcast_presence() (sends to port 9878)
//   2. The chat listener (port 9878) in messaging.rs echoing back discovery
//
// This eliminates the socket2 dependency from the critical path.

use crate::network::peer_registry::{Peer, PeerRegistry};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{interval, Duration, Instant};

/// The UDP port used for peer discovery broadcasts.
pub const DISCOVERY_PORT: u16 = 9877;

/// Broadcasts this device's presence on the network every 3 seconds.
///
/// Uses THREE delivery methods, each best-effort:
///   1. Broadcast to 255.255.255.255 (home WiFi — may fail on iSH)
///   2. Multicast to 239.255.255.250 (enterprise WiFi — may fail on iSH)
///   3. Directed subnet sweep to x.x.x.1-254 on BOTH ports (always works)
///
/// The subnet sweep runs on every tick. It's the primary mechanism on iSH
/// where broadcast/multicast are not supported.
pub async fn broadcast_presence(
    username: String,
    ip: String,
    chat_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Use plain tokio UDP — no socket2 dependency.
    // Binds to port 0 (any ephemeral port). This works on every platform
    // including iSH where socket2's Socket::new() may fail with EINVAL.
    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    // Try to enable broadcast on the underlying socket (best-effort).
    // If it fails (iSH), we still have the directed sweep.
    let _ = socket.set_broadcast(true);

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
    loop {
        tick.tick().await;

        // Method 1: Broadcast (may fail on iSH — that's fine)
        let _ = socket.send_to(data, &broadcast_addr).await;
        // Method 2: Multicast (may fail on iSH — that's fine)
        let _ = socket.send_to(data, &multicast_addr).await;

        // Method 3: Directed subnet sweep — THE RELIABLE FALLBACK.
        // Sends to every IP on the subnet, targeting BOTH the discovery port
        // (9877) and the chat port (9878). This ensures the packet reaches
        // at least one listener on the target device.
        if let Some(ref prefix) = subnet_prefix {
            for i in 1..=254u8 {
                let target = format!("{}.{}:{}", prefix, i, DISCOVERY_PORT);
                let _ = socket.send_to(data, &target).await;
                let target_chat = format!("{}.{}:{}", prefix, i, crate::PREFERRED_CHAT_PORT);
                let _ = socket.send_to(data, &target_chat).await;
            }
        }
    }
}

/// Listens for UDP discovery broadcasts from other peers.
///
/// Parses packets matching `HOPCHAT|username|ip|port` and
/// updates the shared peer registry.
///
/// If the bind to DISCOVERY_PORT fails (e.g. on iSH), this function
/// returns an error. The chat port listener in messaging.rs is the
/// fallback that handles discovery packets arriving on port 9878.
pub async fn listen_for_peers(
    _own_ip: String,
    own_username: String,
    registry: PeerRegistry,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Try socket2 first for port reuse, fall back to plain tokio
    let socket = match create_listener_socket_socket2() {
        Ok(s) => s,
        Err(_) => {
            // socket2 failed (iSH) — try plain tokio
            UdpSocket::bind(format!("0.0.0.0:{}", DISCOVERY_PORT)).await?
        }
    };

    let mut buf = [0u8; 1024];
    loop {
        if let Ok((len, src_addr)) = socket.recv_from(&mut buf).await {
            if let Ok(text) = std::str::from_utf8(&buf[..len]) {
                let packet_str = text.trim();
                let parts: Vec<&str> = packet_str.split('|').collect();

                // Validate packet structure: HOPCHAT|username|ip|port
                if parts.len() == 4 && parts[0] == "HOPCHAT" {
                    let packet_username = match sanitize_network_username(parts[1]) {
                        Some(u) => u,
                        None => continue,
                    };
                    
                    // Trust the actual packet source, not the advertised payload IP.
                    // This fixes the issue where iSH advertises 127.0.0.1 due to failing IP detection.
                    let packet_ip = src_addr.ip().to_string();
                    
                    if let Ok(packet_port) = parts[3].parse::<u16>() {
                        if packet_username == own_username {
                            continue;
                        }

                        let mut registry_lock = registry.lock().await;

                        if registry_lock.len() >= 1000 && !registry_lock.contains_key(&packet_username) {
                            continue;
                        }

                        if let Some(existing) = registry_lock.get_mut(&packet_username) {
                            existing.last_seen = Instant::now();
                            existing.ip = packet_ip;
                            existing.port = packet_port;
                        } else {
                            let peer = Peer {
                                username: packet_username.clone(),
                                ip: packet_ip.clone(),
                                port: packet_port,
                                hostname: None,
                                last_seen: Instant::now(),
                            };
                            registry_lock.insert(packet_username.clone(), peer);
                            drop(registry_lock);
                            crate::network::peer_registry::resolve_hostname(
                                registry.clone(), packet_username, packet_ip,
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Creates a listener socket using socket2 for port reuse support.
/// This is an optional enhancement — if it fails, we fall back to plain tokio.
fn create_listener_socket_socket2() -> Result<UdpSocket, std::io::Error> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::{Ipv4Addr, UdpSocket as StdUdpSocket};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let _ = socket.set_reuse_address(true);
    #[cfg(not(target_os = "windows"))]
    let _ = socket.set_reuse_port(true);
    let _ = socket.set_broadcast(true);

    let addr: SocketAddr = format!("0.0.0.0:{}", DISCOVERY_PORT)
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    socket.bind(&addr.into())?;

    // Multicast join — best-effort
    let multicast_addr = Ipv4Addr::new(239, 255, 255, 250);
    let any_addr = Ipv4Addr::UNSPECIFIED;
    let _ = socket.join_multicast_v4(&multicast_addr, &any_addr);

    socket.set_nonblocking(true)?;
    let std_socket: StdUdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
}

/// Sanitizes a network-provided username by stripping non-alphanumeric
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
