// =============================================================================
// HOPCHAT — Network Module: UDP Peer Discovery
// =============================================================================
//
// Uses directed UDP unicast to discover peers on the LAN.
// Each device broadcasts a signed discovery packet every 10 seconds.
// Discovered peers are added to a shared peer list.
//
// Architecture:
//   broadcast_presence() — uses a plain tokio UDP socket (port 0) to send
//                          signed discovery packets. Tries broadcast/multicast
//                          first, falls back to directed subnet sweep.
//   listen_for_peers()   — binds to DISCOVERY_PORT (9877) to receive broadcasts.
//                          Falls back gracefully if bind fails (iSH).
//
// Packet format (v2.3.0):
//   HOPCHAT|username|ip|port|timestamp|ed25519_pub|signature
//
// Backward compatibility: listen_for_peers() also accepts the old 4-field
// format (HOPCHAT|username|ip|port) from v2.2.0 clients.

use crate::network::peer_registry::{Peer, PeerRegistry};
use crate::network::messaging;
use crate::user::identity::LocalIdentity;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{interval, Duration, Instant};

/// The UDP port used for peer discovery broadcasts.
pub const DISCOVERY_PORT: u16 = 9877;

/// Broadcasts this device's presence on the network every 10 seconds.
///
/// Uses THREE delivery methods, each best-effort:
///   1. Broadcast to 255.255.255.255 (home WiFi — may fail on iSH)
///   2. Multicast to 239.255.255.250 (enterprise WiFi — may fail on iSH)
///   3. Directed subnet sweep to x.x.x.1-254 on BOTH ports (always works)
///
/// All packets are signed with the local Ed25519 identity.
pub async fn broadcast_presence(
    username: String,
    ip: String,
    chat_port: u16,
    identity: Arc<LocalIdentity>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let _ = socket.set_broadcast(true);

    let broadcast_addr = format!("255.255.255.255:{}", DISCOVERY_PORT);
    let multicast_addr = format!("239.255.255.250:{}", DISCOVERY_PORT);

    // Compute the subnet prefix for directed sweep
    let parts: Vec<&str> = ip.split('.').collect();
    let subnet_prefix = if parts.len() == 4 {
        Some(format!("{}.{}.{}", parts[0], parts[1], parts[2]))
    } else {
        None
    };

    let mut tick = interval(Duration::from_secs(10));
    loop {
        tick.tick().await;

        // Generate a fresh signed packet each tick (timestamp changes)
        let signed = messaging::create_signed_discovery(&username, &ip, chat_port, &identity);
        let data = signed.as_bytes();

        // Method 1: Broadcast
        let _ = socket.send_to(data, &broadcast_addr).await;
        // Method 2: Multicast
        let _ = socket.send_to(data, &multicast_addr).await;

        // Method 3: Directed subnet sweep
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
/// Accepts both signed (v2.3.0+) and unsigned (v2.2.0) discovery packets.
/// Updates the shared peer registry on valid packets.
pub async fn listen_for_peers(
    _own_ip: String,
    own_username: String,
    registry: PeerRegistry,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket = match create_listener_socket_socket2() {
        Ok(s) => s,
        Err(_) => UdpSocket::bind(format!("0.0.0.0:{}", DISCOVERY_PORT)).await?,
    };

    let mut buf = [0u8; 4096];
    loop {
        if let Ok((len, src_addr)) = socket.recv_from(&mut buf).await {
            if let Ok(text) = std::str::from_utf8(&buf[..len]) {
                let packet_str = text.trim();

                // Use the shared parser (handles both old and new format)
                let src_ip_str = src_addr.ip().to_string();
                if let Some((peer_username, peer_ip, peer_port)) =
                    messaging::parse_discovery_packet(packet_str, &src_ip_str)
                {
                    if peer_username == own_username {
                        continue;
                    }

                    let mut registry_lock = registry.lock().await;

                    if registry_lock.len() >= 1000 && !registry_lock.contains_key(&peer_username) {
                        continue;
                    }

                    if let Some(existing) = registry_lock.get_mut(&peer_username) {
                        existing.last_seen = Instant::now();
                        existing.ip = peer_ip;
                        existing.port = peer_port;
                    } else {
                        let peer = Peer {
                            username: peer_username.clone(),
                            ip: peer_ip.clone(),
                            port: peer_port,
                            hostname: None,
                            last_seen: Instant::now(),
                        };
                        registry_lock.insert(peer_username.clone(), peer);
                        drop(registry_lock);
                        crate::network::peer_registry::resolve_hostname(
                            registry.clone(), peer_username, peer_ip,
                        );
                    }
                }
            }
        }
    }
}

/// Creates a listener socket using socket2 for port reuse support.
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
