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

use crate::network::peer_registry::{resolve_hostname, upsert_peer, PeerRegistry, Upsert};
use crate::network::messaging;
use crate::user::identity::LocalIdentity;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{interval, Duration};

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
    chat_port: u16,
    identity: Arc<LocalIdentity>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let _ = socket.set_broadcast(true);

    let broadcast_addr = format!("255.255.255.255:{}", DISCOVERY_PORT);
    let multicast_addr = format!("239.255.255.250:{}", DISCOVERY_PORT);

    // A full sweep is 508 packets. Sending it every tick flooded the LAN,
    // saturated the receivers' socket buffers and tripped their rate limiters,
    // so it runs once a minute while the cheap two-packet announcements stay on
    // the ten second cadence.
    const SWEEP_EVERY_TICKS: u32 = 6;
    let mut ticks: u32 = 0;
    let mut warned = false;

    let mut tick = interval(Duration::from_secs(10));
    loop {
        tick.tick().await;

        // Re-read the address every tick. A laptop that roams to another
        // network would otherwise keep announcing — and sweeping — its old
        // subnet for as long as it runs.
        let ip = crate::get_local_ip();
        let subnet = subnet_prefix(&ip);
        if subnet.is_none() && !warned {
            warned = true;
            eprintln!(
                "[hopchat] no IPv4 LAN address ({}); relying on broadcast and multicast only",
                ip
            );
        }

        // Generate a fresh signed packet each tick (timestamp changes)
        let signed = messaging::create_signed_discovery(&username, &ip, chat_port, &identity);
        let data = signed.as_bytes();

        // Method 1: Broadcast
        let _ = socket.send_to(data, &broadcast_addr).await;
        // Method 2: Multicast
        let _ = socket.send_to(data, &multicast_addr).await;

        // Method 3: Directed subnet sweep
        ticks = ticks.wrapping_add(1);
        if let Some(ref prefix) = subnet {
            if ticks % SWEEP_EVERY_TICKS == 0 {
                sweep(&socket, prefix, data, chat_port).await;
            }
        }
    }
}

/// The first three octets of an IPv4 address, or None for anything else.
///
/// The directed sweep assumes a /24. That is the overwhelmingly common LAN
/// shape; on a wider net the sweep still covers the sender's own /24.
pub fn subnet_prefix(ip: &str) -> Option<String> {
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() == 4 {
        Some(format!("{}.{}.{}", octets[0], octets[1], octets[2]))
    } else {
        None
    }
}

/// Sends `data` to every host in the /24 on both the discovery and chat ports.
///
/// Paced in small batches: a 500-packet burst overruns the receiver's socket
/// buffer and most of it is dropped before it can be read.
async fn sweep(socket: &UdpSocket, prefix: &str, data: &[u8], chat_port: u16) {
    for host in 1..=254u8 {
        for port in [DISCOVERY_PORT, chat_port] {
            let target = format!("{}.{}:{}", prefix, host, port);
            let _ = socket.send_to(data, &target).await;
        }
        if host % 8 == 0 {
            tokio::time::sleep(Duration::from_millis(4)).await;
        }
    }
}

/// Listens for UDP discovery broadcasts from other peers.
///
/// Accepts both signed (v2.3.0+) and unsigned (v2.2.0) discovery packets.
/// Updates the shared peer registry on valid packets.
pub async fn listen_for_peers(
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
                if let Some(disc) = messaging::parse_discovery_packet(packet_str, &src_ip_str) {
                    if disc.username == own_username {
                        continue;
                    }

                    let outcome = {
                        let mut reg = registry.lock().await;
                        upsert_peer(
                            &mut reg,
                            &disc.username,
                            &disc.ip,
                            disc.port,
                            disc.authenticated,
                        )
                    };

                    if outcome == Upsert::Inserted {
                        resolve_hostname(registry.clone(), disc.username, disc.ip);
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
