// =============================================================================
// HOPCHAT — Network Module: Peer Registry
// =============================================================================
//
// Manages the list of discovered peers and handles timeouts for inactive peers.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration, Instant};

/// Represents a discovered peer on the network.
#[derive(Debug, Clone)]
pub struct Peer {
    /// The peer's username
    pub username: String,
    /// The peer's IP address
    pub ip: String,
    /// The peer's TCP port for messaging
    pub port: u16,
    /// The device hostname if resolved
    pub hostname: Option<String>,
    /// The last time a discovery packet was received from this peer
    pub last_seen: Instant,
}

impl Peer {
    /// Returns the peer's socket address for TCP connections.
    pub fn socket_addr(&self) -> Result<SocketAddr, std::net::AddrParseError> {
        format!("{}:{}", self.ip, self.port).parse()
    }
}

/// A thread-safe, shared registry of active peers.
pub type PeerRegistry = Arc<Mutex<HashMap<String, Peer>>>;

/// Background task that removes peers not seen within the last 15 seconds.
pub async fn cleanup_task(registry: PeerRegistry) {
    let mut tick = interval(Duration::from_secs(1));
    let timeout = Duration::from_secs(15);

    loop {
        tick.tick().await;
        let now = Instant::now();
        let mut registry_lock = registry.lock().await;

        registry_lock.retain(|_, peer| now.duration_since(peer.last_seen) < timeout);
    }
}

/// Spawns a background task to resolve the hostname of a peer.
pub fn resolve_hostname(registry: PeerRegistry, username: String, ip: String) {
    tokio::spawn(async move {
        if let Ok(ip_addr) = ip.parse::<std::net::IpAddr>() {
            if let Ok(hostname) = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip_addr))
                .await
                .unwrap_or_else(|_| Err(std::io::Error::new(std::io::ErrorKind::Other, "task failed")))
            {
                let mut reg = registry.lock().await;
                if let Some(peer) = reg.get_mut(&username) {
                    peer.hostname = Some(hostname);
                }
            }
        }
    });
}
