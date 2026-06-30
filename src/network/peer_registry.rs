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
    /// The peer's UDP port for messaging
    pub port: u16,
    /// The device hostname if resolved
    pub hostname: Option<String>,
    /// The last time a discovery packet was received from this peer
    pub last_seen: Instant,
}

impl Peer {
    /// Returns the peer's socket address for UDP connections.
    pub fn socket_addr(&self) -> Result<SocketAddr, std::net::AddrParseError> {
        format!("{}:{}", self.ip, self.port).parse()
    }
}

/// A thread-safe, shared registry of active peers.
pub type PeerRegistry = Arc<Mutex<HashMap<String, Peer>>>;

/// Background task that removes peers not seen within the timeout.
/// Uses 60-second timeout instead of 15s — the old value was too aggressive
/// and evicted peers before they could complete key exchange, especially
/// on iSH where discovery is slow and unreliable.
pub async fn cleanup_task(registry: PeerRegistry) {
    let mut tick = interval(Duration::from_secs(5));
    let timeout = Duration::from_secs(60);

    loop {
        tick.tick().await;
        let now = Instant::now();

        // Phase 1: Collect stale keys (brief lock)
        let stale_keys: Vec<String> = {
            let reg = registry.lock().await;
            reg.iter()
                .filter(|(_, p)| now.duration_since(p.last_seen) >= timeout)
                .map(|(k, _)| k.clone())
                .collect()
        };

        // Phase 2: Remove stale keys (only if needed)
        if !stale_keys.is_empty() {
            let mut reg = registry.lock().await;
            for key in stale_keys {
                reg.remove(&key);
            }
        }

        // Yield to prevent starvation of other tasks on single-core systems
        tokio::task::yield_now().await;
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
