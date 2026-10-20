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

/// Upper bound on tracked peers, so a hostile LAN cannot exhaust memory.
pub const MAX_PEERS: usize = 1000;

/// Outcome of registering a peer announced by a discovery packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upsert {
    /// Peer was not previously known and has been added.
    Inserted,
    /// Known peer refreshed with a new address.
    Updated,
    /// Update refused.
    Rejected,
}

/// Registers or refreshes a peer from a discovery announcement.
///
/// `authenticated` is false for legacy unsigned packets. Those may introduce a
/// peer we have never seen, but they may never move one we already track —
/// otherwise anyone on the LAN could redirect traffic for a known username by
/// simply claiming it.
pub fn upsert_peer(
    registry: &mut HashMap<String, Peer>,
    username: &str,
    ip: &str,
    port: u16,
    authenticated: bool,
) -> Upsert {
    if let Some(existing) = registry.get_mut(username) {
        if !authenticated {
            return Upsert::Rejected;
        }
        existing.ip = ip.to_string();
        existing.port = port;
        existing.last_seen = Instant::now();
        Upsert::Updated
    } else if registry.len() >= MAX_PEERS {
        Upsert::Rejected
    } else {
        registry.insert(
            username.to_string(),
            Peer {
                username: username.to_string(),
                ip: ip.to_string(),
                port,
                hostname: None,
                last_seen: Instant::now(),
            },
        );
        Upsert::Inserted
    }
}

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
