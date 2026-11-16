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
    /// The last time any valid packet was received from this peer
    pub last_seen: Instant,
    /// False once the peer has been silent for `OFFLINE_AFTER`. The entry is
    /// kept so the friend list does not lose people when a single broadcast
    /// is dropped, which on a phone hotspot is most of them.
    pub online: bool,
    /// True once a session key has been negotiated over UDP.
    pub connected: bool,
    /// True while an authenticated Bluetooth link is open. Kept separate from
    /// `connected` because a peer can be reachable over either transport (or
    /// both) and losing one must not mark the other as down.
    pub ble_connected: bool,
    /// Last authenticated Bluetooth traffic, tracked separately from UDP so a
    /// quiet radio link is not aged out by LAN silence (and vice versa).
    pub ble_last_seen: Instant,
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

/// How long a peer may stay silent before it is shown as offline.
///
/// Announcements go out every ten seconds, so this tolerates a dozen misses.
/// The earlier behaviour deleted the peer after 60 seconds, which made anyone
/// on a lossy link flicker out of the friend list while still sitting on the
/// same network.
pub const OFFLINE_AFTER: Duration = Duration::from_secs(120);

/// Bluetooth heartbeats run every 20 seconds; allow four missed beats before
/// deciding the link itself is stale.
const BLE_OFFLINE_AFTER: Duration = Duration::from_secs(90);

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
    if registry.contains_key(username) {
        // An unsigned packet may introduce a new name but never redirect one
        // we already track, so anyone can claim a username that is not yet
        // in use but nobody can take over an established one.
        if !authenticated {
            return Upsert::Rejected;
        }
        if let Some(existing) = registry.get_mut(username) {
            existing.ip = ip.to_string();
            existing.port = port;
            existing.last_seen = Instant::now();
            existing.online = true;
        }
        return Upsert::Updated;
    }

    // Make room by dropping the longest-silent offline peer. Entries are
    // otherwise kept for the whole session, so without this the cap would
    // permanently block anyone new once it filled up.
    if registry.len() >= MAX_PEERS {
        let victim = registry
            .iter()
            .filter(|(_, p)| !p.online)
            .min_by_key(|(_, p)| p.last_seen)
            .map(|(k, _)| k.clone());
        match victim {
            Some(key) => {
                registry.remove(&key);
            }
            None => return Upsert::Rejected,
        }
    }

    registry.insert(
        username.to_string(),
        Peer {
            username: username.to_string(),
            ip: ip.to_string(),
            port,
            hostname: None,
            last_seen: Instant::now(),
            online: true,
            connected: false,
            ble_connected: false,
            ble_last_seen: Instant::now(),
        },
    );
    Upsert::Inserted
}

/// Records that a peer is alive and reachable at `ip`.
///
/// Called for any valid packet from a known peer — discovery, key exchange,
/// chat message or acknowledgement — so liveness does not depend on one
/// particular packet type surviving the network.
pub fn mark_reachable(registry: &mut HashMap<String, Peer>, username: &str, ip: &str) {
    if let Some(peer) = registry.get_mut(username) {
        peer.last_seen = Instant::now();
        peer.online = true;
        if peer.ip != ip {
            peer.ip = ip.to_string();
        }
    }
}

/// Marks a peer as having a negotiated session.
pub fn mark_connected(registry: &mut HashMap<String, Peer>, username: &str) {
    if let Some(peer) = registry.get_mut(username) {
        peer.connected = true;
        peer.online = true;
        peer.last_seen = Instant::now();
    }
}

/// Records that an authenticated Bluetooth link to this peer is open.
#[cfg_attr(
    not(all(
        any(target_os = "macos", target_os = "linux"),
        not(target_arch = "x86")
    )),
    allow(dead_code)
)]
pub fn mark_ble_connected(registry: &mut HashMap<String, Peer>, username: &str) {
    if let Some(peer) = registry.get_mut(username) {
        peer.ble_connected = true;
        peer.online = true;
        peer.last_seen = Instant::now();
        peer.ble_last_seen = Instant::now();
    }
}

/// Records that this peer's Bluetooth link closed. The UDP session, if any,
/// is intentionally left alone.
#[cfg_attr(
    not(all(
        any(target_os = "macos", target_os = "linux"),
        not(target_arch = "x86")
    )),
    allow(dead_code)
)]
pub fn mark_ble_disconnected(registry: &mut HashMap<String, Peer>, username: &str) {
    if let Some(peer) = registry.get_mut(username) {
        peer.ble_connected = false;
    }
}

/// Background task that flags silent peers as offline.
///
/// Entries are kept rather than deleted: a peer that drops one broadcast is
/// still on the network, and removing them from the list mid-conversation
/// looks like a disconnect. Only when the registry is full are the longest
/// silent offline entries dropped to stay within `MAX_PEERS`.
pub async fn cleanup_task(registry: PeerRegistry) {
    let mut tick = interval(Duration::from_secs(5));

    loop {
        tick.tick().await;
        let mut reg = registry.lock().await;

        for peer in reg.values_mut() {
            // Bluetooth liveness is independent of UDP silence. Clearing it
            // from the UDP timer made a live BLE peer flicker offline whenever
            // a heartbeat arrived late, so only the BLE-specific age can drop
            // the flag here; normal link teardown clears it earlier.
            if peer.ble_connected && peer.ble_last_seen.elapsed() >= BLE_OFFLINE_AFTER {
                peer.ble_connected = false;
            }
            if peer.last_seen.elapsed() >= OFFLINE_AFTER {
                peer.connected = false;
                if !peer.ble_connected {
                    peer.online = false;
                }
            }
        }

        drop(reg);

        // Yield to prevent starvation of other tasks on single-core systems
        tokio::task::yield_now().await;
    }
}

/// Spawns a background task to resolve the hostname of a peer.
///
/// Reverse DNS is best-effort display data. It gets its own short timeout so
/// a broken resolver cannot pin a blocking thread and starve other lookups.
pub fn resolve_hostname(registry: PeerRegistry, username: String, ip: String) {
    tokio::spawn(async move {
        let Ok(ip_addr) = ip.parse::<std::net::IpAddr>() else {
            return;
        };
        let lookup = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip_addr));
        let Ok(Ok(Ok(hostname))) = tokio::time::timeout(Duration::from_secs(3), lookup).await
        else {
            return;
        };

        let mut reg = registry.lock().await;
        if let Some(peer) = reg.get_mut(&username) {
            peer.hostname = Some(hostname);
        }
    });
}
