// =============================================================================
// HOPCHAT — Network Module: Bluetooth LE Transport
// =============================================================================
//
// A real BLE transport: every node advertises a GATT service (peripheral role)
// *and* scans for the same service (central role), so two devices find each
// other without either one being configured as a server. Chat packets use the
// existing UDP wire format, carried over a small fragmentation frame because
// BLE gives us ~182 usable bytes per write on an iPhone.
//
// Security is not re-invented here. The BLE handshake is the same Ed25519
// identity + X25519 key agreement the UDP path uses, with the same TOFU
// database, and messages are encrypted with the same XChaCha20-Poly1305
// envelope. The session key is identical on both transports, so a message
// replayed from UDP onto BLE (or the reverse) is still rejected by the shared
// per-peer replay window.
//
// Platform support:
//   macOS / Linux  — full implementation (CoreBluetooth / BlueZ)
//   iSH (i586)     — compiled out. iSH exposes no Bluetooth hardware to the
//                    guest Linux userland, so there is nothing to talk to.
//                    `start()` returns a handle that reports "unavailable".
//
// The platform code lives in `backend.rs`; this file is always compiled so
// the rest of the app can reference `BleHandle` on every target.

// On targets with no BLE backend (iSH), the handle and status are still used
// but the wire format is not; keep that build warning-free without sprinkling
// cfg attributes over every constant.
#![cfg_attr(
    not(all(
        any(target_os = "macos", target_os = "linux"),
        not(target_arch = "x86")
    )),
    allow(dead_code)
)]

use crate::crypto::key_exchange::X25519KeyPair;
use crate::network::messaging::{ChatHistory, PeerKeyRegistry, TrustRegistry};
use crate::network::peer_registry::PeerRegistry;
use crate::user::identity::LocalIdentity;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio::sync::{mpsc, oneshot};

/// GATT service advertised by every HopChat node.
pub const SERVICE_UUID: &str = "6f1a7c00-9e3b-4a7d-b2c5-5c1e8a4d9f01";
/// Central → peripheral: chat frames are written here.
pub const WRITE_CHARACTERISTIC_UUID: &str = "6f1a7c01-9e3b-4a7d-b2c5-5c1e8a4d9f01";
/// Peripheral → central: incoming chat frames arrive as notifications here.
pub const NOTIFY_CHARACTERISTIC_UUID: &str = "6f1a7c02-9e3b-4a7d-b2c5-5c1e8a4d9f01";

/// Prefix of the short name put in BLE advertisements: `HC` + 8 hex chars of
/// the SHA-256 of the node's Ed25519 public key.
pub const ADVERT_NAME_PREFIX: &str = "HC";

/// Bytes of text carried in one BLE frame. 160 + our 7-byte header is 167,
/// which fits the 182-byte ATT payload an iPhone allows. The GATT stack may
/// negotiate more on desktop-to-desktop links, but designing for the smallest
/// pipe keeps every link working.
pub const MAX_FRAGMENT_PAYLOAD: usize = 160;

/// Absolute ceiling for one reassembled packet. A max-size UDP chat packet is
/// a little over 8 KiB of hex; 16 KiB leaves headroom without letting a peer
/// make us allocate without bound.
pub const MAX_PACKET_BYTES: usize = 16 * 1024;

/// Maximum whole packets that fit in one BLE message (255 fragments × 160 B).
const MAX_FRAGMENTS: usize = 255;

const FRAME_MAGIC: u8 = b'H';
const FRAME_VERSION: u8 = 1;
const FRAME_HEADER_LEN: usize = 7;

/// A partial packet is abandoned if the rest never arrives.
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);

// =============================================================================
// Status reported to the UI
// =============================================================================

#[derive(Clone, Debug, Default)]
pub struct BleStatus {
    /// False in builds with no Bluetooth backend (iSH).
    pub supported: bool,
    /// User-controlled on/off switch.
    pub enabled: bool,
    /// The adapter exists and is powered on.
    pub powered: bool,
    /// We are advertising our GATT service.
    pub advertising: bool,
    /// We are scanning for other HopChat nodes.
    pub scanning: bool,
    /// Number of authenticated peer links.
    pub links: usize,
    /// Human-readable state or the most recent error.
    pub detail: String,
}

impl BleStatus {
    /// One-line summary for the status bar.
    pub fn summary(&self) -> String {
        if !self.supported {
            return "n/a".to_string();
        }
        if !self.enabled {
            return "off".to_string();
        }
        if !self.powered {
            return "starting".to_string();
        }
        if self.links > 0 {
            format!(
                "on ({} link{})",
                self.links,
                if self.links == 1 { "" } else { "s" }
            )
        } else if self.advertising && self.scanning {
            "on, searching".to_string()
        } else {
            "on".to_string()
        }
    }
}

/// Result of trying to send one packet over Bluetooth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendOutcome {
    /// Queued on an authenticated link.
    Sent,
    /// Connected, but the link's queue is full — caller should fall back.
    Busy,
    /// No Bluetooth link to that peer.
    NotLinked,
    /// Bluetooth is disabled or unsupported.
    Disabled,
    /// Packet is larger than the reassembly ceiling; caller should use UDP.
    TooLarge,
}

// =============================================================================
// Runtime handle
// =============================================================================

struct LinkEntry {
    /// Monotonic id so a late teardown cannot remove a newer link to the same
    /// peer (reconnect races are real on flaky radios).
    id: usize,
    tx: mpsc::Sender<Vec<u8>>,
}

/// Pending delivery acknowledgements: (peer, message id) → notifier.
type AckWaiters = HashMap<(String, u64), oneshot::Sender<()>>;

/// Shared, cloneable handle the rest of the app uses to talk to Bluetooth.
///
/// It deliberately exposes a synchronous `send_packet`: the chat input path
/// should never stall the UI on a radio, so packets are queued and the
/// per-link writer drains them.
#[derive(Clone)]
pub struct BleHandle {
    status: Arc<Mutex<BleStatus>>,
    links: Arc<std::sync::Mutex<HashMap<String, LinkEntry>>>,
    /// Pending BLE delivery acknowledgements, keyed by peer and message id.
    acks: Arc<std::sync::Mutex<AckWaiters>>,
    next_link_id: Arc<AtomicUsize>,
    enabled: Arc<AtomicBool>,
}

impl BleHandle {
    fn new(enabled: Arc<AtomicBool>) -> Self {
        Self {
            status: Arc::new(Mutex::new(BleStatus::default())),
            links: Arc::new(std::sync::Mutex::new(HashMap::new())),
            acks: Arc::new(std::sync::Mutex::new(HashMap::new())),
            next_link_id: Arc::new(AtomicUsize::new(1)),
            enabled,
        }
    }

    /// Whether the user has Bluetooth switched on.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Turns advertising/scanning on or off at runtime.
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
        if !on {
            // No link can deliver while the radio is off; fail waiters now
            // rather than making every send wait for its timeout.
            let mut acks = match self.acks.lock() {
                Ok(a) => a,
                Err(poisoned) => poisoned.into_inner(),
            };
            acks.clear();
        }
    }

    /// Snapshot of the current state for rendering/commands.
    pub async fn status(&self) -> BleStatus {
        let mut snapshot = self.status.lock().await.clone();
        snapshot.enabled = self.is_enabled();
        snapshot.links = self.linked_peers().len();
        snapshot
    }

    /// Usernames with an authenticated BLE link, sorted for stable output.
    pub fn linked_peers(&self) -> Vec<String> {
        let links = match self.links.lock() {
            Ok(l) => l,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut names: Vec<String> = links.keys().cloned().collect();
        names.sort();
        names
    }

    /// Queues a raw HopChat packet for one peer.
    pub fn send_packet(&self, peer: &str, packet: &str) -> SendOutcome {
        self.send_packet_inner(peer, packet, None).0
    }

    /// Queues a packet and returns a receiver that fires when the peer
    /// acknowledges that message id over the BLE link. The outcome says only
    /// that the packet was queued; the receiver reports actual delivery.
    pub fn send_packet_awaiting_ack(
        &self,
        peer: &str,
        packet: &str,
        message_id: u64,
    ) -> (SendOutcome, Option<oneshot::Receiver<()>>) {
        self.send_packet_inner(peer, packet, Some(message_id))
    }

    fn send_packet_inner(
        &self,
        peer: &str,
        packet: &str,
        ack_id: Option<u64>,
    ) -> (SendOutcome, Option<oneshot::Receiver<()>>) {
        if !self.is_enabled() {
            return (SendOutcome::Disabled, None);
        }
        // Refusing here instead of queueing a packet the framer will discard
        // keeps the sender honest and lets it fall back to UDP.
        if packet.len() > MAX_PACKET_BYTES {
            return (SendOutcome::TooLarge, None);
        }

        // Register before queueing: the peer can answer as soon as the writer
        // has sent the last fragment, which may be before this function
        // returns on a fast local link.
        let receiver = if let Some(id) = ack_id {
            let (tx, rx) = oneshot::channel();
            let mut acks = match self.acks.lock() {
                Ok(a) => a,
                Err(poisoned) => poisoned.into_inner(),
            };
            acks.insert((peer.to_string(), id), tx);
            Some(rx)
        } else {
            None
        };

        let outcome = {
            let links = match self.links.lock() {
                Ok(l) => l,
                Err(poisoned) => poisoned.into_inner(),
            };
            match links.get(peer) {
                Some(entry) => match entry.tx.try_send(packet.as_bytes().to_vec()) {
                    Ok(()) => SendOutcome::Sent,
                    Err(mpsc::error::TrySendError::Full(_)) => SendOutcome::Busy,
                    Err(mpsc::error::TrySendError::Closed(_)) => SendOutcome::NotLinked,
                },
                None => SendOutcome::NotLinked,
            }
        };

        if outcome != SendOutcome::Sent {
            if let Some(id) = ack_id {
                self.forget_ack(peer, id);
            }
            return (outcome, None);
        }
        (outcome, receiver)
    }

    /// Completes a pending delivery when the peer acknowledges it over BLE.
    pub fn acknowledge(&self, peer: &str, message_id: u64) {
        let mut acks = match self.acks.lock() {
            Ok(a) => a,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(tx) = acks.remove(&(peer.to_string(), message_id)) {
            let _ = tx.send(());
        }
    }

    fn forget_ack(&self, peer: &str, message_id: u64) {
        let mut acks = match self.acks.lock() {
            Ok(a) => a,
            Err(poisoned) => poisoned.into_inner(),
        };
        acks.remove(&(peer.to_string(), message_id));
    }

    /// Fails every pending delivery for a peer whose link just closed, so the
    /// sender reports a real failure instead of waiting for the timeout.
    fn fail_pending_acks(&self, peer: &str) {
        let mut acks = match self.acks.lock() {
            Ok(a) => a,
            Err(poisoned) => poisoned.into_inner(),
        };
        acks.retain(|(name, _), _| name != peer);
    }

    pub(crate) async fn update<F>(&self, change: F)
    where
        F: FnOnce(&mut BleStatus),
    {
        let mut status = self.status.lock().await;
        change(&mut status);
        status.enabled = self.is_enabled();
    }

    pub(crate) async fn set_detail(&self, detail: impl Into<String>) {
        let detail = detail.into();
        self.update(|s| s.detail = detail).await;
    }

    /// Registers (or replaces) the outbound queue for an authenticated peer.
    /// Returns a token the caller must present to unregister this exact link.
    pub(crate) async fn register_link(&self, username: &str, tx: mpsc::Sender<Vec<u8>>) -> usize {
        let id = self.next_link_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut links = match self.links.lock() {
                Ok(l) => l,
                Err(poisoned) => poisoned.into_inner(),
            };
            links.insert(username.to_string(), LinkEntry { id, tx });
        }
        let count = self.linked_peers().len();
        self.update(|s| {
            s.links = count;
            s.detail = format!("linked with {} over Bluetooth", username);
        })
        .await;
        id
    }

    /// Drops a peer's outbound queue, but only if it is still the link that
    /// registered this token. Returns true when the link was actually removed.
    pub(crate) async fn unregister_link(&self, username: &str, token: usize) -> bool {
        let removed = {
            let mut links = match self.links.lock() {
                Ok(l) => l,
                Err(poisoned) => poisoned.into_inner(),
            };
            match links.get(username) {
                Some(entry) if entry.id == token => {
                    links.remove(username);
                    true
                }
                _ => false,
            }
        };
        if removed {
            self.fail_pending_acks(username);
        }
        let count = self.linked_peers().len();
        self.update(|s| {
            s.links = count;
            if removed && s.detail.starts_with("linked with") {
                s.detail = "Bluetooth link closed".to_string();
            }
        })
        .await;
        removed
    }
}

/// Everything the Bluetooth backend needs from the running app.
pub struct BleConfig {
    pub username: String,
    pub chat_port: u16,
    pub identity: Arc<LocalIdentity>,
    pub keypair: Arc<X25519KeyPair>,
    pub peers: PeerRegistry,
    pub peer_keys: PeerKeyRegistry,
    pub history: ChatHistory,
    pub trust_db: TrustRegistry,
}

/// Starts the Bluetooth backend. Returns immediately: the radio is brought up
/// in a background task so a permission prompt or an absent adapter can never
/// delay the TUI.
#[cfg(all(
    any(target_os = "macos", target_os = "linux"),
    not(target_arch = "x86")
))]
pub async fn start(config: BleConfig, enabled: Arc<AtomicBool>) -> BleHandle {
    let handle = BleHandle::new(enabled);
    let was_enabled = handle.is_enabled();
    handle
        .update(|s| {
            s.supported = true;
            s.detail = if was_enabled {
                "starting Bluetooth...".to_string()
            } else {
                "disabled at startup (use /bluetooth on)".to_string()
            };
        })
        .await;

    let config = Arc::new(config);
    let task_handle = handle.clone();
    tokio::spawn(async move {
        backend::run(config, task_handle).await;
    });
    handle
}

/// iSH and any other target without a BLE backend: report unavailable and
/// keep the rest of the app working unchanged.
#[cfg(not(all(
    any(target_os = "macos", target_os = "linux"),
    not(target_arch = "x86")
)))]
pub async fn start(_config: BleConfig, enabled: Arc<AtomicBool>) -> BleHandle {
    let handle = BleHandle::new(enabled);
    handle
        .update(|s| {
            s.supported = false;
            s.detail =
                "Bluetooth is unavailable on this platform. iSH cannot access Bluetooth hardware; Wi-Fi still works."
                    .to_string();
        })
        .await;
    handle
}

/// Returns the 10-character advertisement name for an Ed25519 public key.
///
/// Two devices both run a GATT server and a GATT client, so without a rule
/// they would connect to each other twice. The rule here is that only the node
/// with the lexicographically smaller name makes the outgoing connection. The
/// name is a hash, not the username, because BLE advertisements cannot carry a
/// 32-character name.
pub fn advert_name(public_key_hex: &str) -> String {
    use sha2::{Digest, Sha256};
    let bytes = hex::decode(public_key_hex).unwrap_or_default();
    let digest = Sha256::digest(&bytes);
    let tag = hex::encode(&digest[..4]);
    format!("{}{}", ADVERT_NAME_PREFIX, tag)
}

/// Current Unix time in seconds, used to keep replayed handshakes out.
pub(crate) fn read_packet_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Builds the signed introduction sent when a BLE link opens.
///
/// Format: `HOPCHAT_BLE|username|x25519|ed25519|sig|ip|port|timestamp`
/// The signature covers the X25519 key, the advertised address/port and the
/// timestamp, so a recorded hello cannot be replayed after the freshness
/// window or used to redirect a known peer to another host.
pub(crate) fn build_hello(config: &BleConfig) -> String {
    let ip = crate::get_local_ip();
    let timestamp = read_packet_timestamp();
    let x25519 = config.keypair.public_key_hex();
    let ed25519 = config.identity.public_key_hex();
    let signed = format!("{}|{}|{}|{}", x25519, ip, config.chat_port, timestamp);
    let signature = config.identity.sign_payload(signed.as_bytes());
    format!(
        "HOPCHAT_BLE|{}|{}|{}|{}|{}|{}|{}",
        config.username, x25519, ed25519, signature, ip, config.chat_port, timestamp
    )
}

// =============================================================================
// Framing
// =============================================================================

/// Splits one packet into BLE-sized frames.
///
/// Frame layout:
///   [0]     magic 'H'
///   [1]     version
///   [2..4]  message id (big endian)
///   [4..6]  fragment sequence (big endian, starts at 0)
///   [6]     total fragment count
///   [7..]   payload
pub fn fragment_packet(packet: &[u8], message_id: u16) -> Vec<Vec<u8>> {
    if packet.is_empty() || packet.len() > MAX_PACKET_BYTES {
        return Vec::new();
    }
    let total = (packet.len() + MAX_FRAGMENT_PAYLOAD - 1) / MAX_FRAGMENT_PAYLOAD;
    if total == 0 || total > MAX_FRAGMENTS {
        return Vec::new();
    }

    let mut frames = Vec::with_capacity(total);
    for (index, chunk) in packet.chunks(MAX_FRAGMENT_PAYLOAD).enumerate() {
        let seq = index as u16;
        let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + chunk.len());
        frame.push(FRAME_MAGIC);
        frame.push(FRAME_VERSION);
        frame.extend_from_slice(&message_id.to_be_bytes());
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.push(total as u8);
        frame.extend_from_slice(chunk);
        frames.push(frame);
    }
    frames
}

/// Reassembles one peer's frames back into packets.
///
/// Frames on a BLE link arrive in order, but a disconnection or a dropped
/// notification can leave a hole. In that case the partial packet is dropped
/// and the receiver waits for the next fragment zero. Partial packets also
/// expire, so a truncated message cannot hold memory forever.
pub struct Reassembler {
    active: bool,
    message_id: u16,
    total: u16,
    next_seq: u16,
    buffer: Vec<u8>,
    last_activity: Instant,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    pub fn new() -> Self {
        Self {
            active: false,
            message_id: 0,
            total: 0,
            next_seq: 0,
            buffer: Vec::new(),
            last_activity: Instant::now(),
        }
    }

    /// Feeds one frame in; returns a complete packet when the last fragment
    /// arrives.
    pub fn push(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        if frame.len() <= FRAME_HEADER_LEN || frame[0] != FRAME_MAGIC || frame[1] != FRAME_VERSION {
            return None;
        }

        let message_id = u16::from_be_bytes([frame[2], frame[3]]);
        let seq = u16::from_be_bytes([frame[4], frame[5]]);
        let total = frame[6] as u16;
        let payload = &frame[FRAME_HEADER_LEN..];

        if total == 0 || total > MAX_FRAGMENTS as u16 || seq >= total {
            self.active = false;
            return None;
        }
        if self.buffer.len() + payload.len() > MAX_PACKET_BYTES {
            self.active = false;
            return None;
        }

        let now = Instant::now();
        if self.active && now.duration_since(self.last_activity) > REASSEMBLY_TIMEOUT {
            self.active = false;
            self.buffer.clear();
        }

        if seq == 0 {
            // A new packet always starts cleanly, even if the previous one
            // never finished.
            self.active = true;
            self.message_id = message_id;
            self.total = total;
            self.next_seq = 0;
            self.buffer.clear();
        } else if !self.active || message_id != self.message_id || total != self.total {
            return None;
        }

        if seq != self.next_seq {
            // Hole in the sequence: discard the partial packet.
            self.active = false;
            self.buffer.clear();
            return None;
        }

        self.buffer.extend_from_slice(payload);
        self.next_seq += 1;
        self.last_activity = now;

        if self.next_seq == self.total {
            self.active = false;
            Some(std::mem::take(&mut self.buffer))
        } else {
            None
        }
    }
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux"),
    not(target_arch = "x86")
))]
mod backend;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packets_round_trip_through_fragments() {
        let packet = vec![b'x'; MAX_FRAGMENT_PAYLOAD * 3 + 17];
        let frames = fragment_packet(&packet, 42);
        assert_eq!(frames.len(), 4);

        let mut reassembler = Reassembler::new();
        let mut result = None;
        for frame in frames {
            result = reassembler.push(&frame).or(result);
        }
        assert_eq!(result, Some(packet));
    }

    #[test]
    fn a_dropped_fragment_discards_the_whole_packet() {
        let packet = vec![b'y'; MAX_FRAGMENT_PAYLOAD * 2 + 1];
        let frames = fragment_packet(&packet, 7);
        assert_eq!(frames.len(), 3);

        let mut reassembler = Reassembler::new();
        assert!(reassembler.push(&frames[0]).is_none());
        // Skip frame 1, deliver frame 2: the gap must drop the packet.
        assert!(reassembler.push(&frames[2]).is_none());
        // The next complete message is still accepted.
        let next = fragment_packet(b"hello", 8);
        let mut result = None;
        for frame in next {
            result = reassembler.push(&frame).or(result);
        }
        assert_eq!(result, Some(b"hello".to_vec()));
    }

    #[test]
    fn a_new_message_replaces_a_stale_partial_with_the_same_id() {
        // The 16-bit wire id can wrap or be reused. A stale partial must not
        // merge into the next complete packet, because every new message
        // starts at sequence zero and resets the reassembler.
        let stale = fragment_packet(&[b'a'; MAX_FRAGMENT_PAYLOAD + 10], 99);
        let fresh = fragment_packet(b"new message", 99);

        let mut reassembler = Reassembler::new();
        assert!(reassembler.push(&stale[0]).is_none());

        let mut result = None;
        for frame in fresh {
            result = reassembler.push(&frame).or(result);
        }
        assert_eq!(result, Some(b"new message".to_vec()));
    }

    #[tokio::test]
    async fn a_queued_message_is_delivered_only_after_its_ack() {
        let handle = BleHandle::new(Arc::new(AtomicBool::new(true)));
        let (tx, _rx) = mpsc::channel(4);
        handle.register_link("bob", tx).await;

        let (outcome, ack) = handle.send_packet_awaiting_ack("bob", "packet", 42);
        assert_eq!(outcome, SendOutcome::Sent);
        let ack = ack.expect("a queued packet must have a delivery waiter");

        // An acknowledgement for the wrong peer or id must not complete it.
        handle.acknowledge("alice", 42);
        handle.acknowledge("bob", 41);

        handle.acknowledge("bob", 42);
        assert!(tokio::time::timeout(Duration::from_secs(1), ack)
            .await
            .expect("acknowledgement should arrive")
            .is_ok());
    }

    #[test]
    fn advert_name_is_short_and_stable() {
        let name = advert_name("ab".repeat(32).as_str());
        assert!(name.starts_with(ADVERT_NAME_PREFIX));
        assert_eq!(name.len(), ADVERT_NAME_PREFIX.len() + 8);
        assert_eq!(name, advert_name("ab".repeat(32).as_str()));
    }
}
