// =============================================================================
// HOPCHAT — Chat Module: Message Structure
// =============================================================================
//
// Defines the ChatMessage struct used for all peer-to-peer communication.
// Messages are serialized to a custom pipe-delimited string format:
// HOPCHAT_MSG|id|sender|receiver|timestamp|content

use crate::crypto::encryption;
use once_cell::sync::Lazy;
use rand::Rng;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A thread-safe ID generator for outgoing messages.
/// Seeded from a random starting point to prevent adversaries from
/// counting messages by observing sequential ACK IDs on the wire.
/// Uses AtomicUsize (not AtomicU64) for 32-bit i686 target compatibility.
static NEXT_MESSAGE_ID: Lazy<AtomicUsize> = Lazy::new(|| {
    AtomicUsize::new(rand::thread_rng().gen::<usize>())
});

use serde::{Serialize, Deserialize};

/// Represents a single chat message between peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// A unique incrementing ID for this message
    pub id: u64,
    /// The username of the sender
    pub sender: String,
    /// The username of the receiver
    pub receiver: String,
    /// The message content string
    pub content: String,
    /// Unix timestamp in seconds
    pub timestamp: u64,
}

impl ChatMessage {
    /// Creates a new ChatMessage with an auto-incrementing ID and current timestamp.
    pub fn new(sender: &str, receiver: &str, content: &str) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Increment the ID generator for each new outgoing message
        let id = NEXT_MESSAGE_ID.fetch_add(1, Ordering::SeqCst) as u64;

        Self {
            id,
            sender: sender.to_string(),
            receiver: receiver.to_string(),
            content: content.to_string(),
            timestamp,
        }
    }

    /// Serializes the entire message struct to JSON, encrypts it into a hex string,
    /// and returns the HOPCHAT_MSG pipe-delimited boundary format.
    /// This completely masks routing metadata (sender, receiver, id, timestamp)
    /// from the local network.
    pub fn to_packet_string(&self, key: &[u8; 32]) -> Result<String, String> {
        let json_payload = serde_json::to_string(self).unwrap_or_default();
        let ciphertext_hex = encryption::encrypt_message(key, &json_payload)?;
        Ok(format!("HOPCHAT_MSG|{}", ciphertext_hex))
    }

    /// Deserializes a ChatMessage from the HOPCHAT_MSG pipe-delimited format,
    /// decrypting the hex payload and expanding the JSON back into a struct.
    /// Fails silently (returns None) if decryption or parsing fails.
    pub fn from_packet_string(text: &str, key: &[u8; 32]) -> Option<Self> {
        let parts: Vec<&str> = text.splitn(2, '|').collect();
        if parts.len() == 2 && parts[0] == "HOPCHAT_MSG" {
            let ciphertext_hex = parts[1];
            
            // Attempt to decrypt; drop packet if it fails authentication
            // (e.g. if we are trial-decrypting with the wrong peer key)
            if let Ok(json_payload) = encryption::decrypt_message(key, ciphertext_hex) {
                if let Ok(msg) = serde_json::from_str::<Self>(&json_payload) {
                    return Some(msg);
                }
            }
        }
        None
    }
}
