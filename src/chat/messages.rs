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
use std::time::{SystemTime, UNIX_EPOCH};

// [SEC-8] Use AtomicU64 on 64-bit targets for lock-free, panic-proof ID generation.
// On 32-bit targets (iSH/i586), AtomicU64 may not be available, so fall back to Mutex<u64>.

#[cfg(target_pointer_width = "64")]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(not(target_pointer_width = "64"))]
use std::sync::Mutex;

#[cfg(target_pointer_width = "64")]
static NEXT_MESSAGE_ID: Lazy<AtomicU64> = Lazy::new(|| {
    AtomicU64::new(rand::thread_rng().gen::<u64>())
});

#[cfg(not(target_pointer_width = "64"))]
static NEXT_MESSAGE_ID: Lazy<Mutex<u64>> = Lazy::new(|| {
    Mutex::new(rand::thread_rng().gen::<u64>())
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

        // [SEC-8] Increment the ID generator atomically (64-bit) or via Mutex (32-bit)
        #[cfg(target_pointer_width = "64")]
        let id = NEXT_MESSAGE_ID.fetch_add(1, Ordering::Relaxed);

        #[cfg(not(target_pointer_width = "64"))]
        let id = {
            // On 32-bit targets, use Mutex. unwrap_or_else handles poison gracefully.
            let mut lock = NEXT_MESSAGE_ID.lock().unwrap_or_else(|e| e.into_inner());
            let current = *lock;
            *lock = current.wrapping_add(1);
            current
        };

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
    /// [SEC-1] Properly propagates serialization errors instead of silently sending empty strings.
    pub fn to_packet_string(&self, key: &[u8; 32]) -> Result<String, String> {
        let json_payload = serde_json::to_string(self)
            .map_err(|e| format!("Message serialization failed: {}", e))?;
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

// CHANGES:
// [SEC-1] to_packet_string: Replaced unwrap_or_default() with proper error propagation
//         via map_err. Empty-string encryption on serialization failure is no longer possible.
// [SEC-8] Replaced global Mutex<u64> with AtomicU64 on 64-bit targets for lock-free,
//         panic-proof ID generation. 32-bit targets retain Mutex with poison recovery
//         via unwrap_or_else(|e| e.into_inner()).
