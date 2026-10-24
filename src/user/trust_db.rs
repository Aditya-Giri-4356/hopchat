// =============================================================================
// HOPCHAT — User Module: TOFU Trust Database
// =============================================================================
//
// Persists Trust-On-First-Use (TOFU) fingerprints to disk so that identity
// pinning survives across restarts. Without this, an attacker only needs to
// wait for a restart to impersonate a peer.
//
// Storage: ~/.hopchat_trust_db (JSON, chmod 0600 on Unix)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// On-disk trust database mapping peer usernames to their pinned Ed25519
/// public key hex strings.
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct TrustDb {
    /// Maps peer username → Ed25519 public key hex (pinned on first contact)
    pub known_peers: HashMap<String, String>,
}

impl TrustDb {
    /// Loads the trust database from disk, or returns an empty one if the
    /// file doesn't exist or is corrupt.
    pub fn load() -> Self {
        let path = Self::db_path();
        match std::fs::read_to_string(&path) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Saves the trust database to disk with restrictive permissions.
    pub fn save(&self) {
        let path = Self::db_path();
        let json = match serde_json::to_string_pretty(self) {
            Ok(j) => j,
            Err(_) => return,
        };

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true).mode(0o600);
            if let Ok(mut file) = opts.open(&path) {
                let _ = std::io::Write::write_all(&mut file, json.as_bytes());
            }
        }

        #[cfg(not(unix))]
        {
            let _ = std::fs::write(&path, json);
        }
    }

    /// Verifies a peer's identity against the trust database.
    ///
    /// - First contact: pins the fingerprint and returns `true`.
    /// - Known peer, same key: returns `true`.
    /// - Known peer, DIFFERENT key: returns `false` (possible MITM).
    ///
    /// Constant-time comparison is used to prevent timing side-channels.
    pub fn verify_or_pin(&mut self, username: &str, ed25519_pub_hex: &str) -> bool {
        if let Some(pinned) = self.known_peers.get(username) {
            // Existing peer — compare using constant-time equality
            let matches = crate::crypto::verify::ct_eq_hex(pinned, ed25519_pub_hex);
            if !matches {
                eprintln!(
                    "⚠️  CRITICAL SECURITY ALERT: Peer '{}' presented a DIFFERENT identity key!",
                    username
                );
                eprintln!("   Pinned:   {}", pinned);
                eprintln!("   Received: {}", ed25519_pub_hex);
                eprintln!("   This may indicate a Man-in-the-Middle attack. Packet dropped.");
            }
            matches
        } else {
            // First contact — pin this identity
            self.known_peers.insert(username.to_string(), ed25519_pub_hex.to_string());
            self.save();
            true
        }
    }

    /// Every pinned username and its hex public key, sorted by name.
    pub fn entries(&self) -> Vec<(String, String)> {
        let mut all: Vec<(String, String)> = self
            .known_peers
            .iter()
            .map(|(user, key)| (user.clone(), key.clone()))
            .collect();
        all.sort_by(|a, b| a.0.cmp(&b.0));
        all
    }

    /// Forgets a pinned key so the peer is re-pinned on next contact.
    ///
    /// Without this, a peer who reinstalls and regenerates their identity is
    /// locked out for good: their new key fails the mismatch check every time
    /// and the only escape is deleting the database file by hand.
    pub fn unpin(&mut self, username: &str) -> bool {
        let removed = self.known_peers.remove(username).is_some();
        if removed {
            self.save();
        }
        removed
    }

    fn db_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".hopchat_trust_db")
    }
}
