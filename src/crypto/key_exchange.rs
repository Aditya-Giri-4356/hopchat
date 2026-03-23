// =============================================================================
// HOPCHAT — Crypto Module: X25519 Key Exchange
// =============================================================================
//
// Implements Diffie-Hellman key exchange using X25519 to establish secure
// symmetric session keys between peers dynamically.
// Also uses SHA-256 to hash the shared secret into a 32-byte key suitable
// for XChaCha20-Poly1305.

use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// Represents a local user's X25519 keypair.
pub struct X25519KeyPair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl X25519KeyPair {
    /// Generates a new random X25519 keypair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Returns the public key encoded as a hex string for UDP transport.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public.as_bytes())
    }

    /// Derives a 32-byte symmetric session key given a peer's hex public key.
    /// Uses X25519 Diffie-Hellman and passes the resulting shared secret
    /// through SHA-256.
    pub fn derive_session_key(&self, peer_pub_key_hex: &str) -> Result<[u8; 32], String> {
        // Decode the hex string back to binary
        let peer_bytes = hex::decode(peer_pub_key_hex)
            .map_err(|e| format!("Peer public key hex decode error: {}", e))?;

        if peer_bytes.len() != 32 {
            return Err("Peer public key must be exactly 32 bytes".to_string());
        }

        // Parse into an X25519 PublicKey
        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(&peer_bytes);
        let peer_public = PublicKey::from(public_bytes);

        // Perform Diffie-Hellman Key Agreement
        let shared_secret = self.secret.diffie_hellman(&peer_public);

        // Hash the resulting secret bytes through SHA-256 to derive a strong symmetric key
        let mut hasher = Sha256::new();
        hasher.update(shared_secret.as_bytes());
        let result = hasher.finalize();

        let mut symmetric_key = [0u8; 32];
        symmetric_key.copy_from_slice(&result);

        Ok(symmetric_key)
    }

    /// Generates a "Trust on First Use" (TOFU) fingerprint.
    /// This is a truncated SHA-256 hash of the X25519 public key.
    /// Used by the UI to display a "Security Code" so humans can verify
    /// non-MITM'd channels out-of-band if necessary.
    pub fn tofu_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.public.as_bytes());
        let result = hasher.finalize();
        let hex = hex::encode(result);
        hex[..16].to_string()
    }
}
