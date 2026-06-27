// =============================================================================
// HOPCHAT — User Module: Identity Management
// =============================================================================
//
// Manages the local user's long-term cryptographic identity using ed25519-dalek.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

/// The structure saved to `~/.hopchat_id` providing persistent identity
#[derive(Serialize, Deserialize)]
pub struct LocalIdentity {
    pub username: String,
    // Store the 32-byte secret seed to reconstruct the SigningKey
    pub secret_seed: [u8; 32],
}

impl LocalIdentity {
    /// Loads the identity from `~/.hopchat_id` or creates a new one
    pub fn load_or_create(raw_username: &str) -> Self {
        // Defense-in-Depth: Sanitize even if the caller already did.
        let safe_username: String = raw_username.chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
            
        let username = if safe_username.is_empty() {
            "anon".to_string()
        } else {
            safe_username
        };

        let path = Self::get_path(&username);

        if path.exists() {
            if let Ok(data) = fs::read_to_string(&path) {
                if let Ok(mut identity) = serde_json::from_str::<LocalIdentity>(&data) {
                    // Update username if they typed a new one, but keep the private key
                    if identity.username != username {
                        identity.username = username.to_string();
                        identity.save();
                    }
                    return identity;
                }
            }
        }

        // Generate a new long-term Ed25519 identity
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        
        let mut seed = [0u8; 32];
        seed.copy_from_slice(signing_key.to_bytes().as_slice());

        let identity = LocalIdentity {
            username: username.to_string(),
            secret_seed: seed,
        };
        identity.save();
        identity
    }

    /// Returns the active SigningKey
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.secret_seed)
    }

    /// Returns our public key hex for transmitting in handshakes
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key().verifying_key().to_bytes())
    }

    /// Signs a payload (like the ephemeral X25519 key) to prove identity ownership
    pub fn sign_payload(&self, payload: &[u8]) -> String {
        let signature = self.signing_key().sign(payload);
        hex::encode(signature.to_bytes())
    }

    /// Verifies another peer's signature over a payload given their public key hex
    pub fn verify_signature(pub_hex: &str, payload: &[u8], sig_hex: &str) -> bool {
        let pub_bytes = match hex::decode(pub_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => return false,
        };
        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) if b.len() == 64 => b,
            _ => return false,
        };

        if let Ok(verifying_key) = VerifyingKey::from_bytes(pub_bytes.as_slice().try_into().unwrap()) {
            if let Ok(signature) = Signature::from_slice(&sig_bytes) {
                return verifying_key.verify(payload, &signature).is_ok();
            }
        }
        false
    }

    /// Generates a "Trust on First Use" (TOFU) fingerprint.
    /// This is a truncated SHA-256 hash of the persistent Ed25519 public key.
    /// Used by the UI to display a "Security Code" so humans can verify
    /// non-MITM'd channels out-of-band if necessary.
    pub fn tofu_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.signing_key().verifying_key().to_bytes());
        let result = hasher.finalize();
        let hex = hex::encode(result);
        hex[..16].to_string()
    }

    fn get_path(username: &str) -> PathBuf {
        let mut path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push(format!(".hopchat_id_{}", username));
        path
    }

    fn save(&self) {
        if let Ok(json) = serde_json::to_string_pretty(self) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create(true).truncate(true).mode(0o600);
                if let Ok(mut file) = options.open(Self::get_path(&self.username)) {
                    let _ = std::io::Write::write_all(&mut file, json.as_bytes());
                }
            }
            #[cfg(not(unix))]
            {
                let _ = fs::write(Self::get_path(&self.username), json);
            }
        }
    }
}
