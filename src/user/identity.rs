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

/// The structure saved to `~/.hopchat_id` providing persistent identity.
/// Note: `signing_key`, `verifying_key`, and `tofu` are derived caches
/// computed once at load time and not serialized.
#[derive(Serialize, Deserialize)]
pub struct LocalIdentity {
    pub username: String,
    // Store the 32-byte secret seed to reconstruct the SigningKey.
    // Private: no external module should access the raw secret directly.
    secret_seed: [u8; 32],
    // Cached derived values — computed once, not serialized
    #[serde(skip)]
    signing_key: Option<SigningKey>,
    #[serde(skip)]
    verifying_key: Option<VerifyingKey>,
    #[serde(skip)]
    tofu: Option<String>,
}

impl Drop for LocalIdentity {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret_seed.zeroize();
    }
}

impl LocalIdentity {
    /// Initializes the cached derived values from the secret seed.
    /// Must be called after deserialization or construction.
    fn init_cached(&mut self) {
        let sk = SigningKey::from_bytes(&self.secret_seed);
        let vk = sk.verifying_key();
        // Compute TOFU fingerprint once
        let mut hasher = Sha256::new();
        hasher.update(vk.to_bytes());
        let result = hasher.finalize();
        let hex_str = hex::encode(result);
        self.tofu = Some(hex_str[..16].to_string());
        self.verifying_key = Some(vk);
        self.signing_key = Some(sk);
    }

    /// Loads the identity from `~/.hopchat_id` or creates a new one
    pub fn load_or_create(raw_username: &str) -> Self {
        // Defense-in-Depth: Sanitize even if the caller already did.
        let safe_username: String = raw_username
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();

        let username = if safe_username.is_empty() {
            "anon".to_string()
        } else {
            safe_username
        };

        let path = Self::get_path(&username);

        if path.exists() {
            match fs::read_to_string(&path) {
                Ok(data) => match serde_json::from_str::<LocalIdentity>(&data) {
                    Ok(mut identity) => {
                        // Update username if they typed a new one, but keep the private key
                        if identity.username != username {
                            identity.username = username.to_string();
                            identity.init_cached();
                            identity.save();
                        } else {
                            identity.init_cached();
                        }
                        return identity;
                    }
                    Err(e) => eprintln!(
                        "[hopchat] identity file {} is corrupt ({}); generating a new identity",
                        path.display(),
                        e
                    ),
                },
                Err(e) => eprintln!(
                    "[hopchat] could not read identity file {}: {}; generating a new identity",
                    path.display(),
                    e
                ),
            }
        }

        // Generate a new long-term Ed25519 identity
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        let mut seed = [0u8; 32];
        seed.copy_from_slice(signing_key.to_bytes().as_slice());

        let mut identity = LocalIdentity {
            username: username.to_string(),
            secret_seed: seed,
            signing_key: None,
            verifying_key: None,
            tofu: None,
        };
        identity.init_cached();
        identity.save();
        identity
    }

    /// Returns our public key hex for transmitting in handshakes.
    /// Uses the cached verifying key, deriving it only if the cache is absent.
    pub fn public_key_hex(&self) -> String {
        let bytes = match &self.verifying_key {
            Some(verifying_key) => verifying_key.to_bytes(),
            None => SigningKey::from_bytes(&self.secret_seed)
                .verifying_key()
                .to_bytes(),
        };
        hex::encode(bytes)
    }

    /// Signs a payload (like the ephemeral X25519 key) to prove identity ownership.
    /// Uses the cached signing key, deriving it only if the cache is absent.
    pub fn sign_payload(&self, payload: &[u8]) -> String {
        let signature = match &self.signing_key {
            Some(signing_key) => signing_key.sign(payload),
            None => SigningKey::from_bytes(&self.secret_seed).sign(payload),
        };
        hex::encode(signature.to_bytes())
    }

    /// Verifies another peer's signature over a payload given their public key hex.
    /// This function is entirely infallible — every error path returns `false`.
    /// [SEC-2] Uses explicit fallible conversion instead of try_into().unwrap().
    pub fn verify_signature(pub_hex: &str, payload: &[u8], sig_hex: &str) -> bool {
        let pub_bytes = match hex::decode(pub_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => return false,
        };
        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) if b.len() == 64 => b,
            _ => return false,
        };

        // [SEC-2] Explicit fallible conversion — never panics
        let pub_array: [u8; 32] = match pub_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let verifying_key = match VerifyingKey::from_bytes(&pub_array) {
            Ok(k) => k,
            Err(_) => return false,
        };

        if let Ok(signature) = Signature::from_slice(&sig_bytes) {
            return verifying_key.verify(payload, &signature).is_ok();
        }
        false
    }

    /// Returns the pre-computed TOFU fingerprint.
    /// This is a truncated SHA-256 hash of the persistent Ed25519 public key,
    /// used by the UI to display a "Security Code" for out-of-band verification.
    pub fn tofu_fingerprint(&self) -> String {
        if let Some(fingerprint) = &self.tofu {
            return fingerprint.clone();
        }

        let verifying_key = match &self.verifying_key {
            Some(key) => key.to_bytes(),
            None => SigningKey::from_bytes(&self.secret_seed)
                .verifying_key()
                .to_bytes(),
        };
        let mut hasher = Sha256::new();
        hasher.update(verifying_key);
        let digest = hex::encode(hasher.finalize());
        digest[..16].to_string()
    }

    fn get_path(username: &str) -> PathBuf {
        let mut path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push(format!(".hopchat_id_{}", username));
        path
    }

    fn save(&self) {
        let json = match serde_json::to_string_pretty(self) {
            Ok(json) => json,
            Err(e) => {
                eprintln!("[hopchat] could not serialize identity: {}", e);
                return;
            }
        };
        // This file holds the long-term signing seed: 0600 on every write,
        // not only when it is first created.
        if let Err(e) = crate::user::write_private_file(&Self::get_path(&self.username), json.as_bytes()) {
            eprintln!("[hopchat] could not write identity: {}", e);
        }
    }
}
