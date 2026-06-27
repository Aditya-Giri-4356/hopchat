// =============================================================================
// HOPCHAT — Crypto Module: XChaCha20-Poly1305 Encryption
// =============================================================================
//
// Provides end-to-end encryption for chat messages using the pure-Rust
// `chacha20poly1305` crate.
//
// Data format: [24-byte XNonce][Encrypted Payload (Ciphertext + MAC)]
// For UDP transport, the resulting binary is hex-encoded into a string.

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;

/// Encrypts a plaintext string and returns a hex-encoded string containing
/// the nonce and ciphertext.
pub fn encrypt_message(key: &[u8; 32], plaintext: &str) -> Result<String, String> {
    let cipher = XChaCha20Poly1305::new(key.into());

    // Generate a random 24-byte nonce (XNonce)
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    // Encrypt the payload
    // Aead::encrypt returns Ciphertext + MAC
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Prepend the 24-byte nonce to the ciphertext
    let mut combined = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    // Encode to a hex string for safe transmission over UDP string packets
    Ok(hex::encode(combined))
}

/// Decrypts a hex-encoded string containing the nonce and ciphertext,
/// returning the plaintext string on success.
pub fn decrypt_message(key: &[u8; 32], hex_payload: &str) -> Result<String, String> {
    // Decode the hex string back to binary
    let combined = hex::decode(hex_payload)
        .map_err(|e| format!("Hex decode error: {}", e))?;

    // Ensure the payload is at least as long as the 24-byte nonce
    if combined.len() < 24 {
        return Err("Payload too short (missing nonce)".to_string());
    }

    let cipher = XChaCha20Poly1305::new(key.into());

    // Split the combined data into nonce and ciphertext
    let (nonce_bytes, ciphertext) = combined.split_at(24);
    let nonce = XNonce::from_slice(nonce_bytes);

    // Decrypt the payload
    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption/Authentication failed".to_string())?;

    // Convert back to a UTF-8 string
    String::from_utf8(plaintext_bytes)
        .map_err(|e| format!("Invalid UTF-8 in decrypted data: {}", e))
}
