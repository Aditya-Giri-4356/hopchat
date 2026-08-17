// =============================================================================
// HOPCHAT — Crypto Module: Constant-Time Verification Utilities
// =============================================================================
//
// Provides constant-time comparison to prevent timing side-channel attacks
// when comparing cryptographic material (TOFU fingerprints, key hashes).
//
// Note: ed25519-dalek's verify() already uses the `subtle` crate internally
// for constant-time signature verification. This module covers our own
// application-level comparisons.

/// Constant-time equality check for byte slices.
///
/// Uses XOR accumulation — the control flow does not depend on the content
/// of either slice, only on their lengths. This prevents an attacker from
/// measuring response time to learn partial matches.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

/// Constant-time equality check for hex-encoded strings.
///
/// Decodes both strings to bytes first, then compares in constant time.
/// Returns false if either string is not valid hex.
pub fn ct_eq_hex(a: &str, b: &str) -> bool {
    let a_bytes = match hex::decode(a) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let b_bytes = match hex::decode(b) {
        Ok(b) => b,
        Err(_) => return false,
    };
    ct_eq(&a_bytes, &b_bytes)
}
