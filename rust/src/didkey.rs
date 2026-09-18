//! `did:key` decoding (base58btc multicodec 0xed01) and Ed25519 verification.
//!
//! Mirrors `continuity_receipt/keys.py`: `did_key_to_pubkey` requires the
//! `did:key:z` prefix, 34 decoded bytes, and the `0xed 0x01` Ed25519
//! multicodec prefix. Verification returns `false` for any malformed input
//! rather than raising, exactly like `keys.verify`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

const MULTICODEC_ED25519: [u8; 2] = [0xed, 0x01];

/// Decode a `did:key` Ed25519 public key to its raw 32 bytes.
pub fn decode_public_key(did: &str) -> Option<[u8; 32]> {
    let encoded = did.strip_prefix("did:key:z")?;
    let raw = bs58::decode(encoded).into_vec().ok()?;
    if raw.len() != 34 || raw[..2] != MULTICODEC_ED25519 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw[2..]);
    Some(key)
}

/// Decode unpadded (or padded) URL-safe base64 as the Python reference does.
pub fn b64u_decode(text: &str) -> Option<Vec<u8>> {
    let trimmed = text.trim_end_matches('=');
    URL_SAFE_NO_PAD.decode(trimmed).ok()
}

/// Verify an Ed25519 signature made by `pubkey_did` over `message`.
pub fn verify(pubkey_did: &str, message: &[u8], signature_b64u: &str) -> bool {
    let Some(key_bytes) = decode_public_key(pubkey_did) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Some(signature_bytes) = b64u_decode(signature_b64u) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&signature_bytes) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}
