//! Selective disclosure tooling for Continuity Receipt bundles.
//!
//! Mirrors `continuity_receipt/disclose.py`: replace optional fields with
//! salted commitments, keep the salt+value map separate, and merge a map back
//! into a bundle for verification. Path grammar matches the verifier:
//! `receipts[i].body.<field>[.<nested>...]`.
//!
//! Redaction is an issuance-time act: the modified receipts (and everything
//! after them) are re-signed, so `redact` requires the issuer's signing key.

use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::canon::{canonical_bytes, commit_field, CanonError};
use crate::verify::{receipt_digest, required_field_for_path, unsigned_view};

/// Disclosure tooling failure (malformed path, required field, missing signer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscloseError(pub String);

impl fmt::Display for DiscloseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for DiscloseError {}

impl From<CanonError> for DiscloseError {
    fn from(error: CanonError) -> Self {
        Self(error.0)
    }
}

fn malformed(path: &str) -> DiscloseError {
    DiscloseError(format!("malformed path: {path:?}"))
}

fn tokens(path: &str) -> Result<Vec<&str>, DiscloseError> {
    let parts: Vec<&str> = path.split('.').collect();
    if parts.is_empty() || parts.iter().any(|part| part.is_empty()) {
        return Err(malformed(path));
    }
    Ok(parts)
}

/// Parse one `name[123]` index token (`^([A-Za-z_][A-Za-z0-9_]*)\[(\d+)\]$`).
fn index_token(token: &str) -> Option<(&str, usize)> {
    let (name, rest) = token.split_once('[')?;
    let digits = rest.strip_suffix(']')?;
    let mut characters = name.chars();
    let first = characters.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    if !characters.all(|character| character.is_ascii_alphanumeric() || character == '_') {
        return None;
    }
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some((name, digits.parse().ok()?))
}

fn descend<'a>(node: &'a Value, token: &str) -> Option<&'a Value> {
    match index_token(token) {
        Some((name, index)) => node.get(name)?.as_array()?.get(index),
        None => node.get(token),
    }
}

fn descend_mut<'a>(node: &'a mut Value, token: &str) -> Result<&'a mut Value, DiscloseError> {
    let missing = || DiscloseError(format!("path not found: {token}"));
    match index_token(token) {
        Some((name, index)) => node
            .get_mut(name)
            .and_then(Value::as_array_mut)
            .and_then(|array| array.get_mut(index))
            .ok_or_else(missing),
        None => node.get_mut(token).ok_or_else(missing),
    }
}

fn walk<'a>(node: &'a Value, path: &str) -> Result<&'a Value, DiscloseError> {
    let mut current = node;
    for token in tokens(path)? {
        current = descend(current, token)
            .ok_or_else(|| DiscloseError(format!("path not found: {path}")))?;
    }
    Ok(current)
}

fn set_value(node: &mut Value, path: &str, value: Value) -> Result<(), DiscloseError> {
    let parts = tokens(path)?;
    let (last, parents) = parts.split_last().expect("tokens are non-empty");
    let mut current = node;
    for token in parents {
        current = descend_mut(current, token)?;
    }
    match index_token(last) {
        Some((name, index)) => {
            let slot = current
                .get_mut(name)
                .and_then(Value::as_array_mut)
                .and_then(|array| array.get_mut(index))
                .ok_or_else(|| DiscloseError(format!("path not found: {path}")))?;
            *slot = value;
        }
        None => {
            let map = current
                .as_object_mut()
                .ok_or_else(|| DiscloseError(format!("path not found: {path}")))?;
            map.insert((*last).to_string(), value);
        }
    }
    Ok(())
}

fn receipt_index(path: &str) -> Result<usize, DiscloseError> {
    let parts = tokens(path)?;
    match index_token(parts[0]) {
        Some(("receipts", index)) => Ok(index),
        _ => Err(DiscloseError(format!(
            "path must start with receipts[i]: {path:?}"
        ))),
    }
}

/// `did:key` for an Ed25519 signing key (base58btc multicodec `0xed01`).
#[must_use]
pub fn did_from_signing_key(key: &SigningKey) -> String {
    let public = key.verifying_key().to_bytes();
    let mut multicodec = Vec::with_capacity(34);
    multicodec.extend_from_slice(&[0xed, 0x01]);
    multicodec.extend_from_slice(&public);
    format!("did:key:z{}", bs58::encode(multicodec).into_string())
}

fn random_salt_hex() -> Result<String, DiscloseError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| DiscloseError(format!("os randomness unavailable: {error}")))?;
    let mut out = String::with_capacity(32);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

/// `records.sign_receipt`: sign the unsigned view, then append the signature.
fn sign_receipt(receipt: &Map<String, Value>, key: &SigningKey) -> Result<Value, DiscloseError> {
    let message = canonical_bytes(&Value::Object(unsigned_view(receipt)))?;
    let signature = key.sign(&message);
    let mut signed = receipt.clone();
    signed.insert(
        "sig".to_string(),
        serde_json::json!({
            "alg": "ed25519",
            "key": did_from_signing_key(key),
            "value": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        }),
    );
    Ok(Value::Object(signed))
}

/// Rebuild `prev` links and signatures from `start` to the end of the chain.
fn resign_tail(bundle: &mut Value, start: usize, key: &SigningKey) -> Result<(), DiscloseError> {
    let did = did_from_signing_key(key);
    let receipts = bundle
        .get_mut("receipts")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| DiscloseError("bundle has no receipts list".to_string()))?;
    let mut prev = if start > 0 {
        let previous = receipts
            .get(start - 1)
            .and_then(Value::as_object)
            .ok_or_else(|| DiscloseError("receipt is not an object".to_string()))?;
        Some(receipt_digest(previous)?)
    } else {
        None
    };
    for (index, slot) in receipts.iter_mut().enumerate().skip(start) {
        let mut receipt = std::mem::take(slot);
        let map = receipt
            .as_object_mut()
            .ok_or_else(|| DiscloseError("receipt is not an object".to_string()))?;
        let issuer = map
            .get("issuer")
            .and_then(Value::as_object)
            .and_then(|issuer| issuer.get("id"))
            .and_then(Value::as_str)
            .map(str::to_string);
        if issuer.as_deref() != Some(did.as_str()) {
            return Err(DiscloseError(format!(
                "receipt {index} issuer {issuer:?} != signer {did:?}; cannot re-sign"
            )));
        }
        map.insert("seq".to_string(), serde_json::json!(index));
        map.insert(
            "prev".to_string(),
            prev.clone().map_or(Value::Null, Value::String),
        );
        map.remove("sig");
        *slot = sign_receipt(map, key)?;
        let updated = slot
            .as_object()
            .ok_or_else(|| DiscloseError("receipt is not an object".to_string()))?;
        prev = Some(receipt_digest(updated)?);
    }
    Ok(())
}

/// Replace each optional field with a commitment; return `(redacted, map)`.
///
/// `salts` supplies deterministic salts per path (tests and vectors); paths
/// absent from it get 16 random bytes, hex-encoded. `signer` is required when
/// any path is modified, because the redacted tail is re-signed.
pub fn redact(
    bundle: &Value,
    paths: &[String],
    salts: Option<&Map<String, Value>>,
    signer: Option<&SigningKey>,
) -> Result<(Value, Value), DiscloseError> {
    let mut redacted = bundle.clone();
    let receipts_snapshot: Vec<Value> = redacted
        .get("receipts")
        .and_then(Value::as_array)
        .ok_or_else(|| DiscloseError("bundle has no receipts list".to_string()))?
        .clone();
    let mut disclosure = Map::new();
    let mut modified: Vec<usize> = Vec::new();
    for path in paths {
        if required_field_for_path(path, &receipts_snapshot).is_some() {
            return Err(DiscloseError(format!(
                "required field cannot be redacted: {path}"
            )));
        }
        let value = walk(&redacted, path)?.clone();
        let salt = match salts
            .and_then(|map| map.get(path))
            .and_then(Value::as_str)
            .filter(|salt| !salt.is_empty())
        {
            Some(salt) => salt.to_string(),
            None => random_salt_hex()?,
        };
        let commit = commit_field(&salt, &value)?;
        set_value(
            &mut redacted,
            path,
            serde_json::json!({"redacted": true, "commit": commit}),
        )?;
        disclosure.insert(
            path.clone(),
            serde_json::json!({"salt": salt, "value": value}),
        );
        modified.push(receipt_index(path)?);
    }
    if !modified.is_empty() {
        let key = signer.ok_or_else(|| {
            DiscloseError(
                "redaction rewrites signed receipts; pass signer=(private_key, did)".to_string(),
            )
        })?;
        let start = *modified.iter().min().expect("modified is non-empty");
        resign_tail(&mut redacted, start, key)?;
    }
    Ok((redacted, Value::Object(disclosure)))
}

/// Merge a disclosure map into a bundle (`disclosure_map`), keeping entries
/// that were already attached.
pub fn attach(bundle: &Value, disclosure: &Value) -> Result<Value, DiscloseError> {
    let mut attached = bundle.clone();
    let mut merged = attached
        .get("disclosure_map")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if let Some(entries) = disclosure.as_object() {
        for (path, entry) in entries {
            merged.insert(path.clone(), entry.clone());
        }
    }
    let root = attached
        .as_object_mut()
        .ok_or_else(|| DiscloseError("bundle is not an object".to_string()))?;
    root.insert("disclosure_map".to_string(), Value::Object(merged));
    Ok(attached)
}

/// Build a package disclosing only the requested paths from a full map.
pub fn reveal(
    redacted: &Value,
    disclosure: &Value,
    paths: &[String],
) -> Result<Value, DiscloseError> {
    let map = disclosure
        .as_object()
        .ok_or_else(|| DiscloseError("disclosure map is not an object".to_string()))?;
    let missing: Vec<&String> = paths
        .iter()
        .filter(|path| !map.contains_key(*path))
        .collect();
    if !missing.is_empty() {
        return Err(DiscloseError(format!(
            "paths not in disclosure map: {missing:?}"
        )));
    }
    let mut subset = Map::new();
    for path in paths {
        if let Some(entry) = map.get(path) {
            subset.insert(path.clone(), entry.clone());
        }
    }
    attach(redacted, &Value::Object(subset))
}

/// Deterministic 32-byte seed used by tests and vectors (never for production).
#[must_use]
pub fn deterministic_seed(label: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(format!("continuity-receipt/{label}").as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_tokens_match_python_grammar() {
        assert_eq!(index_token("receipts[12]"), Some(("receipts", 12)));
        assert_eq!(index_token("receipts[0]"), Some(("receipts", 0)));
        assert_eq!(index_token("_x[3]"), Some(("_x", 3)));
        assert_eq!(index_token("receipts[]"), None);
        assert_eq!(index_token("receipts[a]"), None);
        assert_eq!(index_token("9receipts[1]"), None);
        assert_eq!(index_token("receipts[1]x"), None);
        assert_eq!(index_token("receipts"), None);
    }

    #[test]
    fn malformed_paths_are_rejected() {
        assert!(tokens("").is_err());
        assert!(tokens("a..b").is_err());
        assert!(tokens(".a").is_err());
        assert_eq!(tokens("a.b[1].c").expect("valid").len(), 3);
    }

    #[test]
    fn deterministic_seed_matches_python_labels() {
        let key = SigningKey::from_bytes(&deterministic_seed("gate-1"));
        assert_eq!(
            did_from_signing_key(&key),
            "did:key:z6MkwSG2hFkD41K85fvQFtNGCZXYFUwEZDqrzahZvWHt5hm1"
        );
    }

    fn vector(name: &str) -> Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../vectors")
            .join(name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("cannot parse {}: {error}", path.display()))
    }

    fn gate_key() -> SigningKey {
        SigningKey::from_bytes(&deterministic_seed("gate-1"))
    }

    /// Vector 02 plus a benign optional field on the first receipt, re-signed
    /// so the whole chain can be re-signed from index 0.
    fn optional_note_bundle() -> Value {
        let mut bundle = vector("02_happy_full.json");
        bundle["receipts"][0]["body"]["note"] = serde_json::json!("synthetic-optional");
        resign_tail(&mut bundle, 0, &gate_key()).expect("setup re-sign");
        bundle
    }

    #[test]
    fn whole_chain_resign_after_first_receipt_redaction() {
        let bundle = optional_note_bundle();
        let original: Vec<String> = bundle["receipts"]
            .as_array()
            .expect("receipts")
            .iter()
            .map(|receipt| {
                receipt["sig"]["value"]
                    .as_str()
                    .expect("signature")
                    .to_string()
            })
            .collect();
        let salts: Map<String, Value> =
            [("receipts[0].body.note".to_string(), serde_json::json!("00"))]
                .into_iter()
                .collect();
        let (redacted, map) = redact(
            &bundle,
            &["receipts[0].body.note".to_string()],
            Some(&salts),
            Some(&gate_key()),
        )
        .expect("redaction succeeds");
        for index in 0..original.len() {
            assert_ne!(
                redacted["receipts"][index]["sig"]["value"]
                    .as_str()
                    .expect("signature"),
                original[index],
                "receipt {index} must be re-signed"
            );
        }
        let attached = attach(&redacted, &map).expect("attach");
        assert_eq!(
            crate::verify::verify_bundle(&attached, false).verdict(),
            "TRUSTED"
        );
    }

    #[test]
    fn reveal_withholds_unrequested_paths() {
        let bundle = optional_note_bundle();
        let salts: Map<String, Value> = [
            ("receipts[0].body.note".to_string(), serde_json::json!("00")),
            (
                "receipts[3].body.spec_ref".to_string(),
                serde_json::json!("11"),
            ),
        ]
        .into_iter()
        .collect();
        let (redacted, map) = redact(
            &bundle,
            &[
                "receipts[0].body.note".to_string(),
                "receipts[3].body.spec_ref".to_string(),
            ],
            Some(&salts),
            Some(&gate_key()),
        )
        .expect("redaction succeeds");
        let package = reveal(
            &redacted,
            &map,
            &["receipts[3].body.spec_ref".to_string()],
        )
        .expect("reveal");
        assert_eq!(
            crate::verify::verify_bundle(&package, false).verdict(),
            "PROVISIONAL",
            "a withheld path must stay PROVISIONAL"
        );
        let full = attach(&redacted, &map).expect("attach");
        assert_eq!(
            crate::verify::verify_bundle(&full, false).verdict(),
            "TRUSTED"
        );
    }
}
