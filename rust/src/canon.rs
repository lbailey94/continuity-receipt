//! JCS-subset canonicalization for Continuity Receipts (v0).
//!
//! Mirrors `continuity_receipt/canon.py`: deterministic bytes for signing and
//! hashing with sorted keys (Unicode code point order; UTF-8 byte order for
//! valid strings is identical), compact separators, UTF-8 output, and
//! integers/strings/bools/null only. Floats are rejected.

use std::fmt;

use serde_json::Value;
use sha2::{Digest, Sha256};

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Canonicalization failure (float encountered, invalid commitment salt, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonError(pub String);

impl fmt::Display for CanonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CanonError {}

/// Deterministic bytes for signing and hashing (pinned JCS subset).
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>, CanonError> {
    let mut out = Vec::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut Vec<u8>) -> Result<(), CanonError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => {
            let token = number.to_string();
            if token.contains('.') || token.contains('e') || token.contains('E') {
                return Err(CanonError(
                    "floats are not allowed in continuity receipts (v0)".to_string(),
                ));
            }
            out.extend_from_slice(token.as_bytes());
        }
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push(b'{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                if let Some(item) = map.get(key.as_str()) {
                    write_value(item, out)?;
                }
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// JSON string escaping matching Python `json.dumps(..., ensure_ascii=False)`.
fn write_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for character in text.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                let escape = format!("\\u{:04x}", c as u32);
                out.extend_from_slice(escape.as_bytes());
            }
            c => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// `sha256:<lowercase hex>` hash form (`sha256_prefixed` in Python).
pub fn sha256_prefixed(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// v0 reference commitment: `sha256(salt_bytes || 0x7c || JCS(value))`.
///
/// `salt_hex` is the hex-encoded random salt. The delimiter `0x7c` is `|`.
pub fn commit_field(salt_hex: &str, value: &Value) -> Result<String, CanonError> {
    let salt = hex_decode(salt_hex)
        .ok_or_else(|| CanonError(format!("invalid salt hex: {salt_hex:?}")))?;
    let mut data = salt;
    data.push(0x7c);
    data.extend_from_slice(&canonical_bytes(value)?);
    Ok(sha256_prefixed(&data))
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let high = hex_value(bytes[index])?;
        let low = hex_value(bytes[index + 1])?;
        out.push((high << 4) | low);
        index += 2;
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
