//! OpenTimestamps proof verification — 0.3 anchor companion tool.
//!
//! Mirrors `continuity_receipt/anchor.py`: replay a detached `.ots` proof from
//! the file digest to every attestation, and verify a Bitcoin attestation
//! against an 80-byte block header by exact byte equality with the header's
//! merkle root (bytes 36..68). Header *chain* validation (proof-of-work,
//! confirmation depth, reorg handling) is out of scope by design: supply the
//! header from a source you trust and read `status=verified` as "this digest
//! is the merkle root of that header", not "that header is buried under N
//! blocks".
//!
//! Wire format: python-opentimestamps `DetachedTimestampFile` — magic, uint8
//! major version, file-hash op tag, digest, then the timestamp tree. Varints
//! are LEB128 (unsigned little-endian base-128), *not* Bitcoin CompactSize.
//!
//! Statuses: `verified` / `unverified` / `mismatch` / `invalid` with
//! machine-readable codes, exactly as the Python companion.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ripemd::Ripemd160;
use serde_json::{json, Map, Value};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};

use crate::verify::receipt_digest;

pub const MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
pub const MAJOR_VERSION: u8 = 1;

const MAX_MSG: usize = 4096;
const MAX_RESULT: usize = 4096;
const MAX_ATT_PAYLOAD: usize = 8192;
const MAX_URI: usize = 1000;
const MAX_NODES: usize = 10_000;
const MAX_DEPTH: usize = 256;
const MAX_VARUINT_BYTES: usize = 10;

const KECCAK_TAG: u8 = 0x67;
const ATT_PENDING: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const ATT_BITCOIN: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const ATT_LITECOIN: [u8; 8] = [0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45];

const HEADER_LEN: usize = 80;
const MERKLE_OFFSET: usize = 36;
const TIME_OFFSET: usize = 68;

/// Proof-format error; `code` is a machine-readable identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorError {
    pub code: String,
    pub detail: String,
}

impl AnchorError {
    fn new(code: &str, detail: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            detail: detail.into(),
        }
    }
}

impl fmt::Display for AnchorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for AnchorError {}

fn hash_op(tag: u8) -> Option<(&'static str, usize)> {
    match tag {
        0x02 => Some(("sha1", 20)),
        0x03 => Some(("ripemd160", 20)),
        0x08 => Some(("sha256", 32)),
        _ => None,
    }
}

fn binary_op(tag: u8) -> Option<&'static str> {
    match tag {
        0xF0 => Some("append"),
        0xF1 => Some("prepend"),
        _ => None,
    }
}

fn unary_op(tag: u8) -> Option<&'static str> {
    match tag {
        0xF2 => Some("reverse"),
        0xF3 => Some("hexlify"),
        _ => None,
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read(&mut self, count: usize) -> Result<&'a [u8], AnchorError> {
        if self.pos + count > self.data.len() {
            return Err(AnchorError::new("truncated", "proof is truncated"));
        }
        let out = &self.data[self.pos..self.pos + count];
        self.pos += count;
        Ok(out)
    }

    fn read_varuint(&mut self) -> Result<u64, AnchorError> {
        let mut value: u64 = 0;
        let mut shift = 0;
        for _ in 0..MAX_VARUINT_BYTES {
            let byte = self.read(1)?[0];
            value |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
        Err(AnchorError::new("invalid_varuint", "varuint exceeds 10 bytes"))
    }

    fn read_varbytes(&mut self, max_len: usize, min_len: usize) -> Result<&'a [u8], AnchorError> {
        let length = usize::try_from(self.read_varuint()?).unwrap_or(usize::MAX);
        if length > max_len {
            return Err(AnchorError::new(
                "invalid_length",
                format!("varbytes length {length} exceeds {max_len}"),
            ));
        }
        if length < min_len {
            return Err(AnchorError::new(
                "invalid_length",
                format!("varbytes length {length} below {min_len}"),
            ));
        }
        self.read(length)
    }

    fn assert_eof(&self) -> Result<(), AnchorError> {
        if self.pos != self.data.len() {
            return Err(AnchorError::new(
                "trailing_data",
                "unexpected bytes after proof node",
            ));
        }
        Ok(())
    }
}

/// One parsed attestation leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attestation {
    Pending(String),
    Bitcoin(u64),
    Litecoin(u64),
    Unknown { tag: String, payload: String },
}

impl Attestation {
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Pending(_) => "pending",
            Self::Bitcoin(_) => "bitcoin",
            Self::Litecoin(_) => "litecoin",
            Self::Unknown { .. } => "unknown",
        }
    }

    #[must_use]
    pub fn as_dict(&self) -> Value {
        match self {
            Self::Pending(uri) => json!({"kind": "pending", "value": uri}),
            Self::Bitcoin(height) => json!({"kind": "bitcoin", "value": height}),
            Self::Litecoin(height) => json!({"kind": "litecoin", "value": height}),
            Self::Unknown { tag, payload } => {
                json!({"kind": "unknown", "tag": tag, "payload": payload})
            }
        }
    }
}

/// Parsed detached proof: version, file-hash op, digest, and leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedProof {
    pub version: u8,
    pub file_hash_op: String,
    pub file_digest: Vec<u8>,
    pub leaves: Vec<(Vec<u8>, Attestation)>,
}

/// Verification result, mirroring the Python `AnchorResult` JSON shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorResult {
    pub status: String,
    pub code: String,
    pub detail: String,
    pub file_digest: String,
    pub attestations: Vec<Value>,
    pub confirmed: Option<Value>,
}

impl AnchorResult {
    fn new(status: &str, code: &str, detail: impl Into<String>) -> Self {
        Self {
            status: status.to_string(),
            code: code.to_string(),
            detail: detail.into(),
            file_digest: String::new(),
            attestations: Vec::new(),
            confirmed: None,
        }
    }

    #[must_use]
    pub fn ok(&self) -> bool {
        self.status == "verified"
    }

    #[must_use]
    pub fn as_dict(&self) -> Value {
        let mut out = Map::new();
        out.insert("status".to_string(), json!(self.status));
        out.insert("code".to_string(), json!(self.code));
        out.insert("detail".to_string(), json!(self.detail));
        out.insert("file_digest".to_string(), json!(self.file_digest));
        out.insert("attestations".to_string(), json!(self.attestations));
        if let Some(confirmed) = &self.confirmed {
            out.insert("confirmed".to_string(), confirmed.clone());
        }
        Value::Object(out)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let high = (bytes[index] as char).to_digit(16)?;
        let low = (bytes[index + 1] as char).to_digit(16)?;
        out.push(((high << 4) | low) as u8);
        index += 2;
    }
    Some(out)
}

/// Normalize hex / `sha256:<hex>` / `0x`-prefixed text into a raw digest.
#[must_use]
pub fn digest_bytes(value: &Value) -> Option<Vec<u8>> {
    let text = value.as_str()?.trim();
    let text = match text.split_once(':') {
        Some(("sha256", rest)) => rest,
        Some(_) => return None,
        None => text,
    };
    let text = text.strip_prefix("0x").unwrap_or(text);
    hex_decode(text)
}

fn apply_op(name: &str, arg: Option<&[u8]>, message: &[u8]) -> Result<Vec<u8>, AnchorError> {
    if message.len() > MAX_MSG {
        return Err(AnchorError::new(
            "message_too_long",
            format!("operation input exceeds {MAX_MSG} bytes"),
        ));
    }
    let result = match name {
        "append" => {
            let mut out = message.to_vec();
            out.extend_from_slice(arg.unwrap_or(&[]));
            out
        }
        "prepend" => {
            let mut out = arg.unwrap_or(&[]).to_vec();
            out.extend_from_slice(message);
            out
        }
        "reverse" => message.iter().rev().copied().collect(),
        "hexlify" => hex_encode(message).into_bytes(),
        "sha1" => Sha1::digest(message).to_vec(),
        "ripemd160" => Ripemd160::digest(message).to_vec(),
        "sha256" => Sha256::digest(message).to_vec(),
        other => {
            return Err(AnchorError::new(
                "unsupported_op",
                format!("hash {other} unavailable"),
            ))
        }
    };
    if result.is_empty() || result.len() > MAX_RESULT {
        return Err(AnchorError::new(
            "invalid_result",
            format!("{name} produced {} bytes", result.len()),
        ));
    }
    Ok(result)
}

fn parse_attestation(payload_tag: &[u8], payload: &[u8]) -> Result<Attestation, AnchorError> {
    let mut reader = Reader::new(payload);
    if payload_tag == ATT_PENDING.as_slice() {
        let uri = reader.read_varbytes(MAX_URI, 0)?;
        reader.assert_eof()?;
        return Ok(Attestation::Pending(
            String::from_utf8_lossy(uri).into_owned(),
        ));
    }
    if payload_tag == ATT_BITCOIN.as_slice() || payload_tag == ATT_LITECOIN.as_slice() {
        let height = reader.read_varuint()?;
        reader.assert_eof()?;
        return Ok(if payload_tag == ATT_BITCOIN.as_slice() {
            Attestation::Bitcoin(height)
        } else {
            Attestation::Litecoin(height)
        });
    }
    Ok(Attestation::Unknown {
        tag: hex_encode(payload_tag),
        payload: hex_encode(payload),
    })
}

fn handle_tag(
    reader: &mut Reader<'_>,
    tag: &[u8],
    message: &[u8],
    leaves: &mut Vec<(Vec<u8>, Attestation)>,
    nodes: &mut usize,
    depth: usize,
) -> Result<(), AnchorError> {
    if tag == [0x00] {
        let tag8 = reader.read(8)?.to_vec();
        let payload = reader.read_varbytes(MAX_ATT_PAYLOAD, 0)?.to_vec();
        leaves.push((message.to_vec(), parse_attestation(&tag8, &payload)?));
        return Ok(());
    }
    let tag_byte = tag[0];
    if tag_byte == KECCAK_TAG {
        return Err(AnchorError::new(
            "unsupported_op",
            "keccak256 proofs are not supported",
        ));
    }
    if let Some((name, _)) = hash_op(tag_byte) {
        let next = apply_op(name, None, message)?;
        return parse_timestamp(reader, &next, leaves, nodes, depth + 1);
    }
    if let Some(name) = binary_op(tag_byte) {
        let arg = reader.read_varbytes(MAX_RESULT, 1)?.to_vec();
        let next = apply_op(name, Some(&arg), message)?;
        return parse_timestamp(reader, &next, leaves, nodes, depth + 1);
    }
    if let Some(name) = unary_op(tag_byte) {
        let next = apply_op(name, None, message)?;
        return parse_timestamp(reader, &next, leaves, nodes, depth + 1);
    }
    Err(AnchorError::new(
        "unknown_op",
        format!("unknown operation tag 0x{tag_byte:02x}"),
    ))
}

fn parse_timestamp(
    reader: &mut Reader<'_>,
    message: &[u8],
    leaves: &mut Vec<(Vec<u8>, Attestation)>,
    nodes: &mut usize,
    depth: usize,
) -> Result<(), AnchorError> {
    if depth > MAX_DEPTH {
        return Err(AnchorError::new(
            "recursion_limit",
            "timestamp tree exceeds depth limit",
        ));
    }
    *nodes += 1;
    if *nodes > MAX_NODES {
        return Err(AnchorError::new(
            "too_many_nodes",
            "timestamp tree exceeds node limit",
        ));
    }

    let mut tag = reader.read(1)?;
    while tag == [0xFF] {
        let next = reader.read(1)?.to_vec();
        handle_tag(reader, &next, message, leaves, nodes, depth)?;
        tag = reader.read(1)?;
    }
    handle_tag(reader, tag, message, leaves, nodes, depth)
}

/// Parse a detached `.ots` proof (magic, version, file-hash op, tree).
pub fn parse_detached(data: &[u8]) -> Result<ParsedProof, AnchorError> {
    let mut reader = Reader::new(data);
    if reader.read(MAGIC.len())? != MAGIC {
        return Err(AnchorError::new(
            "bad_magic",
            "not an OpenTimestamps detached proof",
        ));
    }
    let version = reader.read(1)?[0];
    if version != MAJOR_VERSION {
        return Err(AnchorError::new(
            "unsupported_version",
            format!("major version {version} not supported"),
        ));
    }
    let hash_tag = reader.read(1)?[0];
    let Some((file_hash_op, digest_len)) = hash_op(hash_tag) else {
        return Err(AnchorError::new(
            "unknown_op",
            format!("unsupported file hash op 0x{hash_tag:02x}"),
        ));
    };
    let file_digest = reader.read(digest_len)?.to_vec();
    let mut leaves = Vec::new();
    let mut nodes = 0usize;
    parse_timestamp(&mut reader, &file_digest, &mut leaves, &mut nodes, 0)?;
    reader.assert_eof()?;
    Ok(ParsedProof {
        version,
        file_hash_op: file_hash_op.to_string(),
        file_digest,
        leaves,
    })
}

/// Verify a detached proof against a digest and optional headers.
///
/// `block_headers` maps Bitcoin block height -> 80-byte header. When provided,
/// a matching-height Bitcoin attestation is checked by merkle-root equality;
/// other heights are reported but not verified.
#[must_use]
pub fn verify_proof(
    data: &[u8],
    expected: &Value,
    block_headers: Option<&Map<String, Value>>,
) -> AnchorResult {
    let Some(expected) = digest_bytes(expected) else {
        return AnchorResult::new(
            "invalid",
            "bad_digest",
            "expected digest is not bytes/hex/sha256:<hex>",
        );
    };

    let proof = match parse_detached(data) {
        Ok(proof) => proof,
        Err(error) => return AnchorResult::new("invalid", &error.code, error.detail),
    };

    let file_digest = format!("{}:{}", proof.file_hash_op, hex_encode(&proof.file_digest));
    if expected.len() != proof.file_digest.len() || expected != proof.file_digest {
        let mut result = AnchorResult::new(
            "mismatch",
            "digest_mismatch",
            "proof was not created for the expected digest",
        );
        result.file_digest = file_digest;
        return result;
    }

    let mut headers: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    if let Some(supplied) = block_headers {
        for (height, header) in supplied {
            let Ok(height) = height.parse::<u64>() else {
                return AnchorResult::new(
                    "invalid",
                    "bad_header",
                    format!("header height {height:?} is not an integer"),
                );
            };
            let decoded = digest_bytes(header).unwrap_or_default();
            if decoded.len() != HEADER_LEN {
                return AnchorResult::new(
                    "invalid",
                    "bad_header",
                    format!("header for height {height} is not 80 bytes"),
                );
            }
            headers.insert(height, decoded);
        }
    }

    let attestations: Vec<Value> = proof
        .leaves
        .iter()
        .map(|(_, attestation)| attestation.as_dict())
        .collect();
    let bitcoins: Vec<(&Vec<u8>, u64)> = proof
        .leaves
        .iter()
        .filter_map(|(message, attestation)| match attestation {
            Attestation::Bitcoin(height) => Some((message, *height)),
            _ => None,
        })
        .collect();

    for (message, height) in &bitcoins {
        let Some(header) = headers.get(height) else {
            continue;
        };
        if message.as_slice() == &header[MERKLE_OFFSET..MERKLE_OFFSET + 32] {
            let mut time = [0u8; 4];
            time.copy_from_slice(&header[TIME_OFFSET..TIME_OFFSET + 4]);
            let confirmed = json!({
                "block_height": height,
                "merkle_root": hex_encode(message),
                "header_time": u32::from_le_bytes(time),
            });
            let mut result = AnchorResult::new(
                "verified",
                "anchor_verified",
                format!("digest is the merkle root of Bitcoin block {height}"),
            );
            result.file_digest = file_digest;
            result.attestations = attestations;
            result.confirmed = Some(confirmed);
            return result;
        }
    }

    if !bitcoins.is_empty() && !headers.is_empty() {
        let heights = bitcoins
            .iter()
            .map(|(_, height)| height.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let mut result = AnchorResult::new(
            "mismatch",
            "header_mismatch",
            format!("supplied header(s) do not match the proof (attested height(s): {heights})"),
        );
        result.file_digest = file_digest;
        result.attestations = attestations;
        return result;
    }

    if !bitcoins.is_empty() {
        let mut result = AnchorResult::new(
            "unverified",
            "anchor_unverified",
            "proof reaches a Bitcoin attestation; supply the 80-byte block header to confirm",
        );
        result.file_digest = file_digest;
        result.attestations = attestations;
        return result;
    }

    let kinds: BTreeSet<&str> = proof
        .leaves
        .iter()
        .map(|(_, attestation)| attestation.kind())
        .collect();
    if kinds.contains("pending") {
        let mut result = AnchorResult::new(
            "unverified",
            "anchor_pending",
            "proof reaches only pending calendar attestations; upgrade it after confirmation",
        );
        result.file_digest = file_digest;
        result.attestations = attestations;
        return result;
    }
    if kinds.contains("litecoin") {
        let mut result = AnchorResult::new(
            "unverified",
            "anchor_unverified",
            "proof reaches a Litecoin attestation (not checked by this tool)",
        );
        result.file_digest = file_digest;
        result.attestations = attestations;
        return result;
    }
    if !proof.leaves.is_empty() {
        let mut result = AnchorResult::new(
            "unverified",
            "anchor_unknown_type",
            "proof reaches only unknown attestation types",
        );
        result.file_digest = file_digest;
        result.attestations = attestations;
        return result;
    }
    let mut result = AnchorResult::new("invalid", "anchor_empty", "proof contains no attestations");
    result.file_digest = file_digest;
    result
}

/// Convenience wrapper for raw-byte digests and headers (no JSON ceremony).
#[must_use]
pub fn verify_proof_raw(
    data: &[u8],
    expected: &[u8],
    block_headers: &BTreeMap<u64, Vec<u8>>,
) -> AnchorResult {
    let headers: Map<String, Value> = block_headers
        .iter()
        .map(|(height, header)| (height.to_string(), json!(hex_encode(header))))
        .collect();
    verify_proof(data, &json!(hex_encode(expected)), Some(&headers))
}

/// Receipt digest and anchor binding for `receipt_id` inside a bundle.
///
/// Returns `(receipt_digest, binding)` where `binding` is the bundle `anchors`
/// entry whose `anchor.type` is `opentimestamps`, or `None`.
pub fn bundle_digest(
    bundle_path: &str,
    target: &str,
) -> Result<(String, Option<Value>), AnchorError> {
    let text = std::fs::read_to_string(bundle_path)
        .map_err(|error| AnchorError::new("io_error", error.to_string()))?;
    let bundle: Value = serde_json::from_str(&text)
        .map_err(|error| AnchorError::new("io_error", error.to_string()))?;
    let receipts = bundle
        .get("receipts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for receipt in &receipts {
        if receipt.get("receipt_id").and_then(Value::as_str) != Some(target) {
            continue;
        }
        let binding = bundle
            .get("anchors")
            .and_then(Value::as_array)
            .and_then(|anchors| {
                anchors.iter().find(|anchor| {
                    anchor.get("target").and_then(Value::as_str) == Some(target)
                        && anchor
                            .get("anchor")
                            .and_then(Value::as_object)
                            .and_then(|meta| meta.get("type"))
                            .and_then(Value::as_str)
                            == Some("opentimestamps")
                })
            })
            .cloned();
        let object = receipt.as_object().ok_or_else(|| {
            AnchorError::new("invalid_receipt", "receipt is not an object")
        })?;
        let digest = receipt_digest(object).map_err(|error| AnchorError::new("invalid_receipt", error.0))?;
        return Ok((digest, binding));
    }
    Err(AnchorError::new(
        "unknown_target",
        format!("no receipt {target:?} in bundle"),
    ))
}
