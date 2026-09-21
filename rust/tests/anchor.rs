//! Anchor companion tests: synthetic proofs plus the real `.ots` fixtures
//! under `../vectors/anchor/` (mirrors `tests/test_anchor.py`).

use std::fs;
use std::path::PathBuf;

use continuity_receipt::anchor::{parse_detached, verify_proof, verify_proof_raw, Attestation};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const ATT_PENDING: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const ATT_BITCOIN: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";

fn varuint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
            out.push(byte);
        } else {
            out.push(byte);
            return out;
        }
    }
}

fn varbytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = varuint(bytes.len() as u64);
    out.extend_from_slice(bytes);
    out
}

fn pending_att(uri: &str) -> Vec<u8> {
    let mut out = ATT_PENDING.to_vec();
    out.extend_from_slice(&varbytes(&varbytes(uri.as_bytes())));
    out
}

fn bitcoin_att(height: u64) -> Vec<u8> {
    let mut out = ATT_BITCOIN.to_vec();
    out.extend_from_slice(&varbytes(&varuint(height)));
    out
}

fn detached(digest: &[u8], tree: &[u8]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.push(1);
    out.push(0x08);
    out.extend_from_slice(digest);
    out.extend_from_slice(tree);
    out
}

fn header_for(merkle: &[u8], time: u32) -> Vec<u8> {
    assert_eq!(merkle.len(), 32);
    let mut out = vec![0x02, 0x00, 0x00, 0x00];
    out.extend_from_slice(&[0x11; 32]);
    out.extend_from_slice(merkle);
    out.extend_from_slice(&time.to_le_bytes());
    out.extend_from_slice(&[0x00; 8]);
    out
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("rust crate sits inside the repository")
        .to_path_buf()
}

fn fixture(name: &str) -> Vec<u8> {
    fs::read(repo_root().join("vectors").join("anchor").join(name))
        .unwrap_or_else(|error| panic!("cannot read fixture {name}: {error}"))
}

fn fixture_headers() -> Map<String, Value> {
    let text = fs::read_to_string(repo_root().join("vectors").join("anchor").join("headers.json"))
        .expect("headers.json");
    let data: Value = serde_json::from_str(&text).expect("headers JSON");
    data["headers"].as_object().expect("headers object").clone()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Sample {
    digest: Vec<u8>,
    message: Vec<u8>,
    proof: Vec<u8>,
}

fn sample() -> Sample {
    let digest = Sha256::digest(b"continuity-receipt test vector").to_vec();
    let message = Sha256::digest(&digest).to_vec();
    let mut tree = vec![0x08, 0x00];
    tree.extend_from_slice(&bitcoin_att(800_000));
    let proof = detached(&digest, &tree);
    Sample {
        digest,
        message,
        proof,
    }
}

#[test]
fn bitcoin_attestation_verified_against_header() {
    let sample = sample();
    let mut headers = std::collections::BTreeMap::new();
    headers.insert(800_000, header_for(&sample.message, 1_700_000_000));
    let result = verify_proof_raw(&sample.proof, &sample.digest, &headers);
    assert_eq!(result.status, "verified");
    assert_eq!(result.code, "anchor_verified");
    assert!(result.ok());
    let confirmed = result.confirmed.expect("confirmed");
    assert_eq!(confirmed["block_height"], json!(800_000));
    assert_eq!(confirmed["header_time"], json!(1_700_000_000u32));
    assert_eq!(confirmed["merkle_root"], json!(hex(&sample.message)));
}

#[test]
fn bitcoin_attestation_without_header_is_unverified() {
    let sample = sample();
    let result = verify_proof_raw(&sample.proof, &sample.digest, &Default::default());
    assert_eq!(result.status, "unverified");
    assert_eq!(result.code, "anchor_unverified");
    assert_eq!(result.attestations[0]["kind"], json!("bitcoin"));
}

#[test]
fn header_mismatch() {
    let sample = sample();
    let mut headers = std::collections::BTreeMap::new();
    headers.insert(800_000, header_for(&[0u8; 32], 1_700_000_000));
    let result = verify_proof_raw(&sample.proof, &sample.digest, &headers);
    assert_eq!(result.status, "mismatch");
    assert_eq!(result.code, "header_mismatch");
}

#[test]
fn digest_mismatch() {
    let sample = sample();
    let other = Sha256::digest(b"other").to_vec();
    let result = verify_proof_raw(&sample.proof, &other, &Default::default());
    assert_eq!(result.status, "mismatch");
    assert_eq!(result.code, "digest_mismatch");
}

#[test]
fn pending_and_unknown_attestations() {
    let sample = sample();
    let unknown_tag: [u8; 8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let mut tree = vec![0xFF, 0xF0];
    tree.extend_from_slice(&varbytes(b"AAAA"));
    tree.push(0x00);
    tree.extend_from_slice(&pending_att(
        "https://alice.btc.calendar.opentimestamps.org",
    ));
    tree.push(0xF0);
    tree.extend_from_slice(&varbytes(b"BBBB"));
    tree.push(0x00);
    tree.extend_from_slice(&unknown_tag);
    tree.extend_from_slice(&varbytes(&[0x01, 0x02, 0x03]));

    let proof = detached(&sample.digest, &tree);
    let result = verify_proof_raw(&proof, &sample.digest, &Default::default());
    assert_eq!(result.status, "unverified");
    assert_eq!(result.code, "anchor_pending");
    let kinds: std::collections::BTreeSet<&str> = result
        .attestations
        .iter()
        .filter_map(|attestation| attestation["kind"].as_str())
        .collect();
    assert_eq!(kinds, ["pending", "unknown"].into_iter().collect());
}

#[test]
fn leb128_varuints_not_compact_size() {
    let sample = sample();
    let uri = "a".repeat(128);
    let mut tree = vec![0x00];
    tree.extend_from_slice(&ATT_PENDING);
    tree.extend_from_slice(&[0x82, 0x01]);
    tree.extend_from_slice(&[0x80, 0x01]);
    tree.extend_from_slice(uri.as_bytes());
    let parsed = parse_detached(&detached(&sample.digest, &tree)).expect("parses");
    match &parsed.leaves[0].1 {
        Attestation::Pending(value) => assert_eq!(value, &uri),
        other => panic!("expected pending, got {other:?}"),
    }

    let mut tree300 = vec![0x00];
    tree300.extend_from_slice(&ATT_BITCOIN);
    tree300.extend_from_slice(&varbytes(&[0xAC, 0x02]));
    let parsed = parse_detached(&detached(&sample.digest, &tree300)).expect("parses");
    assert_eq!(parsed.leaves[0].1, Attestation::Bitcoin(300));
}

#[test]
fn reverse_and_prepend_ops() {
    let sample = sample();
    let prefix = vec![b'X'; 8];
    let mut tree = vec![0xF1];
    tree.extend_from_slice(&varbytes(&prefix));
    tree.push(0xF2);
    tree.push(0x00);
    tree.extend_from_slice(&pending_att("https://ots.example"));
    let parsed = parse_detached(&detached(&sample.digest, &tree)).expect("parses");
    let (reached, attestation) = &parsed.leaves[0];
    let mut expected = prefix.clone();
    expected.extend_from_slice(&sample.digest);
    expected.reverse();
    assert_eq!(reached, &expected);
    assert!(matches!(attestation, Attestation::Pending(_)));
}

#[test]
fn truncated_and_bad_magic() {
    let sample = sample();
    let truncated = &sample.proof[..sample.proof.len() - 3];
    let result = verify_proof_raw(truncated, &sample.digest, &Default::default());
    assert_eq!(result.code, "truncated");

    let mut bad = vec![0u8; 16];
    bad.extend_from_slice(&sample.proof);
    let result = verify_proof_raw(&bad, &sample.digest, &Default::default());
    assert_eq!(result.code, "bad_magic");
}

#[test]
fn keccak_is_unsupported_not_silent() {
    let sample = sample();
    let mut tree = vec![0x67, 0x00];
    tree.extend_from_slice(&pending_att("https://ots.example"));
    let proof = detached(&sample.digest, &tree);
    let error = parse_detached(&proof).expect_err("keccak is unsupported");
    assert_eq!(error.code, "unsupported_op");
    let result = verify_proof_raw(&proof, &sample.digest, &Default::default());
    assert_eq!(result.status, "invalid");
    assert_eq!(result.code, "unsupported_op");
}

#[test]
fn overlong_varuint_is_rejected() {
    let sample = sample();
    let mut tree = vec![0x00];
    tree.extend_from_slice(&ATT_PENDING);
    tree.extend_from_slice(&[0x80; 10]);
    tree.push(0x00);
    let error = parse_detached(&detached(&sample.digest, &tree)).expect_err("varuint too long");
    assert_eq!(error.code, "invalid_varuint");
}

#[test]
fn hello_world_binds_to_the_file_digest() {
    let parsed = parse_detached(&fixture("hello-world.txt.ots")).expect("parses");
    let expected = Sha256::digest(fixture("hello-world.txt")).to_vec();
    assert_eq!(parsed.file_digest, expected);
    assert_eq!(parsed.file_hash_op, "sha256");
}

#[test]
fn hello_world_verified_against_block_358391() {
    let proof = fixture("hello-world.txt.ots");
    let expected = Sha256::digest(fixture("hello-world.txt")).to_vec();
    let result = verify_proof(&proof, &json!(hex(&expected)), Some(&fixture_headers()));
    assert_eq!(result.status, "verified");
    assert_eq!(result.confirmed.expect("confirmed")["block_height"], json!(358391));
}

#[test]
fn sha1_bitcoin_pdf_verified_against_block_465751() {
    let proof = fixture("bitcoin.pdf.ots");
    let parsed = parse_detached(&proof).expect("parses");
    assert_eq!(parsed.file_hash_op, "sha1");
    let result = verify_proof(
        &proof,
        &json!(hex(&parsed.file_digest)),
        Some(&fixture_headers()),
    );
    assert_eq!(result.status, "verified");
    assert_eq!(result.confirmed.expect("confirmed")["block_height"], json!(465751));
}

#[test]
fn gdp_2025_proof_verified_against_block_912095() {
    let proof = fixture("gdp2q25-2nd.pdf.ots");
    let parsed = parse_detached(&proof).expect("parses");
    let result = verify_proof(
        &proof,
        &json!(hex(&parsed.file_digest)),
        Some(&fixture_headers()),
    );
    assert_eq!(result.status, "verified");
    assert_eq!(result.confirmed.expect("confirmed")["block_height"], json!(912095));
}

#[test]
fn known_and_unknown_notary_reports_both() {
    let proof = fixture("known-and-unknown-notary.txt.ots");
    let parsed = parse_detached(&proof).expect("parses");
    let result = verify_proof(&proof, &json!(hex(&parsed.file_digest)), None);
    assert_eq!(result.status, "unverified");
    assert_eq!(result.code, "anchor_pending");
    let kinds: std::collections::BTreeSet<&str> = result
        .attestations
        .iter()
        .filter_map(|attestation| attestation["kind"].as_str())
        .collect();
    assert_eq!(kinds, ["pending", "unknown"].into_iter().collect());
}

#[test]
fn different_blockchains_fails_loudly_on_keccak() {
    let proof = fixture("different-blockchains.txt.ots");
    let error = parse_detached(&proof).expect_err("keccak path");
    assert_eq!(error.code, "unsupported_op");
    let result = verify_proof(&proof, &json!(hex(&[0u8; 32])), None);
    assert_eq!(result.status, "invalid");
    assert_eq!(result.code, "unsupported_op");
}
