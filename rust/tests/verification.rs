//! Verification-receipt vector runner: every entry in
//! `../vectors/verification/manifest.json` must match its expected validity
//! and error set (mirrors `tests/test_verification_receipts.py`).

use std::fs;
use std::path::PathBuf;

use continuity_receipt::canon::{canonical_bytes, sha256_prefixed};
use continuity_receipt::verification::{receipt_digest, verify_verification_receipt};
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("rust crate sits inside the repository")
        .to_path_buf()
}

fn read_json(path: &PathBuf) -> Value {
    let text = fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("cannot read {}: {error}", path.display());
    });
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("cannot parse {}: {error}", path.display()))
}

#[test]
fn all_verification_vectors_match_manifest() {
    let vectors = repo_root().join("vectors").join("verification");
    let manifest = read_json(&vectors.join("manifest.json"));
    let entries = manifest["vectors"]
        .as_array()
        .expect("manifest has a vectors array");
    assert_eq!(entries.len(), 20, "manifest vector count");

    for entry in entries {
        let file = entry["file"].as_str().expect("vector file name");
        let expected_valid = entry["expected_valid"].as_bool().expect("expected_valid");
        let expected_errors: Vec<&str> = entry["expected_errors"]
            .as_array()
            .expect("expected_errors")
            .iter()
            .map(|value| value.as_str().expect("error code"))
            .collect();

        let receipt = read_json(&vectors.join(file));
        let bundle = entry
            .get("bundle_file")
            .and_then(Value::as_str)
            .map(|name| read_json(&vectors.join(name)));
        let revocations = entry
            .get("revocations_file")
            .and_then(Value::as_str)
            .map(|name| {
                read_json(&vectors.join(name))["statements"]
                    .as_array()
                    .cloned()
                    .expect("statements array")
            });

        let result = verify_verification_receipt(&receipt, bundle.as_ref(), revocations.as_deref());
        assert_eq!(result.valid, expected_valid, "{file}: {:?}", result.errors);
        let mut actual: Vec<&str> = result.errors.iter().map(String::as_str).collect();
        let mut expected = expected_errors.clone();
        actual.sort_unstable();
        expected.sort_unstable();
        assert_eq!(actual, expected, "{file}");
    }
}

#[test]
fn receipt_digest_matches_canonical_view() {
    let vectors = repo_root().join("vectors").join("verification");
    let receipt = read_json(&vectors.join("01_valid.json"));
    let digest = receipt_digest(&receipt).expect("digest");
    let mut unsigned = receipt.as_object().expect("object").clone();
    unsigned.remove("sig");
    let canonical = canonical_bytes(&Value::Object(unsigned)).expect("canonical");
    assert_eq!(digest, sha256_prefixed(&canonical));
    assert!(digest.starts_with("sha256:"));
}

#[test]
fn malformed_receipts_fail_closed() {
    let cases: Vec<(Value, &str)> = vec![
        (serde_json::json!([]), "not_an_object"),
        (serde_json::json!("nope"), "not_an_object"),
        (serde_json::json!({}), "bad_kind"),
        (
            serde_json::json!({"kind": "continuity-receipt-verification"}),
            "bad_version",
        ),
        (
            serde_json::json!({
                "kind": "continuity-receipt-verification",
                "version": 1,
                "verdict": "MAYBE"
            }),
            "bad_verdict",
        ),
    ];
    for (receipt, code) in cases {
        let result = verify_verification_receipt(&receipt, None, None);
        assert!(!result.valid, "{receipt}");
        assert!(
            result.errors.iter().any(|entry| entry == code),
            "{receipt}: expected {code}, got {:?}",
            result.errors
        );
    }
}

#[test]
fn unsigned_revocation_fails_closed() {
    let receipt = serde_json::json!({
        "kind": "continuity-receipt-verification",
        "version": 1,
        "bundle_digest": "sha256:".to_string() + &"0".repeat(64),
        "verdict": "TRUSTED",
        "error_codes": [],
        "errors": [],
        "provisional_reasons": [],
        "insufficient_reasons": [],
        "summary": {},
        "verified_at": "2026-09-23T21:00:00Z",
        "verifier": {"implementation": "test", "version": "0"},
        "issuer": "did:key:zTest",
        "sig": {"alg": "ed25519", "key": "did:key:zTest", "value": "AAAA"}
    });
    let statement = serde_json::json!({
        "key": "did:key:zTest",
        "revoked_at": "2026-09-23T20:00:00Z"
    });
    let result = verify_verification_receipt(&receipt, None, Some(&[statement]));
    assert!(!result.valid);
    assert!(
        result.errors.iter().any(|entry| entry == "bad_revocation"),
        "{:?}",
        result.errors
    );
}
