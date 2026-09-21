//! Disclosure tests: redact/reveal/attach against the frozen vectors and the
//! same deterministic test keys the Python vector generator uses.

use std::fs;
use std::path::PathBuf;

use continuity_receipt::canon::commit_field;
use continuity_receipt::disclose::{
    attach, deterministic_seed, did_from_signing_key, redact, reveal,
};
use continuity_receipt::verify::verify_bundle;
use ed25519_dalek::SigningKey;
use serde_json::{json, Map, Value};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("rust crate sits inside the repository")
        .to_path_buf()
}

fn read_json(name: &str) -> Value {
    let path = repo_root().join("vectors").join(name);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("cannot parse {}: {error}", path.display()))
}

fn gate_key() -> SigningKey {
    SigningKey::from_bytes(&deterministic_seed("gate-1"))
}

fn salt_map(entries: &[(&str, &str)]) -> Map<String, Value> {
    entries
        .iter()
        .map(|(path, salt)| ((*path).to_string(), json!(*salt)))
        .collect()
}

const SPEC_REF: &str = "receipts[3].body.spec_ref";
const SPEND_CAP: &str = "receipts[0].body.spend_cap";
const SALT_A: &str = "00112233445566778899aabbccddeeff";
const SALT_B: &str = "ffeeddccbbaa99887766554433221100";

#[test]
fn redact_optional_field_then_verify_trusted() {
    let bundle = read_json("02_happy_full.json");
    let salts = salt_map(&[(SPEC_REF, SALT_A)]);
    let (redacted, map) = redact(
        &bundle,
        &[SPEC_REF.to_string()],
        Some(&salts),
        Some(&gate_key()),
    )
    .expect("redaction succeeds");

    let entry = map.get(SPEC_REF).expect("map entry");
    assert_eq!(entry["salt"], json!(SALT_A));
    assert_eq!(entry["value"], json!("continuity-receipt/0.2"));

    let field = &redacted["receipts"][3]["body"]["spec_ref"];
    assert_eq!(field["redacted"], json!(true));
    assert_eq!(
        field["commit"],
        json!(commit_field(SALT_A, &json!("continuity-receipt/0.2")).expect("commit"))
    );

    assert_eq!(
        verify_bundle(&redacted, false).verdict(),
        "PROVISIONAL",
        "withheld disclosure must stay PROVISIONAL"
    );
    let attached = attach(&redacted, &map).expect("attach");
    assert_eq!(verify_bundle(&attached, false).verdict(), "TRUSTED");
}

#[test]
fn redaction_resigns_the_modified_tail() {
    let bundle = read_json("02_happy_full.json");
    let original_sig = bundle["receipts"][5]["sig"]["value"].clone();
    let salts = salt_map(&[(SPEC_REF, SALT_A)]);
    let (redacted, _) = redact(
        &bundle,
        &[SPEC_REF.to_string()],
        Some(&salts),
        Some(&gate_key()),
    )
    .expect("redaction succeeds");

    assert_ne!(
        redacted["receipts"][5]["sig"]["value"], original_sig,
        "the tail after the redacted receipt must be re-signed"
    );
    assert_eq!(
        redacted["receipts"][2]["sig"]["value"], bundle["receipts"][2]["sig"]["value"],
        "receipts before the first modified one keep their signatures"
    );
}

#[test]
fn redacting_a_cross_checked_field_fails_closed() {
    // `spend_cap` is optional for redaction but load-bearing for the cap
    // cross-check: a commitment cannot prove the cap, so the verdict drops to
    // UNTRUSTED instead of PROVISIONAL (fail closed, same as Python).
    let bundle = read_json("02_happy_full.json");
    let salts = salt_map(&[(SPEND_CAP, SALT_B)]);
    let (redacted, map) = redact(
        &bundle,
        &[SPEND_CAP.to_string()],
        Some(&salts),
        Some(&gate_key()),
    )
    .expect("redaction succeeds");
    let attached = attach(&redacted, &map).expect("attach");
    let result = verify_bundle(&attached, false);
    assert_eq!(result.verdict(), "UNTRUSTED");
    assert!(result.codes().contains(&"cap_exceeded"));
}

#[test]
fn required_fields_cannot_be_redacted() {
    let bundle = read_json("02_happy_full.json");
    let error = redact(
        &bundle,
        &["receipts[1].body.action".to_string()],
        None,
        Some(&gate_key()),
    )
    .expect_err("required field must be refused")
    .to_string();
    assert!(
        error.contains("required field cannot be redacted"),
        "{error}"
    );
}

#[test]
fn unknown_paths_are_refused() {
    let bundle = read_json("02_happy_full.json");
    let error = redact(
        &bundle,
        &["receipts[3].body.nope".to_string()],
        None,
        Some(&gate_key()),
    )
    .expect_err("missing path must be refused")
    .to_string();
    assert!(error.contains("path not found"), "{error}");
}

#[test]
fn redaction_without_the_issuer_signer_is_refused() {
    let bundle = read_json("02_happy_full.json");
    let salts = salt_map(&[(SPEC_REF, SALT_A)]);
    let error = redact(&bundle, &[SPEC_REF.to_string()], Some(&salts), None)
        .expect_err("signer is required")
        .to_string();
    assert!(error.contains("pass signer"), "{error}");

    let wrong_key = SigningKey::from_bytes(&deterministic_seed("agent-1"));
    let error = redact(
        &bundle,
        &[SPEC_REF.to_string()],
        Some(&salts),
        Some(&wrong_key),
    )
    .expect_err("wrong issuer must be refused")
    .to_string();
    assert!(error.contains("cannot re-sign"), "{error}");
}

#[test]
fn reveal_discloses_only_requested_paths() {
    let bundle = read_json("02_happy_full.json");
    let salts = salt_map(&[(SPEC_REF, SALT_A)]);
    let (redacted, map) = redact(
        &bundle,
        &[SPEC_REF.to_string()],
        Some(&salts),
        Some(&gate_key()),
    )
    .expect("redaction succeeds");

    let package = reveal(&redacted, &map, &[SPEC_REF.to_string()]).expect("reveal");
    let disclosure = package["disclosure_map"]
        .as_object()
        .expect("disclosure map");
    assert_eq!(disclosure.len(), 1, "only the requested path is disclosed");
    assert!(disclosure.contains_key(SPEC_REF));
    assert_eq!(verify_bundle(&package, false).verdict(), "TRUSTED");

    let missing = reveal(&redacted, &map, &["receipts[3].body.absent".to_string()])
        .expect_err("unknown disclosure path must be refused")
        .to_string();
    assert!(missing.contains("paths not in disclosure map"), "{missing}");
}

#[test]
fn vector_08_commit_recomputes_from_its_map() {
    let bundle = read_json("08_redacted_disclosed.json");
    let entry = &bundle["disclosure_map"]["receipts[3].body.quality_flags"];
    let salt = entry["salt"].as_str().expect("salt");
    let value = entry["value"].clone();
    let expected = commit_field(salt, &value).expect("commit");
    let committed = bundle["receipts"][3]["body"]["quality_flags"]["commit"]
        .as_str()
        .expect("commit in vector");
    assert_eq!(expected, committed);
}

#[test]
fn attach_preserves_existing_disclosure_entries() {
    let bundle = read_json("08_redacted_disclosed.json");
    let extra = json!({"receipts[3].body.quality_flags": {"salt": "aa", "value": ["quality-ok"]}});
    let attached = attach(&bundle, &extra).expect("attach");
    let disclosure = attached["disclosure_map"].as_object().expect("map");
    assert_eq!(disclosure.len(), 1, "same path is overwritten, not duplicated");
    assert_eq!(disclosure["receipts[3].body.quality_flags"]["salt"], json!("aa"));

    let other = json!({"receipts[3].body.spec_ref": {"salt": "bb", "value": "x"}});
    let attached = attach(&bundle, &other).expect("attach");
    assert_eq!(
        attached["disclosure_map"].as_object().expect("map").len(),
        2,
        "new paths are merged alongside existing ones"
    );
}

#[test]
fn did_derivation_matches_the_vector_issuer() {
    assert_eq!(
        did_from_signing_key(&gate_key()),
        "did:key:z6MkwSG2hFkD41K85fvQFtNGCZXYFUwEZDqrzahZvWHt5hm1"
    );
}
