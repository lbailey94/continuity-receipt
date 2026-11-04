//! Signed malformed timestamps must fail closed in every verifier.
use std::fs;
use std::path::PathBuf;

use continuity_receipt::verification::verify_verification_receipt;
use continuity_receipt::verify::verify_bundle;
use serde_json::Value;

#[test]
fn signed_impossible_dates_fail_closed() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/test-inputs/signed-timestamp-boundaries.json");
    let signed: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(
        verify_bundle(&signed["valid_bundle"], false).verdict(),
        "TRUSTED"
    );
    let bad = verify_bundle(&signed["invalid_bundle"], false);
    assert_eq!(bad.verdict(), "UNTRUSTED");
    assert!(bad.codes().iter().all(|code| *code == "malformed"));
    assert!(!bad.codes().is_empty());
    assert!(verify_verification_receipt(&signed["valid_receipt"], None, None).valid);
    let bad_receipt = verify_verification_receipt(&signed["invalid_receipt"], None, None);
    assert!(!bad_receipt.valid);
    assert_eq!(bad_receipt.errors, ["bad_verified_at"]);
    let mut with_revocations = signed["valid_bundle"].clone();
    with_revocations["revocations"] = serde_json::json!([signed["invalid_revocation"]]);
    let result = verify_bundle(&with_revocations, false);
    assert_eq!(result.verdict(), "UNTRUSTED");
    assert_eq!(result.codes(), ["bad_revocation"]);
}
