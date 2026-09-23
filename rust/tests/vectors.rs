//! Vector runner: every entry in `../vectors/manifest.json` must match its
//! expected verdict and error code (mirrors `tests/test_vectors.py`).

use std::fs;
use std::path::PathBuf;

use continuity_receipt::verify::verify_bundle;
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
fn all_vectors_match_manifest() {
    let vectors = repo_root().join("vectors");
    let manifest = read_json(&vectors.join("manifest.json"));
    let entries = manifest["vectors"]
        .as_array()
        .expect("manifest has a vectors array");
    assert_eq!(entries.len(), 24, "manifest vector count");

    for entry in entries {
        let file = entry["file"].as_str().expect("vector file name");
        let expected_verdict = entry["expected_verdict"]
            .as_str()
            .expect("expected verdict");
        let expected_code = entry["expected_code"].as_str();
        let require_anchor = entry["require_anchor"]
            .as_bool()
            .expect("require_anchor flag");

        let bundle = read_json(&vectors.join(file));
        let result = verify_bundle(&bundle, require_anchor);

        assert_eq!(
            result.verdict(),
            expected_verdict,
            "{file}: verdict {:?} != {expected_verdict}; errors={:?}",
            result.verdict(),
            result.errors
        );
        if let Some(code) = expected_code {
            assert!(
                result.codes().contains(&code),
                "{file}: expected error {code}, got {:?}",
                result.codes()
            );
        }
    }
}

#[test]
fn malformed_bundles_fail_closed_without_panicking() {
    let cases: Vec<(&str, Value, &str)> = vec![
        ("empty array", serde_json::json!([]), "malformed"),
        ("string bundle", serde_json::json!("nope"), "malformed"),
        ("empty object", serde_json::json!({}), "version_unsupported"),
        (
            "missing receipts",
            serde_json::json!({"spec": "continuity-receipt/0.2"}),
            "malformed",
        ),
        (
            "empty receipts",
            serde_json::json!({"spec": "continuity-receipt/0.2", "receipts": []}),
            "malformed",
        ),
        (
            "unknown spec",
            serde_json::json!({"spec": "continuity-receipt/9.9", "receipts": [{}]}),
            "version_unsupported",
        ),
        (
            "non-object receipt",
            serde_json::json!({"spec": "continuity-receipt/0.2", "task_id": "t", "receipts": [42]}),
            "malformed",
        ),
        (
            "unknown record type",
            serde_json::json!({
                "spec": "continuity-receipt/0.2",
                "task_id": "t",
                "receipts": [{"spec": "continuity-receipt/0.2", "task_id": "t", "type": "nope", "seq": 0}]
            }),
            "unknown_type",
        ),
    ];

    for (name, bundle, code) in cases {
        let result = verify_bundle(&bundle, false);
        assert_eq!(result.verdict(), "UNTRUSTED", "{name}: {bundle}");
        assert!(
            result.codes().contains(&code),
            "{name}: expected {code}, got {:?}",
            result.codes()
        );
    }
}

#[test]
fn canonicalization_pins_the_subset() {
    use continuity_receipt::canon::{canonical_bytes, commit_field};

    let first = canonical_bytes(&serde_json::json!({
        "b": 1,
        "a": [1, 2, {"d": "x", "c": true}]
    }))
    .expect("canonicalizes");
    let second = canonical_bytes(&serde_json::json!({
        "a": [1, 2, {"c": true, "d": "x"}],
        "b": 1
    }))
    .expect("canonicalizes");
    assert_eq!(first, second);
    assert_eq!(first, br#"{"a":[1,2,{"c":true,"d":"x"}],"b":1}"#);

    let big: Value =
        serde_json::from_str(r#"{"n": 123456789012345678901234567890}"#).expect("big integer");
    assert_eq!(
        canonical_bytes(&big).expect("canonicalizes"),
        br#"{"n":123456789012345678901234567890}"#
    );

    let escaped = canonical_bytes(&serde_json::json!({"s": "a\"b\\c\u{1}f\n"})).expect("escapes");
    assert_eq!(escaped, br#"{"s":"a\"b\\c\u0001f\n"}"#);

    assert!(canonical_bytes(&serde_json::json!({"amount": 1.5})).is_err());
    assert!(commit_field("zz", &serde_json::json!(1)).is_err());
}
