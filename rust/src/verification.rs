//! Verification receipts (companion, version 1).
//!
//! Port of `continuity_receipt/verification.py`: a receipt is a signed record
//! of a verification run — the full result (verdict, errors, reasons,
//! summary) bound to the JCS-canonical bundle digest. Wire format and
//! semantics: `VERIFICATION_RECEIPTS.md`.
//!
//! Malformed-input notes (same policy as `verify.rs`): Python compares the
//! `version` field with `!= 1`, which accepts `1.0`/`true`; this port accepts
//! only integer `1` and fails closed with `bad_version` otherwise. Nothing in
//! the format or vectors depends on the looser comparison.

use serde_json::{Map, Value};

use crate::canon::{canonical_bytes, sha256_prefixed, CanonError};
use crate::didkey;
use crate::verify::{parse_timestamp, validate_timestamp, verify_revocation_statements};

pub const KIND: &str = "continuity-receipt-verification";
pub const VERSION: u64 = 1;
pub const VERDICTS: [&str; 4] = [
    "TRUSTED",
    "PROVISIONAL",
    "INSUFFICIENT_EVIDENCE",
    "UNTRUSTED",
];

/// Mirrors Python's `VerificationReceiptResult` (`as_dict` shape).
#[derive(Debug, Clone, Default)]
pub struct VerificationReceiptResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub issuer: Option<String>,
    pub verdict: Option<String>,
    pub verified_at: Option<String>,
    pub bundle_digest: Option<String>,
    pub digest_match: Option<bool>,
}

impl VerificationReceiptResult {
    pub fn as_dict(&self) -> Value {
        let mut map = Map::new();
        map.insert("valid".to_string(), Value::Bool(self.valid));
        map.insert(
            "errors".to_string(),
            Value::Array(self.errors.iter().map(|e| Value::String(e.clone())).collect()),
        );
        map.insert(
            "issuer".to_string(),
            self.issuer.clone().map(Value::String).unwrap_or(Value::Null),
        );
        map.insert(
            "verdict".to_string(),
            self.verdict.clone().map(Value::String).unwrap_or(Value::Null),
        );
        map.insert(
            "verified_at".to_string(),
            self.verified_at.clone().map(Value::String).unwrap_or(Value::Null),
        );
        map.insert(
            "bundle_digest".to_string(),
            self.bundle_digest.clone().map(Value::String).unwrap_or(Value::Null),
        );
        map.insert(
            "digest_match".to_string(),
            self.digest_match.map(Value::Bool).unwrap_or(Value::Null),
        );
        Value::Object(map)
    }
}

/// SHA-256 of the canonical bytes of a verification receipt minus its `sig`
/// (the digest to anchor — `VERIFICATION_RECEIPTS.md` §Anchoring).
pub fn receipt_digest(receipt: &Value) -> Result<String, CanonError> {
    let Some(object) = receipt.as_object() else {
        return Err(CanonError("receipt is not an object".to_string()));
    };
    let mut unsigned = object.clone();
    unsigned.remove("sig");
    Ok(sha256_prefixed(&canonical_bytes(&Value::Object(unsigned))?))
}

fn is_digest(text: &str) -> bool {
    match text.strip_prefix("sha256:") {
        Some(hex) => {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        }
        None => false,
    }
}

fn errors_well_formed(value: &Value) -> bool {
    value
        .as_array()
        .map(|items| {
            items.iter().all(|item| {
                item.as_object()
                    .map(|entry| entry.get("code").and_then(Value::as_str).is_some())
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn string_list(value: &Value) -> bool {
    value
        .as_array()
        .map(|items| items.iter().all(Value::is_string))
        .unwrap_or(false)
}

fn list_non_empty(value: &Value) -> bool {
    value
        .as_array()
        .map(|items| !items.is_empty())
        .unwrap_or(false)
}

fn verdict_class(errors: &Value, provisional: &Value, insufficient: &Value) -> &'static str {
    if list_non_empty(errors) {
        "UNTRUSTED"
    } else if list_non_empty(insufficient) {
        "INSUFFICIENT_EVIDENCE"
    } else if list_non_empty(provisional) {
        "PROVISIONAL"
    } else {
        "TRUSTED"
    }
}

/// Verify a verification receipt (Python `verify_verification_receipt`).
///
/// `bundle` (already parsed), when supplied, additionally checks
/// `bundle_digest` against the bundle's canonical bytes and reports
/// `digest_match`. `revocations` (statements in the 0.2 §7.5 shape), when
/// supplied, checks whether the issuer key was revoked at or before
/// `verified_at` (`key_revoked`).
pub fn verify_verification_receipt(
    receipt: &Value,
    bundle: Option<&Value>,
    revocations: Option<&[Value]>,
) -> VerificationReceiptResult {
    let Some(object) = receipt.as_object() else {
        return VerificationReceiptResult {
            valid: false,
            errors: vec!["not_an_object".to_string()],
            ..Default::default()
        };
    };
    let mut errors: Vec<String> = Vec::new();

    if object.get("kind").and_then(Value::as_str) != Some(KIND) {
        errors.push("bad_kind".to_string());
    }
    if object.get("version").and_then(Value::as_u64) != Some(VERSION) {
        errors.push("bad_version".to_string());
    }
    let verdict = object.get("verdict").and_then(Value::as_str);
    if !verdict.map(|value| VERDICTS.contains(&value)).unwrap_or(false) {
        errors.push("bad_verdict".to_string());
    }
    let verified_at = object.get("verified_at").and_then(Value::as_str);
    if !validate_timestamp(object.get("verified_at")) {
        errors.push("bad_verified_at".to_string());
    }
    if !object
        .get("bundle_digest")
        .and_then(Value::as_str)
        .map(is_digest)
        .unwrap_or(false)
    {
        errors.push("bad_bundle_digest".to_string());
    }

    let result_errors = object.get("errors");
    let errors_ok = result_errors.map(errors_well_formed).unwrap_or(false);
    if !errors_ok {
        errors.push("bad_errors".to_string());
    }
    let provisional = object.get("provisional_reasons");
    let provisional_ok = provisional.map(string_list).unwrap_or(false);
    if !provisional_ok {
        errors.push("bad_provisional_reasons".to_string());
    }
    let insufficient = object.get("insufficient_reasons");
    let insufficient_ok = insufficient.map(string_list).unwrap_or(false);
    if !insufficient_ok {
        errors.push("bad_insufficient_reasons".to_string());
    }
    if !object.get("summary").map(Value::is_object).unwrap_or(false) {
        errors.push("bad_summary".to_string());
    }

    let error_codes = object.get("error_codes");
    let codes_ok = error_codes.map(string_list).unwrap_or(false);
    if !codes_ok {
        errors.push("bad_error_codes".to_string());
    } else if errors_ok {
        let expected: Vec<&str> = result_errors
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|entry| entry.get("code").and_then(Value::as_str).unwrap_or_default())
                    .collect()
            })
            .unwrap_or_default();
        let actual: Vec<&str> = error_codes
            .and_then(Value::as_array)
            .map(|items| items.iter().map(Value::as_str).map(|v| v.unwrap_or_default()).collect())
            .unwrap_or_default();
        if expected != actual {
            errors.push("error_codes_mismatch".to_string());
        }
    }
    if verdict.map(|value| VERDICTS.contains(&value)).unwrap_or(false)
        && errors_ok
        && provisional_ok
        && insufficient_ok
    {
        let class = verdict_class(
            result_errors.unwrap(),
            provisional.unwrap(),
            insufficient.unwrap(),
        );
        if verdict != Some(class) {
            errors.push("verdict_mismatch".to_string());
        }
    }

    let issuer = object.get("issuer").and_then(Value::as_str);
    let sig = object.get("sig").and_then(Value::as_object);
    let sig_shape_ok = sig
        .map(|entry| {
            entry.get("alg").and_then(Value::as_str) == Some("ed25519")
                && entry.get("key").and_then(Value::as_str).is_some()
                && entry
                    .get("value")
                    .and_then(Value::as_str)
                    .map(|value| !value.is_empty())
                    .unwrap_or(false)
        })
        .unwrap_or(false);
    if !sig_shape_ok {
        errors.push("bad_signature_shape".to_string());
    } else {
        let key_matches = issuer.map(|value| !value.is_empty()).unwrap_or(false)
            && sig.and_then(|entry| entry.get("key")).and_then(Value::as_str) == issuer;
        if !key_matches {
            errors.push("bad_signature".to_string());
        } else {
            let mut unsigned = object.clone();
            unsigned.remove("sig");
            let verified = match canonical_bytes(&Value::Object(unsigned)) {
                Ok(message) => didkey::verify(
                    issuer.unwrap_or_default(),
                    &message,
                    sig.and_then(|entry| entry.get("value"))
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                ),
                Err(_) => false,
            };
            if !verified {
                errors.push("bad_signature".to_string());
            }
        }
    }

    let mut digest_match: Option<bool> = None;
    if let Some(bundle_value) = bundle {
        match canonical_bytes(bundle_value) {
            Ok(canonical) => {
                let expected = sha256_prefixed(&canonical);
                digest_match = Some(
                    object.get("bundle_digest").and_then(Value::as_str) == Some(expected.as_str()),
                );
            }
            Err(_) => digest_match = Some(false),
        }
        if digest_match != Some(true) {
            errors.push("bundle_digest_mismatch".to_string());
        }
    }

    if let Some(statements) = revocations.filter(|items| !items.is_empty()) {
        let (revoked, statement_errors) = verify_revocation_statements(statements);
        errors.extend(statement_errors.into_iter().map(|entry| entry.code));
        if let (Some(at_text), Some(issuer_id)) = (verified_at, issuer) {
            if let Some(at) = parse_timestamp(at_text) {
                for (key_id, revoked_at) in &revoked {
                    if key_id == issuer_id && at >= *revoked_at {
                        errors.push("key_revoked".to_string());
                    }
                }
            }
        }
    }

    VerificationReceiptResult {
        valid: errors.is_empty(),
        errors,
        issuer: issuer.map(str::to_string),
        verdict: verdict.map(str::to_string),
        verified_at: verified_at.map(str::to_string),
        bundle_digest: object
            .get("bundle_digest")
            .and_then(Value::as_str)
            .map(str::to_string),
        digest_match,
    }
}
