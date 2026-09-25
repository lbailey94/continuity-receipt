//! Bundle verification (0.1 + 0.2).
//!
//! Port of `continuity_receipt/verify.py`. Verdict precedence is
//! `errors -> UNTRUSTED`, `insufficient -> INSUFFICIENT_EVIDENCE`,
//! `provisional -> PROVISIONAL`, else `TRUSTED`. Error codes are identical to
//! the Python verifier. Docstrings note the few places where malformed input
//! that would raise in Python (floats in canonicalization, unhashable
//! members, non-object shapes) is failed closed with a structured error
//! instead.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::canon::{canonical_bytes, commit_field, sha256_prefixed, CanonError};
use crate::didkey;

pub const SUPPORTED_SPECS: [&str; 5] = [
    "continuity-receipt/0.1",
    "continuity-receipt/0.2",
    "continuity-receipt/0.3",
    "continuity-receipt/0.4",
    "continuity-receipt/0.5",
];
pub const RECORD_TYPES: [&str; 10] = [
    "session.pass.created",
    "task.decision",
    "task.execution",
    "delivery.attestation",
    "task.termination",
    "settlement",
    "authority.succession",
    "agreement.offer",
    "agreement.accept",
    "state.commitment",
];

const ANCHOR_TYPES: [&str; 3] = ["opentimestamps", "public-chain", "custom"];
const PROVENANCE_PREFIXES: [&str; 2] = ["sha256:", "merkle-sha256:"];
/// 0.4: record types an `agreement.accept` binds.
const BOUND_TYPES: [&str; 4] = [
    "task.decision",
    "task.execution",
    "delivery.attestation",
    "settlement",
];

const PASS_FIELDS: [&str; 7] = [
    "gate_id",
    "mandala_class",
    "quotas",
    "expires_at",
    "policy_version",
    "mandate_ref",
    "agent_id",
];
const DECISION_FIELDS: [&str; 6] = [
    "action",
    "action_args_hash",
    "model",
    "input_provenance",
    "decision",
    "policy_version",
];
const EXECUTION_FIELDS: [&str; 4] = ["tool_calls", "egress", "resources", "sandbox_class"];
const DELIVERY_FIELDS: [&str; 3] = ["request_hash", "response_hash", "counterparty"];
const TERMINATION_FIELDS: [&str; 3] = ["reason", "limits_at_stop", "remaining"];
const SETTLEMENT_FIELDS: [&str; 5] = [
    "rail",
    "rail_ref",
    "amount",
    "gated_on_delivery",
    "settled_at",
];
const SUCCESSION_FIELDS: [&str; 4] = ["from_authority", "to_authority", "effective_at", "reason"];
const OFFER_FIELDS: [&str; 5] = ["offer_id", "offeree", "terms_hash", "valid_until", "nonce"];
const ACCEPT_FIELDS: [&str; 3] = ["offer_ref", "offer_id", "terms_hash"];
/// 0.4: the accept names the offeree (mirrors `REQUIRED_FIELDS_04`).
const ACCEPT_FIELDS_04: [&str; 4] = ["offer_ref", "offer_id", "terms_hash", "offeree"];
const COMMITMENT_FIELDS: [&str; 4] = ["state_kind", "scope", "count", "head_digest"];

fn required_fields(record_type: &str, spec: Option<&str>) -> Option<&'static [&'static str]> {
    if matches!(spec, Some("continuity-receipt/0.4" | "continuity-receipt/0.5")) && record_type == "agreement.accept" {
        return Some(&ACCEPT_FIELDS_04);
    }
    match record_type {
        "session.pass.created" => Some(&PASS_FIELDS),
        "task.decision" => Some(&DECISION_FIELDS),
        "task.execution" => Some(&EXECUTION_FIELDS),
        "delivery.attestation" => Some(&DELIVERY_FIELDS),
        "task.termination" => Some(&TERMINATION_FIELDS),
        "settlement" => Some(&SETTLEMENT_FIELDS),
        "authority.succession" => Some(&SUCCESSION_FIELDS),
        "agreement.offer" => Some(&OFFER_FIELDS),
        "agreement.accept" => Some(&ACCEPT_FIELDS),
        "state.commitment" if spec == Some("continuity-receipt/0.5") => Some(&COMMITMENT_FIELDS),
        _ => None,
    }
}

fn prefixed_hex(value: Option<&Value>, prefix: &str) -> bool {
    value.and_then(Value::as_str).is_some_and(|text| {
        text.strip_prefix(prefix).is_some_and(|hex| {
            hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    })
}

fn check_05_body(
    result: &mut VerifyResult,
    record_type: &str,
    body: &Map<String, Value>,
    receipt_id: Option<&Value>,
) {
    let mut bad = Vec::new();
    match record_type {
        "session.pass.created" => {
            if !matches!(body.get("mandala_class").and_then(Value::as_str), Some("gate-lite" | "gate-hard" | "local")) {
                bad.push("mandala_class must be gate-lite, gate-hard, or local");
            }
        }
        "task.execution" => {
            if !matches!(body.get("sandbox_class").and_then(Value::as_str), Some("bwrap-landlock" | "microvm-ch" | "microvm-fc" | "none")) {
                bad.push("sandbox_class is unknown");
            }
        }
        "state.commitment" => {
            if !body.get("state_kind").and_then(Value::as_str).is_some_and(|text| !text.is_empty()) {
                bad.push("state_kind must be nonempty text");
            }
            if !body.get("scope").and_then(Value::as_str).is_some_and(|text| !text.is_empty()) {
                bad.push("scope must be nonempty text");
            }
            if !body.get("count").and_then(Value::as_u64).is_some() {
                bad.push("count must be an unsigned 64-bit integer");
            }
            if !prefixed_hex(body.get("head_digest"), "sha256:") {
                bad.push("head_digest must be a sha256 digest");
            }
            if body.get("merkle_root").is_some_and(|root| !root.is_null()) && !prefixed_hex(body.get("merkle_root"), "merkle-sha256:") {
                bad.push("merkle_root must be a merkle-sha256 digest");
            }
        }
        _ => {}
    }
    for detail in bad {
        fatal(result, "malformed", detail, receipt_id);
    }
}

/// One structured verification failure.
#[derive(Debug, Clone)]
pub struct ErrorEntry {
    pub code: String,
    pub detail: String,
    pub receipt_id: Value,
}

/// Mirrors Python's `VerifyResult` (`as_dict` produces the same JSON shape).
#[derive(Debug, Clone, Default)]
pub struct VerifyResult {
    pub errors: Vec<ErrorEntry>,
    pub provisional_reasons: Vec<String>,
    pub insufficient_reasons: Vec<String>,
    pub summary: Map<String, Value>,
}

impl VerifyResult {
    /// CTQ-aligned verdict, computed from the collected reasons/errors.
    pub fn verdict(&self) -> &'static str {
        if !self.errors.is_empty() {
            "UNTRUSTED"
        } else if !self.insufficient_reasons.is_empty() {
            "INSUFFICIENT_EVIDENCE"
        } else if !self.provisional_reasons.is_empty() {
            "PROVISIONAL"
        } else {
            "TRUSTED"
        }
    }

    pub fn codes(&self) -> Vec<&str> {
        self.errors
            .iter()
            .map(|entry| entry.code.as_str())
            .collect()
    }

    /// `VerifyResult.as_dict()` equivalent.
    pub fn as_dict(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "verdict".to_string(),
            Value::String(self.verdict().to_string()),
        );
        map.insert("errors".to_string(), self.errors_value());
        map.insert(
            "provisional_reasons".to_string(),
            Value::Array(
                self.provisional_reasons
                    .iter()
                    .map(|reason| Value::String(reason.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "insufficient_reasons".to_string(),
            Value::Array(
                self.insufficient_reasons
                    .iter()
                    .map(|reason| Value::String(reason.clone()))
                    .collect(),
            ),
        );
        map.insert("summary".to_string(), Value::Object(self.summary.clone()));
        Value::Object(map)
    }

    fn errors_value(&self) -> Value {
        Value::Array(
            self.errors
                .iter()
                .map(|entry| {
                    let mut item = Map::new();
                    item.insert("code".to_string(), Value::String(entry.code.clone()));
                    item.insert("detail".to_string(), Value::String(entry.detail.clone()));
                    item.insert("receipt_id".to_string(), entry.receipt_id.clone());
                    Value::Object(item)
                })
                .collect(),
        )
    }

    /// Result carrying a single `malformed` error (used for unparseable input).
    pub fn malformed(detail: impl Into<String>) -> Self {
        Self::coded("malformed", detail)
    }

    /// A result carrying a single error with the given code (CLI input guards).
    pub fn coded(code: &str, detail: impl Into<String>) -> Self {
        let mut result = Self::default();
        fatal(&mut result, code, detail.into(), None);
        result
    }
}

fn fatal(
    result: &mut VerifyResult,
    code: &str,
    detail: impl Into<String>,
    receipt_id: Option<&Value>,
) {
    result.errors.push(ErrorEntry {
        code: code.to_string(),
        detail: detail.into(),
        receipt_id: receipt_id.cloned().unwrap_or(Value::Null),
    });
}

fn spec_supported(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .map(|spec| SUPPORTED_SPECS.contains(&spec))
        .unwrap_or(false)
}

/// Iterative depth probe so hostile nesting cannot exhaust the stack
/// (mirrors Python `_depth_exceeded`).
fn depth_exceeded(value: &Value, limit: usize) -> bool {
    let mut stack = vec![(value, 1usize)];
    while let Some((current, depth)) = stack.pop() {
        if depth > limit {
            return true;
        }
        match current {
            Value::Object(map) => stack.extend(map.values().map(|item| (item, depth + 1))),
            Value::Array(items) => stack.extend(items.iter().map(|item| (item, depth + 1))),
            _ => {}
        }
    }
    false
}

/// Whole-shape validation before any semantic check (mirrors Python
/// `_check_shape`): structural violations are recorded up front so every
/// later pass can rely on shape.
fn check_shape(result: &mut VerifyResult, bundle_object: &Map<String, Value>, receipts: &[Value]) {
    for (index, receipt) in receipts.iter().enumerate() {
        let Some(record) = receipt.as_object() else {
            fatal(
                result,
                "malformed",
                format!("receipt {index} is not an object"),
                None,
            );
            continue;
        };
        let receipt_id = record.get("receipt_id").filter(|value| value.is_string());
        if !record.get("body").map(Value::is_object).unwrap_or(false) {
            fatal(result, "malformed", "body is not an object", receipt_id);
        }
        if !record.get("issuer").map(Value::is_object).unwrap_or(false) {
            fatal(result, "malformed", "issuer is not an object", receipt_id);
        }
    }
    if let Some(anchors) = bundle_object.get("anchors") {
        if !anchors.is_null() && !anchors.is_array() {
            fatal(result, "malformed", "anchors is not a list", None);
        } else if let Some(items) = anchors.as_array() {
            for anchor in items {
                if !anchor.is_object() {
                    fatal(result, "anchor_invalid", "anchor entry is not an object", None);
                }
            }
        }
    }
    if let Some(revocations) = bundle_object.get("revocations") {
        if !revocations.is_null() && !revocations.is_array() {
            fatal(result, "bad_revocation", "revocations must be a list", None);
        } else if let Some(items) = revocations.as_array() {
            for statement in items {
                if !statement.is_object() {
                    fatal(
                        result,
                        "bad_revocation",
                        "revocation statements must be objects",
                        None,
                    );
                }
            }
        }
    }
    if let Some(disclosure) = bundle_object.get("disclosure_map") {
        if !disclosure.is_null() && !disclosure.is_object() {
            fatal(result, "malformed", "disclosure_map is not an object", None);
        }
    }
}

/// Verify a parsed bundle (Python `verify_bundle`).
pub fn verify_bundle(bundle: &Value, require_anchor: bool) -> VerifyResult {
    let mut result = VerifyResult::default();

    let Some(bundle_object) = bundle.as_object() else {
        fatal(&mut result, "malformed", "bundle is not an object", None);
        return result;
    };

    const MAX_NESTING_DEPTH: usize = 64;
    if depth_exceeded(bundle, MAX_NESTING_DEPTH) {
        fatal(
            &mut result,
            "nesting_too_deep",
            format!("bundle nesting exceeds depth {MAX_NESTING_DEPTH}"),
            None,
        );
        return result;
    }

    if !spec_supported(bundle_object.get("spec")) {
        fatal(
            &mut result,
            "version_unsupported",
            format!("spec={}", py_repr(bundle_object.get("spec"))),
            None,
        );
        return result;
    }

    let Some(receipts) = bundle_object
        .get("receipts")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
    else {
        fatal(&mut result, "malformed", "bundle has no receipts", None);
        return result;
    };

    const MAX_RECEIPTS: usize = 10_000;
    if receipts.len() > MAX_RECEIPTS {
        fatal(
            &mut result,
            "too_many_receipts",
            format!("{} receipts exceeds limit {MAX_RECEIPTS}", receipts.len()),
            None,
        );
        return result;
    }

    // Missing and explicit-null compare equal here, as Python's dict.get does.
    let task_id = bundle_object
        .get("task_id")
        .filter(|value| !value.is_null());
    let mut expected_prev: Option<String> = None;
    let mut type_by_seq: BTreeMap<usize, String> = BTreeMap::new();

    check_shape(&mut result, bundle_object, receipts);

    for (index, receipt) in receipts.iter().enumerate() {
        let Some(record) = receipt.as_object() else {
            continue;
        };
        let receipt_id = record.get("receipt_id");

        if !spec_supported(record.get("spec")) {
            fatal(
                &mut result,
                "version_unsupported",
                format!("receipt spec={}", py_repr(record.get("spec"))),
                receipt_id,
            );
        }
        if record.get("task_id").filter(|value| !value.is_null()) != task_id {
            fatal(
                &mut result,
                "task_mismatch",
                "receipt task_id != bundle task_id",
                receipt_id,
            );
        }

        let record_type = record.get("type").and_then(Value::as_str);
        let Some(record_type) = record_type.filter(|name| RECORD_TYPES.contains(name) && (*name != "state.commitment" || record.get("spec").and_then(Value::as_str) == Some("continuity-receipt/0.5"))) else {
            fatal(
                &mut result,
                "unknown_type",
                format!("type={}", py_repr(record.get("type"))),
                receipt_id,
            );
            continue;
        };
        type_by_seq.insert(index, record_type.to_string());

        let Some(body) = record.get("body").and_then(Value::as_object) else {
            continue;
        };
        let missing: Vec<&str> =
            required_fields(record_type, record.get("spec").and_then(Value::as_str))
                .unwrap_or(&[])
                .iter()
                .copied()
                .filter(|name| !body.contains_key(*name))
            .collect();
        if !missing.is_empty() {
            let listed = missing
                .iter()
                .map(|name| quote_py_string(name))
                .collect::<Vec<_>>()
                .join(", ");
            fatal(
                &mut result,
                "malformed",
                format!("missing body fields [{listed}]"),
                receipt_id,
            );
        }
        if record.get("spec").and_then(Value::as_str) == Some("continuity-receipt/0.5") {
            check_05_body(&mut result, record_type, body, receipt_id);
        }

        if !validate_timestamp(record.get("issued_at")) {
            fatal(
                &mut result,
                "malformed",
                format!(
                    "issued_at not RFC 3339 UTC: {}",
                    py_repr(record.get("issued_at"))
                ),
                receipt_id,
            );
        }

        if !seq_matches(record.get("seq"), index) {
            fatal(
                &mut result,
                "chain_break",
                format!("seq {} != position {index}", py_str(record.get("seq"))),
                receipt_id,
            );
        }
        let prev = record.get("prev").filter(|value| !value.is_null());
        let prev_matches = match (prev, expected_prev.as_deref()) {
            (None, None) => true,
            (Some(Value::String(text)), Some(expected)) => text == expected,
            _ => false,
        };
        if !prev_matches {
            fatal(
                &mut result,
                "chain_break",
                "prev digest mismatch",
                receipt_id,
            );
        }

        match receipt_digest(record) {
            Ok(digest) => expected_prev = Some(digest),
            Err(error) => {
                fatal(
                    &mut result,
                    "malformed",
                    format!("canonicalization failed: {error}"),
                    receipt_id,
                );
                expected_prev = None;
                continue;
            }
        }

        let sig = record.get("sig").and_then(Value::as_object);
        let sig_shape_ok = sig
            .and_then(|value| value.get("alg"))
            .and_then(Value::as_str)
            == Some("ed25519")
            && py_truthy(sig.and_then(|value| value.get("value")));
        if !sig_shape_ok {
            fatal(
                &mut result,
                "bad_signature",
                "missing or unsupported sig",
                receipt_id,
            );
            continue;
        }
        let issuer = record
            .get("issuer")
            .and_then(Value::as_object)
            .and_then(|issuer| issuer.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let signature = sig
            .and_then(|value| value.get("value"))
            .and_then(Value::as_str);
        match canonical_bytes(&Value::Object(unsigned_view(record))) {
            Ok(message) => {
                let verified = signature
                    .map(|value| didkey::verify(issuer, &message, value))
                    .unwrap_or(false);
                if !verified {
                    fatal(
                        &mut result,
                        "bad_signature",
                        "signature does not verify",
                        receipt_id,
                    );
                }
            }
            Err(error) => fatal(
                &mut result,
                "malformed",
                format!("canonicalization failed: {error}"),
                receipt_id,
            ),
        }
    }

    check_cross_record(&mut result, receipts, &type_by_seq);
    check_agreements(&mut result, receipts);
    check_redactions(
        &mut result,
        receipts,
        bundle_object
            .get("disclosure_map")
            .and_then(Value::as_object),
    );
    check_attestations(&mut result, receipts);
    check_provenance(&mut result, receipts);
    check_revocations(&mut result, bundle_object, receipts);
    check_anchors(&mut result, bundle_object, receipts, require_anchor);

    let summary = build_summary(receipts, &type_by_seq);
    let extras = std::mem::take(&mut result.summary);
    result.summary = summary;
    for (key, value) in extras {
        result.summary.insert(key, value);
    }
    result
}

fn check_cross_record(
    result: &mut VerifyResult,
    receipts: &[Value],
    type_by_seq: &BTreeMap<usize, String>,
) {
    let pass_receipts: Vec<&Map<String, Value>> = receipts
        .iter()
        .filter_map(Value::as_object)
        .filter(|record| record.get("type").and_then(Value::as_str) == Some("session.pass.created"))
        .collect();
    if pass_receipts.is_empty() {
        fatal(
            result,
            "malformed",
            "chain has no session.pass.created receipt",
            None,
        );
        return;
    }
    let Some(pass_body) = pass_receipts[0].get("body").and_then(Value::as_object) else {
        return;
    };
    let policy_version = pass_body.get("policy_version");

    for receipt in receipts.iter().filter_map(Value::as_object) {
        if receipt.get("type").and_then(Value::as_str) != Some("task.decision") {
            continue;
        }
        let Some(decision_body) = receipt.get("body").and_then(Value::as_object) else {
            continue;
        };
        let decision_policy = decision_body.get("policy_version");
        if decision_policy != policy_version {
            fatal(
                result,
                "policy_mismatch",
                format!(
                    "decision policy {} != pass policy {}",
                    py_repr(decision_policy),
                    py_repr(policy_version)
                ),
                receipt.get("receipt_id"),
            );
        }
    }

    let mut spend_cap = pass_body.get("spend_cap").filter(|value| !value.is_null());
    if spend_cap.is_some() && !spend_cap.map(Value::is_object).unwrap_or(false) {
        fatal(
            result,
            "malformed",
            "pass spend_cap is not an object",
            pass_receipts[0].get("receipt_id"),
        );
        spend_cap = None;
    }
    let settlement_indexes: Vec<usize> = type_by_seq
        .iter()
        .filter(|(_, record_type)| record_type.as_str() == "settlement")
        .map(|(index, _)| *index)
        .collect();
    let delivery_indexes: Vec<usize> = type_by_seq
        .iter()
        .filter(|(_, record_type)| record_type.as_str() == "delivery.attestation")
        .map(|(index, _)| *index)
        .collect();

    for index in settlement_indexes {
        let Some(settlement) = receipts.get(index).and_then(Value::as_object) else {
            continue;
        };
        let Some(body) = settlement.get("body").and_then(Value::as_object) else {
            continue;
        };
        let amount = body.get("amount");
        if amount.is_some() && !amount.map(Value::is_object).unwrap_or(false) {
            fatal(
                result,
                "malformed",
                "settlement amount is not an object",
                settlement.get("receipt_id"),
            );
            continue;
        }
        if let Some(cap) = spend_cap {
            let cap_object = cap.as_object();
            let amount_object = amount.and_then(Value::as_object);
            let currency_mismatch = amount_object.and_then(|item| item.get("currency"))
                != cap_object.and_then(|item| item.get("currency"));
            let exceeded = if currency_mismatch {
                true
            } else {
                match (minor_units(amount_object), minor_units(cap_object)) {
                    (Some(settled), Some(limit)) => settled > limit,
                    _ => {
                        fatal(
                            result,
                            "malformed",
                            "settlement amount is not numeric",
                            settlement.get("receipt_id"),
                        );
                        false
                    }
                }
            };
            if exceeded {
                let amount_repr = amount
                    .map(py_repr_value)
                    .unwrap_or_else(|| "{}".to_string());
                fatal(
                    result,
                    "cap_exceeded",
                    format!(
                        "settlement {amount_repr} exceeds cap {}",
                        py_repr(Some(cap))
                    ),
                    settlement.get("receipt_id"),
                );
            }
        }
        if py_truthy(body.get("gated_on_delivery")) {
            let gated_late =
                delivery_indexes.is_empty() || delivery_indexes.iter().min().copied() > Some(index);
            if gated_late {
                fatal(
                    result,
                    "delivery_before_settlement",
                    "gated settlement recorded before any delivery attestation",
                    settlement.get("receipt_id"),
                );
            }
        }
    }

    if !type_by_seq
        .values()
        .any(|record_type| record_type == "task.termination")
    {
        fatal(
            result,
            "missing_termination",
            "task has no termination receipt",
            None,
        );
    }
}

/// 0.3: `agreement.accept` binds to a preceding `agreement.offer` (spec §4.9).
///
/// `offer_ref` is the digest of the offer receipt; an accept whose offer is
/// absent from the bundle is unverifiable, not false (INSUFFICIENT_EVIDENCE,
/// `missing_offer`). A present offer with a different `offer_id`/`terms_hash`
/// is `offer_mismatch`; an accept issued after `valid_until` is
/// `offer_expired`.
fn check_agreements(result: &mut VerifyResult, receipts: &[Value]) {
    let mut offers: BTreeMap<String, &Map<String, Value>> = BTreeMap::new();
    let mut accepts: BTreeMap<String, &Map<String, Value>> = BTreeMap::new();
    for receipt in receipts.iter().filter_map(Value::as_object) {
        match receipt.get("type").and_then(Value::as_str) {
            Some("agreement.offer") => {
                if let Ok(digest) = receipt_digest(receipt) {
                    offers.insert(digest, receipt);
                }
            }
            Some("agreement.accept") => {
                if let Ok(digest) = receipt_digest(receipt) {
                    accepts.insert(digest, receipt);
                }
            }
            _ => {}
        }
    }

    for accept in accepts.values() {
        check_accept(result, accept, &offers);
    }

    let mut referenced: BTreeSet<String> = BTreeSet::new();
    for receipt in receipts.iter().filter_map(Value::as_object) {
        let Some(record_type) = receipt.get("type").and_then(Value::as_str) else {
            continue;
        };
        if !BOUND_TYPES.contains(&record_type) {
            continue;
        }
        if !matches!(receipt.get("spec").and_then(Value::as_str), Some("continuity-receipt/0.4" | "continuity-receipt/0.5")) {
            continue;
        }
        let Some(body) = receipt.get("body").and_then(Value::as_object) else {
            continue;
        };
        let Some(reference) = body.get("agreement_ref").filter(|value| !value.is_null()) else {
            continue;
        };
        let accept = reference
            .as_str()
            .and_then(|reference| accepts.get(reference));
        let Some(accept) = accept else {
            result.insufficient_reasons.push(format!(
                "missing_agreement:{}",
                receipt
                    .get("receipt_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
            ));
            continue;
        };
        referenced.insert(reference.as_str().unwrap_or("").to_string());
        let Some(accept_body) = accept.get("body").and_then(Value::as_object) else {
            continue;
        };
        let accept_issued = accept
            .get("issued_at")
            .and_then(Value::as_str)
            .and_then(parse_timestamp);
        let bound_issued = receipt
            .get("issued_at")
            .and_then(Value::as_str)
            .and_then(parse_timestamp);
        if let (Some(accept_issued), Some(bound_issued)) = (accept_issued, bound_issued) {
            if bound_issued < accept_issued {
                fatal(
                    result,
                    "agreement_before_accept",
                    format!(
                        "bound receipt issued before its accept {}",
                        py_repr(accept.get("receipt_id"))
                    ),
                    receipt.get("receipt_id"),
                );
            }
        }
        let issuer_id = receipt
            .get("issuer")
            .and_then(Value::as_object)
            .and_then(|issuer| issuer.get("id"))
            .and_then(Value::as_str);
        if let Some(offeree) = accept_body.get("offeree").and_then(Value::as_str) {
            if issuer_id != Some(offeree) {
                fatal(
                    result,
                    "agreement_issuer_mismatch",
                    format!("bound receipt issuer {issuer_id:?} is not the offeree"),
                    receipt.get("receipt_id"),
                );
            }
        }
    }

    check_agreement_completeness(result, receipts, &accepts, &referenced);
}

/// 0.3 offer resolution plus the 0.4 offeree and chronology rules.
fn check_accept(
    result: &mut VerifyResult,
    receipt: &Map<String, Value>,
    offers: &BTreeMap<String, &Map<String, Value>>,
) {
    let Some(body) = receipt.get("body").and_then(Value::as_object) else {
        return;
    };
    let offer = body
        .get("offer_ref")
        .and_then(Value::as_str)
        .and_then(|reference| offers.get(reference));
    let Some(offer) = offer else {
        result.insufficient_reasons.push(format!(
            "missing_offer:{}",
            receipt
                .get("receipt_id")
                .and_then(Value::as_str)
                .unwrap_or("")
        ));
        return;
    };
    let Some(offer_body) = offer.get("body").and_then(Value::as_object) else {
        return;
    };
    let valid_until = offer_body.get("valid_until");
    if !validate_timestamp(valid_until) {
        fatal(
            result,
            "malformed",
            format!(
                "offer valid_until not RFC 3339 UTC: {}",
                py_repr(valid_until)
            ),
            offer.get("receipt_id"),
        );
        return;
    }
    let same_offer_id = body.get("offer_id") == offer_body.get("offer_id");
    let same_terms = body.get("terms_hash") == offer_body.get("terms_hash");
    if !same_offer_id || !same_terms {
        fatal(
            result,
            "offer_mismatch",
            "accept does not match the referenced offer",
            receipt.get("receipt_id"),
        );
        return;
    }
    let accept_issued = receipt
        .get("issued_at")
        .and_then(Value::as_str)
        .and_then(parse_timestamp);
    let valid_until_at = valid_until.and_then(Value::as_str).and_then(parse_timestamp);
    if let (Some(accept_issued), Some(valid_until_at)) = (accept_issued, valid_until_at) {
        if accept_issued > valid_until_at {
            fatal(
                result,
                "offer_expired",
                format!(
                    "accept issued after offer valid_until {}",
                    py_repr(offer_body.get("valid_until"))
                ),
                receipt.get("receipt_id"),
            );
        }
    }
    if !matches!(receipt.get("spec").and_then(Value::as_str), Some("continuity-receipt/0.4" | "continuity-receipt/0.5")) {
        return;
    }
    let offeree = body.get("offeree").and_then(Value::as_str);
    let issuer_id = receipt
        .get("issuer")
        .and_then(Value::as_object)
        .and_then(|issuer| issuer.get("id"))
        .and_then(Value::as_str);
    match offeree {
        None | Some("") => fatal(
            result,
            "malformed",
            format!("accept offeree is not a string: {}", py_repr(body.get("offeree"))),
            receipt.get("receipt_id"),
        ),
        Some(offeree) => {
            if issuer_id != Some(offeree)
                || offer_body.get("offeree").and_then(Value::as_str) != Some(offeree)
            {
                fatal(
                    result,
                    "offeree_mismatch",
                    format!(
                        "accept offeree {offeree:?} does not match the signer {issuer_id:?} / offer"
                    ),
                    receipt.get("receipt_id"),
                );
            }
        }
    }
    let offer_issued = offer
        .get("issued_at")
        .and_then(Value::as_str)
        .and_then(parse_timestamp);
    if let (Some(accept_issued), Some(offer_issued)) = (accept_issued, offer_issued) {
        if accept_issued < offer_issued {
            fatal(
                result,
                "accept_before_offer",
                format!("accept issued before offer {}", py_repr(offer.get("receipt_id"))),
                receipt.get("receipt_id"),
            );
        }
    }
}

/// 0.4 completeness: unreferenced accepts, and offeree receipts that skip the ref.
fn check_agreement_completeness(
    result: &mut VerifyResult,
    receipts: &[Value],
    accepts: &BTreeMap<String, &Map<String, Value>>,
    referenced: &BTreeSet<String>,
) {
    for (digest, accept) in accepts {
        if matches!(accept.get("spec").and_then(Value::as_str), Some("continuity-receipt/0.4" | "continuity-receipt/0.5"))
            && !referenced.contains(digest)
        {
            result.provisional_reasons.push(format!(
                "agreement_unreferenced:{}",
                accept
                    .get("receipt_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
            ));
        }
    }
    for receipt in receipts.iter().filter_map(Value::as_object) {
        if !matches!(receipt.get("spec").and_then(Value::as_str), Some("continuity-receipt/0.4" | "continuity-receipt/0.5")) {
            continue;
        }
        let Some(record_type) = receipt.get("type").and_then(Value::as_str) else {
            continue;
        };
        if !BOUND_TYPES.contains(&record_type) {
            continue;
        }
        let Some(body) = receipt.get("body").and_then(Value::as_object) else {
            continue;
        };
        let has_ref = body
            .get("agreement_ref")
            .map(|value| !value.is_null())
            .unwrap_or(false);
        if has_ref {
            continue;
        }
        let issuer_id = receipt
            .get("issuer")
            .and_then(Value::as_object)
            .and_then(|issuer| issuer.get("id"))
            .and_then(Value::as_str);
        let bound_issued = receipt
            .get("issued_at")
            .and_then(Value::as_str)
            .and_then(parse_timestamp);
        let (Some(issuer_id), Some(bound_at)) = (issuer_id, bound_issued) else {
            continue;
        };
        for accept in accepts.values() {
            if !matches!(accept.get("spec").and_then(Value::as_str), Some("continuity-receipt/0.4" | "continuity-receipt/0.5")) {
                continue;
            }
            let Some(accept_body) = accept.get("body").and_then(Value::as_object) else {
                continue;
            };
            if accept_body.get("offeree").and_then(Value::as_str) != Some(issuer_id) {
                continue;
            }
            let accept_issued = accept
                .get("issued_at")
                .and_then(Value::as_str)
                .and_then(parse_timestamp);
            let Some(accept_at) = accept_issued else {
                continue;
            };
            if accept_at <= bound_at {
                result.provisional_reasons.push(format!(
                    "missing_agreement_ref:{}",
                    receipt
                        .get("receipt_id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                ));
                break;
            }
        }
    }
}

fn check_redactions(
    result: &mut VerifyResult,
    receipts: &[Value],
    disclosure_map: Option<&Map<String, Value>>,
) {
    let root = Value::Array(receipts.to_vec());
    let mut redactions: Vec<(String, &Map<String, Value>)> = Vec::new();
    iter_redactions(&root, "receipts", &mut redactions);

    for (path, field) in redactions {
        if required_field_for_path(&path, receipts).is_some() {
            fatal(
                result,
                "redacted_required",
                format!("required field redacted at {path}"),
                None,
            );
            continue;
        }
        if let Some(entry) = disclosure_map
            .and_then(|map| map.get(path.as_str()))
            .and_then(Value::as_object)
        {
            if !entry.is_empty() && entry.contains_key("salt") && entry.contains_key("value") {
                let computed = match (
                    entry.get("salt").and_then(Value::as_str),
                    entry.get("value"),
                ) {
                    (Some(salt), Some(value)) => commit_field(salt, value).ok(),
                    _ => None,
                };
                if computed.as_deref() != field.get("commit").and_then(Value::as_str) {
                    fatal(
                        result,
                        "commit_mismatch",
                        format!("commit mismatch at {path}"),
                        None,
                    );
                }
                continue;
            }
        }
        if py_truthy(field.get("erased")) {
            result
                .insufficient_reasons
                .push(format!("erased_content:{path}"));
        } else {
            result
                .provisional_reasons
                .push(format!("redacted_without_disclosure:{path}"));
        }
    }
}

/// Collect `(path, node)` for every `{"redacted": true}` node, Python order not
/// required for verdicts (paths/reasons are identical).
fn iter_redactions<'a>(
    node: &'a Value,
    path: &str,
    out: &mut Vec<(String, &'a Map<String, Value>)>,
) {
    match node {
        Value::Object(map) => {
            if map.get("redacted") == Some(&Value::Bool(true)) {
                out.push((path.to_string(), map));
                return;
            }
            for (key, value) in map {
                let child = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                iter_redactions(value, &child, out);
            }
        }
        Value::Array(items) => {
            for (index, value) in items.iter().enumerate() {
                iter_redactions(value, &format!("{path}[{index}]"), out);
            }
        }
        _ => {}
    }
}

/// `_required_field_for_path`: required body fields may not be redacted.
pub(crate) fn required_field_for_path(path: &str, receipts: &[Value]) -> Option<String> {
    let parts: Vec<&str> = path.split('.').collect();
    if parts.len() < 3 || !parts[0].starts_with("receipts[") || parts[1] != "body" {
        return None;
    }
    let index_text = parts[0].strip_prefix("receipts[")?.trim_end_matches(']');
    let index: usize = index_text.parse().ok()?;
    let receipt = receipts.get(index).and_then(Value::as_object)?;
    let record_type = receipt.get("type").and_then(Value::as_str)?;
    required_fields(record_type, receipt.get("spec").and_then(Value::as_str))
        .filter(|fields| fields.contains(&parts[2]))
        .map(|_| parts[2].to_string())
}

/// 0.2: counterparty attestations are verified per-signature and reported.
/// Absence is reported in the summary but does not change the verdict.
fn check_attestations(result: &mut VerifyResult, receipts: &[Value]) {
    let mut seen: Vec<Value> = Vec::new();
    for receipt in receipts.iter().filter_map(Value::as_object) {
        if receipt.get("type").and_then(Value::as_str) != Some("delivery.attestation") {
            continue;
        }
        let body = receipt.get("body").and_then(Value::as_object);
        let counterparty = body
            .and_then(|body| body.get("counterparty"))
            .and_then(Value::as_object);
        let counterparty_id = counterparty.and_then(|item| item.get("id"));
        let attestation = counterparty.and_then(|item| item.get("attestation"));

        if !py_truthy(attestation) {
            let mut entry = Map::new();
            entry.insert(
                "receipt_id".to_string(),
                receipt.get("receipt_id").cloned().unwrap_or(Value::Null),
            );
            entry.insert(
                "counterparty".to_string(),
                counterparty_id.cloned().unwrap_or(Value::Null),
            );
            entry.insert(
                "attestation".to_string(),
                Value::String("absent".to_string()),
            );
            seen.push(Value::Object(entry));
            continue;
        }

        let attestation_object = attestation.and_then(Value::as_object);
        let algorithm_ok = attestation_object
            .and_then(|item| item.get("alg"))
            .and_then(Value::as_str)
            == Some("ed25519");
        let key = attestation_object
            .and_then(|item| item.get("key"))
            .and_then(Value::as_str);
        let value = attestation_object
            .and_then(|item| item.get("value"))
            .and_then(Value::as_str);
        let valid = match (body, key, value) {
            (Some(body), Some(key), Some(value)) if algorithm_ok => {
                let message = Value::Object(attestation_view(body));
                canonical_bytes(&message)
                    .map(|bytes| didkey::verify(key, &bytes, value))
                    .unwrap_or(false)
            }
            _ => false,
        };

        let mut entry = Map::new();
        entry.insert(
            "receipt_id".to_string(),
            receipt.get("receipt_id").cloned().unwrap_or(Value::Null),
        );
        entry.insert(
            "counterparty".to_string(),
            counterparty_id.cloned().unwrap_or(Value::Null),
        );
        entry.insert(
            "attestation".to_string(),
            Value::String(if valid { "valid" } else { "invalid" }.to_string()),
        );
        entry.insert(
            "key".to_string(),
            attestation_object
                .and_then(|item| item.get("key"))
                .cloned()
                .unwrap_or(Value::Null),
        );
        seen.push(Value::Object(entry));

        if !valid {
            fatal(
                result,
                "bad_attestation",
                "counterparty attestation does not verify",
                receipt.get("receipt_id"),
            );
        }
    }
    if !seen.is_empty() {
        result
            .summary
            .insert("attestations".to_string(), Value::Array(seen));
    }
}

/// The view a counterparty attestation signs: body without
/// `counterparty.attestation`.
fn attestation_view(body: &Map<String, Value>) -> Map<String, Value> {
    let mut view = body.clone();
    if let Some(counterparty) = view.get("counterparty").and_then(Value::as_object).cloned() {
        let mut counterparty = counterparty;
        counterparty.remove("attestation");
        view.insert("counterparty".to_string(), Value::Object(counterparty));
    }
    view
}

/// 0.2: `observed_sources_hash` is a flat sha256 or a merkle-sha256 root.
fn check_provenance(result: &mut VerifyResult, receipts: &[Value]) {
    for receipt in receipts.iter().filter_map(Value::as_object) {
        if receipt.get("type").and_then(Value::as_str) != Some("task.decision") {
            continue;
        }
        let Some(provenance) = receipt
            .get("body")
            .and_then(Value::as_object)
            .and_then(|body| body.get("input_provenance"))
            .and_then(Value::as_object)
        else {
            continue;
        };
        let Some(observed) = provenance
            .get("observed_sources_hash")
            .filter(|value| !value.is_null())
        else {
            continue;
        };
        let supported = observed
            .as_str()
            .map(|text| {
                PROVENANCE_PREFIXES
                    .iter()
                    .any(|prefix| text.starts_with(*prefix))
            })
            .unwrap_or(false);
        if !supported {
            fatal(
                result,
                "provenance_invalid",
                format!(
                    "observed_sources_hash has unsupported form: {}",
                    py_repr(Some(observed))
                ),
                receipt.get("receipt_id"),
            );
        }
    }
}

/// 0.2: bundle-level revocation statements, self-signed by the revoked key.
///
/// A receipt is `UNTRUSTED` (`key_revoked`) when its issuer key was revoked at
/// or before the receipt's `issued_at`; receipts before revocation remain
/// valid, and invalid statements are themselves an error (fail-closed).
fn check_revocations(result: &mut VerifyResult, bundle: &Map<String, Value>, receipts: &[Value]) {
    let raw = bundle.get("revocations");
    if !py_truthy(raw) {
        return;
    }
    let Some(statements) = raw.and_then(Value::as_array) else {
        return;
    };
    if statements.iter().any(|statement| !statement.is_object()) {
        return;
    }

    let (revoked, statement_errors) = verify_revocation_statements(statements);
    result.errors.extend(statement_errors);
    let checked = revoked.len();

    for receipt in receipts.iter().filter_map(Value::as_object) {
        let key_id = receipt
            .get("issuer")
            .and_then(Value::as_object)
            .and_then(|issuer| issuer.get("id"))
            .and_then(Value::as_str);
        let Some(key_id) = key_id else {
            continue;
        };
        let issued_at = receipt.get("issued_at");
        if !validate_timestamp(issued_at) {
            continue;
        }
        let Some(issued_timestamp) = issued_at.and_then(Value::as_str).and_then(parse_timestamp)
        else {
            continue;
        };
        for (revoked_key, revoked_at) in &revoked {
            if revoked_key == key_id && issued_timestamp >= *revoked_at {
                fatal(
                    result,
                    "key_revoked",
                    format!(
                        "issuer key {key_id} was revoked at {}",
                        isoformat(revoked_at)
                    ),
                    receipt.get("receipt_id"),
                );
            }
        }
    }
    result
        .summary
        .insert("revocations_checked".to_string(), Value::from(checked));
}

/// Verify self-signed revocation statements (0.2 §7.5), shared by the bundle
/// verifier and the verification-receipt verifier.
///
/// Returns the verified `(key, revoked_at)` pairs plus structured
/// `bad_revocation` errors for statements that do not verify. Callers decide
/// fatality (the bundle verifier fails closed) and how to apply the times.
pub(crate) fn verify_revocation_statements(
    statements: &[Value],
) -> (Vec<(String, Timestamp)>, Vec<ErrorEntry>) {
    let mut revoked: Vec<(String, Timestamp)> = Vec::new();
    let mut errors: Vec<ErrorEntry> = Vec::new();
    for statement in statements {
        let Some(statement) = statement.as_object() else {
            errors.push(ErrorEntry {
                code: "bad_revocation".to_string(),
                detail: "revocation statement is not an object".to_string(),
                receipt_id: Value::Null,
            });
            continue;
        };
        let key_id = statement.get("key").and_then(Value::as_str);
        let revoked_at = statement.get("revoked_at");
        if key_id.is_none() || !validate_timestamp(revoked_at) {
            errors.push(ErrorEntry {
                code: "bad_revocation".to_string(),
                detail: format!(
                    "malformed revocation statement for {}",
                    py_repr(statement.get("key"))
                ),
                receipt_id: Value::Null,
            });
            continue;
        }
        let key_id = key_id.unwrap_or_default();
        let revoked_at_text = revoked_at.and_then(Value::as_str).unwrap_or_default();

        let sig = statement.get("sig").and_then(Value::as_object);
        let signature_ok = sig.and_then(|item| item.get("alg")).and_then(Value::as_str)
            == Some("ed25519")
            && py_truthy(sig.and_then(|item| item.get("value")));
        if !signature_ok {
            errors.push(ErrorEntry {
                code: "bad_revocation".to_string(),
                detail: format!(
                    "revocation statement unsigned for {}",
                    py_repr(statement.get("key"))
                ),
                receipt_id: Value::Null,
            });
            continue;
        }

        let mut unsigned = statement.clone();
        unsigned.remove("sig");
        let verified = match canonical_bytes(&Value::Object(unsigned)) {
            Ok(message) => sig
                .and_then(|item| item.get("value"))
                .and_then(Value::as_str)
                .map(|value| didkey::verify(key_id, &message, value))
                .unwrap_or(false),
            Err(_) => false,
        };
        if !verified {
            errors.push(ErrorEntry {
                code: "bad_revocation".to_string(),
                detail: format!(
                    "revocation signature invalid for {}",
                    py_repr(statement.get("key"))
                ),
                receipt_id: Value::Null,
            });
            continue;
        }
        let Some(revoked_timestamp) = parse_timestamp(revoked_at_text) else {
            continue; // validated above; defensive
        };
        revoked.push((key_id.to_string(), revoked_timestamp));
    }
    (revoked, errors)
}

/// Anchors: shape and digest binding only (`anchor.hash == receipt_digest`).
fn check_anchors(
    result: &mut VerifyResult,
    bundle: &Map<String, Value>,
    receipts: &[Value],
    require_anchor: bool,
) {
    let anchors = bundle.get("anchors");
    if !py_truthy(anchors) {
        if require_anchor {
            result
                .provisional_reasons
                .push("anchor_missing".to_string());
        }
        return;
    }
    let Some(anchor_list) = anchors.and_then(Value::as_array) else {
        return;
    };

    let mut kinds: Vec<Value> = Vec::new();
    for anchor in anchor_list {
        let Some(anchor_object) = anchor.as_object() else {
            continue;
        };
        let target = anchor_object.get("target");
        let target_receipt = find_receipt_by_id(receipts, target);
        let bound = match (
            target_receipt,
            anchor_object
                .get("hash")
                .and_then(Value::as_str),
        ) {
            (Some(receipt), Some(hash)) => receipt_digest(receipt)
                .map(|digest| digest == hash)
                .unwrap_or(false),
            _ => false,
        };
        if !bound {
            fatal(
                result,
                "anchor_invalid",
                format!("anchor invalid for {}", py_str(target)),
                None,
            );
            continue;
        }
        let meta = anchor_object
            .get("anchor")
            .filter(|value| !value.is_null());
        if let Some(meta) = meta {
            let anchor_type = meta.as_object().and_then(|item| item.get("type"));
            match anchor_type
                .and_then(Value::as_str)
                .filter(|name| ANCHOR_TYPES.contains(name))
            {
                Some(name) => kinds.push(Value::String(name.to_string())),
                None => {
                    let rendered = if meta.is_object() {
                        py_repr(anchor_type)
                    } else {
                        py_repr(Some(meta))
                    };
                    fatal(
                        result,
                        "anchor_invalid",
                        format!("unknown anchor type: {rendered}"),
                        None,
                    );
                }
            }
        }
    }
    let summary_kinds = if kinds.is_empty() {
        vec![Value::String("hash-only".to_string())]
    } else {
        kinds
    };
    result
        .summary
        .insert("anchors".to_string(), Value::Array(summary_kinds));
}

/// Last-receipt-wins lookup by `receipt_id`, mirroring the Python dict build.
fn find_receipt_by_id<'a>(
    receipts: &'a [Value],
    target: Option<&Value>,
) -> Option<&'a Map<String, Value>> {
    let target = target.filter(|value| !value.is_null());
    let mut found = None;
    for receipt in receipts.iter().filter_map(Value::as_object) {
        let receipt_id = receipt.get("receipt_id").filter(|value| !value.is_null());
        if receipt_id == target {
            found = Some(receipt);
        }
    }
    found
}

fn build_summary(receipts: &[Value], type_by_seq: &BTreeMap<usize, String>) -> Map<String, Value> {
    let mut summary = Map::new();
    summary.insert("receipts".to_string(), Value::from(receipts.len()));
    summary.insert(
        "types".to_string(),
        Value::Array(
            receipts
                .iter()
                .filter_map(Value::as_object)
                .map(|record| record.get("type").cloned().unwrap_or(Value::Null))
                .collect(),
        ),
    );
    let mut issuers: BTreeSet<String> = BTreeSet::new();
    for record in receipts.iter().filter_map(Value::as_object) {
        let id = record
            .get("issuer")
            .and_then(Value::as_object)
            .and_then(|issuer| issuer.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("");
        issuers.insert(id.to_string());
    }
    summary.insert(
        "issuers".to_string(),
        Value::Array(issuers.into_iter().map(Value::String).collect()),
    );
    summary.insert(
        "terminated".to_string(),
        Value::Bool(
            type_by_seq
                .values()
                .any(|record_type| record_type == "task.termination"),
        ),
    );
    summary.insert(
        "settled".to_string(),
        Value::Bool(
            type_by_seq
                .values()
                .any(|record_type| record_type == "settlement"),
        ),
    );
    summary
}

pub(crate) fn unsigned_view(receipt: &Map<String, Value>) -> Map<String, Value> {
    let mut view = receipt.clone();
    view.remove("sig");
    view
}

pub(crate) fn receipt_digest(receipt: &Map<String, Value>) -> Result<String, CanonError> {
    canonical_bytes(&Value::Object(unsigned_view(receipt))).map(|bytes| sha256_prefixed(&bytes))
}

fn seq_matches(value: Option<&Value>, index: usize) -> bool {
    match value {
        Some(Value::Number(number)) => {
            number.as_u64() == Some(index as u64) || number.as_i64() == Some(index as i64)
        }
        // Python's bool is an int subclass (`True == 1`).
        Some(Value::Bool(flag)) => usize::from(*flag) == index,
        _ => false,
    }
}

fn minor_units(amount: Option<&Map<String, Value>>) -> Option<i128> {
    match amount.and_then(|item| item.get("minor")) {
        None => Some(0),
        Some(value) => py_int(value),
    }
}

/// Python `int()` coercion for the shapes JSON can carry.
fn py_int(value: &Value) -> Option<i128> {
    match value {
        Value::Bool(flag) => Some(i128::from(*flag)),
        Value::Number(number) => number
            .as_i64()
            .map(i128::from)
            .or_else(|| number.as_u64().map(i128::from))
            .or_else(|| number.to_string().parse::<i128>().ok()),
        Value::String(text) => text.trim().parse::<i128>().ok(),
        _ => None,
    }
}

/// Python truthiness (`bool(value)`).
fn py_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64() != Some(0.0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(map)) => !map.is_empty(),
    }
}

/// Python `repr()` for the value shapes that appear in verification details.
fn py_repr(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "None".to_string(),
        Some(Value::Bool(true)) => "True".to_string(),
        Some(Value::Bool(false)) => "False".to_string(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::String(text)) => quote_py_string(text),
        Some(Value::Array(items)) => {
            let parts: Vec<String> = items.iter().map(|item| py_repr(Some(item))).collect();
            format!("[{}]", parts.join(", "))
        }
        Some(Value::Object(map)) => {
            let parts: Vec<String> = map
                .iter()
                .map(|(key, item)| format!("{}: {}", quote_py_string(key), py_repr(Some(item))))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
    }
}

fn py_repr_value(value: &Value) -> String {
    py_repr(Some(value))
}

/// Python `str()` for the value shapes that appear in verification details.
fn py_str(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "None".to_string(),
        Some(Value::Bool(true)) => "True".to_string(),
        Some(Value::Bool(false)) => "False".to_string(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::String(text)) => text.clone(),
        Some(other) => py_repr(Some(other)),
    }
}

fn quote_py_string(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// RFC 3339 UTC with optional 1-3 fractional digits (`records._TIMESTAMP_RE`).
pub(crate) fn validate_timestamp(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .map(is_rfc3339_utc)
        .unwrap_or(false)
}

fn is_rfc3339_utc(text: &str) -> bool {
    let bytes = text.as_bytes();
    let is_digit = |index: usize| {
        bytes
            .get(index)
            .map(|byte| byte.is_ascii_digit())
            .unwrap_or(false)
    };
    if bytes.len() < 20 {
        return false;
    }
    if !(is_digit(0) && is_digit(1) && is_digit(2) && is_digit(3)) {
        return false;
    }
    if bytes[4] != b'-' || !(is_digit(5) && is_digit(6)) {
        return false;
    }
    if bytes[7] != b'-' || !(is_digit(8) && is_digit(9)) {
        return false;
    }
    if bytes[10] != b'T' || !(is_digit(11) && is_digit(12)) {
        return false;
    }
    if bytes[13] != b':' || !(is_digit(14) && is_digit(15)) {
        return false;
    }
    if bytes[16] != b':' || !(is_digit(17) && is_digit(18)) {
        return false;
    }
    if bytes.len() == 20 {
        return bytes[19] == b'Z';
    }
    if bytes[19] != b'.' || bytes[bytes.len() - 1] != b'Z' {
        return false;
    }
    let fraction = &bytes[20..bytes.len() - 1];
    !fraction.is_empty() && fraction.len() <= 3 && fraction.iter().all(|byte| byte.is_ascii_digit())
}

/// Chronologically comparable UTC timestamp (fraction normalized to millis).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Timestamp {
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    millis: u32,
}

pub(crate) fn parse_timestamp(text: &str) -> Option<Timestamp> {
    if !is_rfc3339_utc(text) {
        return None;
    }
    let part = |start: usize, end: usize| -> Option<u32> { text.get(start..end)?.parse().ok() };
    let millis = if text.as_bytes().get(19) == Some(&b'.') {
        let fraction = text.get(20..text.len().checked_sub(1)?)?;
        let mut value = fraction.parse::<u32>().ok()?;
        for _ in fraction.len()..3 {
            value = value.checked_mul(10)?;
        }
        value
    } else {
        0
    };
    Some(Timestamp {
        year: part(0, 4)?,
        month: part(5, 7)?,
        day: part(8, 10)?,
        hour: part(11, 13)?,
        minute: part(14, 16)?,
        second: part(17, 19)?,
        millis,
    })
}

/// Python `datetime.isoformat()` for a parsed UTC timestamp.
pub(crate) fn isoformat(timestamp: &Timestamp) -> String {
    let base = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        timestamp.year,
        timestamp.month,
        timestamp.day,
        timestamp.hour,
        timestamp.minute,
        timestamp.second
    );
    if timestamp.millis == 0 {
        format!("{base}+00:00")
    } else {
        format!("{base}.{:06}+00:00", timestamp.millis * 1000)
    }
}
