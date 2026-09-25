//! CLI: `continuity-receipt-verify-receipt <receipt.json> [--bundle <bundle.json>]
//! [--revocations <document.json>] [--digest] [--canonical <path>]`.
//!
//! Prints the same JSON shape as `python3 -m continuity_receipt.verification`
//! and exits `0` iff the receipt is valid, else `1`. `--revocations` takes a
//! local revocation document (the Python CLI also accepts URLs; the Rust
//! crate has no HTTP client).

use std::process::ExitCode;

use continuity_receipt::canon::canonical_bytes;
use continuity_receipt::strict_json;
use continuity_receipt::verification::{receipt_digest, verify_verification_receipt};
use serde_json::{json, Value};

const USAGE: &str = "usage: continuity-receipt-verify-receipt <receipt.json> [--bundle <bundle.json>] [--revocations <document.json>] [--digest] [--canonical <path>]";
const MAX_REVOCATION_BYTES: u64 = 1 << 20;

fn main() -> ExitCode {
    let mut receipt_path: Option<String> = None;
    let mut bundle_path: Option<String> = None;
    let mut revocations_path: Option<String> = None;
    let mut print_digest = false;
    let mut canonical_path: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--bundle" | "--revocations" | "--canonical" => {
                let Some(value) = args.next() else {
                    eprintln!(
                        "continuity-receipt-verify-receipt: error: {argument} needs a value\n{USAGE}"
                    );
                    return ExitCode::from(2);
                };
                match argument.as_str() {
                    "--bundle" => bundle_path = Some(value),
                    "--revocations" => revocations_path = Some(value),
                    _ => canonical_path = Some(value),
                }
            }
            "--digest" => print_digest = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other if other.starts_with('-') && other != "-" => {
                eprintln!(
                    "continuity-receipt-verify-receipt: error: unrecognized argument: {other}\n{USAGE}"
                );
                return ExitCode::from(2);
            }
            other => {
                if receipt_path.is_some() {
                    eprintln!(
                        "continuity-receipt-verify-receipt: error: unexpected extra argument: {other}\n{USAGE}"
                    );
                    return ExitCode::from(2);
                }
                receipt_path = Some(other.to_string());
            }
        }
    }

    let Some(receipt_path) = receipt_path else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };

    let receipt = match read_json(&receipt_path) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("continuity-receipt-verify-receipt: error: {message}");
            return ExitCode::from(1);
        }
    };

    if let Some(path) = canonical_path.as_deref() {
        let Some(object) = receipt.as_object() else {
            eprintln!("continuity-receipt-verify-receipt: error: receipt is not an object");
            return ExitCode::from(1);
        };
        let mut unsigned = object.clone();
        unsigned.remove("sig");
        let canonical = match canonical_bytes(&Value::Object(unsigned)) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("continuity-receipt-verify-receipt: error: {error}");
                return ExitCode::from(1);
            }
        };
        if let Err(error) = std::fs::write(path, &canonical) {
            eprintln!("continuity-receipt-verify-receipt: error: cannot write {path}: {error}");
            return ExitCode::from(1);
        }
        return match receipt_digest(&receipt) {
            Ok(digest) => {
                println!("{digest}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("continuity-receipt-verify-receipt: error: {error}");
                ExitCode::from(1)
            }
        };
    }

    if print_digest {
        return match receipt_digest(&receipt) {
            Ok(digest) => {
                println!("{digest}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("continuity-receipt-verify-receipt: error: {error}");
                ExitCode::from(1)
            }
        };
    }

    let bundle = match bundle_path.as_deref() {
        Some(path) => match read_json(path) {
            Ok(value) => Some(value),
            Err(message) => {
                eprintln!("continuity-receipt-verify-receipt: error: {message}");
                return ExitCode::from(1);
            }
        },
        None => None,
    };

    let revocations = match revocations_path.as_deref() {
        Some(path) => match load_revocations(path) {
            Ok(statements) => Some(statements),
            Err(code) => {
                let payload = json!({"valid": false, "errors": [code]});
                match serde_json::to_string_pretty(&payload) {
                    Ok(text) => println!("{text}"),
                    Err(_) => println!("{{\"valid\": false, \"errors\": [\"{code}\"]}}"),
                }
                return ExitCode::from(1);
            }
        },
        None => None,
    };

    let result = verify_verification_receipt(&receipt, bundle.as_ref(), revocations.as_deref());
    match serde_json::to_string_pretty(&result.as_dict()) {
        Ok(text) => println!("{text}"),
        Err(error) => {
            eprintln!("continuity-receipt-verify-receipt: error: cannot serialize result: {error}");
            return ExitCode::from(1);
        }
    }
    if result.valid {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn read_json(path: &str) -> Result<Value, String> {
    let text = std::fs::read_to_string(path).map_err(|error| format!("cannot read {path}: {error}"))?;
    strict_json::from_str(&text).map_err(|error| format!("{path} is not valid JSON: {error}"))
}

/// Local revocation document loader (mirrors `revocations.load_statements`).
fn load_revocations(path: &str) -> Result<Vec<Value>, &'static str> {
    let metadata = std::fs::metadata(path).map_err(|_| "revocations_unreachable")?;
    if metadata.len() > MAX_REVOCATION_BYTES {
        return Err("revocations_too_large");
    }
    let text = std::fs::read_to_string(path).map_err(|_| "revocations_unreachable")?;
    let document: Value = strict_json::from_str(&text).map_err(|_| "bad_revocations_document")?;
    let Some(object) = document.as_object() else {
        return Err("bad_revocations_document");
    };
    if object.get("kind").and_then(Value::as_str) != Some("continuity-receipt-revocations") {
        return Err("bad_revocations_document");
    }
    if object.get("version").and_then(Value::as_u64) != Some(1) {
        return Err("bad_revocations_document");
    }
    object
        .get("statements")
        .and_then(Value::as_array)
        .cloned()
        .ok_or("bad_revocations_document")
}
