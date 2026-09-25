//! CLI: `continuity-receipt-verify <bundle.json> [--require-anchor]`.
//!
//! Prints the same JSON shape as `python3 -m continuity_receipt.verify` and
//! exits `0` iff the verdict is `TRUSTED`, else `1`.

use std::process::ExitCode;

use continuity_receipt::verify::{verify_bundle, VerifyResult};
use continuity_receipt::strict_json;
use serde_json::Value;

const USAGE: &str = "usage: continuity-receipt-verify <bundle.json> [--require-anchor]";

fn main() -> ExitCode {
    let mut bundle_path: Option<String> = None;
    let mut require_anchor = false;

    for argument in std::env::args().skip(1) {
        match argument.as_str() {
            "--require-anchor" => require_anchor = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other if other.starts_with('-') && other != "-" => {
                eprintln!(
                    "continuity-receipt-verify: error: unrecognized argument: {other}\n{USAGE}"
                );
                return ExitCode::from(2);
            }
            other => {
                if bundle_path.is_some() {
                    eprintln!("continuity-receipt-verify: error: unexpected extra argument: {other}\n{USAGE}");
                    return ExitCode::from(2);
                }
                bundle_path = Some(other.to_string());
            }
        }
    }

    let Some(path) = bundle_path else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };

    const MAX_BUNDLE_BYTES: u64 = 8 * 1024 * 1024;
    match std::fs::metadata(&path) {
        Ok(metadata) if metadata.len() > MAX_BUNDLE_BYTES => {
            print_result(&VerifyResult::coded(
                "bundle_too_large",
                format!("{} bytes exceeds limit {MAX_BUNDLE_BYTES}", metadata.len()),
            ));
            return ExitCode::from(1);
        }
        _ => {}
    }

    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("continuity-receipt-verify: error: cannot read {path}: {error}");
            return ExitCode::from(1);
        }
    };

    let bundle: Value = match strict_json::from_str(&text) {
        Ok(bundle) => bundle,
        Err(error) => {
            let message = error.to_string();
            let code = if message.contains("recursion limit exceeded")
                || message.contains("JSON nesting exceeds parser limit")
            {
                "nesting_too_deep"
            } else {
                "malformed"
            };
            print_result(&VerifyResult::coded(
                code,
                format!("bundle is not valid JSON: {message}"),
            ));
            return ExitCode::from(1);
        }
    };

    let result = verify_bundle(&bundle, require_anchor);
    print_result(&result);
    if result.verdict() == "TRUSTED" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn print_result(result: &VerifyResult) {
    match serde_json::to_string_pretty(&result.as_dict()) {
        Ok(text) => println!("{text}"),
        Err(error) => {
            eprintln!("continuity-receipt-verify: error: cannot serialize result: {error}");
        }
    }
}
