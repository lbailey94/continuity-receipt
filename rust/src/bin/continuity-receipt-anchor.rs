//! CLI: `continuity-receipt-anchor verify <proof> [options]`.
//!
//! Mirrors `python3 -m continuity_receipt.anchor`:
//! `verify <proof> (--digest <hex> | --bundle <path> --target <id>)`
//! `[--header <hex> [--height <int>]] [--json]`.
//! Exits `0` iff the status is `verified`, else `1`; usage errors exit `2`.

use std::process::ExitCode;

use continuity_receipt::anchor::{bundle_digest, verify_proof, AnchorResult};
use serde_json::{json, Value};

const USAGE: &str = "\
usage: continuity-receipt-anchor verify <proof> [options]

options:
  --digest <hex|sha256:hex>   expected file digest
  --bundle <path>             bundle JSON (requires --target)
  --target <receipt_id>       receipt_id inside the bundle
  --header <hex>              80-byte Bitcoin block header
  --height <int>              block height the header belongs to
  --json                      print the full result as JSON";

fn usage_error(message: &str) -> ExitCode {
    eprintln!("continuity-receipt-anchor: error: {message}\n{USAGE}");
    ExitCode::from(2)
}

fn fail_json(code: &str, detail: &str) -> ExitCode {
    println!("{}", json!({"status": "invalid", "code": code, "detail": detail}));
    ExitCode::from(1)
}

struct Options {
    proof: Option<String>,
    digest: Option<String>,
    bundle: Option<String>,
    target: Option<String>,
    header: Option<String>,
    height: Option<String>,
    json: bool,
}

fn parse(arguments: &[String]) -> Result<Options, String> {
    let mut options = Options {
        proof: None,
        digest: None,
        bundle: None,
        target: None,
        header: None,
        height: None,
        json: false,
    };
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        match argument.as_str() {
            "--json" => options.json = true,
            "--digest" | "--bundle" | "--target" | "--header" | "--height" => {
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| format!("{argument} needs a value"))?
                    .clone();
                match argument.as_str() {
                    "--digest" => options.digest = Some(value),
                    "--bundle" => options.bundle = Some(value),
                    "--target" => options.target = Some(value),
                    "--header" => options.header = Some(value),
                    "--height" => options.height = Some(value),
                    _ => unreachable!(),
                }
            }
            other if other.starts_with('-') => {
                return Err(format!("unrecognized argument: {other}"));
            }
            other => {
                if options.proof.is_some() {
                    return Err(format!("unexpected extra argument: {other}"));
                }
                options.proof = Some(other.to_string());
            }
        }
        index += 1;
    }
    Ok(options)
}

fn print_result(result: &AnchorResult, json_output: bool) -> ExitCode {
    if json_output {
        match serde_json::to_string_pretty(&result.as_dict()) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                return fail_json("serialize_error", &error.to_string());
            }
        }
    } else {
        println!("{}: {} — {}", result.status, result.code, result.detail);
        if !result.file_digest.is_empty() {
            println!("  file digest: {}", result.file_digest);
        }
        for attestation in &result.attestations {
            println!("  attestation: {attestation}");
        }
        if let Some(confirmed) = &result.confirmed {
            println!("  confirmed: {confirmed}");
        }
    }
    if result.ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = arguments.first() else {
        return usage_error("a command is required");
    };
    if matches!(command.as_str(), "-h" | "--help") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if command != "verify" {
        return usage_error(&format!("unknown command: {command}"));
    }
    let options = match parse(&arguments[1..]) {
        Ok(options) => options,
        Err(error) => return usage_error(&error),
    };
    let Some(proof_path) = options.proof else {
        return usage_error("the proof path is required");
    };
    if options.digest.is_some() && options.bundle.is_some() {
        return usage_error("--digest and --bundle are mutually exclusive");
    }
    if options.digest.is_none() && options.bundle.is_none() {
        return usage_error("one of --digest or --bundle is required");
    }

    let mut expected = options.digest.clone().unwrap_or_default();
    let mut binding: Option<Value> = None;
    if let Some(bundle_path) = &options.bundle {
        let Some(target) = &options.target else {
            return usage_error("--bundle requires --target");
        };
        match bundle_digest(bundle_path, target) {
            Ok((digest, anchor_binding)) => {
                expected = digest;
                binding = anchor_binding;
            }
            Err(error) => return fail_json(&error.code, &error.detail),
        }
    }

    let headers: Option<serde_json::Map<String, Value>> = options.header.as_ref().map(|header| {
        let height = options
            .height
            .as_deref()
            .and_then(|height| height.parse::<u64>().ok())
            .unwrap_or(0);
        let mut map = serde_json::Map::new();
        map.insert(height.to_string(), json!(header));
        map
    });

    let data = match std::fs::read(&proof_path) {
        Ok(data) => data,
        Err(error) => return fail_json("io_error", &error.to_string()),
    };

    let mut result = verify_proof(&data, &json!(expected), headers.as_ref());

    if let Some(binding) = &binding {
        if binding.get("hash").and_then(Value::as_str) != Some(expected.as_str()) {
            let mut mismatch = AnchorResult {
                status: "mismatch".to_string(),
                code: "anchor_binding_mismatch".to_string(),
                detail: "bundle anchor hash disagrees with the receipt digest".to_string(),
                file_digest: result.file_digest.clone(),
                attestations: result.attestations.clone(),
                confirmed: None,
            };
            std::mem::swap(&mut result, &mut mismatch);
        } else {
            result.detail = format!("{}; bundle binding ok", result.detail);
        }
    }

    print_result(&result, options.json)
}
