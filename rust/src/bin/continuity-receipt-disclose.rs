//! CLI: `continuity-receipt-disclose <redact|verify|reveal|check> [options]`.
//!
//! Mirrors `python3 -m continuity_receipt.disclose` (same subcommands and exit
//! codes: `verify` exits `0` iff the verdict is `TRUSTED`; `check` exits `0`
//! iff the commitment matches).
//!
//! Documented differences: `verify` does not accept `--revocations` until the
//! Rust revocation-list loader lands (external lists remain Python-only), and
//! `redact` additionally accepts repeatable `--salt <path>=<hex>` for
//! reproducible commitments (the Python CLI always randomizes salts).

use std::collections::HashMap;
use std::process::ExitCode;

use continuity_receipt::canon::commit_field;
use continuity_receipt::disclose::{attach, redact, reveal};
use continuity_receipt::verify::verify_bundle;
use ed25519_dalek::SigningKey;
use serde_json::Value;

const USAGE: &str = "\
usage: continuity-receipt-disclose <command> [options]

commands:
  redact --bundle <path> --path <path> [--path ...] --out <path> --map <path> --gate-key <path>
         [--salt <path>=<hex> ...]
  verify --bundle <path> [--map <path>] [--require-anchor]
  reveal --bundle <path> --map <path> --path <path> [--path ...] --out <path>
  check  --salt <hex> --value <json> --commit <sha256:...>";

fn usage_error(message: &str) -> ExitCode {
    eprintln!("continuity-receipt-disclose: error: {message}\n{USAGE}");
    ExitCode::from(2)
}

fn fail(message: &str) -> ExitCode {
    eprintln!("continuity-receipt-disclose: error: {message}");
    ExitCode::from(1)
}

struct Options {
    flags: HashMap<String, String>,
    paths: Vec<String>,
    salts: Vec<String>,
}

impl Options {
    fn required(&self, flag: &str) -> Result<&str, String> {
        self.flags
            .get(flag)
            .map(String::as_str)
            .ok_or_else(|| format!("{flag} is required"))
    }

    fn optional(&self, flag: &str) -> Option<&str> {
        self.flags.get(flag).map(String::as_str)
    }

    fn has(&self, flag: &str) -> bool {
        self.flags.contains_key(flag)
    }
}

fn parse(arguments: &[String]) -> Result<Options, String> {
    let mut flags = HashMap::new();
    let mut paths = Vec::new();
    let mut salts = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        match argument.as_str() {
            "--path" => {
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| "--path needs a value".to_string())?;
                paths.push(value.clone());
            }
            "--salt" => {
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| "--salt needs a value".to_string())?;
                salts.push(value.clone());
            }
            "--require-anchor" => {
                flags.insert(argument.clone(), String::new());
            }
            flag if flag.starts_with("--") => {
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| format!("{flag} needs a value"))?;
                flags.insert(flag.to_string(), value.clone());
            }
            other => return Err(format!("unrecognized argument: {other}")),
        }
        index += 1;
    }
    Ok(Options {
        flags,
        paths,
        salts,
    })
}

fn salt_map(entries: &[String]) -> Result<serde_json::Map<String, Value>, String> {
    let mut map = serde_json::Map::new();
    for entry in entries {
        let (path, salt) = entry
            .split_once('=')
            .ok_or_else(|| format!("--salt must be <path>=<hex>: {entry}"))?;
        if path.is_empty() || salt.is_empty() {
            return Err(format!("--salt must be <path>=<hex>: {entry}"));
        }
        map.insert(path.to_string(), Value::String(salt.to_string()));
    }
    Ok(map)
}

fn read_json(path: &str) -> Result<Value, String> {
    let text = std::fs::read_to_string(path).map_err(|error| format!("cannot read {path}: {error}"))?;
    serde_json::from_str(&text).map_err(|error| format!("{path} is not valid JSON: {error}"))
}

fn write_json(payload: &Value, path: &str) -> Result<(), String> {
    let text = serde_json::to_string_pretty(payload)
        .map_err(|error| format!("cannot serialize output: {error}"))?;
    std::fs::write(path, format!("{text}\n")).map_err(|error| format!("cannot write {path}: {error}"))
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
    let options = match parse(&arguments[1..]) {
        Ok(options) => options,
        Err(error) => return usage_error(&error),
    };
    match command.as_str() {
        "redact" => run_redact(&options),
        "verify" => run_verify(&options),
        "reveal" => run_reveal(&options),
        "check" => run_check(&options),
        other => usage_error(&format!("unknown command: {other}")),
    }
}

fn run_redact(options: &Options) -> ExitCode {
    let (bundle_path, out, map_path, key_path) = match (
        options.required("--bundle"),
        options.required("--out"),
        options.required("--map"),
        options.required("--gate-key"),
    ) {
        (Ok(bundle), Ok(out), Ok(map), Ok(key)) => (bundle, out, map, key),
        (Err(error), ..) | (_, Err(error), ..) | (_, _, Err(error), _) | (_, _, _, Err(error)) => {
            return usage_error(&error);
        }
    };
    if options.paths.is_empty() {
        return usage_error("at least one --path is required");
    }
    let bundle = match read_json(bundle_path) {
        Ok(bundle) => bundle,
        Err(error) => return fail(&error),
    };
    let key_bytes = match std::fs::read(key_path) {
        Ok(bytes) => bytes,
        Err(error) => return fail(&format!("cannot read {key_path}: {error}")),
    };
    if key_bytes.len() != 32 {
        return fail(&format!(
            "{key_path} must hold a raw 32-byte Ed25519 private key (got {} bytes)",
            key_bytes.len()
        ));
    }
    let salts = match salt_map(&options.salts) {
        Ok(salts) => salts,
        Err(error) => return usage_error(&error),
    };
    let key = SigningKey::from_bytes(&key_bytes.try_into().expect("length checked"));
    let supplied_salts = (!salts.is_empty()).then_some(&salts);
    match redact(&bundle, &options.paths, supplied_salts, Some(&key)) {
        Ok((redacted, map)) => {
            if let Err(error) = write_json(&redacted, out) {
                return fail(&error);
            }
            if let Err(error) = write_json(&map, map_path) {
                return fail(&error);
            }
            ExitCode::SUCCESS
        }
        Err(error) => fail(&error.to_string()),
    }
}

fn run_verify(options: &Options) -> ExitCode {
    let bundle_path = match options.required("--bundle") {
        Ok(path) => path,
        Err(error) => return usage_error(&error),
    };
    let mut bundle = match read_json(bundle_path) {
        Ok(bundle) => bundle,
        Err(error) => return fail(&error),
    };
    if let Some(map_path) = options.optional("--map") {
        let map = match read_json(map_path) {
            Ok(map) => map,
            Err(error) => return fail(&error),
        };
        bundle = match attach(&bundle, &map) {
            Ok(attached) => attached,
            Err(error) => return fail(&error.to_string()),
        };
    }
    let result = verify_bundle(&bundle, options.has("--require-anchor"));
    match serde_json::to_string_pretty(&result.as_dict()) {
        Ok(text) => println!("{text}"),
        Err(error) => return fail(&format!("cannot serialize result: {error}")),
    }
    if result.verdict() == "TRUSTED" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn run_reveal(options: &Options) -> ExitCode {
    let (bundle_path, map_path, out) = match (
        options.required("--bundle"),
        options.required("--map"),
        options.required("--out"),
    ) {
        (Ok(bundle), Ok(map), Ok(out)) => (bundle, map, out),
        (Err(error), ..) | (_, Err(error), _) | (_, _, Err(error)) => return usage_error(&error),
    };
    if options.paths.is_empty() {
        return usage_error("at least one --path is required");
    }
    let bundle = match read_json(bundle_path) {
        Ok(bundle) => bundle,
        Err(error) => return fail(&error),
    };
    let map = match read_json(map_path) {
        Ok(map) => map,
        Err(error) => return fail(&error),
    };
    match reveal(&bundle, &map, &options.paths) {
        Ok(package) => {
            if let Err(error) = write_json(&package, out) {
                return fail(&error);
            }
            ExitCode::SUCCESS
        }
        Err(error) => fail(&error.to_string()),
    }
}

fn run_check(options: &Options) -> ExitCode {
    let salt = match options.salts.as_slice() {
        [salt] if !salt.contains('=') => salt.as_str(),
        _ => return usage_error("--salt <hex> is required"),
    };
    let (value_text, commit) = match (options.required("--value"), options.required("--commit")) {
        (Ok(value), Ok(commit)) => (value, commit),
        (Err(error), _) | (_, Err(error)) => return usage_error(&error),
    };
    let value: Value = match serde_json::from_str(value_text) {
        Ok(value) => value,
        Err(error) => return fail(&format!("--value is not valid JSON: {error}")),
    };
    let expected = match commit_field(salt, &value) {
        Ok(expected) => expected,
        Err(error) => return fail(&error.to_string()),
    };
    let matched = expected == commit;
    let payload = serde_json::json!({
        "match": matched,
        "expected": expected,
        "commit": commit,
    });
    match serde_json::to_string_pretty(&payload) {
        Ok(text) => println!("{text}"),
        Err(error) => return fail(&format!("cannot serialize result: {error}")),
    }
    if matched {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
