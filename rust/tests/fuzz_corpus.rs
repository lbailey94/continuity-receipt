//! Generated fuzz corpus: deterministic structural mutations of the frozen
//! vectors (and synthetic malformed shapes) must never panic the verifier and
//! must always produce a structured result with one of the four verdicts.
//!
//! The corpus is generated in-process from a fixed seed, so CI runs are
//! reproducible. Set `CR_FUZZ_CORPUS_DIR` to also write every generated case
//! to disk (for inspection or for seeding a future `cargo fuzz` corpus).

use std::fs;
use std::path::PathBuf;

use continuity_receipt::canon::canonical_bytes;
use continuity_receipt::verify::verify_bundle;
use serde_json::{json, Value};

const VERDICTS: [&str; 4] = [
    "TRUSTED",
    "PROVISIONAL",
    "INSUFFICIENT_EVIDENCE",
    "UNTRUSTED",
];
const ITERATIONS: usize = 500;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("rust crate sits inside the repository")
        .to_path_buf()
}

fn vector_bundles() -> Vec<Value> {
    let vectors = repo_root().join("vectors");
    let manifest_text = fs::read_to_string(vectors.join("manifest.json")).expect("manifest");
    let manifest: Value = serde_json::from_str(&manifest_text).expect("manifest JSON");
    manifest["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .filter_map(|entry| entry["file"].as_str())
        .filter_map(|file| fs::read_to_string(vectors.join(file)).ok())
        .filter_map(|text| serde_json::from_str(&text).ok())
        .collect()
}

fn random_replacement(rng: &mut Rng) -> Value {
    match rng.below(11) {
        0 => Value::Null,
        1 => Value::Bool(true),
        2 => Value::Bool(false),
        3 => json!(0),
        4 => json!(-1),
        5 => json!(u64::MAX),
        6 => json!(""),
        7 => json!("x".repeat(256)),
        8 => json!([]),
        9 => json!([1, "two", null, {"three": 3}]),
        _ => json!({}),
    }
}

fn mutate(value: &mut Value, rng: &mut Rng, depth: usize) {
    if depth > 10 {
        return;
    }
    if rng.below(3) == 0 {
        *value = random_replacement(rng);
        return;
    }
    match value {
        Value::Object(map) => {
            if map.is_empty() {
                return;
            }
            let keys: Vec<String> = map.keys().cloned().collect();
            let key = &keys[rng.below(keys.len())];
            if rng.below(4) == 0 {
                map.remove(key);
            } else if let Some(child) = map.get_mut(key) {
                mutate(child, rng, depth + 1);
            }
        }
        Value::Array(items) => {
            if items.is_empty() {
                return;
            }
            let index = rng.below(items.len());
            if rng.below(4) == 0 {
                items.remove(index);
            } else {
                mutate(&mut items[index], rng, depth + 1);
            }
        }
        _ => {}
    }
}

fn check_case(value: &Value, require_anchor: bool, label: &str) {
    let result = verify_bundle(value, require_anchor);
    assert!(
        VERDICTS.contains(&result.verdict()),
        "{label}: unexpected verdict {:?}",
        result.verdict()
    );
    for error in &result.errors {
        assert!(
            !error.code.is_empty(),
            "{label}: error entry without a code"
        );
    }
    // Canonicalization may fail (floats, unsupported shapes) but must not panic.
    let _ = canonical_bytes(value);
}

#[test]
fn generated_mutations_never_panic_and_stay_structured() {
    let bundles = vector_bundles();
    assert_eq!(bundles.len(), 40, "all manifest vectors load");
    let corpus_dir = std::env::var("CR_FUZZ_CORPUS_DIR").ok();
    if let Some(dir) = &corpus_dir {
        fs::create_dir_all(dir).expect("create corpus dir");
    }

    let mut rng = Rng(0x5EED_2026_0921);
    for case in 0..ITERATIONS {
        let mut value = bundles[rng.below(bundles.len())].clone();
        mutate(&mut value, &mut rng, 0);
        let require_anchor = rng.next().is_multiple_of(2);
        check_case(&value, require_anchor, &format!("case {case}"));

        if let Some(dir) = &corpus_dir {
            let text = serde_json::to_string_pretty(&value).expect("serialize case");
            let anchor = if require_anchor { "anchor" } else { "plain" };
            fs::write(
                PathBuf::from(dir).join(format!("case_{case:05}_{anchor}.json")),
                format!("{text}\n"),
            )
            .expect("write case");
        }
    }
}

#[test]
fn synthetic_malformed_shapes_are_structured() {
    let cases = [
        json!(null),
        json!([]),
        json!({}),
        json!({"receipts": []}),
        json!({"receipts": null}),
        json!({"receipts": [null]}),
        json!({"receipts": [{}]}),
        json!({"receipts": [{"spec": 1, "seq": "x"}]}),
        json!({"spec": "continuity-receipt/9.9", "receipts": []}),
        json!({"receipts": [{"issuer": {"id": "did:key:not-a-key"}, "sig": {"value": "!!"}}]}),
        json!({"receipts": [{"prev": {"nested": ["deep", {"deeper": null}]}}]}),
        json!({"receipts": [{"seq": -1, "body": {"x": 1.5, "huge": u64::MAX}}]}),
        json!({"receipts": [{"body": {"unicode": "✅ 日本語 🎯", "empty": ""}}]}),
    ];
    for (index, case) in cases.iter().enumerate() {
        check_case(case, index % 2 == 0, &format!("synthetic {index}"));
    }
}

#[test]
fn byte_truncations_of_valid_vectors_do_not_panic() {
    let bundles = vector_bundles();
    let mut rng = Rng(0x00C0_FFEE_2026);
    for case in 0..250 {
        let base = &bundles[rng.below(bundles.len())];
        let text = serde_json::to_string(base).expect("serialize");
        let mut cut = rng.below(text.len());
        while cut > 0 && !text.is_char_boundary(cut) {
            cut -= 1;
        }
        let truncated = &text[..cut];
        if let Ok(value) = serde_json::from_str::<Value>(truncated) {
            check_case(
                &value,
                rng.next().is_multiple_of(2),
                &format!("truncated {case}"),
            );
        }
    }
}
