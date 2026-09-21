#!/usr/bin/env python3
"""Differential check: Python vs Rust selective disclosure.

Both implementations redact the same bundle with the same salts. The re-signed
tail must be byte-identical (Ed25519 over the same canonical bytes), each
implementation's output must verify as TRUSTED under the other's verifier, and
refusals (required field, unknown path) must agree. The Rust `check` command is
exercised against a frozen Python-generated commitment.

Requires the Rust binaries:
    cargo build --manifest-path rust/Cargo.toml
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from continuity_receipt import keys  # noqa: E402
from continuity_receipt.disclose import attach as py_attach, redact as py_redact  # noqa: E402

RUST_DISCLOSE = Path(os.environ.get(
    "RUST_DISCLOSE_BIN",
    ROOT / "rust" / "target" / "debug" / "continuity-receipt-disclose",
))
RUST_VERIFY = Path(os.environ.get(
    "RUST_VERIFY_BIN",
    ROOT / "rust" / "target" / "debug" / "continuity-receipt-verify",
))
PY_VERIFY = [sys.executable, "-m", "continuity_receipt.verify"]

PATHS = ["receipts[3].body.spec_ref"]
SALTS = {
    PATHS[0]: "00112233445566778899aabbccddeeff",
}
REQUIRED_PATH = "receipts[1].body.action"
UNKNOWN_PATH = "receipts[3].body.nope"


def run(command):
    return subprocess.run([str(part) for part in command], capture_output=True, text=True, cwd=ROOT)


def verdict_of(proc):
    if proc.returncode not in (0, 1):
        return None
    try:
        return json.loads(proc.stdout)["verdict"]
    except (json.JSONDecodeError, KeyError):
        return None


def main() -> int:
    if not RUST_DISCLOSE.exists() or not RUST_VERIFY.exists():
        print(f"rust binaries missing under {RUST_DISCLOSE.parent}", file=sys.stderr)
        print("build them with: cargo build --manifest-path rust/Cargo.toml", file=sys.stderr)
        return 2

    failures = []

    def check(condition, label):
        if condition:
            print(f"ok   {label}")
        else:
            failures.append(label)
            print(f"FAIL {label}")

    bundle_path = ROOT / "vectors" / "02_happy_full.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    did, key = keys.generate(keys.deterministic_seed("gate-1"))

    with tempfile.TemporaryDirectory() as tmp_name:
        tmp = Path(tmp_name)
        key_path = tmp / "gate.key"
        key_path.write_bytes(keys.deterministic_seed("gate-1"))

        redacted_py, map_py = py_redact(bundle, PATHS, salts=SALTS, signer=(key, did))
        rust_out = tmp / "redacted_rust.json"
        rust_map = tmp / "map_rust.json"
        proc = run(
            [RUST_DISCLOSE, "redact", "--bundle", bundle_path, "--out", rust_out,
             "--map", rust_map, "--gate-key", key_path]
            + [part for path in PATHS for part in ("--path", path)]
            + [part for path in PATHS for part in ("--salt", f"{path}={SALTS[path]}")]
        )
        check(proc.returncode == 0, "rust redact exits 0")
        if proc.returncode != 0:
            print(proc.stderr, file=sys.stderr)
            return 1

        redacted_rust = json.loads(rust_out.read_text(encoding="utf-8"))
        map_rust = json.loads(rust_map.read_text(encoding="utf-8"))

        check(map_py == map_rust, "disclosure maps are identical")
        check(
            all(
                left.get("sig") == right.get("sig")
                for left, right in zip(redacted_py["receipts"], redacted_rust["receipts"])
            ),
            "re-signed receipts are byte-identical (signature equality)",
        )

        for label, payload, verifier in [
            ("python redaction / python verify", redacted_py, PY_VERIFY),
            ("python redaction / rust verify", redacted_py, [RUST_VERIFY]),
            ("rust redaction / python verify", redacted_rust, PY_VERIFY),
            ("rust redaction / rust verify", redacted_rust, [RUST_VERIFY]),
        ]:
            attached = py_attach(payload, map_rust)
            target = tmp / "attached.json"
            target.write_text(json.dumps(attached, indent=2) + "\n")
            check(verdict_of(run(verifier + [target])) == "TRUSTED", label)

        try:
            py_redact(bundle, [REQUIRED_PATH], salts=SALTS, signer=(key, did))
            python_required_refused = False
        except ValueError:
            python_required_refused = True
        proc = run(
            [RUST_DISCLOSE, "redact", "--bundle", bundle_path, "--out", tmp / "x.json",
             "--map", tmp / "x_map.json", "--gate-key", key_path, "--path", REQUIRED_PATH]
        )
        check(
            python_required_refused and proc.returncode != 0,
            "both implementations refuse a required field",
        )

        try:
            py_redact(bundle, [UNKNOWN_PATH], salts=SALTS, signer=(key, did))
            python_unknown_refused = False
        except ValueError:
            python_unknown_refused = True
        proc = run(
            [RUST_DISCLOSE, "redact", "--bundle", bundle_path, "--out", tmp / "y.json",
             "--map", tmp / "y_map.json", "--gate-key", key_path, "--path", UNKNOWN_PATH]
        )
        check(
            python_unknown_refused and proc.returncode != 0,
            "both implementations refuse an unknown path",
        )

        vector08 = json.loads((ROOT / "vectors" / "08_redacted_disclosed.json").read_text())
        entry = vector08["disclosure_map"]["receipts[3].body.quality_flags"]
        commit = vector08["receipts"][3]["body"]["quality_flags"]["commit"]
        accepted = run(
            [RUST_DISCLOSE, "check", "--salt", entry["salt"],
             "--value", json.dumps(entry["value"]), "--commit", commit]
        )
        check(accepted.returncode == 0, "rust check accepts the frozen vector commitment")
        rejected = run(
            [RUST_DISCLOSE, "check", "--salt", entry["salt"],
             "--value", json.dumps(entry["value"]), "--commit", "sha256:" + "0" * 64]
        )
        check(rejected.returncode == 1, "rust check rejects a wrong commitment")

    if failures:
        print(f"differential disclosure: {len(failures)} failure(s)")
        return 1
    print("differential disclosure: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
