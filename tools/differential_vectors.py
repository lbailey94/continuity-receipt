#!/usr/bin/env python3
"""Differential check: Python verifier vs Rust verifier over every vector.

Compares verdict, error codes (sorted), and exit code for each entry in
vectors/manifest.json. Requires the Rust binary:
    cargo build --manifest-path rust/Cargo.toml
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "vectors" / "manifest.json"
PY_CMD = [sys.executable, "-m", "continuity_receipt.verify"]
RUST_BIN = Path(os.environ.get(
    "RUST_VERIFY_BIN", ROOT / "rust" / "target" / "debug" / "continuity-receipt-verify"
))


def run(cmd: list[str], bundle: Path, require_anchor: bool) -> subprocess.CompletedProcess:
    args = cmd + [str(bundle)]
    if require_anchor:
        args.append("--require-anchor")
    return subprocess.run(args, capture_output=True, text=True, cwd=ROOT)


def signature(proc: subprocess.CompletedProcess) -> tuple:
    data = json.loads(proc.stdout)
    return (data["verdict"], sorted(entry["code"] for entry in data["errors"])), proc.returncode


def main() -> int:
    if not RUST_BIN.exists():
        print(f"rust binary missing: {RUST_BIN}", file=sys.stderr)
        print("build it with: cargo build --manifest-path rust/Cargo.toml", file=sys.stderr)
        return 2

    entries = json.loads(MANIFEST.read_text(encoding="utf-8"))["vectors"]
    mismatches = 0
    pending_03 = 0
    for entry in entries:
        bundle = ROOT / "vectors" / entry["file"]
        python_result = signature(run(PY_CMD, bundle, entry["require_anchor"]))
        rust_result = signature(run([str(RUST_BIN)], bundle, entry["require_anchor"]))
        spec = json.loads(bundle.read_text(encoding="utf-8")).get("spec")
        if spec == "continuity-receipt/0.3":
            # The 0.3 record types are not ported to Rust yet. The expected
            # divergence is fail-closed: Rust must answer version_unsupported.
            (rust_verdict, rust_codes), _rc = rust_result
            if rust_verdict == "UNTRUSTED" and "version_unsupported" in rust_codes:
                pending_03 += 1
                continue
            mismatches += 1
            print(
                f"MISMATCH {entry['file']} (0.3 expected fail-closed): "
                f"python={python_result} rust={rust_result}"
            )
            continue
        if python_result != rust_result:
            mismatches += 1
            print(f"MISMATCH {entry['file']}: python={python_result} rust={rust_result}")
    matched = len(entries) - mismatches - pending_03
    print(
        f"differential: {matched}/{len(entries)} match "
        f"({pending_03} pending Rust 0.3 port, fail-closed verified)"
    )
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
