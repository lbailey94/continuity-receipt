#!/usr/bin/env python3
"""Differential check: Python verifier vs Rust verifier over every vector.

Compares verdict, error codes (sorted), and exit code for each entry in
vectors/manifest.json. Requires the Rust binary:
    cargo build --manifest-path rust/Cargo.toml
"""
import json
import argparse
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
    parser = argparse.ArgumentParser(description="Compare Python and Rust over a vector manifest")
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    args = parser.parse_args()
    if not RUST_BIN.exists():
        print(f"rust binary missing: {RUST_BIN}", file=sys.stderr)
        print("build it with: cargo build --manifest-path rust/Cargo.toml", file=sys.stderr)
        return 2

    entries = json.loads(args.manifest.read_text(encoding="utf-8"))["vectors"]
    mismatches = 0
    for entry in entries:
        bundle = ROOT / "vectors" / entry["file"]
        python_result = signature(run(PY_CMD, bundle, entry["require_anchor"]))
        rust_result = signature(run([str(RUST_BIN)], bundle, entry["require_anchor"]))
        if python_result != rust_result:
            mismatches += 1
            print(f"MISMATCH {entry['file']}: python={python_result} rust={rust_result}")
    print(f"differential: {len(entries) - mismatches}/{len(entries)} match")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
