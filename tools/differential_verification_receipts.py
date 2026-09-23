#!/usr/bin/env python3
"""Differential check: Python vs Rust verification-receipt CLI.

Compares validity, error sets, exit codes, and receipt digests for every entry
in `vectors/verification/manifest.json`. Requires the Rust binary:
    cargo build --manifest-path rust/Cargo.toml
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "vectors" / "verification"
MANIFEST = json.loads((VECTORS / "manifest.json").read_text(encoding="utf-8"))
PY_PREFIX = [sys.executable, "-m", "continuity_receipt.verification"]
RUST_BIN = Path(
    os.environ.get(
        "RUST_VERIFY_RECEIPT_BIN",
        ROOT / "rust" / "target" / "debug" / "continuity-receipt-verify-receipt",
    )
)


def cli_args(prefix: list[str], entry: dict) -> list[str]:
    args = prefix + [str(VECTORS / entry["file"])]
    if entry.get("bundle_file"):
        args += ["--bundle", str(VECTORS / entry["bundle_file"])]
    if entry.get("revocations_file"):
        args += ["--revocations", str(VECTORS / entry["revocations_file"])]
    return args


def signature(proc: subprocess.CompletedProcess) -> tuple:
    data = json.loads(proc.stdout)
    return (data["valid"], sorted(data["errors"])), proc.returncode


def main() -> int:
    if not RUST_BIN.exists():
        print(f"rust binary missing: {RUST_BIN}", file=sys.stderr)
        print("build it with: cargo build --manifest-path rust/Cargo.toml", file=sys.stderr)
        return 2

    entries = MANIFEST["vectors"]
    mismatches = 0
    for entry in entries:
        python_result = signature(
            subprocess.run(cli_args(PY_PREFIX, entry), capture_output=True, text=True, cwd=ROOT)
        )
        rust_result = signature(
            subprocess.run(cli_args([str(RUST_BIN)], entry), capture_output=True, text=True, cwd=ROOT)
        )
        if python_result != rust_result:
            mismatches += 1
            print(f"MISMATCH {entry['file']}: python={python_result} rust={rust_result}")
            continue

        python_digest = subprocess.run(
            PY_PREFIX + [str(VECTORS / entry["file"]), "--digest"],
            capture_output=True, text=True, cwd=ROOT,
        )
        rust_digest = subprocess.run(
            [str(RUST_BIN), str(VECTORS / entry["file"]), "--digest"],
            capture_output=True, text=True, cwd=ROOT,
        )
        if python_digest.stdout.strip() != rust_digest.stdout.strip():
            mismatches += 1
            print(
                f"DIGEST MISMATCH {entry['file']}: "
                f"python={python_digest.stdout.strip()} rust={rust_digest.stdout.strip()}"
            )

    print(f"verification-receipt differential: {len(entries) - mismatches}/{len(entries)} match")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
