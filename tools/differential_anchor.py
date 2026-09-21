#!/usr/bin/env python3
"""Differential check: Python vs Rust OpenTimestamps anchor companion.

Runs both CLIs over the real `.ots` fixtures with identical arguments and
compares status, code, confirmed block, file digest, attestation kinds, and
exit codes. Requires the Rust binary:
    cargo build --manifest-path rust/Cargo.toml
"""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from continuity_receipt.anchor import parse_detached  # noqa: E402

RUST_ANCHOR = Path(os.environ.get(
    "RUST_ANCHOR_BIN",
    ROOT / "rust" / "target" / "debug" / "continuity-receipt-anchor",
))
PY_ANCHOR = [sys.executable, "-m", "continuity_receipt.anchor"]
FIXTURES = ROOT / "vectors" / "anchor"


def run(command):
    return subprocess.run([str(part) for part in command], capture_output=True, text=True, cwd=ROOT)


def signature(proc):
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    kinds = sorted(att.get("kind", "") for att in payload.get("attestations", []))
    confirmed = payload.get("confirmed") or {}
    return (
        payload.get("status"),
        payload.get("code"),
        payload.get("file_digest"),
        tuple(kinds),
        confirmed.get("block_height"),
        confirmed.get("header_time"),
        confirmed.get("merkle_root"),
    ), proc.returncode


def main() -> int:
    if not RUST_ANCHOR.exists():
        print(f"rust binary missing: {RUST_ANCHOR}", file=sys.stderr)
        print("build it with: cargo build --manifest-path rust/Cargo.toml", file=sys.stderr)
        return 2

    headers = json.loads((FIXTURES / "headers.json").read_text(encoding="utf-8"))["headers"]
    digests = {}
    for name in [
        "hello-world.txt.ots",
        "bitcoin.pdf.ots",
        "gdp2q25-2nd.pdf.ots",
        "known-and-unknown-notary.txt.ots",
    ]:
        digests[name] = parse_detached((FIXTURES / name).read_bytes()).file_digest.hex()
    # the keccak fixture cannot be parsed by design; any digest exercises the
    # published negative path
    digests["different-blockchains.txt.ots"] = "00" * 32

    cases = [
        ("hello-world with header", "hello-world.txt.ots", digests["hello-world.txt.ots"], "358391", "358391"),
        ("hello-world without header", "hello-world.txt.ots", digests["hello-world.txt.ots"], None, None),
        ("sha1 bitcoin.pdf with header", "bitcoin.pdf.ots", digests["bitcoin.pdf.ots"], "465751", "465751"),
        ("2025 gdp with header", "gdp2q25-2nd.pdf.ots", digests["gdp2q25-2nd.pdf.ots"], "912095", "912095"),
        ("pending + unknown", "known-and-unknown-notary.txt.ots", digests["known-and-unknown-notary.txt.ots"], None, None),
        ("keccak negative case", "different-blockchains.txt.ots", "00" * 32, None, None),
        ("wrong header", "hello-world.txt.ots", digests["hello-world.txt.ots"], "465751", "358391"),
    ]

    mismatches = 0
    for label, fixture, digest, header_height, header_as in cases:
        args = ["verify", FIXTURES / fixture, "--digest", digest, "--json"]
        if header_height is not None:
            args += ["--header", headers[header_height], "--height", header_as]
        python_result = signature(run(PY_ANCHOR + args))
        rust_result = signature(run([RUST_ANCHOR] + args))
        if python_result != rust_result:
            mismatches += 1
            print(f"MISMATCH {label}: python={python_result} rust={rust_result}")
        else:
            print(f"ok   {label}: {python_result[0][0]}/{python_result[0][1]} rc={python_result[1]}")

    print(f"differential anchor: {len(cases) - mismatches}/{len(cases)} match")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
