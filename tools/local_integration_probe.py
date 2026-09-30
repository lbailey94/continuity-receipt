#!/usr/bin/env python3
"""Exercise a real local 0.5 producer and both offline verifier CLIs.

This qualifies the file-snapshot example only. It cannot establish that a
WhiteMagic, Mandala, or independent adopter runtime emits spec 0.5 receipts.
"""

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
RUST_VERIFY = ROOT / "rust/target/debug/continuity-receipt-verify"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def run_json(command: list[str]) -> tuple[dict, int]:
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    require(result.stdout.strip(), f"no JSON output from {command}: {result.stderr}")
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"invalid JSON from {command}: {result.stdout[:300]}") from exc
    return parsed, result.returncode


def verify_both(bundle_path: Path, expected_verdict: str) -> dict:
    commands = {
        "python": [sys.executable, "-m", "continuity_receipt.verify", str(bundle_path)],
        "rust": [str(RUST_VERIFY), str(bundle_path)],
    }
    outcomes = {}
    for implementation, command in commands.items():
        result, code = run_json(command)
        require(result.get("verdict") == expected_verdict, f"{implementation}: {result}")
        require(code == (0 if expected_verdict == "TRUSTED" else 1), f"{implementation}: exit {code}")
        outcomes[implementation] = {
            "verdict": result["verdict"],
            "error_codes": sorted(error["code"] for error in result["errors"]),
        }
    require(outcomes["python"] == outcomes["rust"], f"verifier disagreement: {outcomes}")
    return outcomes["python"]


def main() -> int:
    require(RUST_VERIFY.is_file(), "build the Rust verifier first: cargo build --manifest-path rust/Cargo.toml")
    with tempfile.TemporaryDirectory(prefix="cr-local-integration-") as temp:
        directory = Path(temp)
        state = directory / "state.bin"
        mandate = directory / "mandate.txt"
        key_path = directory / "issuer.pem"
        bundle_path = directory / "bundle.json"
        tampered_path = directory / "tampered.json"

        state_bytes = b"local snapshot\x00with binary bytes\n"
        mandate_bytes = b"authorize local file-snapshot probe\n"
        state.write_bytes(state_bytes)
        mandate.write_bytes(mandate_bytes)
        key = Ed25519PrivateKey.generate()
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))

        produced, code = run_json([
            sys.executable, "tools/emit_file_snapshot.py", str(state),
            "--mandate", str(mandate), "--key-pem", str(key_path),
            "--scope", "probe:binary-state", "--output", str(bundle_path),
        ])
        require(code == 0 and produced.get("verdict") == "TRUSTED", f"producer: {produced}")
        bundle_bytes = bundle_path.read_bytes()
        bundle = json.loads(bundle_bytes)
        require(bundle["spec"] == "continuity-receipt/0.5", "wrong bundle spec")
        bodies = {receipt["type"]: receipt["body"] for receipt in bundle["receipts"]}
        commitment = bodies["state.commitment"]
        expected_state_hash = digest(state_bytes)
        require(commitment["count"] == len(state_bytes), "state byte count differs")
        require(commitment["head_digest"] == expected_state_hash, "state digest differs")
        require(bodies["session.pass.created"]["mandate_ref"] == digest(mandate_bytes), "mandate digest differs")
        require(bodies["task.execution"]["sandbox_class"] == "none", "confinement label differs")
        require(bodies["session.pass.created"]["mandala_class"] == "local", "authority label differs")
        trusted = verify_both(bundle_path, "TRUSTED")

        # A signed bundle cannot be changed without detection.
        tampered = json.loads(bundle_bytes)
        next(receipt for receipt in tampered["receipts"] if receipt["type"] == "state.commitment")["body"]["count"] += 1
        tampered_path.write_text(json.dumps(tampered) + "\n", encoding="utf-8")
        untrusted = verify_both(tampered_path, "UNTRUSTED")
        require("bad_signature" in untrusted["error_codes"], f"tamper was not attributed to signature: {untrusted}")

        # Offline format verification cannot detect a changed external state file.
        state.write_bytes(state_bytes + b"changed\n")
        require(digest(state.read_bytes()) != commitment["head_digest"], "external state change was not detected")
        require(verify_both(bundle_path, "TRUSTED") == trusted, "bundle verdict changed with external file")

        print(json.dumps({
            "profile": "local-file-snapshot-only",
            "result": "PASS",
            "bundle_sha256": digest(bundle_bytes),
            "checks": ["producer-emission", "independent-byte-recomputation", "python-rust-trusted-parity",
                       "signed-body-tamper-rejection", "external-state-mismatch-detected-by-consumer"],
            "limit": "no Mandala, WhiteMagic, or independent adopter 0.5 runtime was exercised",
        }, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(json.dumps({"profile": "local-file-snapshot-only", "result": "FAIL", "reason": str(exc)}))
        raise SystemExit(1)
