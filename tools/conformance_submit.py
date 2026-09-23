#!/usr/bin/env python3
"""Build or verify a conformance submission for the referee.

The referee (`POST /conformance` on the hosted API) grades a verifier's
outputs over the pinned corpus — `vectors/manifest.json` (26 bundles) and
`vectors/verification/manifest.json` (20 verification receipts) — against the
manifests and issues a signed conformance report.

This tool runs a verifier CLI over both corpora and writes the submission
JSON the referee accepts:

    python3 tools/conformance_submit.py --python --version 0.3.3 > submission.json
    python3 tools/conformance_submit.py --rust-bin rust/target/release/continuity-receipt-verify \
        --name continuity-receipt --version 0.3.3 --language rust > submission.json

    # verify a returned report offline (signature + shape)
    python3 tools/conformance_submit.py --verify-report report.json
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from continuity_receipt import keys  # noqa: E402
from continuity_receipt.canon import canonical_bytes  # noqa: E402

BUNDLE_MANIFEST = ROOT / "vectors" / "manifest.json"
RECEIPT_MANIFEST = ROOT / "vectors" / "verification" / "manifest.json"
VECTORS = ROOT / "vectors"
REPORT_KIND = "continuity-receipt-conformance"
REPORT_VERSION = 1


def run_json(cmd: list[str]) -> dict:
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    try:
        return json.loads(proc.stdout)
    except ValueError:
        raise SystemExit(
            f"verifier did not print JSON (rc {proc.returncode}): {' '.join(cmd)}\n"
            f"stderr: {proc.stderr.strip()[:400]}"
        )


def bundle_results(prefix: list[str]) -> dict:
    manifest = json.loads(BUNDLE_MANIFEST.read_text(encoding="utf-8"))
    results = {}
    for vector in manifest["vectors"]:
        cmd = prefix + [str(VECTORS / vector["file"])]
        if vector["require_anchor"]:
            cmd.append("--require-anchor")
        output = run_json(cmd)
        results[vector["file"]] = {
            "verdict": output.get("verdict"),
            "codes": sorted(
                error["code"] for error in output.get("errors", []) if isinstance(error, dict)
            ),
        }
    return results


def receipt_results(prefix: list[str]) -> dict:
    manifest = json.loads(RECEIPT_MANIFEST.read_text(encoding="utf-8"))
    results = {}
    for vector in manifest["vectors"]:
        cmd = prefix + [str(VECTORS / "verification" / vector["file"])]
        if vector.get("bundle_file"):
            cmd += ["--bundle", str(VECTORS / "verification" / vector["bundle_file"])]
        if vector.get("revocations_file"):
            cmd += ["--revocations", str(VECTORS / "verification" / vector["revocations_file"])]
        output = run_json(cmd)
        results[vector["file"]] = {
            "valid": output.get("valid"),
            "errors": sorted(output.get("errors", [])),
        }
    return results


def verify_report(report: dict) -> dict:
    errors = []
    if not isinstance(report, dict):
        return {"valid": False, "errors": ["not_an_object"]}
    if report.get("kind") != REPORT_KIND:
        errors.append("bad_kind")
    if report.get("version") != REPORT_VERSION:
        errors.append("bad_version")
    if report.get("verdict") not in ("CONFORMANT", "PARTIAL", "NONCONFORMANT"):
        errors.append("bad_verdict")
    issuer = report.get("issuer")
    sig = report.get("sig")
    if (
        not isinstance(issuer, str)
        or not isinstance(sig, dict)
        or sig.get("alg") != "ed25519"
        or not isinstance(sig.get("value"), str)
        or not sig.get("value")
    ):
        errors.append("bad_signature_shape")
    elif sig.get("key") != issuer:
        errors.append("bad_signature")
    else:
        try:
            message = canonical_bytes({k: v for k, v in report.items() if k != "sig"})
            valid = keys.verify(issuer, message, sig["value"])
        except (TypeError, ValueError):
            valid = False
        if not valid:
            errors.append("bad_signature")
    return {"valid": not errors, "errors": errors, "verdict": report.get("verdict")}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="conformance_submit")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--python", action="store_true", help="run the Python verifier CLI")
    mode.add_argument("--rust-bin", metavar="PATH", help="run a Rust verifier CLI binary")
    mode.add_argument("--verify-report", metavar="PATH", help="verify a conformance report")
    parser.add_argument("--name", default="continuity-receipt")
    parser.add_argument("--version", default="")
    parser.add_argument("--language", default="")
    parser.add_argument("--url", default="")
    parser.add_argument("--out", metavar="PATH", help="write the submission to PATH")
    args = parser.parse_args(argv)

    if args.verify_report:
        report = json.loads(Path(args.verify_report).read_text(encoding="utf-8"))
        result = verify_report(report)
        print(json.dumps(result, indent=2))
        return 0 if result["valid"] else 1

    if args.python:
        prefix = [sys.executable, "-m", "continuity_receipt.verify"]
        receipt_prefix = [sys.executable, "-m", "continuity_receipt.verification"]
        default_language = "python"
    else:
        prefix = [args.rust_bin]
        derived = args.rust_bin.replace(
            "continuity-receipt-verify", "continuity-receipt-verify-receipt"
        )
        if derived == args.rust_bin or not Path(derived).exists():
            raise SystemExit(
                "cannot derive the Rust receipt CLI; expected a path containing "
                "'continuity-receipt-verify' (and its sibling "
                "'continuity-receipt-verify-receipt' to exist)"
            )
        receipt_prefix = [derived]
        default_language = "rust"

    submission = {
        "implementation": {
            "name": args.name,
            "version": args.version or "unknown",
            "language": args.language or default_language,
            "url": args.url,
        },
        "results": {
            "bundles": bundle_results(prefix),
            "verification_receipts": receipt_results(receipt_prefix),
        },
    }
    text = json.dumps(submission, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
