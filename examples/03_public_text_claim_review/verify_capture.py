#!/usr/bin/env python3
"""Separately check capture hashes and the included 0.5 verification receipt."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from continuity_receipt import verification, verify_bundle  # noqa: E402
from continuity_receipt.canon import canonical_bytes  # noqa: E402
from continuity_receipt.strict_json import loads as strict_loads  # noqa: E402
from claim_policy import validate_claim_review  # noqa: E402

EXPECTED_FILES = {
    "source_excerpt.txt", "claims.json", "provenance.json", "bundle.json",
    "verification_receipt.json",
}
EXPECTED_CAPTURE_ENTRIES = EXPECTED_FILES | {"capture_manifest.json"}


def read_object(path: Path) -> dict:
    value = strict_loads(path.read_bytes().decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name}: expected JSON object")
    return value


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path, help="directory containing capture_manifest.json and artifacts")
    args = parser.parse_args(argv)
    try:
        if args.capture.is_symlink():
            raise ValueError("capture path must be a directory, not a symlink")
        root = args.capture.resolve()
        if not root.is_dir():
            raise ValueError("capture path must be a directory, not a symlink")
        actual_entries = {entry.name for entry in root.iterdir()}
        if actual_entries != EXPECTED_CAPTURE_ENTRIES:
            missing = sorted(EXPECTED_CAPTURE_ENTRIES - actual_entries)
            extra = sorted(actual_entries - EXPECTED_CAPTURE_ENTRIES)
            raise ValueError(
                "capture directory must contain the exact required artifact inventory; "
                f"missing={missing}, extra={extra}"
            )
        if any((root / name).is_symlink() or not (root / name).is_file() for name in actual_entries):
            raise ValueError("capture inventory entries must be regular files, not symlinks or directories")
        manifest = read_object(root / "capture_manifest.json")
        if manifest.get("kind") != "public-text-claim-review-capture/1" or not isinstance(manifest.get("files"), dict):
            raise ValueError("capture manifest kind/files invalid")
        if set(manifest["files"]) != EXPECTED_FILES:
            raise ValueError("capture manifest must list the exact required artifact set")
        checked = {}
        actual_sizes = {}
        for name, expected in manifest["files"].items():
            rel = PurePosixPath(name)
            if rel.is_absolute() or ".." in rel.parts or len(rel.parts) != 1 or not isinstance(expected, dict):
                raise ValueError(f"unsafe or malformed manifest entry: {name!r}")
            path = root / name
            if path.is_symlink():
                raise ValueError(f"symlink artifacts are not accepted: {name}")
            raw = path.read_bytes()
            actual = "sha256:" + hashlib.sha256(raw).hexdigest()
            size = len(raw)
            if actual != expected.get("sha256") or size != expected.get("size"):
                raise ValueError(f"artifact hash or size mismatch: {name}")
            checked[name] = actual
            actual_sizes[name] = size

        bundle = read_object(root / "bundle.json")
        bundle_result = verify_bundle(bundle)
        if bundle_result.verdict != "TRUSTED":
            raise ValueError(f"bundle verdict is not TRUSTED: {bundle_result.verdict}")
        receipt = read_object(root / "verification_receipt.json")
        receipt_result = verification.verify_verification_receipt(receipt, bundle)
        if not receipt_result.valid or not receipt_result.digest_match:
            raise ValueError(f"verification receipt invalid: {receipt_result.errors}")
        if receipt.get("verdict") != bundle_result.verdict:
            raise ValueError("verification receipt verdict differs from local bundle verification")
        decision_records = [
            item for item in bundle.get("receipts", [])
            if isinstance(item, dict) and item.get("type") == "task.decision"
        ]
        if len(decision_records) != 1:
            raise ValueError("expected exactly one task.decision in example bundle")
        decision_body = decision_records[0].get("body")
        if not isinstance(decision_body, dict):
            raise ValueError("task.decision body must be an object")
        claim_review = decision_body.get("claim_review")
        if not isinstance(claim_review, dict):
            raise ValueError("signed claim-review statement missing")
        signed_hashes = claim_review.get("artifact_sha256")
        if not isinstance(signed_hashes, dict):
            raise ValueError("signed claim-review artifact hash map missing")
        signed_artifact_names = {"source_excerpt.txt", "claims.json", "provenance.json"}
        if set(signed_hashes) != signed_artifact_names:
            raise ValueError("signed claim-review hash map must name the exact review artifact set")
        if claim_review.get("claims_artifact") != "claims.json" or claim_review.get("provenance_artifact") != "provenance.json":
            raise ValueError("signed claim-review artifact references do not match this capture")
        for name in sorted(signed_artifact_names):
            if signed_hashes.get(name) != checked.get(name):
                raise ValueError(f"external artifact hash is not bound by the signed decision: {name}")

        source_raw = (root / "source_excerpt.txt").read_bytes()
        claims = read_object(root / "claims.json")
        rows = validate_claim_review(claims, source_raw)

        provenance = read_object(root / "provenance.json")
        if provenance.get("source_url") != claims.get("source", {}).get("url"):
            raise ValueError("provenance source URL differs from claims source")
        if provenance.get("snapshot_commit") != claims.get("source", {}).get("snapshot_commit"):
            raise ValueError("provenance source commit differs from claims source")
        declared_artifacts = provenance.get("artifacts")
        if not isinstance(declared_artifacts, dict) or set(declared_artifacts) != {"source_excerpt.txt", "claims.json"}:
            raise ValueError("provenance artifact map must name the exact source and claims artifacts")
        for name in ("source_excerpt.txt", "claims.json"):
            entry = declared_artifacts.get(name)
            if (
                not isinstance(entry, dict)
                or entry.get("sha256") != checked.get(name)
                or entry.get("size") != actual_sizes.get(name)
            ):
                raise ValueError(f"provenance does not match actual bytes: {name}")
        signed_artifact_view = {
            name: {"sha256": checked[name], "size": actual_sizes[name]}
            for name in ("source_excerpt.txt", "claims.json", "provenance.json")
        }
        expected_action_hash = "sha256:" + hashlib.sha256(canonical_bytes({
            "claims": claims,
            "artifacts": signed_artifact_view,
        })).hexdigest()
        if decision_body.get("action_args_hash") != expected_action_hash:
            raise ValueError("signed action_args_hash does not bind the supplied claims and artifact metadata")
        expected_grade_summary = [
            {"id": row["id"], "grade": row["grade"], "claim": row["claim"], "limit": row["limit"]}
            for row in rows
        ]
        if claim_review.get("claim_grades") != expected_grade_summary:
            raise ValueError("signed claim-grade summary differs from the hashed claims artifact")
        print(json.dumps({
            "capture_files": "MATCH",
            "bundle_verdict": bundle_result.verdict,
            "verification_receipt": "VALID_AND_BUNDLE_DIGEST_MATCHES",
            "independent_verification": False,
            "claim_grades": [
                {"id": row["id"], "grade": row["grade"]} for row in rows
            ],
            "artifact_hashes": checked,
            "interpretation": "hash agreement and receipt integrity pass; source accuracy, research judgment, issuer independence, and underlying claim truth are not established",
        }, indent=2, sort_keys=True))
        return 0
    except (OSError, UnicodeDecodeError, ValueError, TypeError, RecursionError) as exc:
        print(json.dumps({"capture_files": "FAIL", "reason": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
