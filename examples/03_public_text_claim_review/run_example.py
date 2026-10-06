#!/usr/bin/env python3
"""Emit a synthetic 0.5 receipt for a bounded public-text claim review.

The deterministic key is public test material. Never use this fixture key for
real claims. The grading labels and source excerpt are human-authored fixture
data; this script hashes and records them but does not perform research.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from continuity_receipt import keys, verification, verify_bundle  # noqa: E402
from continuity_receipt.bundle import TaskChain  # noqa: E402
from continuity_receipt.canon import canonical_bytes  # noqa: E402

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from claim_policy import validate_claim_review  # noqa: E402

OUTPUT = HERE / "out"
STAMP = "2026-10-05T12:00:00Z"
TASK_ID = "urn:example:public-text-claim-review-fixture"


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def dump(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=HERE / "out", help="capture output directory (default: example/out)")
    args = parser.parse_args(argv)
    global OUTPUT
    OUTPUT = args.out.resolve()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    source_bytes = (HERE / "source_excerpt.txt").read_bytes()
    claim_bytes = (HERE / "claims.json").read_bytes()
    (OUTPUT / "source_excerpt.txt").write_bytes(source_bytes)
    (OUTPUT / "claims.json").write_bytes(claim_bytes)
    claims = json.loads(claim_bytes)
    claim_rows = validate_claim_review(claims, source_bytes)

    artifacts = {
        "source_excerpt.txt": {"sha256": sha256(source_bytes), "size": len(source_bytes)},
        "claims.json": {"sha256": sha256(claim_bytes), "size": len(claim_bytes)},
    }
    provenance = {
        "kind": "public-text-review-provenance-fixture",
        "source_url": claims["source"]["url"],
        "snapshot_commit": claims["source"]["snapshot_commit"],
        "capture_note": claims["source"]["capture_note"],
        "artifacts": artifacts,
        "grade_method": "human-authored labels; supported grades require an exact quoted span in this snapshot",
        "scope_limit": "textual support only; no live retrieval, registry lookup, truth adjudication, or adoption evidence",
    }
    dump(OUTPUT / "provenance.json", provenance)
    provenance_bytes = (OUTPUT / "provenance.json").read_bytes()
    artifacts["provenance.json"] = {"sha256": sha256(provenance_bytes), "size": len(provenance_bytes)}

    did, key = keys.generate(keys.deterministic_seed("public-text-claim-review-example-only"))
    chain = TaskChain(task_id=TASK_ID, spec="continuity-receipt/0.5")
    chain.add("session.pass.created", "example", did, key, {
        "gate_id": "public-text-fixture",
        "mandala_class": "local",
        "quotas": {"cpu_ms": 1000, "mem_mb": 64, "disk_mb": 1, "wall_ms": 1000},
        "expires_at": "2026-10-05T12:01:00Z",
        "policy_version": "example-text-grade-v1",
        "mandate_ref": sha256(b"synthetic example mandate"),
        "agent_id": did,
    }, issued_at=STAMP)
    decision_hash = sha256(canonical_bytes({"claims": claims, "artifacts": artifacts}))
    chain.add("task.decision", "example", did, key, {
        "action": "grade_public_text_claims",
        "action_args_hash": decision_hash,
        "model": {"provider": "human-reviewed-fixture", "id": "bounded-text-review"},
        "input_provenance": {
            "policy_id": "example-text-grade-v1",
            "allowed_sources": [claims["source"]["url"]],
            "observed_sources_hash": artifacts["source_excerpt.txt"]["sha256"],
        },
        "decision": "allow",
        "policy_version": "example-text-grade-v1",
        "claim_review": {
            "claims_artifact": "claims.json",
            "provenance_artifact": "provenance.json",
            "claim_grades": [
                {"id": row["id"], "grade": row["grade"], "claim": row["claim"], "limit": row["limit"]}
                for row in claim_rows
            ],
            "artifact_sha256": {name: item["sha256"] for name, item in artifacts.items()},
            "meaning": "issuer-signed record of the supplied text review; not a finding that the underlying claims are true",
        },
    }, issued_at="2026-10-05T12:00:01Z")
    chain.add("task.termination", "example", did, key, {
        "reason": "fixture_complete",
        "limits_at_stop": {"cpu_ms": 1000, "mem_mb": 64, "disk_mb": 1, "wall_ms": 1000},
        "remaining": {"cpu_ms": 1000, "mem_mb": 64, "disk_mb": 1, "wall_ms": 999},
    }, issued_at="2026-10-05T12:00:02Z")
    bundle = chain.bundle()
    result = verify_bundle(bundle)
    dump(OUTPUT / "bundle.json", bundle)
    receipt = verification.issue_verification_receipt(
        bundle,
        result,
        issuer=did,
        private_key=key,
        implementation="python-reference-fixture",
        verified_at="2026-10-05T12:00:03Z",
    )
    dump(OUTPUT / "verification_receipt.json", receipt)

    capture_files = ["source_excerpt.txt", "claims.json", "provenance.json", "bundle.json", "verification_receipt.json"]
    capture_manifest = {
        "kind": "public-text-claim-review-capture/1",
        "fixture": True,
        "files": {
            name: {"sha256": sha256((OUTPUT / name).read_bytes()), "size": (OUTPUT / name).stat().st_size}
            for name in capture_files
        },
        "limits": [
            "manifest is unsigned and should be obtained with the files over a trusted channel",
            "the CR verifier checks receipt structure, signatures, and chain rules, not statement truth",
            "the verification receipt records the result but is not independently administered verification",
            "artifact hash agreement is separate from protocol-bundle validity",
        ],
    }
    dump(OUTPUT / "capture_manifest.json", capture_manifest)
    print(json.dumps({"output": str(OUTPUT), "bundle_verdict": result.verdict, "files_hashed": capture_files}, indent=2))
    return 0 if result.verdict == "TRUSTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
