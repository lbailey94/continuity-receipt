#!/usr/bin/env python3
"""Bounded dry-run demonstration of a relying agent's own refusal gates.

This script never invokes tools, performs a payment, or changes external state.
It exercises the local Continuity Receipt consumer assessment and reports
whether a separate hypothetical action gate would refuse the request.
"""
from __future__ import annotations

import copy
import hashlib
import argparse
import importlib
import importlib.metadata
import json
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = Path(__file__).resolve().parent
MAX_LOCAL_FILE_BYTES = 1024 * 1024
consumer = None


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_bounded(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) > MAX_LOCAL_FILE_BYTES:
        raise ValueError(f"local pilot input too large: {path.name}")
    return data


def source_fingerprint() -> dict:
    names = (
        "continuity_receipt.consumer",
        "continuity_receipt.verify",
        "continuity_receipt.canon",
        "continuity_receipt.strict_json",
        "continuity_receipt.records",
        "continuity_receipt.keys",
        "continuity_receipt.agreements",
        "continuity_receipt.bundle",
        "continuity_receipt.revocations",
    )
    paths = (
        "continuity_receipt/consumer.py",
        "continuity_receipt/verify.py",
        "continuity_receipt/canon.py",
        "continuity_receipt/strict_json.py",
        "continuity_receipt/records.py",
        "continuity_receipt/keys.py",
        "continuity_receipt/agreements.py",
        "continuity_receipt/bundle.py",
        "continuity_receipt/revocations.py",
    )
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
            text=True, check=True, timeout=5,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain", "--", *paths], cwd=ROOT,
            capture_output=True, text=True, check=True, timeout=5,
        ).stdout
        dirty = bool(status.strip())
    except (OSError, subprocess.SubprocessError):
        commit, dirty = None, None
    imported_files = {}
    for name in names:
        module = importlib.import_module(name)
        module_path = Path(module.__file__).resolve()
        imported_files[str(module_path)] = digest(module_path.read_bytes())
    try:
        distribution_version = importlib.metadata.version("continuity-receipt")
    except importlib.metadata.PackageNotFoundError:
        distribution_version = None
    return {
        "repository_head": commit,
        "runtime_sources_dirty": dirty,
        "imported_consumer_path": str(Path(consumer.__file__).resolve()),
        "imported_module_file_sha256": imported_files,
        "installed_distribution_version": distribution_version,
        "python": platform.python_version(),
    }


def action_gate(assessment, *, external_gates: dict[str, bool], replay_seen: bool = False,
                freshness_unproven: bool = False, recovery_state: str | None = None) -> dict:
    """Classify a hypothetical action; even a clear result never actuates."""
    if assessment.outcome != "ACCEPT":
        return {"decision": "REFUSE", "reasons": ["consumer_assessment_not_accept"]}
    if replay_seen:
        return {"decision": "REFUSE", "reasons": ["caller_replay_ledger_hit"]}
    if freshness_unproven:
        return {"decision": "REFUSE", "reasons": ["freshness_unproven"]}
    if recovery_state == "PREPARED":
        return {"decision": "REFUSE", "reasons": ["interrupted_recovery_unresolved"],
                "simulated_journal_state": recovery_state}
    missing = sorted(name for name, passed in external_gates.items() if passed is not True)
    if missing:
        return {"decision": "REFUSE", "reasons": ["external_evidence_missing"], "missing_gates": missing}
    # This demonstration intentionally has no path that carries out an action.
    return {"decision": "OPERATOR_REVIEW_REQUIRED", "reasons": ["dry_run_never_actuates"]}


def make_case(name, assessment, *, expected, expected_core=None, external_gates=None,
              replay_seen=False, freshness_unproven=False, recovery_state=None,
              evidence_note=None) -> dict:
    if assessment.outcome != expected:
        raise AssertionError(f"{name}: expected {expected}, got {assessment.outcome}: {assessment.reason_codes}")
    if expected_core is not None and assessment.core.get("verdict") != expected_core:
        raise AssertionError(f"{name}: expected core {expected_core}, got {assessment.core.get('verdict')}")
    gate = action_gate(
        assessment,
        external_gates=external_gates or {
            "independent_principal_identity": False,
            "action_authority_and_scope": False,
            "trusted_freshness_source": False,
            "durable_replay_ledger": False,
            "external_state_binding": False,
            "recovery_checkpoint": False,
        },
        replay_seen=replay_seen,
        freshness_unproven=freshness_unproven,
        recovery_state=recovery_state,
    )
    return {
        "scenario": name,
        "consumer_outcome": assessment.outcome,
        "core_verdict": assessment.core.get("verdict"),
        "core_errors": assessment.core.get("errors", []),
        "reason_codes": assessment.reason_codes,
        "bundle_digest": assessment.bundle_digest,
        "action_gate": gate,
        "evidence_note": evidence_note,
        "side_effects": "none",
    }


def main() -> int:
    global consumer
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--installed-package", action="store_true",
        help="use the installed distribution, and fail if it resolves to this checkout",
    )
    args = parser.parse_args()
    if args.installed_package:
        consumer = importlib.import_module("continuity_receipt.consumer")
        imported_path = Path(consumer.__file__).resolve()
        if imported_path.is_relative_to(ROOT):
            raise ValueError("installed package resolves to the repository checkout; use an isolated non-editable install")
    else:
        sys.path.insert(0, str(ROOT))
        consumer = importlib.import_module("continuity_receipt.consumer")

    bundle_path = EXAMPLE / "bundle.json"
    policy_path = EXAMPLE / "policy.json"
    raw_bundle = read_bounded(bundle_path)
    raw_policy = read_bounded(policy_path)
    bundle = consumer._parse_raw(raw_bundle, "bundle")
    policy = consumer._parse_raw(raw_policy, "policy")
    artifact_manifest = json.loads(read_bounded(EXAMPLE / "artifact-manifest.json"))
    artifact_entry = artifact_manifest["files"][0]
    artifact = read_bounded(EXAMPLE / artifact_entry["path"])
    if len(artifact) != artifact_entry["size"] or digest(artifact) != artifact_entry["sha256"]:
        raise AssertionError("checked-in local artifact fixture does not match its manifest")

    cases = []
    base = consumer.assess_bundle(bundle, policy)
    cases.append(make_case(
        "explicit-0.4-policy-accepts-fixture", base, expected="ACCEPT", expected_core="TRUSTED",
        evidence_note="Only the local bundle/policy checks pass; this is not action authorization.",
    ))

    denied_policy = copy.deepcopy(policy)
    denied_policy["id"] = "pilot-denied-issuer-v1"
    denied_policy["trusted_issuers"] = ["did:key:z6Mknot-in-this-fixture"]
    denied = consumer.assess_bundle(bundle, denied_policy)
    if "issuer_not_trusted" not in denied.reason_codes:
        raise AssertionError(f"issuer-denial reason absent: {denied.reason_codes}")
    cases.append(make_case("explicit-issuer-denial", denied, expected="REJECT"))

    unsupported_bundle = copy.deepcopy(bundle)
    unsupported_bundle["spec"] = "continuity-receipt/0.5"
    unsupported = consumer.assess_bundle(unsupported_bundle, policy)
    if "spec_not_accepted" not in unsupported.reason_codes:
        raise AssertionError(f"unsupported-spec reason absent: {unsupported.reason_codes}")
    cases.append(make_case("unsupported-consumer-profile-spec", unsupported, expected="REJECT"))

    evidence_policy = copy.deepcopy(policy)
    evidence_policy["id"] = "pilot-requires-unprovided-succession-v1"
    evidence_policy["required_record_types"] = ["authority.succession"]
    missing = consumer.assess_bundle(bundle, evidence_policy)
    if "required_record_missing" not in missing.reason_codes:
        raise AssertionError(f"missing-evidence reason absent: {missing.reason_codes}")
    cases.append(make_case(
        "caller-required-record-absent", missing, expected="NEEDS_EVIDENCE",
        expected_core="TRUSTED",
        evidence_note="Core verification stays TRUSTED; this caller's additional record requirement is unmet.",
    ))

    cases.append(make_case(
        "replay-seen-by-local-demo-ledger", base, expected="ACCEPT", replay_seen=True,
        evidence_note="The profile has no replay ledger; this refusal comes from the harness's simulated caller ledger.",
    ))
    cases.append(make_case(
        "freshness-unproven", base, expected="ACCEPT",
        freshness_unproven=True,
        evidence_note="The profile does not establish freshness. No trusted clock/time evidence is supplied.",
    ))
    cases.append(make_case(
        "interrupted-operation-recovery", base, expected="ACCEPT",
        recovery_state="PREPARED",
        evidence_note="A simulated PREPARED-without-terminal journal state is not recovered or replayed.",
    ))

    altered_artifact = artifact + b"altered"
    artifact_changed = digest(altered_artifact) != artifact_entry["sha256"]
    if not artifact_changed:
        raise AssertionError("altered-artifact control unexpectedly matched original hash")
    cases.append({
        "scenario": "caller-side-artifact-bytes-altered",
        "consumer_outcome": base.outcome,
        "core_verdict": base.core.get("verdict"),
        "core_errors": base.core.get("errors", []),
        "reason_codes": base.reason_codes,
        "bundle_digest": base.bundle_digest,
        "action_gate": {"decision": "REFUSE", "reasons": ["external_artifact_hash_mismatch"]},
        "evidence_note": "The sample artifact/manifest is not signed or referenced by the 0.4 bundle; this is an independent caller-side check.",
        "side_effects": "none",
    })

    report = {
        "format": "continuity-receipt-independent-agent-local-demo/1",
        "status": "LOCAL_DRY_RUN_ONLY",
        "raw_inputs": {
            "bundle_bytes": len(raw_bundle),
            "bundle_raw_sha256": digest(raw_bundle),
            "bundle_canonical_sha256": base.bundle_digest,
            "policy_bytes": len(raw_policy),
            "policy_raw_sha256": digest(raw_policy),
            "policy_canonical_sha256": base.policy_digest,
            "artifact_manifest_sha256": digest(read_bounded(EXAMPLE / "artifact-manifest.json")),
            "artifact_bytes_sha256": digest(artifact),
        },
        "source_pins_observed_locally": source_fingerprint(),
        "cases": cases,
        "limitations": [
            "This is a checked-in signed vector and local harness, not an independent operator run or adoption claim.",
            "No action is executed, even if every hypothetical external gate were marked complete.",
            "No principal identity, authority, real execution, completeness, freshness, replay resistance, recovery, revocation, or external state is proven by ACCEPT.",
        ],
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ImportError, ValueError, KeyError, TypeError, AssertionError) as exc:
        print(json.dumps({"status": "LOCAL_DEMO_FAILED", "error": str(exc)}, sort_keys=True))
        raise SystemExit(1)
