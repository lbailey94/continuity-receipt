"""Offline relying-agent policy assessment for Continuity Receipt bundles.

This layer reports a caller's policy decision alongside the core verifier result.
It does not establish the real-world identity of an issuer or authorize actions.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from . import records, strict_json
from .canon import canonical_bytes, sha256_prefixed
from .verify import MAX_BUNDLE_BYTES, VerifyResult, verify_bundle

# This first consumer profile deliberately targets only the published 0.4 line.
PROFILE_SPECS = (
    "continuity-receipt/0.1",
    "continuity-receipt/0.2",
    "continuity-receipt/0.3",
    "continuity-receipt/0.4",
)
PROFILE_RECORD_TYPES = tuple(
    record_type for record_type in records.RECORD_TYPES
    if record_type not in ("state.commitment", "authority.grant")
)
OUTCOMES = ("ACCEPT", "NEEDS_EVIDENCE", "REJECT")


class InputError(ValueError):
    """Invalid or out-of-bounds policy/bundle input."""


@dataclass
class Assessment:
    outcome: str
    reason_codes: list[str]
    core: dict
    bundle_digest: str | None
    policy_id: str | None
    policy_digest: str | None

    def as_dict(self) -> dict:
        return {
            "kind": "continuity-receipt-consumer-assessment",
            "version": 1,
            "outcome": self.outcome,
            "reason_codes": self.reason_codes,
            "bundle_digest": self.bundle_digest,
            "core": self.core,
            "policy": {"id": self.policy_id, "digest": self.policy_digest},
        }


def _parse_raw(raw: bytes, label: str):
    if len(raw) > MAX_BUNDLE_BYTES:
        raise InputError(f"{label}_too_large")
    try:
        # Match the reference CLI's strict UTF-8 boundary; json.loads(bytes)
        # otherwise auto-detects UTF-16/32 and accepts a UTF-8 BOM.
        decoded = raw.decode("utf-8")
        if decoded.startswith("\ufeff"):
            raise ValueError("UTF-8 BOM is not permitted")
        value = strict_json.loads(decoded)
        if not isinstance(value, dict):
            raise InputError(f"{label}_not_object")
        return value
    except InputError:
        raise
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise InputError(f"{label}_invalid_json") from exc


def load_raw(path: str | Path, label: str):
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise InputError(f"{label}_unreadable") from exc
    return _parse_raw(raw, label)


def _validate_policy(policy) -> tuple[list[str], list[str], list[str]]:
    if not isinstance(policy, dict):
        raise InputError("policy_not_object")
    if set(policy) - {"id", "accepted_specs", "trusted_issuers", "required_record_types"}:
        raise InputError("policy_unknown_field")
    pid = policy.get("id")
    specs = policy.get("accepted_specs")
    issuers = policy.get("trusted_issuers")
    required = policy.get("required_record_types", [])
    if not isinstance(pid, str) or not pid.strip():
        raise InputError("policy_id_invalid")
    if not isinstance(specs, list) or not specs or any(s not in PROFILE_SPECS for s in specs):
        raise InputError("policy_specs_invalid")
    if len(set(specs)) != len(specs):
        raise InputError("policy_specs_duplicate")
    if not isinstance(issuers, list) or any(not isinstance(x, str) or not x for x in issuers):
        raise InputError("policy_issuers_invalid")
    if len(set(issuers)) != len(issuers):
        raise InputError("policy_issuers_duplicate")
    if not isinstance(required, list) or any(x not in PROFILE_RECORD_TYPES for x in required):
        raise InputError("policy_record_types_invalid")
    if len(set(required)) != len(required):
        raise InputError("policy_record_types_duplicate")
    return specs, issuers, required


def assess_bundle(bundle: dict, policy: dict | None) -> Assessment:
    """Apply an explicit consumer-owned policy after the core bundle verifier."""
    core: VerifyResult = verify_bundle(bundle)
    try:
        bundle_digest = sha256_prefixed(canonical_bytes(bundle))
    except (TypeError, ValueError):
        bundle_digest = None
    if policy is None:
        if core.verdict == "UNTRUSTED":
            return Assessment("REJECT", ["core_untrusted", "policy_missing"], core.as_dict(), bundle_digest, None, None)
        if bundle_digest is None:
            return Assessment("REJECT", ["bundle_not_canonicalizable", "policy_missing"], core.as_dict(), None, None, None)
        return Assessment("NEEDS_EVIDENCE", ["policy_missing"], core.as_dict(), bundle_digest, None, None)
    specs, issuers, required = _validate_policy(policy)
    try:
        policy_digest = sha256_prefixed(canonical_bytes(policy))
    except (TypeError, ValueError) as exc:
        raise InputError("policy_not_canonicalizable") from exc
    reasons: list[str] = []
    receipts = bundle.get("receipts", []) if isinstance(bundle, dict) else []
    if not isinstance(receipts, list):
        receipts = []
    if not isinstance(bundle, dict) or bundle.get("spec") not in specs or any(
        not isinstance(r, dict) or r.get("spec") not in specs
        for r in receipts
    ):
        reasons.append("spec_not_accepted")
    signers = core.summary.get("issuers", [])
    if not issuers:
        reasons.append("trusted_issuer_policy_empty")
    elif not signers or any(s not in issuers for s in signers):
        reasons.append("issuer_not_trusted")
    types = core.summary.get("types", [])
    if any(t not in types for t in required):
        reasons.append("required_record_missing")
    if core.verdict in ("PROVISIONAL", "INSUFFICIENT_EVIDENCE"):
        reasons.append("core_evidence_incomplete")
    if core.verdict == "UNTRUSTED":
        outcome = "REJECT"
        reasons = sorted(set(["core_untrusted", *reasons]))
    elif any(code in reasons for code in ("issuer_not_trusted", "spec_not_accepted")):
        # Explicit allowlist mismatch is a policy denial, even when evidence is
        # incomplete. Missing evidence is actionable only after local policy
        # checks pass.
        outcome = "REJECT"
        reasons = sorted(set(reasons))
    elif core.verdict in ("PROVISIONAL", "INSUFFICIENT_EVIDENCE"):
        outcome = "NEEDS_EVIDENCE"
        reasons = sorted(set(reasons))
    elif core.verdict != "TRUSTED":
        outcome = "REJECT"
        reasons = sorted(set(["core_verdict_unknown", *reasons]))
    elif bundle_digest is None:
        outcome = "REJECT"
        reasons = sorted(set(["bundle_not_canonicalizable", *reasons]))
    elif reasons:
        outcome = "NEEDS_EVIDENCE"
        reasons = sorted(set(reasons))
    else:
        outcome = "ACCEPT"
        reasons = ["policy_satisfied"]
    return Assessment(outcome, reasons, core.as_dict(), bundle_digest, policy["id"], policy_digest)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m continuity_receipt.consumer")
    parser.add_argument("bundle", help="raw bundle JSON path")
    parser.add_argument("--policy", help="consumer policy JSON path")
    args = parser.parse_args(argv)
    try:
        bundle = load_raw(args.bundle, "bundle")
        policy = load_raw(args.policy, "policy") if args.policy else None
        result = assess_bundle(bundle, policy)
    except InputError as exc:
        print(json.dumps({"outcome": "REJECT", "reason_codes": [str(exc)]}, sort_keys=True))
        return 2
    print(json.dumps(result.as_dict(), sort_keys=True, separators=(",", ":")))
    return {"ACCEPT": 0, "NEEDS_EVIDENCE": 1, "REJECT": 2}[result.outcome]


if __name__ == "__main__":
    sys.exit(main())
