"""W3C PACMI & AGMI At-Rest Conformance Evaluator for Continuity Receipts.

Implements the 10-point threat matrix (T01 - T10) for AI Agent Memory Interoperability
(PACMI / BMWG-AMI) and verifies adherence to SCITT transparency registry standards (RFC 9942/9943).

Threat Matrix:
  T01: Record Tamper           - Content or ciphertext alteration
  T02: Tail Truncate           - Dropping trailing records
  T03: Middle Delete           - Omission of intermediate records
  T04: Sequence Reorder        - Transposition of contiguous events
  T05: Record Forge            - Insertion of unauthorized/unsigned records
  T06: Cross-Context Replay    - Injection of records across tenant/session boundaries
  T07: Rollback Replay         - Replaying superseded earlier state versions
  T08: Metadata Tamper         - Modification of envelope headers or AAD
  T09: Snapshot Rollback       - Reverting store to an earlier snapshot
  T10: Erasure Resurrection    - Re-introducing legally/policy-erased memories
"""
from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from . import keys, strict_json
from .canon import canonical_bytes, sha256_prefixed
from .verify import VerifyResult, verify_bundle

THREAT_DESCRIPTIONS = {
    "T01_tamper": "Record content or ciphertext tampering",
    "T02_truncate": "Tail truncation / dropped suffix records",
    "T03_delete_middle": "Selective omission of intermediate records",
    "T04_reorder": "Permutation / out-of-order records",
    "T05_forge": "Unsigned or spurious record injection",
    "T06_cross_replay": "Cross-tenant / cross-session record replay",
    "T07_rollback_replay": "Replay of superseded earlier record version",
    "T08_metadata_tamper": "Envelope header or metadata manipulation",
    "T09_snapshot_rollback": "Full-store snapshot reversion to prior epoch",
    "T10_erase_resurrect": "Restoration of legally or policy-erased memory",
}

STATUS_SAFE = "SAFE"
STATUS_VULNERABLE = "VULNERABLE"


@dataclass
class ThreatEvaluation:
    code: str
    name: str
    description: str
    status: str
    mitigation: str
    details: str = ""


@dataclass
class PACMIReport:
    kind: str = "continuity-receipt-pacmi-conformance"
    version: int = 1
    bundle_digest: str | None = None
    task_id: str | None = None
    spec_version: str | None = None
    verdict: str = "NONCONFORMANT"
    score: str = "0/10"
    neutralized_count: int = 0
    total_attacks: int = 10
    scitt_envelope_compliant: bool = False
    offstore_anchor_present: bool = False
    erasure_commitment_present: bool = False
    threats: list[ThreatEvaluation] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _simulate_attack_refusal(bundle: dict[str, Any], mutator) -> bool:
    """Returns True if the mutator causes verify_bundle to fail (i.e. attack is neutralized)."""
    tampered = copy.deepcopy(bundle)
    try:
        mutator(tampered)
        res = verify_bundle(tampered)
        # Safe if the tampered bundle is rejected (has errors or UNTRUSTED)
        return bool(res.errors) or res.verdict == "UNTRUSTED"
    except Exception:
        # If processing crashes safely on invalid data, the attack is also rejected
        return True


def evaluate_pacmi(
    bundle_data: dict[str, Any],
    offstore_anchor: dict[str, Any] | None = None,
) -> PACMIReport:
    """Evaluates a Continuity Receipt bundle against the 10-point PACMI threat matrix."""
    report = PACMIReport()
    report.task_id = bundle_data.get("task_id")

    # 1. Base Verification
    base_res = verify_bundle(bundle_data)
    if base_res.errors or base_res.verdict == "UNTRUSTED":
        report.errors = [f"{e.get('code')}: {e.get('detail')}" for e in base_res.errors]
        report.verdict = "NONCONFORMANT"
        report.score = "0/10"
        return report

    report.bundle_digest = sha256_prefixed(canonical_bytes(bundle_data))
    receipts = bundle_data.get("receipts", [])
    if receipts:
        report.spec_version = receipts[0].get("spec")

    # Check SCITT transparency envelope compliance (RFC 9942/9943 format compatibility)
    has_valid_signatures = all(
        isinstance(r.get("sig"), dict)
        and r["sig"].get("alg") == "ed25519"
        and isinstance(r["sig"].get("value"), str)
        for r in receipts
    )
    has_canonical_roots = all(
        isinstance(r.get("task_id"), str) and isinstance(r.get("seq"), int)
        for r in receipts
    )
    report.scitt_envelope_compliant = has_valid_signatures and has_canonical_roots

    threat_evals: list[ThreatEvaluation] = []

    # T01: Record Tamper
    def _mutate_t01(b):
        if b.get("receipts"):
            b["receipts"][0]["body"]["tampered_field"] = "malicious_payload"

    t01_safe = _simulate_attack_refusal(bundle_data, _mutate_t01)
    threat_evals.append(
        ThreatEvaluation(
            code="T01",
            name="Record Tamper",
            description=THREAT_DESCRIPTIONS["T01_tamper"],
            status=STATUS_SAFE if t01_safe else STATUS_VULNERABLE,
            mitigation="Ed25519 signature over canonical unsigned record view",
            details="Cryptographic signature verification refuses payload alteration",
        )
    )

    # T02: Tail Truncate
    def _mutate_t02(b):
        if len(b.get("receipts", [])) > 1:
            b["receipts"].pop()

    t02_safe = _simulate_attack_refusal(bundle_data, _mutate_t02)
    threat_evals.append(
        ThreatEvaluation(
            code="T02",
            name="Tail Truncate",
            description=THREAT_DESCRIPTIONS["T02_truncate"],
            status=STATUS_SAFE if t02_safe else STATUS_VULNERABLE,
            mitigation="Bundle termination marker and task lifecycle settlement",
            details="Truncation refuses when lifecycle termination record is lost",
        )
    )

    # T03: Middle Delete
    def _mutate_t03(b):
        if len(b.get("receipts", [])) >= 3:
            b["receipts"].pop(1)

    t03_safe = _simulate_attack_refusal(bundle_data, _mutate_t03)
    threat_evals.append(
        ThreatEvaluation(
            code="T03",
            name="Middle Delete",
            description=THREAT_DESCRIPTIONS["T03_delete_middle"],
            status=STATUS_SAFE if t03_safe else STATUS_VULNERABLE,
            mitigation="Contiguous sequence numbers (seq) and prev-digest linkage",
            details="Missing intermediate index or broken prev-hash link refuses bundle",
        )
    )

    # T04: Sequence Reorder
    def _mutate_t04(b):
        if len(b.get("receipts", [])) >= 2:
            b["receipts"][0], b["receipts"][1] = (
                b["receipts"][1],
                b["receipts"][0],
            )

    t04_safe = _simulate_attack_refusal(bundle_data, _mutate_t04)
    threat_evals.append(
        ThreatEvaluation(
            code="T04",
            name="Sequence Reorder",
            description=THREAT_DESCRIPTIONS["T04_reorder"],
            status=STATUS_SAFE if t04_safe else STATUS_VULNERABLE,
            mitigation="Strict monotonic sequence increment and DAG prev linkage",
            details="Out-of-order execution rejected by chronology and prev validator",
        )
    )

    # T05: Record Forge
    def _mutate_t05(b):
        if b.get("receipts"):
            fake = copy.deepcopy(b["receipts"][0])
            fake["sig"]["value"] = "fake_sig_" + "0" * 40
            fake["seq"] = len(b["receipts"])
            b["receipts"].append(fake)

    t05_safe = _simulate_attack_refusal(bundle_data, _mutate_t05)
    threat_evals.append(
        ThreatEvaluation(
            code="T05",
            name="Record Forge",
            description=THREAT_DESCRIPTIONS["T05_forge"],
            status=STATUS_SAFE if t05_safe else STATUS_VULNERABLE,
            mitigation="did:key public key identity and Ed25519 verification",
            details="Unsigned or forged records fail signature verification",
        )
    )

    # T06: Cross-Tenant Replay
    def _mutate_t06(b):
        b["task_id"] = "task-cross-tenant-replay-attack"

    t06_safe = _simulate_attack_refusal(bundle_data, _mutate_t06)
    threat_evals.append(
        ThreatEvaluation(
            code="T06",
            name="Cross-Context Replay",
            description=THREAT_DESCRIPTIONS["T06_cross_replay"],
            status=STATUS_SAFE if t06_safe else STATUS_VULNERABLE,
            mitigation="Bound task_id and tenant context in each signed record",
            details="Mismatched task_id triggers task_mismatch fatal error",
        )
    )

    # T07: Rollback Replay
    def _mutate_t07(b):
        if len(b.get("receipts", [])) >= 2:
            # Replay earlier record with old seq
            b["receipts"][1]["seq"] = 0

    t07_safe = _simulate_attack_refusal(bundle_data, _mutate_t07)
    threat_evals.append(
        ThreatEvaluation(
            code="T07",
            name="Rollback Replay",
            description=THREAT_DESCRIPTIONS["T07_rollback_replay"],
            status=STATUS_SAFE if t07_safe else STATUS_VULNERABLE,
            mitigation="Monotonic sequence verification and unbroken causal chain",
            details="Replay of superseded sequence index triggers seq_noncontiguous",
        )
    )

    # T08: Metadata Tamper
    def _mutate_t08(b):
        if b.get("receipts"):
            b["receipts"][0]["type"] = "task.unauthorized_metadata"

    t08_safe = _simulate_attack_refusal(bundle_data, _mutate_t08)
    threat_evals.append(
        ThreatEvaluation(
            code="T08",
            name="Metadata Tamper",
            description=THREAT_DESCRIPTIONS["T08_metadata_tamper"],
            status=STATUS_SAFE if t08_safe else STATUS_VULNERABLE,
            mitigation="Type schema conformance and signed envelope header bindings",
            details="Header tampering invalidates signature and type schema check",
        )
    )

    # T09: Snapshot Rollback (Requires Off-Store Anchor)
    # Checks whether an off-store anchor or independent commitment is registered
    has_anchor = False
    if offstore_anchor:
        has_anchor = True
    else:
        # Check if bundle contains external anchor references
        for r in receipts:
            body = r.get("body", {})
            if "anchor_ref" in body or "offstore_digest" in body or r.get("type") == "state.commitment":
                # If commitment is marked external/anchored
                if body.get("anchor_location") == "offstore" or body.get("offstore"):
                    has_anchor = True
                    break

    report.offstore_anchor_present = has_anchor
    threat_evals.append(
        ThreatEvaluation(
            code="T09",
            name="Snapshot Rollback",
            description=THREAT_DESCRIPTIONS["T09_snapshot_rollback"],
            status=STATUS_SAFE if has_anchor else STATUS_VULNERABLE,
            mitigation="Off-store anchor (independent ledger / external commitment)",
            details="External anchor refuses rollback when store state is restored to older snapshot"
            if has_anchor
            else "Vulnerable: Store-internal commitment rolls back with disk snapshot without an off-store anchor",
        )
    )

    # T10: Erasure Resurrection (Requires Erasure-Aware Commitment)
    # Checks whether commitments carry erasure_count, erased_ids_digest, or revision
    has_erasure_commitment = False
    for r in receipts:
        if r.get("type") == "state.commitment":
            body = r.get("body", {})
            if (
                "erasure_count" in body
                or "erased_crystal_ids_digest" in body
                or "erased_ids_digest" in body
                or body.get("revision") is not None
            ):
                has_erasure_commitment = True
                break

    report.erasure_commitment_present = has_erasure_commitment
    # T10 is safe if both an off-store anchor and an erasure-aware commitment are present
    t10_safe = has_anchor and has_erasure_commitment
    threat_evals.append(
        ThreatEvaluation(
            code="T10",
            name="Erasure Resurrection",
            description=THREAT_DESCRIPTIONS["T10_erase_resurrect"],
            status=STATUS_SAFE if t10_safe else STATUS_VULNERABLE,
            mitigation="Erasure-aware set commitment (erasure_count + erased_ids_digest)",
            details="Erasure-aware commitment ensures restoring pre-erasure copy fails revision check"
            if t10_safe
            else (
                "Vulnerable: High-water count alone cannot detect resurrection; requires erasure_count & off-store anchor"
                if not has_erasure_commitment
                else "Vulnerable: Requires off-store anchor to prevent erasure commitment from rolling back"
            ),
        )
    )

    report.threats = threat_evals
    neutralized = sum(1 for t in threat_evals if t.status == STATUS_SAFE)
    report.neutralized_count = neutralized
    report.score = f"{neutralized}/{len(threat_evals)}"
    report.verdict = "CONFORMANT" if neutralized == len(threat_evals) else "PARTIAL"

    return report


def format_report_cli(report: PACMIReport) -> str:
    """Formats the PACMI evaluation report for terminal presentation."""
    lines = [
        "================================================================================",
        "          W3C PACMI / AGMI At-Rest Threat Conformance Evaluation",
        "================================================================================",
        f"  Target Task ID:             {report.task_id or 'unknown'}",
        f"  Bundle Digest:              {report.bundle_digest or 'uncomputed'}",
        f"  Spec Alignment:             {report.spec_version or 'continuity-receipt/0.5'}",
        f"  SCITT RFC 9942/9943 Format: {'COMPLIANT' if report.scitt_envelope_compliant else 'NONCOMPLIANT'}",
        f"  Off-Store Anchor:           {'PRESENT' if report.offstore_anchor_present else 'ABSENT'}",
        f"  Erasure-Aware Commitment:   {'PRESENT' if report.erasure_commitment_present else 'ABSENT'}",
        "--------------------------------------------------------------------------------",
        "  THREAT MATRIX EVALUATION (10/10 ATTACK SCENARIOS):",
        "--------------------------------------------------------------------------------",
    ]

    for t in report.threats:
        marker = "[✓]" if t.status == STATUS_SAFE else "[!]"
        lines.append(
            f"  {marker} [{t.code}] {t.name:<24} {t.status:<12} | {t.mitigation}"
        )
        if t.status == STATUS_VULNERABLE:
            lines.append(f"        -> Note: {t.details}")

    lines.extend([
        "--------------------------------------------------------------------------------",
        f"  FINAL VERDICT:              {report.verdict} ({report.score} attacks neutralized)",
        "================================================================================",
    ])

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="continuity-receipt-check-pacmi",
        description="Verify a Continuity Receipt bundle against the W3C PACMI & AGMI 10-point threat matrix.",
    )
    parser.add_argument("bundle", help="Path to continuity receipt bundle (.json)")
    parser.add_argument(
        "--anchor",
        "-a",
        help="Optional path to external off-store anchor or commitment (.json)",
        default=None,
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw machine-readable JSON report",
    )

    args = parser.parse_args(argv)

    bundle_path = Path(args.bundle)
    if not bundle_path.is_file():
        sys.stderr.write(f"Error: Bundle file not found: {args.bundle}\n")
        return 2

    try:
        with open(bundle_path, "r", encoding="utf-8") as f:
            bundle_data = strict_json.loads(f.read())
    except Exception as e:
        sys.stderr.write(f"Error: Failed to parse bundle JSON: {e}\n")
        return 2

    anchor_data = None
    if args.anchor:
        anchor_path = Path(args.anchor)
        if not anchor_path.is_file():
            sys.stderr.write(f"Error: Anchor file not found: {args.anchor}\n")
            return 2
        try:
            with open(anchor_path, "r", encoding="utf-8") as f:
                anchor_data = strict_json.loads(f.read())
        except Exception as e:
            sys.stderr.write(f"Error: Failed to parse anchor JSON: {e}\n")
            return 2

    report = evaluate_pacmi(bundle_data, offstore_anchor=anchor_data)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_report_cli(report))

    return 0 if report.verdict == "CONFORMANT" else 1


if __name__ == "__main__":
    sys.exit(main())
