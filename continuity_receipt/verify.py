"""Continuity Receipt bundle verification (0.1 + 0.2).

Verdicts: TRUSTED | PROVISIONAL | INSUFFICIENT_EVIDENCE | UNTRUSTED
(IETF CTQ-aligned semantics; see spec §7).
"""
import json
import sys
from dataclasses import dataclass, field as dc_field

from . import keys, records
from .bundle import receipt_digest
from .canon import canonical_bytes, commit_field

ANCHOR_TYPES = ("opentimestamps", "public-chain", "custom")
PROVENANCE_PREFIXES = ("sha256:", "merkle-sha256:")


@dataclass
class VerifyResult:
    verdict: str = "TRUSTED"
    errors: list = dc_field(default_factory=list)
    provisional_reasons: list = dc_field(default_factory=list)
    insufficient_reasons: list = dc_field(default_factory=list)
    summary: dict = dc_field(default_factory=dict)

    def codes(self) -> list[str]:
        return [entry["code"] for entry in self.errors]

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "errors": self.errors,
            "provisional_reasons": self.provisional_reasons,
            "insufficient_reasons": self.insufficient_reasons,
            "summary": self.summary,
        }


def _fatal(result: VerifyResult, code: str, detail: str, receipt_id: str | None = None):
    result.errors.append({"code": code, "detail": detail, "receipt_id": receipt_id})


def _iter_redactions(node, path, out):
    if isinstance(node, dict):
        if node.get("redacted") is True:
            out.append((path, node))
            return
        for key, value in node.items():
            _iter_redactions(value, f"{path}.{key}" if path else key, out)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _iter_redactions(value, f"{path}[{index}]", out)


def verify_bundle(bundle: dict, require_anchor: bool = False) -> VerifyResult:
    result = VerifyResult()

    if not isinstance(bundle, dict):
        _fatal(result, "malformed", "bundle is not an object")
        return _finish(result)

    if bundle.get("spec") not in records.SUPPORTED_SPECS:
        _fatal(result, "version_unsupported", f"spec={bundle.get('spec')!r}")
        return _finish(result)

    receipts = bundle.get("receipts")
    if not isinstance(receipts, list) or not receipts:
        _fatal(result, "malformed", "bundle has no receipts")
        return _finish(result)

    task_id = bundle.get("task_id")
    expected_prev = None
    type_by_seq: dict[int, str] = {}

    for index, receipt in enumerate(receipts):
        if not isinstance(receipt, dict):
            _fatal(result, "malformed", f"receipt {index} is not an object")
            continue
        rid = receipt.get("receipt_id")
        if receipt.get("spec") not in records.SUPPORTED_SPECS:
            _fatal(result, "version_unsupported", f"receipt spec={receipt.get('spec')!r}", rid)
        if receipt.get("task_id") != task_id:
            _fatal(result, "task_mismatch", "receipt task_id != bundle task_id", rid)
        record_type = receipt.get("type")
        if record_type not in records.RECORD_TYPES:
            _fatal(result, "unknown_type", f"type={record_type!r}", rid)
            continue
        type_by_seq[index] = record_type
        body = receipt.get("body")
        if not isinstance(body, dict):
            _fatal(result, "malformed", "body is not an object", rid)
            continue
        missing = [name for name in records.REQUIRED_FIELDS[record_type] if name not in body]
        if missing:
            _fatal(result, "malformed", f"missing body fields {missing}", rid)

        if not records.validate_timestamp(receipt.get("issued_at")):
            _fatal(result, "malformed", f"issued_at not RFC 3339 UTC: {receipt.get('issued_at')!r}", rid)

        if receipt.get("seq") != index:
            _fatal(result, "chain_break", f"seq {receipt.get('seq')} != position {index}", rid)
        if receipt.get("prev") != expected_prev:
            _fatal(result, "chain_break", "prev digest mismatch", rid)
        expected_prev = receipt_digest(receipt)

        sig = receipt.get("sig")
        if not isinstance(sig, dict) or sig.get("alg") != "ed25519" or not sig.get("value"):
            _fatal(result, "bad_signature", "missing or unsupported sig", rid)
        else:
            issuer = receipt.get("issuer", {}).get("id", "")
            message = canonical_bytes(records.unsigned_view(receipt))
            if not keys.verify(issuer, message, sig["value"]):
                _fatal(result, "bad_signature", "signature does not verify", rid)

    _check_cross_record(result, receipts, type_by_seq)
    _check_redactions(result, receipts, bundle.get("disclosure_map") or {})
    _check_attestations(result, receipts)
    _check_provenance(result, receipts)
    _check_revocations(result, bundle, receipts)
    _check_anchors(result, bundle, receipts, require_anchor)

    summary = {
        "receipts": len(receipts),
        "types": [r.get("type") for r in receipts if isinstance(r, dict)],
        "issuers": sorted(
            {r.get("issuer", {}).get("id", "") for r in receipts if isinstance(r, dict)}
        ),
        "terminated": "task.termination" in type_by_seq.values(),
        "settled": "settlement" in type_by_seq.values(),
    }
    result.summary = {**summary, **result.summary}
    return _finish(result)


def _check_cross_record(result: VerifyResult, receipts: list, type_by_seq: dict) -> None:
    pass_receipts = [r for r in receipts if r.get("type") == "session.pass.created"]
    if not pass_receipts:
        _fatal(result, "malformed", "chain has no session.pass.created receipt")
        return
    pass_body = pass_receipts[0]["body"]
    policy_version = pass_body.get("policy_version")

    for receipt in receipts:
        if receipt.get("type") == "task.decision":
            if receipt["body"].get("policy_version") != policy_version:
                _fatal(
                    result,
                    "policy_mismatch",
                    f"decision policy {receipt['body'].get('policy_version')!r} "
                    f"!= pass policy {policy_version!r}",
                    receipt.get("receipt_id"),
                )

    spend_cap = pass_body.get("spend_cap")
    settlement_indexes = [i for i, t in type_by_seq.items() if t == "settlement"]
    delivery_indexes = [i for i, t in type_by_seq.items() if t == "delivery.attestation"]

    for index in settlement_indexes:
        settlement = receipts[index]
        amount = settlement["body"].get("amount", {})
        if spend_cap is not None and (
            amount.get("currency") != spend_cap.get("currency")
            or int(amount.get("minor", 0)) > int(spend_cap.get("minor", 0))
        ):
            _fatal(
                result,
                "cap_exceeded",
                f"settlement {amount} exceeds cap {spend_cap}",
                settlement.get("receipt_id"),
            )
        if settlement["body"].get("gated_on_delivery") and (
            not delivery_indexes or min(delivery_indexes) > index
        ):
            _fatal(
                result,
                "delivery_before_settlement",
                "gated settlement recorded before any delivery attestation",
                settlement.get("receipt_id"),
            )

    if "task.termination" not in type_by_seq.values():
        _fatal(result, "missing_termination", "task has no termination receipt")


def _check_redactions(result: VerifyResult, receipts: list, disclosure_map: dict) -> None:
    redactions: list[tuple[str, dict]] = []
    _iter_redactions(receipts, "receipts", redactions)
    for path, field in redactions:
        if _required_field_for_path(path, receipts):
            _fatal(result, "redacted_required", f"required field redacted at {path}")
            continue
        entry = disclosure_map.get(path)
        if entry and "salt" in entry and "value" in entry:
            if commit_field(entry["salt"], entry["value"]) != field.get("commit"):
                _fatal(result, "commit_mismatch", f"commit mismatch at {path}")
            continue
        if field.get("erased"):
            result.insufficient_reasons.append(f"erased_content:{path}")
        else:
            result.provisional_reasons.append(f"redacted_without_disclosure:{path}")


def _check_attestations(result: VerifyResult, receipts: list) -> None:
    """0.2: counterparty attestations are verified per-signature and reported.

    Absence of an attestation is visible in the summary but does not change the
    verdict (documented in the threat model; counterparty id alone is the
    minimum required evidence).
    """
    seen = []
    for receipt in receipts:
        if receipt.get("type") != "delivery.attestation":
            continue
        body = receipt.get("body", {})
        counterparty = body.get("counterparty", {}) if isinstance(body, dict) else {}
        attestation = counterparty.get("attestation") if isinstance(counterparty, dict) else None
        if not attestation:
            seen.append(
                {
                    "receipt_id": receipt.get("receipt_id"),
                    "counterparty": counterparty.get("id") if isinstance(counterparty, dict) else None,
                    "attestation": "absent",
                }
            )
            continue
        valid = (
            isinstance(attestation, dict)
            and attestation.get("alg") == "ed25519"
            and isinstance(attestation.get("key"), str)
            and isinstance(attestation.get("value"), str)
            and keys.verify(
                attestation["key"],
                canonical_bytes(records.attestation_view(body)),
                attestation["value"],
            )
        )
        seen.append(
            {
                "receipt_id": receipt.get("receipt_id"),
                "counterparty": counterparty.get("id") if isinstance(counterparty, dict) else None,
                "attestation": "valid" if valid else "invalid",
                "key": attestation.get("key") if isinstance(attestation, dict) else None,
            }
        )
        if not valid:
            _fatal(
                result,
                "bad_attestation",
                "counterparty attestation does not verify",
                receipt.get("receipt_id"),
            )
    if seen:
        result.summary["attestations"] = seen


def _check_provenance(result: VerifyResult, receipts: list) -> None:
    """0.2: observed_sources_hash is a flat sha256 or a merkle-sha256 root."""
    for receipt in receipts:
        if receipt.get("type") != "task.decision":
            continue
        provenance = receipt.get("body", {}).get("input_provenance")
        if not isinstance(provenance, dict):
            continue
        observed = provenance.get("observed_sources_hash")
        if observed is None:
            continue
        if not isinstance(observed, str) or not observed.startswith(PROVENANCE_PREFIXES):
            _fatal(
                result,
                "provenance_invalid",
                f"observed_sources_hash has unsupported form: {observed!r}",
                receipt.get("receipt_id"),
            )


def _check_revocations(result: VerifyResult, bundle: dict, receipts: list) -> None:
    """0.2: bundle-level revocation statements (self-signed by the revoked key).

    A receipt is UNTRUSTED (`key_revoked`) when its issuer key was revoked at or
    before the receipt's issued_at. Receipts issued before revocation remain
    valid; invalid revocation statements are themselves an error (fail-closed).
    """
    revocations = bundle.get("revocations") or []
    if not isinstance(revocations, list):
        _fatal(result, "bad_revocation", "revocations must be a list")
        return
    revoked: list[tuple[str, object]] = []
    checked = 0
    for statement in revocations:
        if not isinstance(statement, dict):
            _fatal(result, "bad_revocation", "revocation statement is not an object")
            continue
        key_id, revoked_at, sig = statement.get("key"), statement.get("revoked_at"), statement.get("sig")
        if not isinstance(key_id, str) or not records.validate_timestamp(revoked_at):
            _fatal(result, "bad_revocation", f"malformed revocation statement for {key_id!r}")
            continue
        if not isinstance(sig, dict) or sig.get("alg") != "ed25519" or not sig.get("value"):
            _fatal(result, "bad_revocation", f"revocation statement unsigned for {key_id!r}")
            continue
        message = canonical_bytes({k: v for k, v in statement.items() if k != "sig"})
        if not keys.verify(key_id, message, sig["value"]):
            _fatal(result, "bad_revocation", f"revocation signature invalid for {key_id!r}")
            continue
        revoked.append((key_id, records.parse_timestamp(revoked_at)))
        checked += 1

    for receipt in receipts:
        key_id = receipt.get("issuer", {}).get("id")
        issued = receipt.get("issued_at")
        if not isinstance(key_id, str) or not records.validate_timestamp(issued):
            continue
        issued_at = records.parse_timestamp(issued)
        for revoked_key, revoked_at in revoked:
            if revoked_key == key_id and issued_at >= revoked_at:
                _fatal(
                    result,
                    "key_revoked",
                    f"issuer key {key_id} was revoked at {revoked_at.isoformat()}",
                    receipt.get("receipt_id"),
                )
    if revocations:
        result.summary["revocations_checked"] = checked


def _required_field_for_path(path: str, receipts: list) -> str | None:
    parts = path.split(".")
    if len(parts) >= 3 and parts[0].startswith("receipts[") and parts[1] == "body":
        index_text = parts[0][len("receipts[") :].rstrip("]")
        try:
            receipt = receipts[int(index_text)]
        except (ValueError, IndexError):
            return None
        record_type = receipt.get("type")
        if record_type in records.REQUIRED_FIELDS and parts[2] in records.REQUIRED_FIELDS[record_type]:
            return parts[2]
    return None


def _check_anchors(result: VerifyResult, bundle: dict, receipts: list, require_anchor: bool) -> None:
    anchors = bundle.get("anchors")
    if not anchors:
        if require_anchor:
            result.provisional_reasons.append("anchor_missing")
        return
    by_id = {r.get("receipt_id"): r for r in receipts if isinstance(r, dict)}
    kinds = []
    for anchor in anchors:
        target = by_id.get(anchor.get("target"))
        if target is None or anchor.get("hash") != receipt_digest(target):
            _fatal(result, "anchor_invalid", f"anchor invalid for {anchor.get('target')}")
            continue
        meta = anchor.get("anchor")
        if meta is not None:
            if not isinstance(meta, dict) or meta.get("type") not in ANCHOR_TYPES:
                _fatal(
                    result,
                    "anchor_invalid",
                    f"unknown anchor type: {meta.get('type') if isinstance(meta, dict) else meta!r}",
                )
                continue
            kinds.append(meta.get("type"))
    if anchors:
        result.summary["anchors"] = kinds or ["hash-only"]


def _finish(result: VerifyResult) -> VerifyResult:
    if result.errors:
        result.verdict = "UNTRUSTED"
    elif result.insufficient_reasons:
        result.verdict = "INSUFFICIENT_EVIDENCE"
    elif result.provisional_reasons:
        result.verdict = "PROVISIONAL"
    else:
        result.verdict = "TRUSTED"
    return result


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="continuity-receipt-verify")
    parser.add_argument("bundle", help="path to a bundle JSON file")
    parser.add_argument("--require-anchor", action="store_true")
    args = parser.parse_args(argv)

    with open(args.bundle, "r", encoding="utf-8") as handle:
        bundle = json.load(handle)
    result = verify_bundle(bundle, require_anchor=args.require_anchor)
    print(json.dumps(result.as_dict(), indent=2))
    return 0 if result.verdict == "TRUSTED" else 1


if __name__ == "__main__":
    sys.exit(main())
