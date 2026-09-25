"""Continuity Receipt bundle verification (0.1 + 0.2).

Verdicts: TRUSTED | PROVISIONAL | INSUFFICIENT_EVIDENCE | UNTRUSTED
(IETF CTQ-aligned semantics; see spec §7).
"""
import json
import os
import sys
from dataclasses import dataclass, field as dc_field

from . import agreements, keys, records
from .bundle import receipt_digest
from .canon import canonical_bytes, commit_field
from .revocations import merge_statements, verify_statements

ANCHOR_TYPES = ("opentimestamps", "public-chain", "custom")
PROVENANCE_PREFIXES = ("sha256:", "merkle-sha256:")
MAX_RECEIPTS = 10_000
MAX_NESTING_DEPTH = 64
MAX_BUNDLE_BYTES = 8 * 1024 * 1024


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


def _try_digest(receipt: dict) -> str | None:
    """receipt_digest for a well-formed receipt; None when not canonically encodable."""
    try:
        return receipt_digest(receipt)
    except (TypeError, ValueError):
        return None


def _depth_exceeded(node, limit: int) -> bool:
    """Iterative depth probe so hostile nesting cannot exhaust the stack."""
    stack = [(node, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > limit:
            return True
        if isinstance(current, dict):
            stack.extend((value, depth + 1) for value in current.values())
        elif isinstance(current, list):
            stack.extend((value, depth + 1) for value in current)
    return False


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


def _check_shape(result: VerifyResult, bundle: dict, receipts: list) -> None:
    """Whole-shape validation before any semantic check.

    Structural violations (a value of the wrong JSON type where the format
    requires an object, list, or string) are recorded up front as
    ``malformed``/``bad_revocation``/``anchor_invalid``, so every later pass
    can rely on shape — and hostile input cannot reach a code path that would
    raise. Semantic checks stay in their own passes.
    """
    for index, receipt in enumerate(receipts):
        if not isinstance(receipt, dict):
            _fatal(result, "malformed", f"receipt {index} is not an object")
            continue
        rid = receipt.get("receipt_id") if isinstance(receipt.get("receipt_id"), str) else None
        if not isinstance(receipt.get("body"), dict):
            _fatal(result, "malformed", "body is not an object", rid)
        if not isinstance(receipt.get("issuer"), dict):
            _fatal(result, "malformed", "issuer is not an object", rid)
    anchors = bundle.get("anchors")
    if anchors is not None and not isinstance(anchors, list):
        _fatal(result, "malformed", "anchors is not a list")
    elif isinstance(anchors, list):
        for anchor in anchors:
            if not isinstance(anchor, dict):
                _fatal(result, "anchor_invalid", "anchor entry is not an object")
    revocations = bundle.get("revocations")
    if revocations is not None and not isinstance(revocations, list):
        _fatal(result, "bad_revocation", "revocations must be a list")
    elif isinstance(revocations, list):
        for statement in revocations:
            if not isinstance(statement, dict):
                _fatal(result, "bad_revocation", "revocation statements must be objects")
    disclosure_map = bundle.get("disclosure_map")
    if disclosure_map is not None and not isinstance(disclosure_map, dict):
        _fatal(result, "malformed", "disclosure_map is not an object")


def verify_bundle(
    bundle: dict,
    require_anchor: bool = False,
    external_revocations: list | None = None,
) -> VerifyResult:
    result = VerifyResult()

    if not isinstance(bundle, dict):
        _fatal(result, "malformed", "bundle is not an object")
        return _finish(result)
    if _depth_exceeded(bundle, MAX_NESTING_DEPTH):
        _fatal(result, "nesting_too_deep", f"bundle nesting exceeds depth {MAX_NESTING_DEPTH}")
        return _finish(result)

    if bundle.get("spec") not in records.SUPPORTED_SPECS:
        _fatal(result, "version_unsupported", f"spec={bundle.get('spec')!r}")
        return _finish(result)

    receipts = bundle.get("receipts")
    if not isinstance(receipts, list) or not receipts:
        _fatal(result, "malformed", "bundle has no receipts")
        return _finish(result)
    if len(receipts) > MAX_RECEIPTS:
        _fatal(result, "too_many_receipts", f"{len(receipts)} receipts exceeds limit {MAX_RECEIPTS}")
        return _finish(result)

    _check_shape(result, bundle, receipts)

    task_id = bundle.get("task_id")
    expected_prev = None

    for index, receipt in enumerate(receipts):
        if not isinstance(receipt, dict):
            continue
        rid = receipt.get("receipt_id")
        if receipt.get("spec") not in records.SUPPORTED_SPECS:
            _fatal(result, "version_unsupported", f"receipt spec={receipt.get('spec')!r}", rid)
        if receipt.get("task_id") != task_id:
            _fatal(result, "task_mismatch", "receipt task_id != bundle task_id", rid)
        record_type = receipt.get("type")
        if record_type not in records.RECORD_TYPES or (record_type == "state.commitment" and receipt.get("spec") != "continuity-receipt/0.5"):
            _fatal(result, "unknown_type", f"type={record_type!r}", rid)
            continue
        body = receipt.get("body")
        if not isinstance(body, dict):
            continue
        missing = [
            name
            for name in records.required_fields(record_type, receipt.get("spec"))
            if name not in body
        ]
        if missing:
            _fatal(result, "malformed", f"missing body fields {missing}", rid)
        if receipt.get("spec") == "continuity-receipt/0.5":
            _check_05_body(result, record_type, body, rid)

        if not records.validate_timestamp(receipt.get("issued_at")):
            _fatal(result, "malformed", f"issued_at not RFC 3339 UTC: {receipt.get('issued_at')!r}", rid)

        if receipt.get("seq") != index:
            _fatal(result, "chain_break", f"seq {receipt.get('seq')} != position {index}", rid)
        if receipt.get("prev") != expected_prev:
            _fatal(result, "chain_break", "prev digest mismatch", rid)
        digest = _try_digest(receipt)
        if digest is None:
            _fatal(result, "malformed", "receipt is not canonically encodable (floats are rejected)", rid)
            expected_prev = None
        else:
            expected_prev = digest

        issuer = receipt.get("issuer")
        sig = receipt.get("sig")
        if (
            not isinstance(sig, dict)
            or sig.get("alg") != "ed25519"
            or not isinstance(sig.get("value"), str)
            or not sig.get("value")
        ):
            _fatal(result, "bad_signature", "missing or unsupported sig", rid)
        else:
            issuer_id = issuer.get("id", "") if isinstance(issuer, dict) else ""
            try:
                message = canonical_bytes(records.unsigned_view(receipt))
            except (TypeError, ValueError):
                _fatal(result, "bad_signature", "receipt is not canonically encodable", rid)
            else:
                if not isinstance(issuer_id, str) or not keys.verify(issuer_id, message, sig["value"]):
                    _fatal(result, "bad_signature", "signature does not verify", rid)

    well_formed = [r for r in receipts if isinstance(r, dict)]
    disclosure_map = bundle.get("disclosure_map")
    if not isinstance(disclosure_map, dict):
        disclosure_map = None
    _check_cross_record(result, well_formed)
    _check_agreements(result, well_formed)
    _check_redactions(result, well_formed, disclosure_map or {})
    _check_attestations(result, well_formed)
    _check_provenance(result, well_formed)
    _check_revocations(result, bundle, well_formed, external_revocations)
    _check_anchors(result, bundle, well_formed, require_anchor)

    types = [r.get("type") for r in well_formed]
    summary = {
        "receipts": len(receipts),
        "types": types,
        "issuers": sorted(
            {
                r["issuer"]["id"]
                for r in well_formed
                if isinstance(r.get("issuer"), dict) and isinstance(r["issuer"].get("id"), str)
            }
        ),
        "terminated": "task.termination" in types,
        "settled": "settlement" in types,
    }
    result.summary = {**summary, **result.summary}
    return _finish(result)


def _check_05_body(result: VerifyResult, record_type: str, body: dict, rid) -> None:
    """Validate the 0.5 vocabulary without changing older receipt semantics."""
    if record_type == "session.pass.created" and body.get("mandala_class") not in (
        "gate-lite", "gate-hard", "local"
    ):
        _fatal(result, "malformed", "mandala_class must be gate-lite, gate-hard, or local", rid)
    if record_type == "task.execution" and body.get("sandbox_class") not in (
        "bwrap", "landlock", "bwrap-landlock", "microvm-ch", "microvm-fc", "none"
    ):
        _fatal(result, "malformed", "sandbox_class is unknown", rid)
    if record_type == "state.commitment":
        import re
        digest = re.compile(r"^sha256:[0-9a-f]{64}$")
        merkle = re.compile(r"^merkle-sha256:[0-9a-f]{64}$")
        if not isinstance(body.get("state_kind"), str) or not body["state_kind"]:
            _fatal(result, "malformed", "state_kind must be nonempty text", rid)
        if not isinstance(body.get("scope"), str) or not body["scope"]:
            _fatal(result, "malformed", "scope must be nonempty text", rid)
        if isinstance(body.get("count"), bool) or not isinstance(body.get("count"), int) or not 0 <= body["count"] <= 2**64 - 1:
            _fatal(result, "malformed", "count must be an unsigned 64-bit integer", rid)
        if not isinstance(body.get("head_digest"), str) or not digest.fullmatch(body["head_digest"]):
            _fatal(result, "malformed", "head_digest must be a sha256 digest", rid)
        root = body.get("merkle_root")
        if root is not None and (not isinstance(root, str) or not merkle.fullmatch(root)):
            _fatal(result, "malformed", "merkle_root must be a merkle-sha256 digest", rid)


def _check_cross_record(result: VerifyResult, receipts: list) -> None:
    pass_receipts = [r for r in receipts if r.get("type") == "session.pass.created"]
    if not pass_receipts:
        _fatal(result, "malformed", "chain has no session.pass.created receipt")
        return
    pass_body = pass_receipts[0].get("body")
    if not isinstance(pass_body, dict):
        return
    policy_version = pass_body.get("policy_version")

    for receipt in receipts:
        if receipt.get("type") != "task.decision":
            continue
        body = receipt.get("body")
        if not isinstance(body, dict):
            continue
        if body.get("policy_version") != policy_version:
            _fatal(
                result,
                "policy_mismatch",
                f"decision policy {body.get('policy_version')!r} "
                f"!= pass policy {policy_version!r}",
                receipt.get("receipt_id"),
            )

    spend_cap = pass_body.get("spend_cap")
    if spend_cap is not None and not isinstance(spend_cap, dict):
        _fatal(
            result,
            "malformed",
            "pass spend_cap is not an object",
            pass_receipts[0].get("receipt_id"),
        )
        spend_cap = None
    type_by_seq = {index: r.get("type") for index, r in enumerate(receipts)}
    settlement_indexes = [i for i, t in type_by_seq.items() if t == "settlement"]
    delivery_indexes = [i for i, t in type_by_seq.items() if t == "delivery.attestation"]

    for index in settlement_indexes:
        settlement = receipts[index]
        body = settlement.get("body")
        if not isinstance(body, dict):
            continue
        amount = body.get("amount") if "amount" in body else {}
        if not isinstance(amount, dict):
            _fatal(
                result,
                "malformed",
                "settlement amount is not an object",
                settlement.get("receipt_id"),
            )
            continue
        if spend_cap is not None:
            try:
                exceeds = amount.get("currency") != spend_cap.get("currency") or int(
                    amount.get("minor", 0)
                ) > int(spend_cap.get("minor", 0))
            except (TypeError, ValueError):
                _fatal(
                    result,
                    "malformed",
                    "settlement amount is not numeric",
                    settlement.get("receipt_id"),
                )
                exceeds = False
            if exceeds:
                _fatal(
                    result,
                    "cap_exceeded",
                    f"settlement {amount} exceeds cap {spend_cap}",
                    settlement.get("receipt_id"),
                )
        if body.get("gated_on_delivery") and (
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


def _check_agreements(result: VerifyResult, receipts: list) -> None:
    """Offer → accept binding: 0.3 resolves the offer; 0.4 carries the binding.

    0.3 (unchanged): `offer_ref` resolves to an offer in the bundle; `offer_id`
    and `terms_hash` must match (`offer_mismatch`); an accept after the offer's
    `valid_until` is expired (`offer_expired`). A missing offer is
    INSUFFICIENT_EVIDENCE (`missing_offer`), never silently trusted.

    0.4 additions:
    - The accept names the offeree (`offeree` is required) and must be signed
      by it; it must equal the offer's offeree — otherwise `offeree_mismatch`.
    - The accept must follow the offer in time (`accept_before_offer`).
    - A 0.4 bound record (`BOUND_TYPES`) carrying `agreement_ref` must resolve
      to an accept in the bundle (absent → `missing_agreement`), must follow it
      (`agreement_before_accept`), and its issuer must be the accept's offeree
      (`agreement_issuer_mismatch`). Non-0.4 records ignore `agreement_ref` as
      an additional member.
    - The offeree's post-accept bound records must carry `agreement_ref`
      (`missing_agreement_ref`), and an accept nothing references is
      `agreement_unreferenced` — both PROVISIONAL: the linkage evidence is
      missing, not false.
    """
    offers: dict = {}
    accepts: dict = {}
    for r in receipts:
        record_type = r.get("type")
        if record_type not in ("agreement.offer", "agreement.accept"):
            continue
        digest = _try_digest(r)
        if digest is None:
            continue
        (offers if record_type == "agreement.offer" else accepts)[digest] = r

    for receipt in receipts:
        if receipt.get("type") == "agreement.accept":
            _check_accept(result, receipt, offers)

    referenced: set = set()
    for receipt in receipts:
        if receipt.get("type") not in agreements.BOUND_TYPES:
            continue
        if receipt.get("spec") not in ("continuity-receipt/0.4", "continuity-receipt/0.5"):
            continue
        body = receipt.get("body")
        if not isinstance(body, dict):
            continue
        ref = body.get("agreement_ref")
        if ref is None:
            continue
        accept = accepts.get(ref) if isinstance(ref, str) else None
        if accept is None:
            result.insufficient_reasons.append(
                f"missing_agreement:{receipt.get('receipt_id')}"
            )
            continue
        referenced.add(ref)
        accept_body = accept.get("body")
        if not isinstance(accept_body, dict):
            continue
        accept_issued = accept.get("issued_at")
        bound_issued = receipt.get("issued_at")
        if (
            records.validate_timestamp(accept_issued)
            and records.validate_timestamp(bound_issued)
            and records.parse_timestamp(bound_issued) < records.parse_timestamp(accept_issued)
        ):
            _fatal(
                result,
                "agreement_before_accept",
                f"bound receipt issued before its accept {accept.get('receipt_id')}",
                receipt.get("receipt_id"),
            )
        issuer = receipt.get("issuer")
        issuer_id = issuer.get("id") if isinstance(issuer, dict) else None
        offeree = accept_body.get("offeree")
        if isinstance(offeree, str) and issuer_id != offeree:
            _fatal(
                result,
                "agreement_issuer_mismatch",
                f"bound receipt issuer {issuer_id!r} is not the offeree",
                receipt.get("receipt_id"),
            )

    _check_agreement_completeness(result, receipts, accepts, referenced)


def _check_accept(result: VerifyResult, receipt: dict, offers: dict) -> None:
    body = receipt.get("body")
    if not isinstance(body, dict):
        return
    offer_ref = body.get("offer_ref")
    offer = offers.get(offer_ref) if isinstance(offer_ref, str) else None
    if offer is None:
        result.insufficient_reasons.append(f"missing_offer:{receipt.get('receipt_id')}")
        return
    offer_body = offer.get("body")
    if not isinstance(offer_body, dict):
        return
    valid_until = offer_body.get("valid_until")
    if not records.validate_timestamp(valid_until):
        _fatal(
            result,
            "malformed",
            f"offer valid_until not RFC 3339 UTC: {valid_until!r}",
            offer.get("receipt_id"),
        )
        return
    if (
        body.get("offer_id") != offer_body.get("offer_id")
        or body.get("terms_hash") != offer_body.get("terms_hash")
    ):
        _fatal(
            result,
            "offer_mismatch",
            "accept does not match the referenced offer",
            receipt.get("receipt_id"),
        )
        return
    accept_issued = receipt.get("issued_at")
    if records.validate_timestamp(accept_issued) and records.parse_timestamp(
        accept_issued
    ) > records.parse_timestamp(valid_until):
        _fatal(
            result,
            "offer_expired",
            f"accept issued after offer valid_until {valid_until}",
            receipt.get("receipt_id"),
        )
    if receipt.get("spec") not in ("continuity-receipt/0.4", "continuity-receipt/0.5"):
        return
    offeree = body.get("offeree")
    issuer = receipt.get("issuer")
    issuer_id = issuer.get("id") if isinstance(issuer, dict) else None
    if not isinstance(offeree, str) or not offeree:
        _fatal(
            result,
            "malformed",
            f"accept offeree is not a string: {offeree!r}",
            receipt.get("receipt_id"),
        )
    elif issuer_id != offeree or offeree != offer_body.get("offeree"):
        _fatal(
            result,
            "offeree_mismatch",
            f"accept offeree {offeree!r} does not match the signer {issuer_id!r} / offer",
            receipt.get("receipt_id"),
        )
    offer_issued = offer.get("issued_at")
    if (
        records.validate_timestamp(accept_issued)
        and records.validate_timestamp(offer_issued)
        and records.parse_timestamp(accept_issued) < records.parse_timestamp(offer_issued)
    ):
        _fatal(
            result,
            "accept_before_offer",
            f"accept issued before offer {offer.get('receipt_id')}",
            receipt.get("receipt_id"),
        )


def _check_agreement_completeness(
    result: VerifyResult, receipts: list, accepts: dict, referenced: set
) -> None:
    """0.4: an accept nothing references, and offeree receipts that skip the ref."""
    for digest, accept in accepts.items():
        if accept.get("spec") in ("continuity-receipt/0.4", "continuity-receipt/0.5") and digest not in referenced:
            result.provisional_reasons.append(
                f"agreement_unreferenced:{accept.get('receipt_id')}"
            )
    for receipt in receipts:
        if receipt.get("spec") not in ("continuity-receipt/0.4", "continuity-receipt/0.5"):
            continue
        if receipt.get("type") not in agreements.BOUND_TYPES:
            continue
        body = receipt.get("body")
        if not isinstance(body, dict) or body.get("agreement_ref") is not None:
            continue
        issuer = receipt.get("issuer")
        issuer_id = issuer.get("id") if isinstance(issuer, dict) else None
        bound_issued = receipt.get("issued_at")
        if not isinstance(issuer_id, str) or not records.validate_timestamp(bound_issued):
            continue
        bound_at = records.parse_timestamp(bound_issued)
        for accept in accepts.values():
            if accept.get("spec") not in ("continuity-receipt/0.4", "continuity-receipt/0.5"):
                continue
            accept_body = accept.get("body")
            if not isinstance(accept_body, dict) or accept_body.get("offeree") != issuer_id:
                continue
            accept_issued = accept.get("issued_at")
            if not records.validate_timestamp(accept_issued):
                continue
            if records.parse_timestamp(accept_issued) <= bound_at:
                result.provisional_reasons.append(
                    f"missing_agreement_ref:{receipt.get('receipt_id')}"
                )
                break


def _check_redactions(result: VerifyResult, receipts: list, disclosure_map: dict) -> None:
    redactions: list[tuple[str, dict]] = []
    _iter_redactions(receipts, "receipts", redactions)
    for path, field in redactions:
        if _required_field_for_path(path, receipts):
            _fatal(result, "redacted_required", f"required field redacted at {path}")
            continue
        entry = disclosure_map.get(path)
        if isinstance(entry, dict) and "salt" in entry and "value" in entry:
            try:
                commit = commit_field(entry["salt"], entry["value"])
            except (TypeError, ValueError):
                _fatal(result, "commit_mismatch", f"disclosure entry malformed at {path}")
                continue
            if commit != field.get("commit"):
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
        view = None
        if (
            isinstance(attestation, dict)
            and attestation.get("alg") == "ed25519"
            and isinstance(attestation.get("key"), str)
            and isinstance(attestation.get("value"), str)
        ):
            try:
                view = canonical_bytes(records.attestation_view(body))
            except (TypeError, ValueError):
                view = None
        valid = view is not None and keys.verify(
            attestation["key"], view, attestation["value"]
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
        body = receipt.get("body")
        if not isinstance(body, dict):
            continue
        provenance = body.get("input_provenance")
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


def _check_revocations(
    result: VerifyResult,
    bundle: dict,
    receipts: list,
    external_revocations: list | None = None,
) -> None:
    """0.2: revocation statements (self-signed by the revoked key).

    Statements may arrive inside the bundle and/or from external revocation
    lists (0.3 tooling, REVOCATION_DISTRIBUTION.md); the two are merged and
    deduplicated. A receipt is UNTRUSTED (`key_revoked`) when its issuer key
    was revoked at or before the receipt's issued_at. Receipts issued before
    revocation remain valid; invalid statements are themselves an error
    (fail-closed).
    """
    bundle_revocations = bundle.get("revocations") or []
    if not isinstance(bundle_revocations, list):
        return
    if not all(isinstance(statement, dict) for statement in bundle_revocations):
        return
    try:
        revocations = merge_statements(bundle_revocations, external_revocations)
        revoked, statement_errors = verify_statements(revocations)
    except (TypeError, ValueError) as exc:
        _fatal(result, "bad_revocation", f"revocations unusable: {exc}")
        return
    for code, detail in statement_errors:
        _fatal(result, code, detail)
    checked = len(revoked)

    for receipt in receipts:
        issuer = receipt.get("issuer")
        key_id = issuer.get("id") if isinstance(issuer, dict) else None
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
    if external_revocations is not None:
        result.summary["revocations_external"] = len(external_revocations)


def _required_field_for_path(path: str, receipts: list) -> str | None:
    parts = path.split(".")
    if len(parts) >= 3 and parts[0].startswith("receipts[") and parts[1] == "body":
        index_text = parts[0][len("receipts[") :].rstrip("]")
        try:
            receipt = receipts[int(index_text)]
        except (ValueError, IndexError):
            return None
        record_type = receipt.get("type")
        if (
            isinstance(record_type, str)
            and record_type in records.REQUIRED_FIELDS
            and parts[2] in records.REQUIRED_FIELDS[record_type]
        ):
            return parts[2]
    return None


def _check_anchors(result: VerifyResult, bundle: dict, receipts: list, require_anchor: bool) -> None:
    anchors = bundle.get("anchors")
    if not anchors:
        if require_anchor:
            result.provisional_reasons.append("anchor_missing")
        return
    if not isinstance(anchors, list):
        return
    by_id = {}
    for r in receipts:
        rid = r.get("receipt_id")
        if isinstance(rid, str):
            by_id[rid] = r
    kinds = []
    for anchor in anchors:
        if not isinstance(anchor, dict):
            continue
        target_key = anchor.get("target")
        target = by_id.get(target_key) if isinstance(target_key, str) else None
        digest = _try_digest(target) if target is not None else None
        if target is None or digest is None or anchor.get("hash") != digest:
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

    from . import revocations

    parser = argparse.ArgumentParser(prog="continuity-receipt-verify")
    parser.add_argument("bundle", help="path to a bundle JSON file")
    parser.add_argument("--require-anchor", action="store_true")
    parser.add_argument(
        "--revocations",
        action="append",
        default=None,
        metavar="PATH|URL",
        help="external revocation list (repeatable; REVOCATION_DISTRIBUTION.md)",
    )
    args = parser.parse_args(argv)

    external = None
    if args.revocations:
        try:
            external = revocations.merge_statements(
                *[revocations.load_statements(source) for source in args.revocations]
            )
        except revocations.RevocationError as exc:
            print(
                json.dumps(
                    {
                        "verdict": "INSUFFICIENT_EVIDENCE",
                        "errors": [{"code": exc.code, "detail": exc.detail}],
                    },
                    indent=2,
                )
            )
            return 1

    try:
        size = os.path.getsize(args.bundle)
    except OSError as exc:
        print(f"error: cannot read bundle: {exc}", file=sys.stderr)
        return 2
    if size > MAX_BUNDLE_BYTES:
        print(
            json.dumps(
                {
                    "verdict": "UNTRUSTED",
                    "errors": [
                        {
                            "code": "bundle_too_large",
                            "detail": f"{size} bytes exceeds limit {MAX_BUNDLE_BYTES}",
                        }
                    ],
                },
                indent=2,
            )
        )
        return 1
    try:
        with open(args.bundle, "r", encoding="utf-8") as handle:
            bundle = json.load(handle)
    except RecursionError:
        print(
            json.dumps(
                {
                    "verdict": "UNTRUSTED",
                    "errors": [
                        {
                            "code": "nesting_too_deep",
                            "detail": "JSON nesting exceeds the parser limit",
                        }
                    ],
                },
                indent=2,
            )
        )
        return 1
    except ValueError as exc:
        print(
            json.dumps(
                {
                    "verdict": "UNTRUSTED",
                    "errors": [
                        {"code": "malformed", "detail": f"bundle is not valid JSON: {exc}"}
                    ],
                },
                indent=2,
            )
        )
        return 1
    result = verify_bundle(
        bundle,
        require_anchor=args.require_anchor,
        external_revocations=external,
    )
    print(json.dumps(result.as_dict(), indent=2))
    return 0 if result.verdict == "TRUSTED" else 1


if __name__ == "__main__":
    sys.exit(main())
