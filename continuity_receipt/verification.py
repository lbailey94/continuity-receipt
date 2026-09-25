"""Verification receipts — signed records of a verification run.

Companion to the core spec; wire format and semantics: `VERIFICATION_RECEIPTS.md`.
A verification receipt is issued by a verifier after running the bundle
verification algorithm over a bundle. It records the **full result** — the
verdict, every error, the provisional/insufficient reasons, and the summary —
so a holder can audit not just *what* was decided but *how and why* it was
calculated, and can check the result's internal consistency offline.

Wire format (``kind`` ``continuity-receipt-verification``, version 1)::

    {
      "kind": "continuity-receipt-verification",
      "version": 1,
      "bundle_digest": "sha256:<64 hex>",
      "verdict": "UNTRUSTED",
      "error_codes": ["bad_signature"],
      "errors": [{"code": "bad_signature", "detail": "signature does not verify",
                  "receipt_id": "urn:uuid:..."}],
      "provisional_reasons": [],
      "insufficient_reasons": [],
      "summary": {"receipts": 6, "types": [...], "issuers": [...],
                  "terminated": true, "settled": true},
      "verified_at": "2026-09-23T21:00:00Z",
      "verifier": {"implementation": "python-reference", "version": "0.3.3"},
      "issuer": "did:key:z6Mk...",
      "sig": {"alg": "ed25519", "key": "did:key:z6Mk...", "value": "base64url"}
    }

``bundle_digest`` is the SHA-256 of the JCS-canonical bytes of the verified
bundle object (the same pinned canonicalization the core spec uses for
signatures), so any holder of the bundle can reproduce it regardless of
serialization. The signature covers the JCS-canonical bytes of the receipt
object minus ``sig`` — the same canonical view rule as bundle receipts.
Additional members are allowed and are inside the signed bytes; verifiers
ignore members they do not know.

Consistency is checkable without the bundle: ``error_codes`` must equal the
codes in ``errors`` (in order), and the verdict must be the class implied by
the lists — errors non-empty → ``UNTRUSTED``; else insufficient reasons →
``INSUFFICIENT_EVIDENCE``; else provisional reasons → ``PROVISIONAL``; else
``TRUSTED``.

Error codes (``verify_verification_receipt``): ``not_an_object``, ``bad_kind``,
``bad_version``, ``bad_verdict``, ``bad_verified_at``, ``bad_bundle_digest``,
``bad_error_codes``, ``bad_errors``, ``bad_provisional_reasons``,
``bad_insufficient_reasons``, ``bad_summary``, ``error_codes_mismatch``,
``verdict_mismatch``, ``bad_signature_shape``, ``bad_signature``,
``bundle_digest_mismatch``, ``key_revoked``.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field as dc_field

from . import keys, records
from . import strict_json
from . import revocations as revocations_mod
from ._version import __version__
from .canon import canonical_bytes, sha256_prefixed

KIND = "continuity-receipt-verification"
VERSION = 1
VERDICTS = ("TRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE", "UNTRUSTED")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RESULT_FIELDS = ("verdict", "errors", "provisional_reasons", "insufficient_reasons", "summary")


@dataclass
class VerificationReceiptResult:
    valid: bool = False
    errors: list = dc_field(default_factory=list)
    issuer: str | None = None
    verdict: str | None = None
    verified_at: str | None = None
    bundle_digest: str | None = None
    digest_match: bool | None = None

    def as_dict(self) -> dict:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "issuer": self.issuer,
            "verdict": self.verdict,
            "verified_at": self.verified_at,
            "bundle_digest": self.bundle_digest,
            "digest_match": self.digest_match,
        }


def _bundle_object(bundle) -> dict:
    """Accept a parsed bundle object or its JSON bytes; raise ValueError on junk."""
    if isinstance(bundle, dict):
        return bundle
    if isinstance(bundle, (bytes, bytearray, str)):
        return strict_json.loads(bundle)
    raise ValueError("bundle must be an object or JSON bytes")


def _result_dict(result) -> dict:
    """Normalize a VerifyResult or a result dict to the recorded result fields."""
    if hasattr(result, "as_dict"):
        result = result.as_dict()
    if not isinstance(result, dict):
        raise ValueError("result must be a VerifyResult or a result dict")
    return {
        "verdict": result.get("verdict"),
        "errors": list(result.get("errors") or []),
        "provisional_reasons": list(result.get("provisional_reasons") or []),
        "insufficient_reasons": list(result.get("insufficient_reasons") or []),
        "summary": dict(result.get("summary") or {}),
    }


def _errors_well_formed(errors) -> bool:
    return isinstance(errors, list) and all(
        isinstance(entry, dict) and isinstance(entry.get("code"), str) for entry in errors
    )


def _string_list(value) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _verdict_class(errors: list, provisional: list, insufficient: list) -> str:
    """The verdict implied by a result's errors/reasons (verify.py `_finish`)."""
    if errors:
        return "UNTRUSTED"
    if insufficient:
        return "INSUFFICIENT_EVIDENCE"
    if provisional:
        return "PROVISIONAL"
    return "TRUSTED"


def receipt_digest(receipt: dict) -> str:
    """SHA-256 of the canonical bytes of a verification receipt minus its ``sig``.

    This is the digest to anchor (e.g. with OpenTimestamps) when a receipt's
    ``verified_at`` needs an externally bounded time — see
    `VERIFICATION_RECEIPTS.md` §Anchoring.
    """
    return sha256_prefixed(canonical_bytes({k: v for k, v in receipt.items() if k != "sig"}))


def issue_verification_receipt(
    bundle,
    result,
    *,
    issuer: str,
    private_key,
    implementation: str = "python-reference",
    version: str | None = None,
    verified_at: str | None = None,
) -> dict:
    """Sign a verification receipt for ``bundle`` (object or JSON bytes).

    ``result`` is the verification result to record: a `VerifyResult` or its
    ``as_dict()`` form. Raises ``ValueError`` for a non-enum verdict, a result
    whose verdict does not match its errors/reasons, malformed error entries,
    or a bundle that is not JSON / not canonically encodable (floats are
    rejected). ``verified_at`` defaults to now; pass it explicitly for
    reproducible receipts (issuing the same statement twice yields the same
    bytes).
    """
    result = _result_dict(result)
    if result["verdict"] not in VERDICTS:
        raise ValueError(f"verdict must be one of {VERDICTS}, got {result['verdict']!r}")
    if not _errors_well_formed(result["errors"]):
        raise ValueError("errors entries must be objects with a string code")
    if not _string_list(result["provisional_reasons"]) or not _string_list(
        result["insufficient_reasons"]
    ):
        raise ValueError("provisional_reasons and insufficient_reasons must be string lists")
    if result["verdict"] != _verdict_class(
        result["errors"], result["provisional_reasons"], result["insufficient_reasons"]
    ):
        raise ValueError("result is inconsistent: verdict does not match its errors/reasons")
    statement = {
        "kind": KIND,
        "version": VERSION,
        "bundle_digest": sha256_prefixed(canonical_bytes(_bundle_object(bundle))),
        "verdict": result["verdict"],
        "error_codes": [entry["code"] for entry in result["errors"]],
        "errors": result["errors"],
        "provisional_reasons": result["provisional_reasons"],
        "insufficient_reasons": result["insufficient_reasons"],
        "summary": result["summary"],
        "verified_at": verified_at or records.utc_now_rfc3339(),
        "verifier": {"implementation": implementation, "version": version or __version__},
        "issuer": issuer,
    }
    statement["sig"] = {
        "alg": "ed25519",
        "key": issuer,
        "value": keys.sign(private_key, canonical_bytes(statement)),
    }
    return statement


def verify_verification_receipt(
    receipt,
    bundle=None,
    revocations: list | None = None,
) -> VerificationReceiptResult:
    """Verify a verification receipt's shape, consistency, and signature.

    ``bundle`` (object or JSON bytes), when supplied, additionally checks
    ``bundle_digest`` against the bundle's canonical bytes and reports
    ``digest_match``. ``revocations`` (statements in the 0.2 §7.5 shape), when
    supplied, checks whether the issuer key was revoked at or before
    ``verified_at`` (``key_revoked``) — without revocation input the check is
    simply not performed.
    """
    if not isinstance(receipt, dict):
        return VerificationReceiptResult(valid=False, errors=["not_an_object"])
    errors: list[str] = []
    if receipt.get("kind") != KIND:
        errors.append("bad_kind")
    if receipt.get("version") != VERSION:
        errors.append("bad_version")
    verdict = receipt.get("verdict")
    if verdict not in VERDICTS:
        errors.append("bad_verdict")
    verified_at = receipt.get("verified_at")
    if not records.validate_timestamp(verified_at):
        errors.append("bad_verified_at")
    if not isinstance(receipt.get("bundle_digest"), str) or not DIGEST_RE.fullmatch(
        receipt["bundle_digest"]
    ):
        errors.append("bad_bundle_digest")

    result_errors = receipt.get("errors")
    errors_ok = _errors_well_formed(result_errors)
    if not errors_ok:
        errors.append("bad_errors")
    provisional = receipt.get("provisional_reasons")
    if not _string_list(provisional):
        errors.append("bad_provisional_reasons")
    insufficient = receipt.get("insufficient_reasons")
    if not _string_list(insufficient):
        errors.append("bad_insufficient_reasons")
    if not isinstance(receipt.get("summary"), dict):
        errors.append("bad_summary")

    error_codes = receipt.get("error_codes")
    if not _string_list(error_codes):
        errors.append("bad_error_codes")
    elif errors_ok and error_codes != [entry["code"] for entry in result_errors]:
        errors.append("error_codes_mismatch")
    if (
        verdict in VERDICTS
        and errors_ok
        and _string_list(provisional)
        and _string_list(insufficient)
        and verdict != _verdict_class(result_errors, provisional, insufficient)
    ):
        errors.append("verdict_mismatch")

    issuer = receipt.get("issuer")
    sig = receipt.get("sig")
    sig_shape_ok = (
        isinstance(sig, dict)
        and sig.get("alg") == "ed25519"
        and isinstance(sig.get("key"), str)
        and isinstance(sig.get("value"), str)
        and bool(sig.get("value"))
    )
    if not sig_shape_ok:
        errors.append("bad_signature_shape")
    elif not (isinstance(issuer, str) and issuer and sig["key"] == issuer):
        errors.append("bad_signature")
    else:
        try:
            message = canonical_bytes({k: v for k, v in receipt.items() if k != "sig"})
        except (TypeError, ValueError):
            errors.append("bad_signature")
        else:
            if not keys.verify(issuer, message, sig["value"]):
                errors.append("bad_signature")

    digest_match = None
    if bundle is not None:
        try:
            expected = sha256_prefixed(canonical_bytes(_bundle_object(bundle)))
            digest_match = receipt.get("bundle_digest") == expected
        except (TypeError, ValueError):
            digest_match = False
        if not digest_match:
            errors.append("bundle_digest_mismatch")

    if revocations:
        revoked, statement_errors = revocations_mod.verify_statements(revocations)
        errors.extend(code for code, _ in statement_errors)
        if records.validate_timestamp(verified_at) and isinstance(issuer, str) and issuer:
            at = records.parse_timestamp(verified_at)
            for key_id, revoked_at in revoked:
                if key_id == issuer and at >= revoked_at:
                    errors.append("key_revoked")

    return VerificationReceiptResult(
        valid=not errors,
        errors=errors,
        issuer=issuer,
        verdict=verdict,
        verified_at=verified_at,
        bundle_digest=receipt.get("bundle_digest"),
        digest_match=digest_match,
    )


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="continuity-receipt-verify-receipt")
    parser.add_argument("receipt", help="path to a verification receipt JSON file")
    parser.add_argument(
        "--bundle",
        metavar="PATH",
        help="bundle JSON file to check bundle_digest against",
    )
    parser.add_argument(
        "--revocations",
        action="append",
        default=None,
        metavar="PATH|URL",
        help="revocation list (repeatable; REVOCATION_DISTRIBUTION.md)",
    )
    parser.add_argument(
        "--digest",
        action="store_true",
        help="print the receipt digest (for anchoring) instead of verifying",
    )
    parser.add_argument(
        "--canonical",
        metavar="PATH",
        help="write the canonical view (object minus sig) to PATH and print the digest",
    )
    args = parser.parse_args(argv)

    try:
        with open(args.receipt, "r", encoding="utf-8") as handle:
            receipt = strict_json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"error: receipt is not valid JSON: {exc}", file=sys.stderr)
        return 2

    if args.canonical:
        canonical = canonical_bytes({k: v for k, v in receipt.items() if k != "sig"})
        with open(args.canonical, "wb") as handle:
            handle.write(canonical)
        print(receipt_digest(receipt))
        return 0

    if args.digest:
        print(receipt_digest(receipt))
        return 0

    revocations = None
    if args.revocations:
        try:
            revocations = revocations_mod.merge_statements(
                *[revocations_mod.load_statements(source) for source in args.revocations]
            )
        except revocations_mod.RevocationError as exc:
            print(json.dumps({"valid": False, "errors": [exc.code]}, indent=2))
            return 1

    bundle = None
    if args.bundle:
        with open(args.bundle, "rb") as handle:
            bundle = handle.read()
        try:
            strict_json.loads(bundle)
        except ValueError as exc:
            print(f"error: --bundle is not valid JSON: {exc}", file=sys.stderr)
            return 2
    result = verify_verification_receipt(receipt, bundle, revocations)
    print(json.dumps(result.as_dict(), indent=2))
    return 0 if result.valid else 1


if __name__ == "__main__":
    sys.exit(main())
