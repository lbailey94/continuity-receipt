"""Verification receipts — signed statements that a verification ran.

Companion to the core spec; wire format and semantics: `VERIFICATION_RECEIPTS.md`.
A verification receipt is issued by a verifier after running the bundle
verification algorithm over a bundle; it binds the bundle digest to the
verdict, the verifier implementation, and the time of the run. It is a
standalone document — never part of a bundle chain.

Wire format (``kind`` ``continuity-receipt-verification``, version 1)::

    {
      "kind": "continuity-receipt-verification",
      "version": 1,
      "bundle_digest": "sha256:<64 hex>",
      "verdict": "TRUSTED",
      "error_codes": [],
      "verified_at": "2026-09-23T21:00:00Z",
      "verifier": {"implementation": "python-reference", "version": "0.3.2"},
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

Error codes (``verify_verification_receipt``): ``not_an_object``, ``bad_kind``,
``bad_version``, ``bad_verdict``, ``bad_verified_at``, ``bad_bundle_digest``,
``bad_error_codes``, ``bad_signature_shape``, ``bad_signature``,
``bundle_digest_mismatch``, ``key_revoked``.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field as dc_field

from . import keys, records
from . import revocations as revocations_mod
from ._version import __version__
from .canon import canonical_bytes, sha256_prefixed

KIND = "continuity-receipt-verification"
VERSION = 1
VERDICTS = ("TRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE", "UNTRUSTED")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


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
        return json.loads(bundle)
    raise ValueError("bundle must be an object or JSON bytes")


def issue_verification_receipt(
    bundle,
    verdict: str,
    error_codes: list | None = None,
    *,
    issuer: str,
    private_key,
    implementation: str = "python-reference",
    version: str | None = None,
    verified_at: str | None = None,
) -> dict:
    """Sign a verification receipt for ``bundle`` (object or JSON bytes).

    ``verified_at`` defaults to now; pass it explicitly for reproducible
    receipts (issuing the same statement twice yields the same bytes). Raises
    ``ValueError`` for a non-enum verdict, malformed error codes, or a bundle
    that is not JSON / not canonically encodable (floats are rejected).
    """
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {VERDICTS}, got {verdict!r}")
    codes = list(error_codes or [])
    if not all(isinstance(code, str) for code in codes):
        raise ValueError("error_codes must be a list of strings")
    statement = {
        "kind": KIND,
        "version": VERSION,
        "bundle_digest": sha256_prefixed(canonical_bytes(_bundle_object(bundle))),
        "verdict": verdict,
        "error_codes": codes,
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
    """Verify a verification receipt's shape and signature.

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
    error_codes = receipt.get("error_codes")
    if not isinstance(error_codes, list) or not all(
        isinstance(code, str) for code in error_codes
    ):
        errors.append("bad_error_codes")

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
    args = parser.parse_args(argv)

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
    with open(args.receipt, "r", encoding="utf-8") as handle:
        receipt = json.load(handle)
    result = verify_verification_receipt(receipt, bundle, revocations)
    print(json.dumps(result.as_dict(), indent=2))
    return 0 if result.valid else 1


if __name__ == "__main__":
    sys.exit(main())
