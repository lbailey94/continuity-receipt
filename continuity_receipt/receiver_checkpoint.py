"""Experimental, out-of-band receiver gate for CPR 0.5 bundles.

This module is a bounded prototype. The accepted checkpoint digest and public
key are supplied independently by the receiver; neither is discovered from
the imported bundle/checkpoint.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import strict_json
from .canon import canonical_bytes, sha256_prefixed
from .keys import b64u, b64u_decode
from .verify import MAX_BUNDLE_BYTES, VerifyResult, verify_bundle

CHECKPOINT_KIND = "cpr-experimental-receiver-checkpoint"
CHECKPOINT_VERSION = 1
MAX_CHECKPOINT_BYTES = 16 * 1024
_TIME_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")


@dataclass
class Assessment:
    outcome: str
    reason_codes: list[str]
    core: dict
    bundle_digest: str | None
    checkpoint_digest: str | None

    def as_dict(self) -> dict:
        return {"kind": "cpr-experimental-receiver-assessment", "version": 1,
                "outcome": self.outcome, "reason_codes": self.reason_codes,
                "bundle_digest": self.bundle_digest, "checkpoint_digest": self.checkpoint_digest,
                "core": self.core}


def _time(value: str) -> datetime:
    if not isinstance(value, str) or not _TIME_RE.fullmatch(value):
        raise ValueError("timestamp_invalid")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError("timestamp_invalid") from exc


def issue_checkpoint(bundle_bytes: bytes, *, context: str, issued_at: str,
                     max_age_seconds: int, private_key: Ed25519PrivateKey) -> dict:
    """Create deterministic signed test/checkpoint data from exact bundle bytes."""
    if isinstance(bundle_bytes, bytes):
        bundle_bytes = memoryview(bundle_bytes).tobytes()
    if not isinstance(bundle_bytes, bytes) or len(bundle_bytes) > MAX_BUNDLE_BYTES:
        raise ValueError("bundle_size_invalid")
    if not isinstance(context, str) or not context or len(context) > 512:
        raise ValueError("context_invalid")
    if not isinstance(max_age_seconds, int) or isinstance(max_age_seconds, bool) or not 1 <= max_age_seconds <= 31_536_000:
        raise ValueError("freshness_invalid")
    issued = _time(issued_at)
    statement = {"kind": CHECKPOINT_KIND, "version": CHECKPOINT_VERSION,
                 "bundle_digest": sha256_prefixed(bundle_bytes), "context": context,
                 "issued_at": issued_at, "max_age_seconds": max_age_seconds,
                 "expires_at": (issued + timedelta(seconds=max_age_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    statement["sig"] = {"alg": "Ed25519", "value": b64u(private_key.sign(canonical_bytes(statement)))}
    return statement


def checkpoint_digest(checkpoint: dict) -> str:
    return sha256_prefixed(canonical_bytes(checkpoint))


def _reject(reason: str, core: VerifyResult, bundle_digest: str | None = None,
            checkpoint_hash: str | None = None) -> Assessment:
    return Assessment("REJECT", [reason], core.as_dict(), bundle_digest, checkpoint_hash)


def assess_import(bundle_bytes: bytes, checkpoint_bytes: bytes | None, *,
                  trusted_public_key: Ed25519PublicKey, expected_context: str,
                  accepted_checkpoint_digest: str | None, now: str,
                  max_age_seconds: int) -> Assessment:
    """Assess imported bytes; missing trusted evidence stays NEEDS_EVIDENCE.

    `accepted_checkpoint_digest` is caller-retained state and must be advanced
    only by an explicit trusted refresh operation.
    """
    if isinstance(bundle_bytes, bytes):
        bundle_bytes = memoryview(bundle_bytes).tobytes()
    if not isinstance(bundle_bytes, bytes) or len(bundle_bytes) > MAX_BUNDLE_BYTES:
        core = VerifyResult(verdict="UNTRUSTED", errors=[{"code": "bundle_size_invalid", "detail": "bundle bytes out of bounds", "receipt_id": None}])
        return _reject("bundle_size_invalid", core)
    digest = sha256_prefixed(bundle_bytes)
    try:
        text = bundle_bytes.decode("utf-8")
        if text.startswith("\ufeff"):
            raise ValueError
        bundle = strict_json.loads(text)
        if not isinstance(bundle, dict):
            raise ValueError
        # Reject non-finite numbers, floats and invalid Unicode before invoking
        # the core verifier, including in otherwise ignored extension members.
        canonical_bytes(bundle)
    except (UnicodeDecodeError, ValueError, RecursionError):
        core = VerifyResult(verdict="UNTRUSTED", errors=[{"code": "bundle_invalid_json", "detail": "strict JSON object required", "receipt_id": None}])
        return _reject("bundle_invalid_json", core, digest)
    try:
        core = verify_bundle(bundle)
    except (ValueError, TypeError, OverflowError, RecursionError):
        # The core library can reject invalid calendar dates by raising rather
        # than returning a result. Keep malformed imports off the release path.
        core = VerifyResult(verdict="UNTRUSTED", errors=[{
            "code": "core_invalid_input", "detail": "core verifier could not assess imported fields",
            "receipt_id": None,
        }])
        return _reject("core_invalid_input", core, digest)
    if core.verdict != "TRUSTED":
        return _reject("core_not_trusted", core, digest)
    if bundle.get("spec") != "continuity-receipt/0.5":
        return _reject("receiver_version_unsupported", core, digest)
    if checkpoint_bytes is None:
        return Assessment("NEEDS_EVIDENCE", ["checkpoint_missing"], core.as_dict(), digest, None)
    if isinstance(checkpoint_bytes, bytes):
        checkpoint_bytes = memoryview(checkpoint_bytes).tobytes()
    if not isinstance(checkpoint_bytes, bytes) or len(checkpoint_bytes) > MAX_CHECKPOINT_BYTES:
        return _reject("checkpoint_size_invalid", core, digest)
    if accepted_checkpoint_digest is None:
        return Assessment("NEEDS_EVIDENCE", ["accepted_reference_missing"], core.as_dict(), digest, None)
    if not isinstance(trusted_public_key, Ed25519PublicKey):
        return _reject("checkpoint_trust_key_invalid", core, digest)
    if not isinstance(accepted_checkpoint_digest, str) or not _DIGEST_RE.fullmatch(accepted_checkpoint_digest):
        return _reject("accepted_reference_invalid", core, digest)
    try:
        if not isinstance(expected_context, str) or not expected_context or len(expected_context) > 512:
            raise ValueError("context_invalid")
        if not isinstance(max_age_seconds, int) or isinstance(max_age_seconds, bool) or not 1 <= max_age_seconds <= 31_536_000:
            raise ValueError("freshness_invalid")
        now_dt = _time(now)
        checkpoint = strict_json.loads(checkpoint_bytes.decode("utf-8"))
        if not isinstance(checkpoint, dict) or set(checkpoint) != {"kind", "version", "bundle_digest", "context", "issued_at", "max_age_seconds", "expires_at", "sig"}:
            raise ValueError("checkpoint_shape_invalid")
        if type(checkpoint.get("version")) is not int or type(checkpoint.get("max_age_seconds")) is not int:
            raise ValueError("checkpoint_shape_invalid")
        sig_obj = checkpoint["sig"]
        if not isinstance(sig_obj, dict) or set(sig_obj) != {"alg", "value"} or sig_obj.get("alg") != "Ed25519" or not isinstance(sig_obj.get("value"), str):
            raise ValueError("checkpoint_signature_invalid")
        if not _SIGNATURE_RE.fullmatch(sig_obj["value"]):
            raise ValueError("checkpoint_signature_invalid")
        signature = b64u_decode(sig_obj["value"])
        if len(signature) != 64 or b64u(signature) != sig_obj["value"]:
            raise ValueError("checkpoint_signature_invalid")
        statement = {k: v for k, v in checkpoint.items() if k != "sig"}
        trusted_public_key.verify(signature, canonical_bytes(statement))
        chash = checkpoint_digest(checkpoint)
        if chash != accepted_checkpoint_digest:
            return _reject("checkpoint_reference_mismatch", core, digest, chash)
        if checkpoint.get("kind") != CHECKPOINT_KIND or checkpoint.get("version") != CHECKPOINT_VERSION:
            raise ValueError("checkpoint_version_invalid")
        if checkpoint.get("context") != expected_context:
            raise ValueError("checkpoint_context_mismatch")
        if checkpoint.get("bundle_digest") != digest:
            raise ValueError("checkpoint_bundle_mismatch")
        if checkpoint.get("max_age_seconds") != max_age_seconds:
            raise ValueError("freshness_policy_mismatch")
        issued = _time(checkpoint.get("issued_at"))
        expires = _time(checkpoint.get("expires_at"))
        if expires - issued != timedelta(seconds=max_age_seconds):
            raise ValueError("freshness_policy_mismatch")
        if issued > now_dt or now_dt > expires:
            raise ValueError("checkpoint_not_current")
        return Assessment("ACCEPT", ["checkpoint_current"], core.as_dict(), digest, chash)
    except InvalidSignature:
        return _reject("checkpoint_bad_signature", core, digest)
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError, OverflowError) as exc:
        reason = str(exc) if str(exc) in {"timestamp_invalid", "context_invalid", "freshness_invalid", "checkpoint_shape_invalid", "checkpoint_signature_invalid", "checkpoint_version_invalid", "checkpoint_context_mismatch", "checkpoint_bundle_mismatch", "freshness_policy_mismatch", "checkpoint_not_current"} else "checkpoint_invalid"
        return _reject(reason, core, digest)


def receive_bundle(bundle_bytes: bytes, checkpoint_bytes: bytes | None, *, sink,
                   trusted_public_key: Ed25519PublicKey, expected_context: str,
                   accepted_checkpoint_digest: str | None, now: str,
                   max_age_seconds: int) -> Assessment:
    """Release the exact assessed bundle to a receiving sink on acceptance.

    The caller cannot substitute unrelated context or a fabricated Assessment.
    Immutable input bytes are assessed and parsed without reopening an input
    file. The sink is trusted application code; this prototype does not govern
    what that application subsequently does with the signed receipt claims.
    """
    # Capture the actual immutable buffer once. A bytes subclass can override
    # decode() or __bytes__(); neither may change the object released to a sink.
    if isinstance(bundle_bytes, bytes):
        bundle_bytes = memoryview(bundle_bytes).tobytes()
    result = assess_import(
        bundle_bytes, checkpoint_bytes, trusted_public_key=trusted_public_key,
        expected_context=expected_context,
        accepted_checkpoint_digest=accepted_checkpoint_digest,
        now=now, max_age_seconds=max_age_seconds,
    )
    if result.outcome == "ACCEPT":
        sink(strict_json.loads(bundle_bytes.decode("utf-8")))
    return result
