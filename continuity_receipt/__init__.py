"""Continuity Receipt v0 — reference implementation.

Spec: WHITEMAGIC/planning/specs/CONTINUITY_RECEIPT_v0_SPEC.md
Envelope spec id: continuity-receipt/0.1
"""

from .canon import canonical_bytes, commit_field, sha256_prefixed
from .records import (
    RECORD_TYPES,
    REQUIRED_FIELDS,
    new_envelope,
    sign_receipt,
    validate_body,
)
from .verify import VerifyResult, verify_bundle

SPEC_ID = "continuity-receipt/0.1"

__all__ = [
    "SPEC_ID",
    "RECORD_TYPES",
    "REQUIRED_FIELDS",
    "VerifyResult",
    "canonical_bytes",
    "commit_field",
    "new_envelope",
    "sha256_prefixed",
    "sign_receipt",
    "validate_body",
    "verify_bundle",
]
