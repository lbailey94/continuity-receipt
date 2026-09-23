"""Continuity Receipt reference implementation.

Spec: SPEC.md (continuity-receipt/0.3; 0.1 and 0.2 remain supported)
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

SPEC_ID = "continuity-receipt/0.3"

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
