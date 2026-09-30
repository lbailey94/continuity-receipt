"""Continuity Receipt reference implementation.

Published spec: SPEC.md (continuity-receipt/0.4).
Checkout candidate: SPEC_0.5_DRAFT.md (0.1-0.5 supported here).
Verification receipts (companion): VERIFICATION_RECEIPTS.md
"""

from ._version import __version__
from .canon import canonical_bytes, commit_field, sha256_prefixed
from .records import (
    RECORD_TYPES,
    REQUIRED_FIELDS,
    new_envelope,
    required_fields,
    sign_receipt,
    validate_body,
)
from .verification import (
    VerificationReceiptResult,
    issue_verification_receipt,
    verify_verification_receipt,
)
from .verify import VerifyResult, verify_bundle

SPEC_ID = "continuity-receipt/0.5"

__all__ = [
    "SPEC_ID",
    "__version__",
    "RECORD_TYPES",
    "REQUIRED_FIELDS",
    "VerificationReceiptResult",
    "VerifyResult",
    "canonical_bytes",
    "commit_field",
    "issue_verification_receipt",
    "new_envelope",
    "required_fields",
    "sha256_prefixed",
    "sign_receipt",
    "validate_body",
    "verify_bundle",
    "verify_verification_receipt",
]
