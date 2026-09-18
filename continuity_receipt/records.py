"""Receipt envelopes and body validation (v0)."""
import os
import time
import uuid
from datetime import datetime, timezone

from . import keys

SPEC_ID = "continuity-receipt/0.1"

RECORD_TYPES = (
    "session.pass.created",
    "task.decision",
    "task.execution",
    "delivery.attestation",
    "task.termination",
    "settlement",
)

REQUIRED_FIELDS = {
    "session.pass.created": (
        "gate_id",
        "mandala_class",
        "quotas",
        "expires_at",
        "policy_version",
        "mandate_ref",
        "agent_id",
    ),
    "task.decision": (
        "action",
        "action_args_hash",
        "model",
        "input_provenance",
        "decision",
        "policy_version",
    ),
    "task.execution": ("tool_calls", "egress", "resources", "sandbox_class"),
    "delivery.attestation": ("request_hash", "response_hash", "counterparty"),
    "task.termination": ("reason", "limits_at_stop", "remaining"),
    "settlement": ("rail", "rail_ref", "amount", "gated_on_delivery", "settled_at"),
}


def uuid7() -> uuid.UUID:
    """Time-ordered UUIDv7 (48-bit ms + random), stdlib-only."""
    ms = int(time.time() * 1000)
    rand = os.urandom(10)
    raw = bytearray(16)
    raw[0:6] = ms.to_bytes(6, "big")
    raw[6] = 0x70 | (rand[0] & 0x0F)
    raw[7] = rand[1]
    raw[8] = 0x80 | (rand[2] & 0x3F)
    raw[9:16] = rand[3:10]
    return uuid.UUID(bytes=bytes(raw))


def utc_now_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_body(record_type: str, body: dict) -> None:
    if record_type not in REQUIRED_FIELDS:
        raise ValueError(f"unknown_type: {record_type}")
    if not isinstance(body, dict):
        raise ValueError(f"malformed body for {record_type}: not an object")
    missing = [name for name in REQUIRED_FIELDS[record_type] if name not in body]
    if missing:
        raise ValueError(f"malformed body for {record_type}: missing {missing}")


def new_envelope(
    task_id: str,
    issuer_kind: str,
    issuer_did: str,
    record_type: str,
    seq: int,
    prev: str | None,
    body: dict,
) -> dict:
    validate_body(record_type, body)
    return {
        "spec": SPEC_ID,
        "receipt_id": "urn:uuid:" + str(uuid7()),
        "task_id": task_id,
        "issued_at": utc_now_rfc3339(),
        "issuer": {"kind": issuer_kind, "id": issuer_did},
        "type": record_type,
        "seq": seq,
        "prev": prev,
        "body": body,
    }


def unsigned_view(receipt: dict) -> dict:
    return {key: value for key, value in receipt.items() if key != "sig"}


def sign_receipt(receipt: dict, private_key, key_did: str) -> dict:
    from .canon import canonical_bytes

    signed = dict(receipt)
    signed["sig"] = {
        "alg": "ed25519",
        "key": key_did,
        "value": keys.sign(private_key, canonical_bytes(unsigned_view(receipt))),
    }
    return signed
