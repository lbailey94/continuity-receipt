"""JCS-subset canonicalization for Continuity Receipts (v0)."""
import hashlib
import json


def canonical_bytes(obj) -> bytes:
    """Deterministic bytes for signing and hashing.

    v0 subset: sorted keys, no whitespace, UTF-8, integers/strings/bools/null
    only; floats are rejected. Key sort is by Unicode code point (Python) vs
    UTF-16 code units (JCS) — identical for ASCII keys, which the schema
    requires. Full RFC 8785 edge cases tracked as spec §11 open item 1.
    """
    _reject_floats(obj)
    return json.dumps(
        obj, separators=(",", ":"), ensure_ascii=False, sort_keys=True
    ).encode("utf-8")


def _reject_floats(obj) -> None:
    if isinstance(obj, float):
        raise ValueError("floats are not allowed in continuity receipts (v0)")
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                raise ValueError("object keys must be strings")
            _reject_floats(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            _reject_floats(value)


def sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def commit_field(salt_hex: str, value) -> str:
    """v0 reference commitment: sha256(salt || '|' || JCS(value)).

    Freezes spec §11 open item 2 for the v0 reference implementation.
    """
    return sha256_prefixed(bytes.fromhex(salt_hex) + b"|" + canonical_bytes(value))
