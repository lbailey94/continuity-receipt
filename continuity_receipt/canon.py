"""JCS-subset canonicalization for Continuity Receipts (v0)."""
import hashlib
import json
import sys

_CANON_ENCODE = json.JSONEncoder(
    separators=(",", ":"), ensure_ascii=False, sort_keys=True
).encode


def canonical_bytes(obj) -> bytes:
    """Deterministic bytes for signing and hashing.

    v0 subset: sorted keys, no whitespace, UTF-8, integers/strings/bools/null
    only; floats are rejected. Key sort is by Unicode code point (Python) vs
    UTF-16 code units (JCS) — identical for ASCII keys, which the schema
    requires. Full RFC 8785 edge cases tracked as spec §11 open item 1.
    """
    _reject_floats(obj)
    return _CANON_ENCODE(obj).encode("utf-8")


def _reject_floats(obj) -> None:
    depth_limit = sys.getrecursionlimit()
    stack = [(obj, 1)]
    while stack:
        cur, depth = stack.pop()
        if depth >= depth_limit:
            raise RecursionError("maximum canonicalization recursion depth exceeded")
        ct = type(cur)
        if ct is dict:
            nxt = depth + 1
            for key, value in cur.items():
                if type(key) is not str and not isinstance(key, str):
                    raise ValueError("object keys must be strings")
                vt = type(value)
                if vt is str or vt is int or vt is bool or value is None:
                    continue
                if vt is float or isinstance(value, float):
                    raise ValueError("floats are not allowed in continuity receipts (v0)")
                if vt is dict or vt is list or vt is tuple or isinstance(value, (dict, list, tuple)):
                    stack.append((value, nxt))
        elif ct is list or ct is tuple:
            nxt = depth + 1
            for value in cur:
                vt = type(value)
                if vt is str or vt is int or vt is bool or value is None:
                    continue
                if vt is float or isinstance(value, float):
                    raise ValueError("floats are not allowed in continuity receipts (v0)")
                if vt is dict or vt is list or vt is tuple or isinstance(value, (dict, list, tuple)):
                    stack.append((value, nxt))
        elif ct is float or isinstance(cur, float):
            raise ValueError("floats are not allowed in continuity receipts (v0)")
        elif isinstance(cur, dict):
            nxt = depth + 1
            for key, value in cur.items():
                if not isinstance(key, str):
                    raise ValueError("object keys must be strings")
                stack.append((value, nxt))
        elif isinstance(cur, (list, tuple)):
            nxt = depth + 1
            for value in cur:
                stack.append((value, nxt))


def sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def commit_field(salt_hex: str, value) -> str:
    """v0 reference commitment: sha256(salt || '|' || JCS(value)).

    Freezes spec §11 open item 2 for the v0 reference implementation.
    """
    return sha256_prefixed(bytes.fromhex(salt_hex) + b"|" + canonical_bytes(value))
