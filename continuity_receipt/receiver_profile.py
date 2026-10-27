"""Versioned operator contract for the experimental local memory receiver."""
from __future__ import annotations

from .canon import canonical_bytes, sha256_prefixed


def validate_profile(profile, *, context: str, scope: str, public_key_bytes: bytes) -> dict:
    """Validate the receiver's explicit, pinned input and custody policy."""
    required = {"kind", "version", "id", "export", "trust", "authority", "consent", "retention", "refusal"}
    if type(profile) is not dict or set(profile) != required:
        raise ValueError("receiver_profile_shape_invalid")
    if profile["kind"] != "cpr-experimental-local-receiver-profile" or type(profile["version"]) is not int or profile["version"] != 1:
        raise ValueError("receiver_profile_version_invalid")
    if not isinstance(profile["id"], str) or not profile["id"].strip():
        raise ValueError("receiver_profile_id_invalid")
    export = profile["export"]
    if type(export) is not dict or set(export) != {"scope", "inventory", "optional", "memory_paths"} or export["scope"] != scope:
        raise ValueError("receiver_profile_export_invalid")
    inventory = export["inventory"]
    optional = export["optional"]
    memory_paths = export["memory_paths"]
    if (not isinstance(inventory, list) or not inventory or
            any(not isinstance(p, str) or not p or p.startswith("/") or any(x in ("", ".", "..") for x in p.split("/")) for p in inventory) or
            any(not isinstance(p, str) for p in inventory) or len(set(inventory)) != len(inventory) or
            not isinstance(optional, list) or any(not isinstance(p, str) for p in optional) or
            any(p not in inventory for p in optional) or len(set(optional)) != len(optional) or
            not isinstance(memory_paths, list) or not memory_paths or
            any(not isinstance(p, str) for p in memory_paths) or
            any(p not in inventory for p in memory_paths) or len(set(memory_paths)) != len(memory_paths)):
        raise ValueError("receiver_profile_inventory_invalid")
    trust = profile["trust"]
    if (type(trust) is not dict or set(trust) != {"context", "key_sha256", "reference", "clock"} or
            trust["context"] != context or trust["key_sha256"] != sha256_prefixed(public_key_bytes) or
            trust["reference"] != "receiver-trust-db/current_reference; advanced only by explicit local publish" or
            trust["clock"] != "system-utc"):
        raise ValueError("receiver_profile_trust_invalid")
    if profile["authority"] != {"status": "operator-asserted", "basis": "outside this verifier"}:
        raise ValueError("receiver_profile_authority_invalid")
    if (profile["consent"] != {"status": "operator-asserted", "subject_consent_verified": False} or
            profile["consent"].get("subject_consent_verified") is not False):
        raise ValueError("receiver_profile_consent_invalid")
    if profile["retention"] != {"mode": "retain current generation until explicit replacement; prior generations may remain on disk", "deletion": "operator-managed"}:
        raise ValueError("receiver_profile_retention_invalid")
    if profile["refusal"] != ["missing policy or reference", "untrusted or stale evidence", "inventory mismatch", "selected memory file missing or invalid UTF-8"]:
        raise ValueError("receiver_profile_refusal_invalid")
    canonical_bytes(profile)
    return {"id": profile["id"], "digest": sha256_prefixed(canonical_bytes(profile)),
            "inventory": tuple(sorted(inventory)), "optional": tuple(sorted(optional)),
            "memory_paths": tuple(memory_paths)}
