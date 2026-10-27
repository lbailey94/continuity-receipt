"""Bounded, experimental signed snapshots for local memory handoff.

This layer binds exact file bytes to one CPR 0.5 state commitment and then
requires the existing out-of-band receiver checkpoint before releasing them.
"""
from __future__ import annotations

import hashlib
import unicodedata
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import strict_json
from .bundle import TaskChain
from .canon import canonical_bytes, sha256_prefixed
from .keys import pubkey_to_did_key
from .receiver_checkpoint import Assessment, assess_import

MAX_FILES = 64
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_DIRECTORY_DEPTH = 32
MAX_TREE_ENTRIES = 4096
STATE_KIND = "file-snapshot-v1"


def _path(value: object) -> str:
    if type(value) is not str:
        raise ValueError("snapshot_path_invalid")
    if not value or "\x00" in value or "\\" in value or value.startswith("/"):
        raise ValueError("snapshot_path_invalid")
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        raise ValueError("snapshot_path_invalid_unicode")
    normalized = unicodedata.normalize("NFC", value)
    parts = normalized.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("snapshot_path_invalid")
    if len(parts) - 1 > MAX_DIRECTORY_DEPTH or any(len(part.encode("utf-8")) > 255 for part in parts):
        raise ValueError("snapshot_path_limit_invalid")
    return normalized


def _capture_files(files: dict[str, bytes]) -> dict[str, bytes]:
    if type(files) is not dict or len(files) > MAX_FILES:
        raise ValueError("snapshot_file_count_invalid")
    captured: dict[str, bytes] = {}
    total = 0
    for path, value in files.items():
        normalized = _path(path)
        if normalized in captured:
            raise ValueError("snapshot_duplicate_path")
        if type(value) is not bytes:
            raise ValueError("snapshot_file_bytes_required")
        data = memoryview(value).tobytes()
        if len(data) > MAX_FILE_BYTES:
            raise ValueError("snapshot_file_too_large")
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ValueError("snapshot_total_too_large")
        captured[normalized] = data
    return captured


def build_manifest(files: dict[str, bytes]) -> bytes:
    """Return the canonical file-snapshot-v1 manifest for exact bytes."""
    captured = _capture_files(files)
    manifest = {
        "files": [
            {"path": path, "size": len(captured[path]), "sha256": "sha256:" + hashlib.sha256(captured[path]).hexdigest()}
            for path in sorted(captured)
        ]
    }
    return canonical_bytes(manifest)


def build_bundle(manifest_bytes: bytes, *, scope: str,
                 private_key: Ed25519PrivateKey, issued_at: str) -> bytes:
    """Sign one file-snapshot commitment; no execution records are fabricated."""
    if type(manifest_bytes) is not bytes or len(manifest_bytes) > MAX_TOTAL_BYTES:
        raise ValueError("manifest_bytes_invalid")
    manifest = _parse_manifest(manifest_bytes)
    if type(scope) is not str or not scope or len(scope) > 512 or "\x00" in scope:
        raise ValueError("snapshot_scope_invalid")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("snapshot_signing_key_invalid")
    chain = TaskChain(spec="continuity-receipt/0.5")
    did = pubkey_to_did_key(private_key.public_key())
    try:
        issued = datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise ValueError("snapshot_timestamp_invalid") from exc
    expires_at = (issued + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    chain.add(
        "session.pass.created", "agent", did, private_key,
        {"gate_id": "local:" + scope, "mandala_class": "local", "quotas": {},
         "expires_at": expires_at, "policy_version": "experimental-file-snapshot-v1",
         "mandate_ref": sha256_prefixed(canonical_bytes({"scope": scope, "state_kind": STATE_KIND})),
         "agent_id": did},
        issued_at=issued_at,
    )
    chain.add(
        "state.commitment", "agent", did, private_key,
        {"state_kind": STATE_KIND, "scope": scope, "count": len(manifest["files"]),
         "head_digest": sha256_prefixed(manifest_bytes)},
        issued_at=issued_at,
    )
    chain.add("task.termination", "agent", did, private_key,
              {"reason": "completed", "limits_at_stop": {}, "remaining": {}},
              issued_at=issued_at)
    return canonical_bytes(chain.bundle())


def _parse_manifest(manifest_bytes: bytes) -> dict:
    if type(manifest_bytes) is not bytes or len(manifest_bytes) > MAX_TOTAL_BYTES:
        raise ValueError("snapshot_manifest_invalid")
    try:
        value = strict_json.loads(manifest_bytes.decode("utf-8"))
        canonical_bytes(value)
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError, OverflowError) as exc:
        raise ValueError("snapshot_manifest_invalid") from exc
    if type(value) is not dict or set(value) != {"files"} or type(value["files"]) is not list or len(value["files"]) > MAX_FILES:
        raise ValueError("snapshot_manifest_shape_invalid")
    if canonical_bytes(value) != manifest_bytes:
        raise ValueError("snapshot_manifest_not_canonical")
    seen: set[str] = set()
    total = 0
    for item in value["files"]:
        if type(item) is not dict or set(item) != {"path", "size", "sha256"}:
            raise ValueError("snapshot_manifest_shape_invalid")
        path = _path(item["path"])
        if path != item["path"] or path in seen:
            raise ValueError("snapshot_manifest_path_invalid")
        seen.add(path)
        if type(item["size"]) is not int or not 0 <= item["size"] <= MAX_FILE_BYTES:
            raise ValueError("snapshot_manifest_size_invalid")
        total += item["size"]
        if total > MAX_TOTAL_BYTES:
            raise ValueError("snapshot_total_too_large")
        digest = item["sha256"]
        if type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:") or any(c not in "0123456789abcdef" for c in digest[7:]):
            raise ValueError("snapshot_manifest_digest_invalid")
    if [item["path"] for item in value["files"]] != sorted(seen):
        raise ValueError("snapshot_manifest_order_invalid")
    return value


def _reject_snapshot(assessment: Assessment, reason: str) -> Assessment:
    return Assessment("REJECT", [reason], assessment.core, assessment.bundle_digest, assessment.checkpoint_digest)


def assess_snapshot(bundle_bytes: bytes, checkpoint_bytes: bytes | None, manifest_bytes: bytes,
                    files: dict[str, bytes], *, expected_scope: str,
                    trusted_public_key: Ed25519PublicKey, expected_context: str,
                    accepted_checkpoint_digest: str | None, now: str,
                    max_age_seconds: int) -> Assessment:
    """Verify receiver checkpoint, signed commitment, manifest and actual bytes."""
    # Freeze subclass buffers before either the checkpoint layer or this layer
    # parses them. In particular, never call an overridable bytes.decode().
    if isinstance(bundle_bytes, bytes):
        bundle_bytes = memoryview(bundle_bytes).tobytes()
    if isinstance(checkpoint_bytes, bytes):
        checkpoint_bytes = memoryview(checkpoint_bytes).tobytes()
    if isinstance(manifest_bytes, bytes):
        manifest_bytes = memoryview(manifest_bytes).tobytes()
    result = assess_import(
        bundle_bytes, checkpoint_bytes, trusted_public_key=trusted_public_key,
        expected_context=expected_context,
        accepted_checkpoint_digest=accepted_checkpoint_digest, now=now,
        max_age_seconds=max_age_seconds,
    )
    if result.outcome != "ACCEPT":
        return result
    try:
        captured = _capture_files(files)
        manifest = _parse_manifest(manifest_bytes)
        expected_manifest = build_manifest(captured)
        if expected_manifest != manifest_bytes:
            return _reject_snapshot(result, "snapshot_bytes_mismatch")
        listed_paths = [entry["path"] for entry in manifest["files"]]
        if set(listed_paths) != set(captured) or len(listed_paths) != len(captured):
            return _reject_snapshot(result, "snapshot_fileset_mismatch")
        bundle = strict_json.loads(bundle_bytes.decode("utf-8"))
        receipts = bundle.get("receipts") if type(bundle) is dict else None
        commitments = [r for r in receipts if type(r) is dict and r.get("type") == "state.commitment"] if type(receipts) is list else []
        if len(commitments) != 1:
            return _reject_snapshot(result, "snapshot_commitment_count_invalid")
        receipt = commitments[0]
        body = receipt.get("body")
        key_did = pubkey_to_did_key(trusted_public_key) if isinstance(trusted_public_key, Ed25519PublicKey) else None
        if (type(body) is not dict or body.get("state_kind") != STATE_KIND
                or body.get("scope") != expected_scope
                or type(body.get("count")) is not int or body.get("count") != len(manifest["files"])
                or body.get("head_digest") != sha256_prefixed(manifest_bytes)):
            return _reject_snapshot(result, "snapshot_commitment_mismatch")
        issuer = receipt.get("issuer")
        signature = receipt.get("sig")
        if (key_did is None or type(issuer) is not dict or issuer.get("id") != key_did
                or type(signature) is not dict or signature.get("key") != key_did):
            return _reject_snapshot(result, "snapshot_signer_mismatch")
    except (ValueError, TypeError, UnicodeDecodeError, RecursionError, OverflowError):
        return _reject_snapshot(result, "snapshot_invalid")
    return result
