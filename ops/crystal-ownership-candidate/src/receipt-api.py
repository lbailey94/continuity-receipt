#!/usr/bin/env python3
"""receipt-api — continuity-receipt verification services over HTTP.

Endpoints (all loopback; the gateway in front does auth, caps, and audit):

- `POST /verify` — a receipt bundle (or {"bundle": {...}}, or
  {"bundles": [...]} for a batch) -> the reference verifier's result.
  `?require_anchor=1` requires anchors; `?receipt=1` additionally returns a
  signed verification receipt (a statement the caller can verify offline).
- `POST /verify-receipt` — verify a verification receipt (signature + shape);
  optionally check its `bundle_digest` against supplied bytes.
- `POST /verify-anchor` — an OpenTimestamps detached proof + digest + optional
  block header(s) -> proof status.
- `POST /anchors` (keyed) — store an OpenTimestamps proof for a digest.
- `GET /anchors/<digest>` (keyless) — fetch a stored anchor proof (ETag-aware).
- `GET /revocations/<issuer>` (keyless) — a stored revocation document
  (distribution as a service).
- `POST /mcp` — a minimal MCP surface (JSON-RPC: initialize, tools/list,
  tools/call) exposing verify_bundle / verify_anchor / get_revocations.
- `GET /health`, `GET /info` — keyless.

Properties:
- Verification is stateless (bundles are verified in memory and dropped).
  Storage exists only for the two opt-in distribution services (revocation
  documents, hosted anchor proofs, and sealed crystals), service signing key,
  plus the internal-assertion replay ledger.
- Content-free logging: only method/path/status/bytes (the gateway audits).
- Fail closed: oversized bodies 413, invalid JSON 400, verifier errors are
  returned as structured verdicts, never stack traces.

Auth, metering, and caps are the gateway's job (authd in front). Bind loopback.
"""
import argparse
import base64
import contextlib
import hashlib
import hmac
import json
import os
import pathlib
import re
import sqlite3
import stat
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from continuity_receipt import __version__ as verifier_version, keys, records
from continuity_receipt.anchor import verify_proof
from continuity_receipt.canon import canonical_bytes, sha256_prefixed
from continuity_receipt.revocations import DOCUMENT_KIND, DOCUMENT_VERSION
from continuity_receipt.verification import (
    KIND as RECEIPT_KIND,
    VERSION as RECEIPT_VERSION,
    issue_verification_receipt,
    verify_verification_receipt,
)
from continuity_receipt.verify import verify_bundle
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

MAX_BODY = 1_048_576  # 1 MiB
MAX_CRYSTAL_SIZE_BYTES = 2 * 1024 * 1024  # 2 MiB
MAX_CRYSTAL_BODY = 4 * 1024 * 1024  # 4 MiB (base64 JSON overhead)
MAX_BATCH = 50
SERVICE = "continuity-receipt-verify"
VERDICTS = ["TRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE", "UNTRUSTED"]
MCP_PROTOCOL_DEFAULT = "2025-06-18"
DIGEST_RE = re.compile(r"^(sha256:)?[0-9a-f]{64}$")
STATE_DIR = pathlib.Path(os.environ.get("WM_RECEIPT_API_STATE", "/var/lib/whitemagic-hosted-api"))
SIGNING_KEY_PATH = STATE_DIR / "verify_signing.key"
REVOCATIONS_DIR = STATE_DIR / "revocations"
ANCHORS_DIR = STATE_DIR / "anchors"
RECEIPTS_DIR = STATE_DIR / "receipts"
CRYSTALS_DIR = STATE_DIR / "tenant-crystals"
CRYSTAL_QUARANTINE_DIR = STATE_DIR / "tenant-crystals-quarantine"
NOTARIZE_DIR = STATE_DIR / "notarizations"
INTERNAL_TOKEN_PATH = STATE_DIR / "payment_internal.token"

# Phase 4C candidate (local, not deployed): owner-bound crystal access. authd
# signs a short-lived assertion for an authenticated owner; the API fails
# closed without it and never treats caller-supplied tenant selectors as
# identity. Owner locator = sha256:<owner_id>; the owner id is assigned by the
# gateway's authenticated registry (keys.json entries may carry "owner_id").
CRYSTAL_ASSERTION_HEADER = "X-WM-Crystal-Assertion"
CRYSTAL_ASSERTION_SECRET_PATH = STATE_DIR / "crystal_assertion.secret"
CRYSTAL_ASSERTION_KEYS_PATH = STATE_DIR / "crystal_assertion.keys.json"
CRYSTAL_ASSERTION_REPLAY_PATH = STATE_DIR / "crystal_assertion_replay.sqlite3"
CRYSTAL_ASSERTION_MAX_TTL_S = 120
CRYSTAL_ASSERTION_SKEW_S = 5

SUPPORTED_CIPHERS = {
    "chacha20-poly1305": ChaCha20Poly1305,
    "aes-256-gcm": AESGCM,
}
DEFAULT_CIPHER = "chacha20-poly1305"

ERC8004_SPEC = "erc8004-validation/1.0"
DEFAULT_CHAIN_ID = 8453
DEFAULT_REGISTRY_ADDRESS = "0x8004A15217B1B1E19d7b43851b9eEbFA40306E78"

# Opt-in digest cache (?cache=1 on POST /verify, single-bundle requests only):
# digest + verdict payload in memory, never on disk. Without ?cache=1 nothing
# is retained. TTL and entry cap are policy, not protocol.
CACHE_TTL_S = 900
CACHE_MAX_ENTRIES = 256
CACHE_LOCK = threading.Lock()
VERDICT_CACHE: dict[str, dict] = {}

# Conformance referee: the service grades a verifier's submitted outputs over
# the pinned corpus and signs a report (kind continuity-receipt-conformance).
# The corpus manifests are deployed next to the service; the report binds the
# submission and each corpus section by digest.
CONFORMANCE_KIND = "continuity-receipt-conformance"
CONFORMANCE_VERSION = 1
CONFORMANCE_VERDICTS = ["CONFORMANT", "PARTIAL", "NONCONFORMANT"]
CORPUS: dict | None = None


def _unique_json_members(pairs):
    """Reject ambiguous object members before converting request JSON to dicts."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object member: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value):
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _request_json(raw: bytes):
    """Accept UTF-8 JSON only, including at nested bundle input boundaries."""
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_unique_json_members,
        parse_constant=_reject_json_constant,
    )


# ── memory crystals & erc-8004 primitives ────────────────────────────
class CrystalError(Exception):
    """Base exception for Memory Crystal errors."""


class CrystalSizeExceededError(CrystalError):
    """Raised when a crystal exceeds the 2 MiB hard limit."""


class CrystalIntegrityError(CrystalError):
    """Raised when crystal integrity or content-addressing fails."""


def compute_tenant_hash(tenant_id: str, salt: str = "whitemagic-crystal-salt-v1") -> str:
    digest = hashlib.sha256(f"{salt}:{tenant_id}".encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def build_aad(cipher: str, tenant_hash: str, parent_crystal_id: str | None, created_at: str) -> bytes:
    parent_str = parent_crystal_id if parent_crystal_id is not None else "genesis"
    return f"{cipher}|{tenant_hash}|{parent_str}|{created_at}".encode("utf-8")


class MemoryCrystal:
    """Zero-Knowledge sealed memory unit envelope."""

    def __init__(
        self,
        crystal_id: str,
        parent_crystal_id: str | None,
        tenant_hash: str,
        cipher: str,
        nonce: bytes,
        ciphertext: bytes,
        size_bytes: int,
        created_at: str,
        metadata_public: dict | None = None,
        spec: str = "wm-crystal/1.0",
    ):
        self.crystal_id = crystal_id
        self.parent_crystal_id = parent_crystal_id
        self.tenant_hash = tenant_hash
        self.cipher = cipher
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.size_bytes = size_bytes
        self.created_at = created_at
        self.metadata_public = metadata_public or {}
        self.spec = spec

    def verify_content_address(self) -> bool:
        expected = "sha256:" + hashlib.sha256(self.ciphertext).hexdigest()
        return self.crystal_id.lower() == expected.lower()

    def to_dict(self) -> dict:
        return {
            "spec": self.spec,
            "crystal_id": self.crystal_id,
            "parent_crystal_id": self.parent_crystal_id,
            "tenant_hash": self.tenant_hash,
            "cipher": self.cipher,
            "nonce": base64.urlsafe_b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.urlsafe_b64encode(self.ciphertext).decode("ascii"),
            "size_bytes": self.size_bytes,
            "created_at": self.created_at,
            "metadata_public": self.metadata_public,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MemoryCrystal":
        if not isinstance(data, dict):
            raise CrystalIntegrityError("crystal envelope must be a JSON object")
        for req in ("crystal_id", "tenant_hash", "cipher", "nonce", "ciphertext", "created_at"):
            if req not in data:
                raise CrystalIntegrityError(f"missing required crystal field: {req}")
        try:
            nonce = base64.urlsafe_b64decode(data["nonce"])
            ciphertext = base64.urlsafe_b64decode(data["ciphertext"])
        except Exception as e:
            raise CrystalIntegrityError(f"base64url decoding failed: {e}") from e
        return cls(
            crystal_id=str(data["crystal_id"]),
            parent_crystal_id=str(data["parent_crystal_id"]) if data.get("parent_crystal_id") else None,
            tenant_hash=str(data["tenant_hash"]),
            cipher=str(data["cipher"]),
            nonce=nonce,
            ciphertext=ciphertext,
            size_bytes=int(data.get("size_bytes", len(ciphertext))),
            created_at=str(data["created_at"]),
            metadata_public=data.get("metadata_public") if isinstance(data.get("metadata_public"), dict) else {},
            spec=str(data.get("spec", "wm-crystal/1.0")),
        )

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


def verify_crystal_integrity(crystal: MemoryCrystal) -> tuple[bool, str]:
    if not crystal.crystal_id.lower().startswith("sha256:") or len(crystal.crystal_id) != 71:
        return False, "crystal_id must be sha256:<64 hex>"
    actual_hash = hashlib.sha256(crystal.ciphertext).hexdigest()
    if f"sha256:{actual_hash}" != crystal.crystal_id.lower():
        return False, "content-address mismatch: sha256(ciphertext) != crystal_id"
    if crystal.size_bytes != len(crystal.ciphertext):
        return False, f"declared size_bytes ({crystal.size_bytes}) != len(ciphertext) ({len(crystal.ciphertext)})"
    if crystal.size_bytes > MAX_CRYSTAL_SIZE_BYTES:
        return False, f"size {crystal.size_bytes} exceeds hard ceiling of {MAX_CRYSTAL_SIZE_BYTES} bytes"
    if crystal.cipher.lower() not in SUPPORTED_CIPHERS and crystal.cipher not in SUPPORTED_CIPHERS:
        return False, f"unsupported cipher: {crystal.cipher}"
    if len(crystal.nonce) != 12:
        return False, f"invalid nonce length: {len(crystal.nonce)} bytes (must be 12)"
    return True, "OK"


class TenantCrystalStore:
    def __init__(self, storage_root: pathlib.Path):
        self.root_path = storage_root.resolve()

    def _get_tenant_dir(self, tenant_hash: str) -> pathlib.Path:
        clean = tenant_hash.lower().replace("sha256:", "").strip()
        if not re.fullmatch(r"[0-9a-f]{64}", clean):
            raise ValueError(f"invalid tenant_hash: {tenant_hash}")
        tenant_dir = (self.root_path / clean).resolve()
        if not str(tenant_dir).startswith(str(self.root_path)):
            raise ValueError("directory traversal detected")
        return tenant_dir

    def store_crystal(self, crystal: MemoryCrystal) -> pathlib.Path:
        is_valid, msg = verify_crystal_integrity(crystal)
        if not is_valid:
            raise CrystalIntegrityError(f"corrupt crystal: {msg}")
        tenant_dir = self._get_tenant_dir(crystal.tenant_hash)
        clean_id = crystal.crystal_id.lower().replace("sha256:", "")
        prefix = clean_id[:2]
        crystal_dir = tenant_dir / "crystals" / prefix
        crystal_dir.mkdir(parents=True, exist_ok=True)
        target = crystal_dir / f"{clean_id}.crystal"
        temp = crystal_dir / f".tmp_{clean_id}_{os.getpid()}"
        temp.write_text(crystal.to_json(indent=2) + "\n", encoding="utf-8")
        temp.replace(target)
        return target

    def get_crystal(self, tenant_hash: str, crystal_id: str) -> MemoryCrystal:
        tenant_dir = self._get_tenant_dir(tenant_hash)
        clean_id = crystal_id.lower().replace("sha256:", "").strip()
        if not re.fullmatch(r"[0-9a-f]{64}", clean_id):
            raise ValueError(f"invalid crystal_id: {crystal_id}")
        prefix = clean_id[:2]
        target = tenant_dir / "crystals" / prefix / f"{clean_id}.crystal"
        if not target.is_file():
            raise FileNotFoundError(f"crystal {crystal_id} not found for tenant")
        data = json.loads(target.read_text(encoding="utf-8"))
        crystal = MemoryCrystal.from_dict(data)
        is_valid, msg = verify_crystal_integrity(crystal)
        if not is_valid:
            raise CrystalIntegrityError(f"stored crystal corrupted on disk: {msg}")
        return crystal

    def get_lineage(self, tenant_hash: str) -> list[dict]:
        tenant_dir = self._get_tenant_dir(tenant_hash)
        crystals_dir = tenant_dir / "crystals"
        if not crystals_dir.is_dir():
            return []
        items = []
        for p in sorted(crystals_dir.glob("*/*.crystal")):
            try:
                doc = json.loads(p.read_text(encoding="utf-8"))
                items.append({
                    "crystal_id": doc.get("crystal_id"),
                    "parent_crystal_id": doc.get("parent_crystal_id"),
                    "size_bytes": doc.get("size_bytes"),
                    "created_at": doc.get("created_at"),
                    "metadata_public": doc.get("metadata_public", {}),
                })
            except Exception:
                continue
        return items


def plan_legacy_crystal_quarantine(storage_root: pathlib.Path,
                                   quarantine_root: pathlib.Path,
                                   registered_owner_ids=()) -> dict:
    """Create a hash-bearing dry-run plan for all legacy crystal files.

    No owner is inferred from the locator, crystal ID, ciphertext, or first
    reader. Applying the returned plan is a separate explicit operation.
    """
    source_root = storage_root.resolve()
    target_root = quarantine_root.resolve()
    if source_root == target_root or source_root.is_relative_to(target_root) or target_root.is_relative_to(source_root):
        raise ValueError("source and quarantine roots must be separate and non-overlapping")
    if storage_root.is_symlink() or quarantine_root.is_symlink():
        raise ValueError("source and quarantine roots must not be symlinks")
    if any(not isinstance(owner_id, str) or not re.fullmatch(r"[0-9a-f]{64}", owner_id)
           for owner_id in registered_owner_ids):
        raise ValueError("registered owner IDs must be 64 lowercase hex characters")
    registered_locators = {f"sha256:{owner_id}" for owner_id in registered_owner_ids}
    entries = []
    for directory, dirnames, filenames in os.walk(source_root, followlinks=False):
        directory_path = pathlib.Path(directory)
        for name in list(dirnames):
            child = directory_path / name
            if child.is_symlink() or not child.is_dir():
                raise ValueError(f"non-directory or symlink in legacy source tree: {child.relative_to(source_root)}")
        for name in filenames:
            source = directory_path / name
            info = source.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError(f"non-regular entry in legacy source tree: {source.relative_to(source_root)}")
            if not name.endswith(".crystal"):
                continue
            relative = source.relative_to(source_root)
            raw = source.read_bytes()
            try:
                envelope = _request_json(raw)
                locator = envelope.get("tenant_hash") if isinstance(envelope, dict) else None
            except (ValueError, RecursionError):
                locator = None
            # A current, explicitly registered owner locator is outside this
            # legacy quarantine plan. No locator is ever used to create a map.
            if locator in registered_locators:
                continue
            entries.append({
                "source": relative.as_posix(),
                "destination": relative.as_posix(),
                "source_sha256": hashlib.sha256(raw).hexdigest(),
                "tenant_locator": locator if isinstance(locator, str) else None,
                "disposition": "quarantine_unmapped_legacy_owner",
            })
    return {
        "kind": "wm-crystal-legacy-quarantine-plan",
        "version": 1,
        "mode": "dry-run",
        "source_root": str(source_root),
        "quarantine_root": str(target_root),
        "registered_owner_locators": sorted(registered_locators),
        "entries": entries,
    }


def apply_legacy_crystal_quarantine_plan(plan: dict) -> dict:
    """Apply a dry-run quarantine plan after rechecking every source hash."""
    if not isinstance(plan, dict) or plan.get("kind") != "wm-crystal-legacy-quarantine-plan" or plan.get("version") != 1:
        raise ValueError("unsupported legacy quarantine plan")
    source_root = pathlib.Path(plan["source_root"]).resolve()
    target_root = pathlib.Path(plan["quarantine_root"]).resolve()
    if source_root == target_root or source_root.is_relative_to(target_root) or target_root.is_relative_to(source_root):
        raise ValueError("source and quarantine roots must be separate and non-overlapping")
    if pathlib.Path(plan["source_root"]).is_symlink() or pathlib.Path(plan["quarantine_root"]).is_symlink():
        raise ValueError("source and quarantine roots must not be symlinks")
    prepared = []
    seen_sources = set()
    seen_targets = set()
    for entry in plan.get("entries", []):
        if not isinstance(entry, dict):
            raise ValueError("invalid quarantine plan entry")
        relative = pathlib.PurePosixPath(entry["source"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("unsafe quarantine plan path")
        source_candidate = source_root / pathlib.Path(*relative.parts)
        target_candidate = target_root / pathlib.Path(*relative.parts)
        for root, candidate in ((source_root, source_candidate), (target_root, target_candidate)):
            cursor = root
            for part in relative.parts[:-1]:
                cursor = cursor / part
                if cursor.is_symlink():
                    raise ValueError("symlink in quarantine plan path")
        if source_candidate.is_symlink() or target_candidate.is_symlink():
            raise ValueError("symlink in quarantine plan path")
        source = source_candidate.resolve()
        target = target_candidate.resolve()
        if not source.is_relative_to(source_root) or not target.is_relative_to(target_root):
            raise ValueError("quarantine path escapes configured root")
        if source in seen_sources or target in seen_targets:
            raise ValueError("duplicate source or destination in quarantine plan")
        seen_sources.add(source)
        seen_targets.add(target)
        if source.is_symlink() or not source.is_file() or not stat.S_ISREG(source.lstat().st_mode):
            raise ValueError("legacy source is not a regular file")
        if target.exists() or target.is_symlink():
            raise FileExistsError("quarantine destination already exists")
        raw = source.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if not hmac.compare_digest(digest, entry.get("source_sha256", "")):
            raise ValueError("legacy crystal changed since quarantine plan")
        prepared.append((source, target, raw, digest, entry))

    # No file moves until all paths, types, destination collisions, and source
    # hashes in the complete manifest have passed preflight.
    applied = []
    # Validate every existing destination directory before creating any of
    # them. This keeps a late permissive directory from leaving even an
    # unnecessary partial directory tree behind.
    if target_root.exists():
        if target_root.is_symlink() or not target_root.is_dir():
            raise ValueError("quarantine root must be a real directory")
        if stat.S_IMODE(target_root.stat().st_mode) & 0o077:
            raise PermissionError("quarantine root must be private (mode 0700 or stricter)")
    for _, target, _, _, _ in prepared:
        relative_parent = target.parent.relative_to(target_root)
        parent = target_root
        for component in relative_parent.parts:
            parent = parent / component
            if not parent.exists() and not parent.is_symlink():
                continue
            if parent.is_symlink() or not parent.is_dir():
                raise ValueError("non-directory or symlink in quarantine destination")
            if stat.S_IMODE(parent.stat().st_mode) & 0o077:
                raise PermissionError("quarantine directories must be private (mode 0700 or stricter)")

    target_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if stat.S_IMODE(target_root.stat().st_mode) & 0o077:
        raise PermissionError("quarantine root must be private (mode 0700 or stricter)")
    # Prepare and validate every destination directory before the first link
    # or source unlink.
    for source, target, raw, digest, entry in prepared:
        relative_parent = target.parent.relative_to(target_root)
        parent = target_root
        for component in relative_parent.parts:
            parent = parent / component
            try:
                parent.mkdir(mode=0o700)
            except FileExistsError:
                if parent.is_symlink() or not parent.is_dir():
                    raise ValueError("non-directory or symlink in quarantine destination")
            if stat.S_IMODE(parent.stat().st_mode) & 0o077:
                raise PermissionError("quarantine directories must be private (mode 0700 or stricter)")
    for source, target, raw, digest, entry in prepared:
        os.link(source, target, follow_symlinks=False)  # atomic no-overwrite create
        with target.open("rb") as quarantined:
            if not hmac.compare_digest(hashlib.sha256(quarantined.read()).hexdigest(), digest):
                target.unlink()
                raise OSError("quarantine source changed after preflight")
        _fsync_directory(target.parent)
        source.unlink()
        _fsync_directory(source.parent)
        applied.append({**entry, "status": "quarantined"})
    return {**plan, "mode": "applied", "entries": applied}


def _fsync_directory(path: pathlib.Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _clean_hex64(value):
    if not isinstance(value, str):
        return None
    clean = value.replace("sha256:", "").strip().lower()
    return clean if re.fullmatch(r"[0-9a-f]{64}", clean) else None


class CrystalAssertionError(CrystalError):
    """Raised when the gateway-to-API crystal assertion is missing or invalid."""


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _crystal_assertion_keys() -> dict[str, bytes]:
    """Load a bounded-overlap keyring; retain legacy single-secret compatibility."""
    try:
        document = _request_json(CRYSTAL_ASSERTION_KEYS_PATH.read_bytes())
    except FileNotFoundError:
        try:
            secret = CRYSTAL_ASSERTION_SECRET_PATH.read_bytes()
        except OSError as error:
            raise CrystalAssertionError("assertion secret unavailable") from error
        if len(secret) < 32:
            raise CrystalAssertionError("assertion secret too short")
        return {"legacy": secret}
    except (OSError, ValueError, RecursionError) as error:
        raise CrystalAssertionError("assertion keyring unavailable or malformed") from error
    if not isinstance(document, dict) or not isinstance(document.get("keys"), dict):
        raise CrystalAssertionError("assertion keyring malformed")
    keys = {}
    for kid, encoded in document["keys"].items():
        if not isinstance(kid, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", kid) or not isinstance(encoded, str):
            raise CrystalAssertionError("assertion keyring malformed")
        try:
            key = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        except (ValueError, TypeError):
            raise CrystalAssertionError("assertion keyring malformed") from None
        if len(key) < 32:
            raise CrystalAssertionError("assertion keyring contains a short key")
        keys[kid] = key
    if not keys:
        raise CrystalAssertionError("assertion keyring has no keys")
    return keys


def _reserve_crystal_nonce(nonce: str, expires_at: int, now: int) -> None:
    """Atomically reserve a nonce across threads, processes, and API restarts."""
    CRYSTAL_ASSERTION_REPLAY_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        with contextlib.closing(sqlite3.connect(
                CRYSTAL_ASSERTION_REPLAY_PATH, timeout=10, isolation_level=None)) as db:
            db.execute("PRAGMA busy_timeout=10000")
            db.execute("CREATE TABLE IF NOT EXISTS assertion_nonces (nonce TEXT PRIMARY KEY, retain_until INTEGER NOT NULL)")
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM assertion_nonces WHERE retain_until < ?", (now,))
            db.execute("INSERT INTO assertion_nonces(nonce, retain_until) VALUES (?, ?)", (nonce, expires_at + CRYSTAL_ASSERTION_SKEW_S))
            db.execute("COMMIT")
    except sqlite3.IntegrityError:
        try:
            db.execute("ROLLBACK")
        except (UnboundLocalError, sqlite3.Error):
            pass
        raise CrystalAssertionError("assertion replay") from None
    except sqlite3.Error as error:
        try:
            db.execute("ROLLBACK")
        except (UnboundLocalError, sqlite3.Error):
            pass
        raise CrystalAssertionError("assertion replay store unavailable") from error


def verify_crystal_assertion(header_value, method: str, target: str,
                             body: bytes, now: int | None = None) -> str:
    """Verify the authd-issued crystal assertion; return owner_id or raise.

    Fails closed on a missing keyring, malformed or tampered assertion, method/
    target/body mismatch, expired or over-long lifetime, future issue time, and
    replayed nonce. The keyring is read per request. Rotate by adding a new
    key as active while retaining the old key for at least the max assertion
    lifetime plus skew, then remove the old key. There is no keyless fallback.
    """
    now = int(time.time()) if now is None else now
    if not isinstance(header_value, str) or "." not in header_value:
        raise CrystalAssertionError("missing or malformed assertion")
    payload_b64, signature_b64 = header_value.split(".", 1)
    try:
        keys = _crystal_assertion_keys()
    except CrystalAssertionError:
        raise
    try:
        claims = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        kid = claims.get("kid", "legacy") if isinstance(claims, dict) else None
        secret = keys.get(kid)
        if secret is None:
            raise CrystalAssertionError("unknown assertion key id")
        expected = hmac.new(secret, b"wm-crystal-assertion-v1." + payload_b64.encode("ascii"),
                            hashlib.sha256).digest()
        provided = _b64url_decode(signature_b64)
    except (ValueError, TypeError):
        raise CrystalAssertionError("malformed assertion encoding") from None
    if not hmac.compare_digest(expected, provided):
        raise CrystalAssertionError("assertion signature mismatch")
    try:
        if not isinstance(claims, dict):
            raise ValueError("claims must be object")
    except (ValueError, TypeError, RecursionError):
        raise CrystalAssertionError("malformed assertion payload") from None
    if not isinstance(claims, dict) or claims.get("v") != 1:
        raise CrystalAssertionError("unsupported assertion version")
    owner_id = claims.get("owner_id")
    if not isinstance(owner_id, str) or not re.fullmatch(r"[0-9a-f]{64}", owner_id):
        raise CrystalAssertionError("invalid owner id")
    if str(claims.get("method", "")).upper() != method.upper():
        raise CrystalAssertionError("assertion method mismatch")
    if claims.get("target") != target:
        raise CrystalAssertionError("assertion target mismatch")
    presented_digest = claims.get("body_sha256")
    if not isinstance(presented_digest, str) or \
            not hmac.compare_digest(presented_digest, hashlib.sha256(body).hexdigest()):
        raise CrystalAssertionError("assertion body mismatch")
    iat = claims.get("iat")
    exp = claims.get("exp")
    if type(iat) is not int or type(exp) is not int or iat >= exp:
        raise CrystalAssertionError("invalid assertion lifetime")
    if exp < now - CRYSTAL_ASSERTION_SKEW_S:
        raise CrystalAssertionError("assertion expired")
    if iat > now + CRYSTAL_ASSERTION_SKEW_S:
        raise CrystalAssertionError("assertion issued in the future")
    if exp - iat > CRYSTAL_ASSERTION_MAX_TTL_S:
        raise CrystalAssertionError("assertion lifetime too long")
    nonce = claims.get("nonce")
    if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise CrystalAssertionError("invalid assertion nonce")
    _reserve_crystal_nonce(nonce, exp, now)
    return owner_id


def _check_task_binding(task_hash: str, bundle: dict) -> bool:
    if not isinstance(bundle, dict):
        return False
    clean_expected = task_hash.lower().replace("0x", "").replace("sha256:", "").strip()
    if not clean_expected:
        return False
    candidates = set()
    if "bundle_id" in bundle and bundle["bundle_id"]:
        candidates.add(str(bundle["bundle_id"]))
    if "task_id" in bundle and bundle["task_id"]:
        candidates.add(str(bundle["task_id"]))
    receipts = bundle.get("receipts") or []
    if isinstance(receipts, list):
        for r in receipts:
            if not isinstance(r, dict):
                continue
            if r.get("task_id"):
                candidates.add(str(r["task_id"]))
            body = r.get("body")
            if isinstance(body, dict):
                for key in ("response_hash", "result_hash", "task_id", "task_hash", "output_hash"):
                    val = body.get(key)
                    if val:
                        candidates.add(str(val))
            try:
                candidates.add(sha256_prefixed(canonical_bytes(r)))
            except Exception:
                pass
    for c in candidates:
        if c == task_hash:
            return True
        clean_c = c.lower().replace("0x", "").replace("sha256:", "").strip()
        if clean_c and clean_c == clean_expected:
            return True
    return False


def signing_identity():
    """Load (or lazily create) the service signing key; returns (did, private)."""
    if SIGNING_KEY_PATH.exists():
        raw = bytes.fromhex(SIGNING_KEY_PATH.read_text().strip())
    else:
        _, private = keys.generate()
        SIGNING_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        SIGNING_KEY_PATH.write_text(keys.private_raw(private).hex() + "\n")
        SIGNING_KEY_PATH.chmod(0o600)
        raw = keys.private_raw(private)
    private = keys.private_from_raw(raw)
    return keys.pubkey_to_did_key(private.public_key()), private


def verification_receipt(
    bundle: dict,
    payload: dict,
    verified_at: str | None = None,
    version: str | None = None,
) -> dict:
    """Issue a full-result verification receipt for a parsed bundle object."""
    did, private = signing_identity()
    return issue_verification_receipt(
        bundle,
        payload,
        issuer=did,
        private_key=private,
        version=version or verifier_version,
        verified_at=verified_at,
    )


def cache_key(raw: bytes, require_anchor: bool) -> str:
    return hashlib.sha256(raw).hexdigest() + ("|anchor" if require_anchor else "")


def cache_get(key: str) -> dict | None:
    now = time.monotonic()
    with CACHE_LOCK:
        entry = VERDICT_CACHE.get(key)
        if entry is None:
            return None
        if now - entry["stored_monotonic"] > CACHE_TTL_S:
            del VERDICT_CACHE[key]
            return None
        return {
            "payload": json.loads(json.dumps(entry["payload"])),
            "verified_at": entry["verified_at"],
            "verifier_version": entry["verifier_version"],
            "age_s": int(now - entry["stored_monotonic"]),
        }


def cache_put(key: str, payload: dict, verified_at: str) -> None:
    with CACHE_LOCK:
        VERDICT_CACHE[key] = {
            "payload": payload,
            "verified_at": verified_at,
            "verifier_version": verifier_version,
            "stored_monotonic": time.monotonic(),
        }
        while len(VERDICT_CACHE) > CACHE_MAX_ENTRIES:
            VERDICT_CACHE.pop(next(iter(VERDICT_CACHE)))


# ── conformance referee ───────────────────────────────────────────────
def load_corpus(directory: pathlib.Path) -> dict | None:
    """Load the pinned corpus manifests; None when the corpus is not deployed.

    `hostile-manifest.json` is optional: when it is absent the referee grades
    the two verifier-output corpora only (v1 behavior).
    """
    try:
        bundles_raw = (directory / "bundles-manifest.json").read_bytes()
        receipts_raw = (directory / "verification-manifest.json").read_bytes()
    except OSError:
        return None
    corpus = {
        "bundles": {
            "manifest": json.loads(bundles_raw),
            "digest": sha256_prefixed(bundles_raw),
        },
        "verification_receipts": {
            "manifest": json.loads(receipts_raw),
            "digest": sha256_prefixed(receipts_raw),
        },
    }
    try:
        hostile_raw = (directory / "hostile-manifest.json").read_bytes()
    except OSError:
        hostile_raw = None
    if hostile_raw is not None:
        corpus["hostile_inputs"] = {
            "manifest": json.loads(hostile_raw),
            "digest": sha256_prefixed(hostile_raw),
        }
    return corpus


def _implementation(document: dict) -> dict:
    implementation = document.get("implementation")
    if (
        not isinstance(implementation, dict)
        or not isinstance(implementation.get("name"), str)
        or not implementation["name"]
    ):
        raise ValueError("implementation.name must be a non-empty string")
    normalized = {
        "name": implementation["name"],
        "version": (
            implementation["version"]
            if isinstance(implementation.get("version"), str) and implementation["version"]
            else "unknown"
        ),
        "language": (
            implementation["language"]
            if isinstance(implementation.get("language"), str) and implementation["language"]
            else "unknown"
        ),
    }
    if isinstance(implementation.get("url"), str) and implementation["url"]:
        normalized["url"] = implementation["url"]
    return normalized


def _grade_bundles(entries: dict, corpus: dict) -> tuple[dict, int, int]:
    manifest = corpus["bundles"]["manifest"]["vectors"]
    mismatches = []
    for vector in manifest:
        name = vector["file"]
        got = entries.get(name)
        if not isinstance(got, dict):
            mismatches.append({"vector": name, "reason": "missing"})
            continue
        if got.get("verdict") != vector["expected_verdict"]:
            mismatches.append(
                {
                    "vector": name,
                    "reason": "verdict",
                    "expected": vector["expected_verdict"],
                    "got": got.get("verdict"),
                }
            )
            continue
        if vector.get("expected_code"):
            codes = got.get("codes") if isinstance(got.get("codes"), list) else []
            if vector["expected_code"] not in codes:
                mismatches.append(
                    {"vector": name, "reason": "missing_code", "expected": vector["expected_code"]}
                )
    matched = len(manifest) - len(mismatches)
    return (
        {
            "corpus": {
                "bundles": {
                    "vectors": len(manifest),
                    "manifest_digest": corpus["bundles"]["digest"],
                }
            },
            "results": {
                "bundles": {"matched": matched, "total": len(manifest), "mismatches": mismatches}
            },
        },
        matched,
        len(manifest),
    )


def _grade_receipts(entries: dict, corpus: dict) -> tuple[dict, int, int]:
    manifest = corpus["verification_receipts"]["manifest"]["vectors"]
    mismatches = []
    for vector in manifest:
        name = vector["file"]
        got = entries.get(name)
        if not isinstance(got, dict):
            mismatches.append({"vector": name, "reason": "missing"})
            continue
        if got.get("valid") != vector["expected_valid"]:
            mismatches.append(
                {
                    "vector": name,
                    "reason": "valid",
                    "expected": vector["expected_valid"],
                    "got": got.get("valid"),
                }
            )
            continue
        expected_errors = sorted(vector["expected_errors"])
        raw_errors = got.get("errors")
        got_errors = (
            sorted(error for error in raw_errors if isinstance(error, str))
            if isinstance(raw_errors, list)
            else []
        )
        if got_errors != expected_errors:
            mismatches.append(
                {"vector": name, "reason": "errors", "expected": expected_errors, "got": got_errors}
            )
    matched = len(manifest) - len(mismatches)
    return (
        {
            "corpus": {
                "verification_receipts": {
                    "vectors": len(manifest),
                    "manifest_digest": corpus["verification_receipts"]["digest"],
                }
            },
            "results": {
                "verification_receipts": {
                    "matched": matched,
                    "total": len(manifest),
                    "mismatches": mismatches,
                }
            },
        },
        matched,
        len(manifest),
    )


def _grade_hostile(entries: dict, corpus: dict) -> tuple[dict, int, int]:
    manifest = corpus["hostile_inputs"]["manifest"]["vectors"]
    mismatches = []
    for vector in manifest:
        case = vector["case"]
        got = entries.get(case)
        if not isinstance(got, dict):
            mismatches.append({"case": case, "reason": "missing"})
            continue
        if got.get("structured") is not True:
            mismatches.append({"case": case, "reason": "not_structured"})
            continue
        verdict = got.get("verdict")
        if verdict not in VERDICTS:
            mismatches.append({"case": case, "reason": "verdict", "got": verdict})
            continue
        raw_codes = got.get("codes")
        if not isinstance(raw_codes, list) or not all(
            isinstance(code, str) for code in raw_codes
        ):
            mismatches.append({"case": case, "reason": "codes_shape"})
            continue
        codes = sorted(raw_codes)
        if "expected_verdict" in vector and verdict != vector["expected_verdict"]:
            mismatches.append(
                {
                    "case": case,
                    "reason": "verdict",
                    "expected": vector["expected_verdict"],
                    "got": verdict,
                }
            )
            continue
        if vector.get("expected_codes") is not None:
            expected_codes = sorted(vector["expected_codes"])
            if codes != expected_codes:
                mismatches.append(
                    {"case": case, "reason": "codes", "expected": expected_codes, "got": codes}
                )
    matched = len(manifest) - len(mismatches)
    return (
        {
            "corpus": {
                "hostile_inputs": {
                    "vectors": len(manifest),
                    "manifest_digest": corpus["hostile_inputs"]["digest"],
                }
            },
            "results": {
                "hostile_inputs": {"matched": matched, "total": len(manifest), "mismatches": mismatches}
            },
        },
        matched,
        len(manifest),
    )


def grade_submission(document: dict, corpus: dict) -> dict:
    """Grade a submission against the pinned corpus; raises ValueError on shape."""
    if not isinstance(document, dict):
        raise ValueError("submission must be an object")
    implementation = _implementation(document)
    results = document.get("results")
    if not isinstance(results, dict):
        raise ValueError("results must be an object")
    sections = ["bundles", "verification_receipts"]
    if "hostile_inputs" in corpus:
        sections.append("hostile_inputs")
    provided = [name for name in sections if isinstance(results.get(name), dict)]
    if not provided:
        raise ValueError(
            "results must include 'bundles' and/or 'verification_receipts'"
        )
    if "hostile_inputs" in corpus and "hostile_inputs" not in provided:
        raise ValueError("results must include 'hostile_inputs' (the hostile corpus is pinned)")

    graded = {"implementation": implementation, "corpus": {}, "results": {}}
    matched_total = 0
    total = 0
    if "bundles" in provided:
        section, matched, count = _grade_bundles(results["bundles"], corpus)
        graded["corpus"].update(section["corpus"])
        graded["results"].update(section["results"])
        matched_total += matched
        total += count
    if "verification_receipts" in provided:
        section, matched, count = _grade_receipts(results["verification_receipts"], corpus)
        graded["corpus"].update(section["corpus"])
        graded["results"].update(section["results"])
        matched_total += matched
        total += count
    if "hostile_inputs" in provided:
        section, matched, count = _grade_hostile(results["hostile_inputs"], corpus)
        graded["corpus"].update(section["corpus"])
        graded["results"].update(section["results"])
        matched_total += matched
        total += count
    if matched_total == total:
        graded["verdict"] = "CONFORMANT"
    elif matched_total == 0:
        graded["verdict"] = "NONCONFORMANT"
    else:
        graded["verdict"] = "PARTIAL"
    return graded


def conformance_report(document: dict, graded: dict) -> dict:
    """Sign a conformance report for a graded submission."""
    did, private = signing_identity()
    statement = {
        "kind": CONFORMANCE_KIND,
        "version": CONFORMANCE_VERSION,
        "implementation": graded["implementation"],
        "submission_digest": sha256_prefixed(canonical_bytes(document)),
        "corpus": graded["corpus"],
        "results": graded["results"],
        "verdict": graded["verdict"],
        "issued_at": records.utc_now_rfc3339(),
        "issuer": did,
    }
    statement["sig"] = {
        "alg": "ed25519",
        "key": did,
        "value": keys.sign(private, canonical_bytes(statement)),
    }
    return statement


def mcp_tools() -> list:
    return [
        {
            "name": "verify_bundle",
            "description": "Verify a continuity-receipt bundle and return the verdict (TRUSTED | PROVISIONAL | INSUFFICIENT_EVIDENCE | UNTRUSTED). Add receipt=true to also get a signed verification receipt.",
            "inputSchema": {
                "type": "object",
                "required": ["bundle"],
                "properties": {
                    "bundle": {"type": "object", "description": "The receipt bundle object."},
                    "require_anchor": {"type": "boolean", "description": "Require anchors (PROVISIONAL if absent)."},
                    "receipt": {"type": "boolean", "description": "Return a signed verification receipt."},
                },
            },
        },
        {
            "name": "verify_anchor",
            "description": "Verify an OpenTimestamps detached proof against a digest and optional Bitcoin block header(s); checks merkle-root equality (no proof-of-work/chain validation).",
            "inputSchema": {
                "type": "object",
                "required": ["proof", "digest"],
                "properties": {
                    "proof": {"type": "string", "description": "base64 of the detached .ots proof."},
                    "digest": {"type": "string", "description": "sha256:<hex> the proof is expected to cover."},
                    "headers": {"type": "object", "description": "Optional map of block height -> 80-byte header hex."},
                },
            },
        },
        {
            "name": "get_revocations",
            "description": "Fetch the stored revocation document for an issuer (kind/version checked). Returns statements for continuity-receipt verification.",
            "inputSchema": {
                "type": "object",
                "required": ["issuer"],
                "properties": {"issuer": {"type": "string", "description": "Issuer DID or identifier."}},
            },
        },
    ]


def info_payload() -> dict:
    payload = {
        "service": SERVICE,
        "implementation": "python-reference",
        "verifier_version": verifier_version,
        "spec_versions": list(records.SUPPORTED_SPECS),
        "verdicts": VERDICTS,
        "endpoints": {
            "POST /verify": "bundle -> verdict (?require_anchor=1, ?receipt=1, ?cache=1; {\"bundles\": [...]} batch)",
            "POST /verify-receipt": "verification receipt -> validity (+ optional bundle digest check, optional revocations)",
            "POST /verify-anchor": "OpenTimestamps detached proof + digest + header(s) -> proof status",
            "POST /anchors": "store an OTS proof for a digest (keyed)",
            "POST /conformance": "grade a verifier submission over the pinned corpus -> signed conformance report",
            "GET /anchors/<digest>": "fetch a stored anchor proof (keyless)",
            "POST /payment-receipts": "internal: sign + store a content-free settlement receipt (X-Internal-Token)",
            "GET /receipts/<tx>": "fetch a gateway-emitted settlement receipt (keyless)",
            "GET /revocations/<issuer>": "stored revocation document for an issuer (keyless)",
            "POST /mcp": "MCP surface: verify_bundle / verify_anchor / get_revocations",
            "POST /erc8004/validate": "Derive an outcome from the core verifier verdict and task binding; issuer policy is not evaluated and anchors are not required. Returns an Ed25519-signed canonical JSON statement; this service does not relay it onchain.",
            "POST /crystals": "store sealed Memory Crystal ciphertext (2 MiB max; ChaCha20-Poly1305 / AES-256-GCM)",
            "GET /crystals/owner-locator": "authenticated bootstrap; return the owner locator assigned by the gateway registry",
            "GET /crystals/<id>": "fetch a crystal in the authenticated owner's scope",
            "GET /crystals/lineage": "fetch lineage in the authenticated owner's scope",
            "POST /notarize": "sign caller-supplied context/prompt digests and bounded claims; service does not observe the underlying context or execution",
            "GET /notarize/<digest>": "fetch stored caller-claim attestation (keyless)",
            "GET /openapi.json": "OpenAPI 3.1 contract",
            "GET /info": "this document",
            "GET /health": "liveness",
        },
        "verification_receipt": {
            "kind": RECEIPT_KIND,
            "version": RECEIPT_VERSION,
            "requested_with": "?receipt=1 on POST /verify, or receipt: true on MCP verify_bundle",
            "digest_rule": "sha256 of the JCS-canonical bytes of the verified bundle object",
            "records": [
                "verdict",
                "error_codes",
                "errors",
                "provisional_reasons",
                "insufficient_reasons",
                "summary",
            ],
            "consistency": "error_codes equals the codes in errors; verdict equals the class implied by the errors/reasons",
            "verify_offline": "signature over JCS canonical bytes minus sig; use a compatible continuity-receipt implementation and check /info for the running verifier version and supported specs",
            "docs": "https://github.com/lbailey94/continuity-receipt/blob/main/VERIFICATION_RECEIPTS.md",
            "kit": "https://github.com/lbailey94/continuity-receipt/blob/main/VERIFY_IN_5_MIN.md",
        },
        "conformance": {
            "endpoint": "POST /conformance",
            "kind": CONFORMANCE_KIND,
            "version": CONFORMANCE_VERSION,
            "verdicts": CONFORMANCE_VERDICTS,
            "submission": "implementation metadata + verifier outputs over the pinned corpus; build one with tools/conformance_submit.py",
            "corpus": (
                {
                    name: {
                        "vectors": len(section["manifest"]["vectors"]),
                        "manifest_digest": section["digest"],
                    }
                    for name, section in CORPUS.items()
                }
                if CORPUS
                else None
            ),
        },
        "erc8004": {
            "endpoint": "POST /erc8004/validate",
            "specification": "ERC-8004 Validation Registry Adapter",
            "target_rail": "Base Mainnet (eip155:8453)",
            "outcomes": {
                "0": "REJECT",
                "1": "ACCEPT",
                "2": "NEEDS_EVIDENCE",
            },
            "registry_default": DEFAULT_REGISTRY_ADDRESS,
            "chain_id_default": DEFAULT_CHAIN_ID,
            "checks": "The core verdict and task binding drive the outcome. chain_integrity, signatures_valid, resource_caps_respected, issuer policy, and anchor status are not reported as per-check successes by this adapter; their check fields are null. termination_present only checks for a receipts-list item with type exactly task.termination.",
            "issuer_policy": "Not evaluated: no relying-party issuer allowlist or consumer profile is applied.",
            "anchors": "Not required for the adapter outcome; no independent anchor status is reported. The core verifier may inspect supplied anchor evidence.",
            "attestation": "Ed25519 signature over a canonical JSON message; no EVM-compatible signature or onchain relay is performed by this service.",
            "docs": "https://api.whitemagic.dev/docs",
        },
        "crystals": {
            "specification": "wm-crystal/1.0",
            "endpoints": {
                "write": "POST /crystals (or PUT /crystals/<id>)",
                "read": "GET /crystals/<id> (authenticated owner scope)",
                "lineage": "GET /crystals/lineage (authenticated owner scope)",
            },
            "supported_ciphers": list(SUPPORTED_CIPHERS.keys()),
            "max_crystal_size_bytes": MAX_CRYSTAL_SIZE_BYTES,
            "isolation": "candidate routes derive storage scope from an authenticated gateway assertion mapped through the explicit owner registry; legacy ownerless data must be quarantined",
            "access_model": "all crystal reads and writes require an authenticated owner assertion; GET /crystals/owner-locator returns the registry-mapped locator; no first-reader ownership claim",
            "envelope_compatibility": "wm-crystal/1.0 envelope/AAD retained; new clients may bootstrap and use the registry locator; legacy public-salt locators are not automatically migrated",
            "assertion_replay": "SQLite nonce ledger is persistent across API restarts and shared across worker processes; nonce is retained through exp plus clock-skew allowance",
            "assertion_key_rotation": "keyring carries active_kid and keys; issuer uses active_kid, verifier accepts retained overlap keys until removed",
            "content_addressing": "sha256:hex(sha256(ciphertext))",
        },
        "limits": {
            "max_body_bytes": MAX_BODY,
            "max_batch": MAX_BATCH,
            "digest_cache": {
                "opt_in": "?cache=1 (single-bundle requests)",
                "ttl_s": CACHE_TTL_S,
                "max_entries": CACHE_MAX_ENTRIES,
                "stores": "digest + verdict payload in memory only; never on disk",
            },
        },
        "privacy": "POST /verify evaluates bundles in memory and does not store or log them. Persistent data also includes revocation documents, hosted anchors, payment receipts, caller-claim notarizations, sealed crystals, assertion replay nonces, and the service signing key. Crystal routes require an authenticated owner assertion; legacy ownerless crystals remain quarantined until an explicit operator mapping is established. ?cache=1 opts into an in-memory digest->verdict cache.",
    }
    try:
        did = signing_identity()[0]
        payload["verification_receipt"]["issuer"] = did
        payload["erc8004"]["validator_address"] = did
    except OSError:
        payload["verification_receipt"]["issuer"] = None
        payload["erc8004"]["validator_address"] = None
    return payload


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = SERVICE

    def log_message(self, fmt, *args):  # content-free: the gateway audits
        pass

    def end_headers(self):
        self.send_header("Connection", "close")
        super().end_headers()
        self.close_connection = True

    def _send(self, status: int, payload: dict, extra_headers: tuple = ()):
        body = json.dumps(payload, indent=2).encode()
        self.send_response(status)
        for name, value in extra_headers:
            self.send_header(name, value)
        if urllib.parse.urlsplit(self.path).path == "/crystals" or urllib.parse.urlsplit(self.path).path.startswith("/crystals/"):
            self._send_crystal_cache_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, status: int, body: bytes, content_type: str, etag: str | None = None):
        self.send_response(status)
        if etag:
            self.send_header("ETag", etag)
        if urllib.parse.urlsplit(self.path).path == "/crystals" or urllib.parse.urlsplit(self.path).path.startswith("/crystals/"):
            self._send_crystal_cache_headers()
        elif etag:
            self.send_header("Cache-Control", "public, max-age=300")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_crystal_cache_headers(self):
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("Vary", "Authorization, X-Api-Key, X-Session-Pass, X-WM-Crystal-Assertion")

    def _read_body(self, max_limit: int = MAX_BODY) -> bytes | None:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            self._send(400, {"error": "empty body"})
            return None
        if length > max_limit:
            self._send(413, {"error": f"body exceeds {max_limit} bytes"})
            return None
        return self.rfile.read(length)

    def _etag_matches(self, etag: str) -> bool:
        return self.headers.get("If-None-Match") == etag

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self._send(200, {"ok": True})
        elif path == "/info":
            self._send(200, info_payload())
        elif path.startswith("/revocations/"):
            self._serve_document(REVOCATIONS_DIR, path[len("/revocations/"):], revocation=True)
        elif path.startswith("/anchors/"):
            self._serve_anchor(path[len("/anchors/"):])
        elif path.startswith("/receipts/"):
            self._serve_receipt(path[len("/receipts/"):])
        elif path == "/crystals" or path == "/crystals/":
            self._send(200, {
                "service": "memory-crystals",
                "spec": "wm-crystal/1.0",
                "endpoints": {
                    "write": "POST /crystals (or PUT /crystals/<id>)",
                    "bootstrap": "GET /crystals/owner-locator (authenticated; returns explicit registry mapping)",
                    "read": "GET /crystals/<crystal_id> (authenticated owner scope)",
                    "lineage": "GET /crystals/lineage (authenticated owner scope)",
                },
                "pricing": "$0.02 USDC on Base mainnet (x402) for writes; reads require an authenticated mapped owner",
                "access_model": "all crystal reads and writes require an authenticated owner assertion; GET /crystals/owner-locator returns the registry-mapped locator; no first-reader ownership claim",
                "hard_limit": f"{MAX_CRYSTAL_SIZE_BYTES} bytes (2 MiB)",
            })
        elif path.startswith("/crystals/"):
            self._serve_crystal(path[len("/crystals/"):])
        elif path == "/notarize" or path == "/notarize/":
            self._send(200, {
                "service": "wm-context-notarization",
                "spec": "wm.context-notarization/1.0",
                "endpoints": {
                    "notarize": "POST /notarize",
                    "read": "GET /notarize/<digest>",
                },
                "pricing": "Metered via x402 / session pass lease; reads keyless",
                "description": "The service signs caller-supplied context or prompt digests and bounded claims; it does not observe the underlying context or execution. Retrieval is keyless.",
            })
        elif path.startswith("/notarize/"):
            self._serve_notarization(path[len("/notarize/"):])
        else:
            self._send(404, {"error": "not found"})

    @staticmethod
    def _safe_name(segment: str) -> str | None:
        name = urllib.parse.unquote(segment)
        if not name or "/" in name or ".." in name or "\x00" in name:
            return None
        return urllib.parse.quote(name, safe="")

    def _serve_document(self, directory: pathlib.Path, segment: str, revocation: bool):
        name = self._safe_name(segment)
        if name is None:
            self._send(404, {"error": "not found"})
            return
        document_path = directory / (name + ".json")
        if not document_path.is_file():
            self._send(404, {"error": "no document for this issuer"})
            return
        raw = document_path.read_bytes()
        etag = '"' + hashlib.sha256(raw).hexdigest() + '"'
        if self._etag_matches(etag):
            self._send_bytes(304, b"", "application/json", etag)
            return
        try:
            document = json.loads(raw)
        except ValueError:
            self._send(500, {"error": "stored document is not valid JSON"})
            return
        if revocation and (
            document.get("kind") != DOCUMENT_KIND or document.get("version") != DOCUMENT_VERSION
        ):
            self._send(500, {"error": "stored document has the wrong kind or version"})
            return
        self._send_bytes(200, raw, "application/json", etag)

    def _serve_receipt(self, segment: str):
        name = self._safe_name(segment)
        if name is None:
            self._send(404, {"error": "not found"})
            return
        name = name.lower()
        if not re.fullmatch(r"0x[0-9a-f]{64}", name):
            self._send(404, {
                "error": "invalid_transaction_hash",
                "hint": "tx must be a 66-character hex string (0x followed by 64 hex characters)",
                "example": "0x313772727c39c3cc4f36cc92d6a9ab97397afd9999d31dec2350b930267dc559",
                "docs": "https://api.whitemagic.dev/info",
            })
            return
        document_path = RECEIPTS_DIR / (name + ".json")
        if not document_path.is_file():
            self._send(404, {
                "error": "receipt_not_found",
                "hint": "no stored settlement receipt found for this transaction hash; receipts are signed and stored on successful x402 settlement on Base",
                "tx": name,
                "docs": "https://api.whitemagic.dev/info",
            })
            return
        raw = document_path.read_bytes()
        etag = '"' + name + '"'
        if self._etag_matches(etag):
            self._send_bytes(304, b"", "application/json", etag)
            return
        self._send_bytes(200, raw, "application/json", etag)

    def _store_payment_receipt(self):
        raw = self._read_body()
        if raw is None:
            return
        try:
            document = _request_json(raw)
        except (ValueError, RecursionError) as error:
            self._send(400, {"error": f"invalid JSON: {error}"})
            return
        if not isinstance(document, dict):
            self._send(400, {"error": "body must be an object"})
            return
        try:
            expected = INTERNAL_TOKEN_PATH.read_text().strip()
        except OSError:
            expected = ""
        provided = self.headers.get("X-Internal-Token", "")
        if not expected or not hmac.compare_digest(provided, expected):
            self._send(401, {"error": "internal token required"})
            return
        tx = str(document.get("tx") or "")
        if not re.fullmatch(r"0x[0-9a-fA-F]{64}", tx):
            self._send(400, {"error": "tx must be a 32-byte hex hash"})
            return
        tx = tx.lower()
        target = RECEIPTS_DIR / (tx + ".json")
        if target.is_file():
            try:
                existing = json.loads(target.read_text())
                self._send(200, {"stored": True, "tx": tx,
                                 "digest": existing.get("receipt_digest"),
                                 "idempotent": True, "service": SERVICE})
                return
            except ValueError:
                pass
        try:
            did, private = signing_identity()
        except Exception as error:  # noqa: BLE001
            self._send(500, {"error": f"signing key unavailable: {error}"})
            return
        statement = {
            "kind": "wm.payment-receipt",
            "version": 1,
            "issued_at": records.utc_now_rfc3339(),
            "network": str(document.get("network") or "")[:60],
            "asset": str(document.get("asset") or "")[:80],
            "amount": str(document.get("amount") or "")[:40],
            "pay_to": str(document.get("payTo") or "")[:80],
            "tx": tx,
            "path": str(document.get("path") or "")[:120],
            "issuer": did,
        }
        for key, source, limit in (("rpc", "rpc", 40), ("tool", "tool", 60),
                                   ("ua_family", "ua", 40), ("uah", "uah", 12)):
            value = document.get(source)
            if value:
                statement[key] = str(value)[:limit]
        statement["sig"] = {
            "alg": "ed25519",
            "key": did,
            "value": keys.sign(private, canonical_bytes(statement)),
        }
        digest = sha256_prefixed(canonical_bytes({k: v for k, v in statement.items() if k != "sig"}))
        RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)
        stored = {
            "receipt": statement,
            "receipt_digest": digest,
            "stored_at": records.utc_now_rfc3339(),
            "note": "content-free gateway-emitted settle receipt; signature covers the JCS bytes minus sig",
        }
        target.write_text(json.dumps(stored, indent=2) + "\n", encoding="utf-8")
        self._send(200, {"stored": True, "tx": tx, "digest": digest, "service": SERVICE})

    def _serve_anchor(self, segment: str):
        name = self._safe_name(segment)
        if name is None:
            self._send(404, {"error": "not found"})
            return
        name = name.replace("sha256%3A", "").replace("sha256:", "")
        if not re.fullmatch(r"[0-9a-f]{64}", name):
            self._send(404, {"error": "digest must be sha256:<64 hex>"})
            return
        document_path = ANCHORS_DIR / (name + ".json")
        if not document_path.is_file():
            self._send(404, {"error": "no stored anchor for this digest"})
            return
        raw = document_path.read_bytes()
        etag = '"sha256:' + name + '"'
        if self._etag_matches(etag):
            self._send_bytes(304, b"", "application/json", etag)
            return
        self._send_bytes(200, raw, "application/json", etag)

    def _serve_notarization(self, segment: str):
        name = self._safe_name(segment)
        if name is None:
            self._send(404, {"error": "not found"})
            return
        clean = name.replace("sha256%3A", "").replace("sha256:", "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", clean):
            self._send(404, {
                "error": "invalid_digest",
                "hint": "digest must be 64 hex characters or sha256:<64 hex>",
            })
            return
        document_path = NOTARIZE_DIR / (clean + ".json")
        if not document_path.is_file():
            self._send(404, {
                "error": "notarization_not_found",
                "digest": f"sha256:{clean}",
                "hint": "no stored context notarization found for this digest",
            })
            return
        raw = document_path.read_bytes()
        etag = f'"sha256:{clean}"'
        if self._etag_matches(etag):
            self._send_bytes(304, b"", "application/json", etag)
            return
        self._send_bytes(200, raw, "application/json", etag)

    def _notarize(self):
        raw = self._read_body()
        if raw is None:
            return
        try:
            document = _request_json(raw)
        except (ValueError, RecursionError) as error:
            self._send(400, {"error": f"invalid JSON: {error}"})
            return
        if not isinstance(document, dict):
            self._send(400, {"error": "body must be an object"})
            return

        allowed_fields = {
            "context_digest", "prompt_hash", "action", "model", "agent_id", "metadata"
        }
        unknown_fields = sorted(set(document) - allowed_fields)
        if unknown_fields:
            self._send(400, {"error": "unsupported fields", "fields": unknown_fields})
            return

        if "context_digest" not in document and "prompt_hash" not in document:
            self._send(400, {
                "error": "missing_required_digest",
                "hint": "POST /notarize requires at least 'context_digest' or 'prompt_hash' (64 hex characters or sha256:<64 hex>).",
            })
            return

        norm_context_digest = None
        if "context_digest" in document:
            context_digest = document["context_digest"]
            if not isinstance(context_digest, str):
                self._send(400, {"error": "invalid_context_digest", "hint": "context_digest must be a string"})
                return
            c_str = context_digest
            if not DIGEST_RE.fullmatch(c_str.lower()):
                self._send(400, {
                    "error": "invalid_context_digest",
                    "hint": "context_digest must be sha256:<64 hex> or 64 hex characters",
                })
                return
            norm_context_digest = c_str.lower() if c_str.lower().startswith("sha256:") else f"sha256:{c_str.lower()}"

        norm_prompt_hash = None
        if "prompt_hash" in document:
            prompt_hash = document["prompt_hash"]
            if not isinstance(prompt_hash, str):
                self._send(400, {"error": "invalid_prompt_hash", "hint": "prompt_hash must be a string"})
                return
            p_str = prompt_hash
            if not DIGEST_RE.fullmatch(p_str.lower()):
                self._send(400, {
                    "error": "invalid_prompt_hash",
                    "hint": "prompt_hash must be sha256:<64 hex> or 64 hex characters",
                })
                return
            norm_prompt_hash = p_str.lower() if p_str.lower().startswith("sha256:") else f"sha256:{p_str.lower()}"

        clean_fields = {}
        for field, maxlen in (("action", 120), ("model", 100), ("agent_id", 120)):
            if field not in document:
                continue
            value = document[field]
            if not isinstance(value, str) or len(value) > maxlen:
                self._send(400, {
                    "error": "invalid_field",
                    "field": field,
                    "hint": f"{field} must be a string of at most {maxlen} characters",
                })
                return
            clean_fields[field] = value

        bounded_meta = None
        if "metadata" in document:
            metadata = document["metadata"]
            if not isinstance(metadata, dict):
                self._send(400, {"error": "invalid_metadata", "hint": "metadata must be an object"})
                return
            if len(metadata) > 16:
                self._send(400, {"error": "invalid_metadata", "hint": "metadata may contain at most 16 entries"})
                return
            bounded_meta = {}
            for key, value in metadata.items():
                if not key or not key.isascii() or len(key) > 64:
                    self._send(400, {
                        "error": "invalid_metadata_key",
                        "hint": "metadata keys must be non-empty ASCII strings of at most 64 characters",
                    })
                    return
                if isinstance(value, str):
                    if len(value) > 256:
                        self._send(400, {
                            "error": "invalid_metadata_value",
                            "field": key,
                            "hint": "metadata strings may contain at most 256 characters",
                        })
                        return
                elif type(value) is int and abs(value) > (2**53 - 1):
                    self._send(400, {
                        "error": "invalid_metadata_value",
                        "field": key,
                        "hint": "metadata integers must be within the interoperable safe-integer range",
                    })
                    return
                elif value is not None and type(value) not in (bool, int):
                    self._send(400, {
                        "error": "invalid_metadata_value",
                        "field": key,
                        "hint": "metadata values must be strings, integers, booleans, or null",
                    })
                    return
                bounded_meta[key] = value

        statement = {
            "kind": "wm.context-notarization",
            "version": 1,
            "issued_at": records.utc_now_rfc3339(),
            "issuer": None,
        }
        if norm_context_digest:
            statement["context_digest"] = norm_context_digest
        if norm_prompt_hash:
            statement["prompt_hash"] = norm_prompt_hash

        statement.update(clean_fields)
        if bounded_meta is not None:
            statement["metadata"] = bounded_meta

        try:
            # Validate every caller-derived value before signing_identity can
            # create the service key file. The issuer is the only field filled
            # after this check, and signing_identity supplies its string value.
            canonical_bytes(statement)
        except (TypeError, ValueError, UnicodeError, RecursionError) as error:
            self._send(400, {"error": "invalid_canonical_statement", "detail": str(error)})
            return

        try:
            did, private = signing_identity()
        except Exception as error:  # noqa: BLE001
            self._send(500, {"error": f"signing key unavailable: {error}"})
            return

        statement["issuer"] = did
        try:
            unsigned_canon = canonical_bytes(statement)
        except (TypeError, ValueError, UnicodeError, RecursionError) as error:
            self._send(500, {"error": "service statement canonicalization failed", "detail": str(error)})
            return

        sig_val = keys.sign(private, unsigned_canon)
        statement["sig"] = {
            "alg": "ed25519",
            "key": did,
            "value": sig_val,
        }
        digest = sha256_prefixed(unsigned_canon)

        NOTARIZE_DIR.mkdir(parents=True, exist_ok=True)
        raw_hex = digest.replace("sha256:", "")
        target = NOTARIZE_DIR / (raw_hex + ".json")
        stored = {
            "notarization": statement,
            "notarization_digest": digest,
            "stored_at": records.utc_now_rfc3339(),
            "service": SERVICE,
            "note": "Ed25519 service signature over caller-supplied digests and claims using the continuity-receipt canonical JSON subset; underlying context and execution are not observed",
        }
        target.write_text(json.dumps(stored, indent=2) + "\n", encoding="utf-8")

        self._send(200, {
            "notarized": True,
            "digest": digest,
            "receipt": statement,
            "service": SERVICE,
            "lookup_url": f"/notarize/{raw_hex}",
        })

    def do_PUT(self):
        path = self.path.split("?", 1)[0]
        if path == "/crystals" or path.startswith("/crystals/"):
            self._store_crystal()
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/verify":
            self._verify()
        elif path == "/verify-receipt":
            self._verify_receipt()
        elif path == "/verify-anchor":
            self._verify_anchor()
        elif path == "/anchors":
            self._store_anchor()
        elif path == "/payment-receipts":
            self._store_payment_receipt()
        elif path == "/notarize":
            self._notarize()
        elif path == "/conformance":
            self._conformance()
        elif path == "/erc8004/validate":
            self._erc8004_validate()
        elif path == "/crystals":
            self._store_crystal()
        elif path == "/mcp":
            self._mcp()
        else:
            self._send(404, {"error": "not found"})

    # ── verification ────────────────────────────────────────────────────
    def _verify(self):
        raw = self._read_body()
        if raw is None:
            return
        try:
            document = _request_json(raw)
        except (ValueError, RecursionError) as error:
            self._send(400, {"error": f"invalid JSON: {error}"})
            return
        require_anchor = "require_anchor=1" in self.path
        want_receipt = "receipt=1" in self.path
        use_cache = "cache=1" in self.path

        if isinstance(document, dict) and isinstance(document.get("bundles"), list):
            bundles = document["bundles"]
            if len(bundles) > MAX_BATCH:
                self._send(400, {"error": f"batch exceeds {MAX_BATCH} bundles"})
                return
            results = []
            for bundle in bundles:
                results.append(self._verify_one(bundle, require_anchor))
            self._send(200, {"results": results, "service": SERVICE})
            return

        bundle = document.get("bundle") if isinstance(document, dict) and "bundle" in document else document
        if not isinstance(bundle, dict):
            self._send(400, {"error": "body must be a bundle object, {\"bundle\": {...}} or {\"bundles\": [...]}"})
            return
        payload = None
        receipt_verified_at = None
        receipt_version = None
        if use_cache:
            key = cache_key(raw, require_anchor)
            cached = cache_get(key)
            if cached is not None:
                payload = cached["payload"]
                receipt_verified_at = cached["verified_at"]
                receipt_version = cached["verifier_version"]
                payload["cache"] = {"hit": True, "cached_at": receipt_verified_at, "age_s": cached["age_s"]}
        if payload is None:
            payload = self._verify_one(bundle, require_anchor)
            if use_cache:
                receipt_verified_at = records.utc_now_rfc3339()
                payload["cache"] = {"hit": False, "cached_at": receipt_verified_at}
                cache_put(key, {k: v for k, v in payload.items() if k != "cache"}, receipt_verified_at)
        payload["service"] = SERVICE
        if want_receipt:
            try:
                payload["verification_receipt"] = verification_receipt(
                    bundle, payload, verified_at=receipt_verified_at, version=receipt_version
                )
            except OSError as error:
                payload["verification_receipt_error"] = f"signing key unavailable: {error}"
            except ValueError as error:
                payload["verification_receipt_error"] = f"bundle cannot be digested: {error}"
        self._send(200, payload)

    @staticmethod
    def _verify_one(bundle: dict, require_anchor: bool) -> dict:
        try:
            return verify_bundle(bundle, require_anchor=require_anchor).as_dict()
        except Exception as error:  # fail closed, no stack traces over the wire
            return {
                "verdict": "INSUFFICIENT_EVIDENCE",
                "errors": [],
                "provisional_reasons": [],
                "insufficient_reasons": [f"verifier_exception:{error}"],
                "summary": {},
            }

    def _verify_receipt(self):
        raw = self._read_body()
        if raw is None:
            return
        try:
            document = _request_json(raw)
        except (ValueError, RecursionError) as error:
            self._send(400, {"error": f"invalid JSON: {error}"})
            return
        if not isinstance(document, dict):
            self._send(400, {"error": "body must be an object"})
            return
        receipt = document.get("receipt") if "receipt" in document else document
        bundle = None
        if isinstance(document.get("bundle"), dict):
            bundle = document["bundle"]
        elif isinstance(document.get("bundle_bytes_b64"), str):
            try:
                bundle_bytes = base64.b64decode(document["bundle_bytes_b64"], validate=True)
            except (ValueError, TypeError) as error:
                self._send(400, {"error": f"bundle_bytes_b64 is not valid base64: {error}"})
                return
            try:
                bundle = _request_json(bundle_bytes)
            except (ValueError, RecursionError) as error:
                self._send(400, {"error": f"bundle_bytes_b64 is not JSON: {error}"})
                return
        revocations = document.get("revocations") if isinstance(document.get("revocations"), list) else None
        payload = verify_verification_receipt(receipt, bundle, revocations).as_dict()
        payload["service"] = SERVICE
        self._send(200, payload)

    def _verify_anchor(self):
        raw = self._read_body()
        if raw is None:
            return
        try:
            document = _request_json(raw)
        except (ValueError, RecursionError) as error:
            self._send(400, {"error": f"invalid JSON: {error}"})
            return
        result = self._anchor_result(document)
        if isinstance(result, tuple):
            status, payload = result
            self._send(status, payload)
            return
        payload = result.as_dict()
        payload["service"] = SERVICE
        self._send(200, payload)

    @staticmethod
    def _anchor_result(document):
        if not isinstance(document, dict) or not isinstance(document.get("proof"), str):
            return 400, {"error": "body must be {\"proof\": \"<base64>\", \"digest\": \"sha256:<hex>\", \"headers\": {\"<height>\": \"<hex>\"}}"}
        try:
            proof = base64.b64decode(document["proof"], validate=True)
        except (ValueError, TypeError) as error:
            return 400, {"error": f"proof is not valid base64: {error}"}
        headers: dict[int, bytes] = {}
        header_map = document.get("headers")
        if isinstance(header_map, dict):
            for height, value in header_map.items():
                try:
                    headers[int(height)] = bytes.fromhex(value)
                except (ValueError, TypeError):
                    return 400, {"error": f"header for height {height} is not hex"}
        elif document.get("header") is not None and document.get("height") is not None:
            try:
                headers[int(document["height"])] = bytes.fromhex(document["header"])
            except (ValueError, TypeError):
                return 400, {"error": "header/height must be hex/int"}
        return verify_proof(proof, document.get("digest"), headers or None)

    def _store_anchor(self):
        raw = self._read_body()
        if raw is None:
            return
        try:
            document = _request_json(raw)
        except (ValueError, RecursionError) as error:
            self._send(400, {"error": f"invalid JSON: {error}"})
            return
        if not isinstance(document, dict) or not isinstance(document.get("digest"), str):
            self._send(400, {"error": "body must be {\"digest\": \"sha256:<hex>\", \"proof\": \"<base64>\", \"note\": \"...\"}"})
            return
        digest = document["digest"].lower()
        if not DIGEST_RE.fullmatch(digest):
            self._send(400, {"error": "digest must be sha256:<64 hex>"})
            return
        if not isinstance(document.get("proof"), str):
            self._send(400, {"error": "proof must be base64"})
            return
        result = self._anchor_result({"proof": document["proof"], "digest": digest})
        if isinstance(result, tuple):
            self._send(result[0], result[1])
            return
        if result.status in ("invalid", "mismatch"):
            self._send(400, {"error": f"proof rejected: {result.code}: {result.detail}"})
            return
        hex_digest = digest.split(":", 1)[1] if digest.startswith("sha256:") else digest
        stored = {
            "digest": "sha256:" + hex_digest,
            "proof": document["proof"],
            "note": document.get("note", ""),
            "stored_at": records.utc_now_rfc3339(),
            "status": result.status,
        }
        ANCHORS_DIR.mkdir(parents=True, exist_ok=True)
        path = ANCHORS_DIR / (hex_digest + ".json")
        path.write_text(json.dumps(stored, indent=2) + "\n", encoding="utf-8")
        self._send(200, {"stored": True, "digest": stored["digest"], "status": result.status,
                         "bytes": len(document["proof"]), "service": SERVICE})

    # ── erc-8004 validation adapter (wedge A) ───────────────────────────
    def _erc8004_validate(self):
        raw = self._read_body()
        if raw is None:
            return
        try:
            document = _request_json(raw)
        except (ValueError, RecursionError) as error:
            self._send(400, {"error": f"invalid JSON: {error}"})
            return
        if not isinstance(document, dict):
            self._send(400, {"error": "body must be an object"})
            return

        request_id = document.get("request_id")
        task_hash = document.get("task_hash")
        bundle = document.get("bundle")
        if not request_id or not task_hash or not isinstance(bundle, dict):
            self._send(400, {
                "error": "request_id, task_hash, and bundle are required",
                "docs": "https://api.whitemagic.dev/info",
            })
            return

        registry_address = document.get("registry_address") or DEFAULT_REGISTRY_ADDRESS
        chain_id_header = self.headers.get("X-WM-Chain-Id")
        try:
            chain_id = int(chain_id_header) if chain_id_header else int(document.get("chain_id") or DEFAULT_CHAIN_ID)
        except (ValueError, TypeError):
            chain_id = DEFAULT_CHAIN_ID

        # Verify bundle using reference verifier
        vr = self._verify_one(bundle, require_anchor=False)
        cr_verdict = vr.get("verdict", "UNTRUSTED")

        # Task binding check
        task_bound = _check_task_binding(str(task_hash), bundle)

        # Outcome derivation
        if not task_bound:
            outcome = 0
            outcome_label = "REJECT"
        elif cr_verdict == "TRUSTED":
            outcome = 1
            outcome_label = "ACCEPT"
        elif cr_verdict == "UNTRUSTED":
            outcome = 0
            outcome_label = "REJECT"
        else:  # INSUFFICIENT_EVIDENCE or PROVISIONAL
            outcome = 2
            outcome_label = "NEEDS_EVIDENCE"

        try:
            bundle_digest = sha256_prefixed(canonical_bytes(bundle))
            receipt_hash = "0x" + bundle_digest.replace("sha256:", "")
        except Exception:
            receipt_hash = "0x" + hashlib.sha256(raw).hexdigest()

        try:
            did, private = signing_identity()
        except Exception as error:
            self._send(500, {"error": f"signing key unavailable: {error}"})
            return

        now_ts = int(time.time())
        attestation_message = {
            "requestId": str(request_id),
            "outcome": outcome,
            "receiptHash": receipt_hash,
            "timestamp": now_ts,
        }
        sig_value = keys.sign(private, canonical_bytes(attestation_message))

        receipts_list = bundle.get("receipts")
        if not isinstance(receipts_list, list):
            receipts_list = []
        checks = {
            "task_bound": task_bound,
            "chain_integrity": None,
            "signatures_valid": None,
            "termination_present": any(
                isinstance(r, dict) and r.get("type") == "task.termination"
                for r in receipts_list
            ),
            "policy_compliant": None,
            "issuer_policy_evaluated": False,
            "resource_caps_respected": None,
            "anchors_verified": None,
            "anchors_required": False,
        }

        attestation = {
            "domain": {
                "name": "WhiteMagic ERC8004 Validator",
                "version": "1",
                "chainId": chain_id,
                "verifyingContract": registry_address,
            },
            "primaryType": "ValidationResponse",
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "ValidationResponse": [
                    {"name": "requestId", "type": "bytes32"},
                    {"name": "outcome", "type": "uint8"},
                    {"name": "receiptHash", "type": "bytes32"},
                    {"name": "timestamp", "type": "uint64"},
                ],
            },
            "message": attestation_message,
            "signature": sig_value,
            "signer": did,
        }

        response_payload = {
            "status": "error" if not task_bound else "success",
            "request_id": str(request_id),
            "outcome": outcome,
            "outcome_label": outcome_label,
            "cr_verdict": cr_verdict,
            "evaluation_scope": {
                "core_verdict": cr_verdict,
                "task_binding": "matched" if task_bound else "mismatch",
                "issuer_policy": "not_evaluated",
                "anchors": "not_required; no_independent_status_reported",
                "individual_checks": "not_reported_by_adapter",
                "attestation": "ed25519_signature_over_canonical_json_message",
                "evm_relay": "not_performed",
            },
            "receipt_hash": receipt_hash,
            "validator_address": did,
            "timestamp": now_ts,
            "checks": checks,
            "attestation": attestation,
            "onchain": {"relayed": False, "tx_hash": None},
            "service": SERVICE,
        }
        if not task_bound:
            response_payload["error"] = "task_mismatch"
            response_payload["hint"] = "task_hash does not match any task_id, response_hash, or termination receipt in bundle"
            self._send(422, response_payload)
            return

        self._send(200, response_payload)

    # ── memory crystals storage (wedge B) ───────────────────────────────
    def _store_crystal(self):
        raw = self._read_body(max_limit=MAX_CRYSTAL_BODY)
        if raw is None:
            return
        try:
            owner_id = verify_crystal_assertion(
                self.headers.get(CRYSTAL_ASSERTION_HEADER), self.command, self.path, raw)
        except CrystalAssertionError:
            self._send(401, {"error": "crystal access denied"})
            return
        try:
            document = _request_json(raw)
        except (ValueError, RecursionError) as error:
            self._send(400, {"error": f"invalid JSON: {error}"})
            return
        if not isinstance(document, dict):
            self._send(400, {"error": "body must be a crystal envelope object"})
            return
        try:
            crystal = MemoryCrystal.from_dict(document)
        except (CrystalError, KeyError, ValueError) as error:
            self._send(400, {"error": f"invalid crystal envelope: {error}"})
            return

        is_valid, msg = verify_crystal_integrity(crystal)
        if not is_valid:
            self._send(400, {"error": f"crystal integrity error: {msg}"})
            return

        if _clean_hex64(crystal.tenant_hash) != owner_id:
            # The envelope's AAD tenant locator is never an access credential;
            # an owner may only write envelopes under its own server-assigned
            # locator.
            self._send(403, {"error": "crystal owner mismatch"})
            return

        store = TenantCrystalStore(CRYSTALS_DIR)
        try:
            store.store_crystal(crystal)
        except Exception as error:
            self._send(500, {"error": f"storage error: {error}"})
            return

        self._send(201, {
            "stored": True,
            "crystal_id": crystal.crystal_id,
            "parent_crystal_id": crystal.parent_crystal_id,
            "tenant_hash": crystal.tenant_hash,
            "size_bytes": crystal.size_bytes,
            "service": SERVICE,
        })

    def _serve_crystal(self, segment: str):
        length = int(self.headers.get("Content-Length") or 0)
        raw_body = self.rfile.read(length) if 0 < length <= MAX_CRYSTAL_BODY else b""
        try:
            owner_id = verify_crystal_assertion(
                self.headers.get(CRYSTAL_ASSERTION_HEADER), self.command, self.path, raw_body)
        except CrystalAssertionError:
            self._send(401, {"error": "crystal access denied"})
            return
        scope = f"sha256:{owner_id}"

        if segment == "owner-locator":
            if self.command != "GET":
                self._send(405, {"error": "method not allowed"})
                return
            self._send(200, {"owner_locator": scope, "specification": "wm-crystal/1.0"})
            return

        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if segment == "lineage":
            selector = (
                self.headers.get("X-Tenant-Hash")
                or (query.get("tenant") and query["tenant"][0])
                or (query.get("tenant_hash") and query["tenant_hash"][0])
            )
            if selector and _clean_hex64(selector) != owner_id:
                # Uniform miss: caller-supplied locators cannot select another
                # owner's scope and must not act as an existence oracle.
                self._send(404, {"error": "crystal not found"})
                return
            store = TenantCrystalStore(CRYSTALS_DIR)
            try:
                lineage = store.get_lineage(scope)
                self._send(200, {
                    "tenant_hash": scope,
                    "crystals": lineage,
                    "count": len(lineage),
                    "service": SERVICE,
                })
            except Exception as error:
                self._send(500, {"error": f"failed to retrieve lineage: {error}"})
            return

        parts = segment.strip("/").split("/")
        if len(parts) == 2:
            raw_tenant, raw_id = parts
        elif len(parts) == 1:
            raw_id = parts[0]
            raw_tenant = (
                self.headers.get("X-Tenant-Hash")
                or (query.get("tenant") and query["tenant"][0])
                or (query.get("tenant_hash") and query["tenant_hash"][0])
            )
        else:
            self._send(404, {"error": "not found"})
            return

        if raw_tenant and _clean_hex64(raw_tenant) != owner_id:
            self._send(404, {"error": "crystal not found"})
            return

        clean_id = raw_id.replace("sha256:", "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", clean_id):
            self._send(400, {"error": "invalid crystal_id format (must be 64-character hex)"})
            return

        store = TenantCrystalStore(CRYSTALS_DIR)
        try:
            crystal = store.get_crystal(scope, f"sha256:{clean_id}")
        except FileNotFoundError:
            self._send(404, {"error": "crystal not found"})
            return
        except Exception as error:
            self._send(400, {"error": str(error)})
            return

        raw_bytes = crystal.to_json(indent=2).encode("utf-8")
        etag = '"' + crystal.crystal_id + '"'
        if self._etag_matches(etag):
            self._send_bytes(304, b"", "application/json", etag)
            return
        self._send_bytes(200, raw_bytes, "application/json", etag)

    # ── conformance referee ─────────────────────────────────────────────
    def _conformance(self):
        raw = self._read_body()
        if raw is None:
            return
        try:
            document = _request_json(raw)
        except (ValueError, RecursionError) as error:
            self._send(400, {"error": f"invalid JSON: {error}"})
            return
        if CORPUS is None:
            self._send(503, {"error": "conformance corpus is not deployed"})
            return
        try:
            graded = grade_submission(document, CORPUS)
        except ValueError as error:
            self._send(400, {"error": str(error)})
            return
        try:
            report = conformance_report(document, graded)
        except OSError as error:
            self._send(500, {"error": f"signing key unavailable: {error}"})
            return
        except ValueError as error:
            self._send(400, {"error": f"submission cannot be digested: {error}"})
            return
        self._send(200, {"report": report, "service": SERVICE})

    # ── MCP surface ─────────────────────────────────────────────────────
    def _mcp(self):
        raw = self._read_body()
        if raw is None:
            return
        try:
            document = _request_json(raw)
        except (ValueError, RecursionError) as error:
            self._send(400, {"error": f"invalid JSON: {error}"})
            return
        if not isinstance(document, dict):
            self._send(400, {"error": "body must be a JSON-RPC object"})
            return
        method = document.get("method")
        request_id = document.get("id")
        if method == "initialize":
            params = document.get("params") or {}
            version = params.get("protocolVersion") if isinstance(params, dict) else None
            result = {
                "protocolVersion": version if isinstance(version, str) else MCP_PROTOCOL_DEFAULT,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "WhiteMagic Receipt Verification", "version": verifier_version},
            }
        elif method in ("notifications/initialized", "notifications/cancelled"):
            self._send_bytes(202, b"", "application/json")
            return
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": mcp_tools()}
        elif method == "tools/call":
            result = self._mcp_call(document.get("params") or {})
        else:
            self._send(200, {"jsonrpc": "2.0", "id": request_id,
                             "error": {"code": -32601, "message": f"method not found: {method}"}})
            return
        self._send(200, {"jsonrpc": "2.0", "id": request_id, "result": result})

    def _mcp_call(self, params: dict) -> dict:
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if name == "verify_bundle":
            bundle = arguments.get("bundle")
            if not isinstance(bundle, dict):
                return self._mcp_error("bundle must be an object")
            payload = self._verify_one(bundle, bool(arguments.get("require_anchor")))
            if arguments.get("receipt"):
                try:
                    payload["verification_receipt"] = verification_receipt(bundle, payload)
                except OSError as error:
                    payload["verification_receipt_error"] = f"signing key unavailable: {error}"
                except ValueError as error:
                    payload["verification_receipt_error"] = f"bundle cannot be digested: {error}"
        elif name == "verify_anchor":
            result = self._anchor_result(arguments)
            if isinstance(result, tuple):
                return self._mcp_error(result[1].get("error", "bad request"))
            payload = result.as_dict()
        elif name == "get_revocations":
            issuer = arguments.get("issuer")
            if not isinstance(issuer, str) or not issuer:
                return self._mcp_error("issuer must be a string")
            filename = urllib.parse.quote(issuer, safe="") + ".json"
            path = REVOCATIONS_DIR / filename
            if not path.is_file():
                return self._mcp_error("no revocation document for this issuer")
            payload = json.loads(path.read_text(encoding="utf-8"))
        else:
            return self._mcp_error(f"unknown tool: {name}")
        return {
            "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
            "structuredContent": payload,
            "isError": False,
        }

    @staticmethod
    def _mcp_error(detail: str) -> dict:
        return {
            "content": [{"type": "text", "text": json.dumps({"error": detail})}],
            "isError": True,
        }


def main():
    parser = argparse.ArgumentParser(prog="receipt-api")
    parser.add_argument("--listen", default="127.0.0.1:18791")
    parser.add_argument(
        "--corpus-dir",
        default="/opt/whitemagic-api/corpus",
        help="directory holding bundles-manifest.json, verification-manifest.json, and hostile-manifest.json",
    )
    args = parser.parse_args()
    host, port = args.listen.rsplit(":", 1)

    global CORPUS
    CORPUS = load_corpus(pathlib.Path(args.corpus_dir))
    if CORPUS is None:
        print("receipt-api: conformance corpus not found; /conformance will answer 503", file=sys.stderr)

    class Server(ThreadingHTTPServer):
        request_queue_size = 128

    server = Server((host, int(port)), Handler)
    print(f"receipt-api listening on {host}:{port} (verifier {verifier_version})", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
