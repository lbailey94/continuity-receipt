"""Local trusted publisher and read gate for file-snapshot-v1 receipts.

The trust database and operator private key are deliberately external to the
snapshot data root. This protects the retained reference from a data-only
restore; it does not protect against an operator or host that can restore both.
"""
from __future__ import annotations

import ctypes
import os
import re
import secrets
import sqlite3
import stat
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canon import canonical_bytes, sha256_prefixed
from .keys import raw_pubkey_bytes
from .memory_snapshot import MAX_DIRECTORY_DEPTH, MAX_TREE_ENTRIES, _path
from .receiver_checkpoint import MAX_CHECKPOINT_BYTES, issue_checkpoint
from .verify import MAX_BUNDLE_BYTES

_GENERATION_RE = re.compile(r"^[0-9a-f]{32}$")
_MAX_FILES = 64
_MAX_FILE_BYTES = 1024 * 1024
_MAX_TOTAL_BYTES = 4 * 1024 * 1024
_MAX_MANIFEST_BYTES = 256 * 1024


class StoreError(ValueError):
    """Configuration or local storage is unsafe or inconsistent."""


def _absolute(path) -> Path:
    p = Path(path).expanduser()
    return Path(os.path.abspath(os.fspath(p)))


def _check_components(path: Path, *, allow_missing: bool = True) -> None:
    """Reject symlinked existing components, including the leaf."""
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            if allow_missing:
                continue
            raise StoreError("path_missing")
        if stat.S_ISLNK(mode):
            raise StoreError("symlink_path_rejected")


def _ensure_directory(path: Path) -> None:
    fd = _open_directory_path(path, create=True)
    os.close(fd)


def _dir_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def _open_directory_path(path: Path, *, create=False) -> int:
    """Open every absolute path component relative to a pinned directory fd."""
    path = _absolute(path)
    fd = os.open(path.anchor, _dir_flags())
    try:
        for part in path.parts[1:]:
            try:
                child = os.open(part, _dir_flags(), dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                child = os.open(part, _dir_flags(), dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_child_dir(parent_fd: int, name: str, *, create=False) -> int:
    if name in ("", ".", "..") or "/" in name or "\x00" in name:
        raise StoreError("directory_name_invalid")
    try:
        return os.open(name, _dir_flags(), dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            raise
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        return os.open(name, _dir_flags(), dir_fd=parent_fd)


def _regular_file(path: Path, *, missing_ok: bool = False) -> bool:
    _check_components(path)
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        if missing_ok:
            return False
        raise StoreError("file_missing")
    if not stat.S_ISREG(mode):
        raise StoreError("file_type_invalid")
    return True


def _read_file_at(parent_fd: int, name: str, limit: int) -> bytes:
    if name in ("", ".", "..") or "/" in name or "\x00" in name:
        raise StoreError("file_name_invalid")
    fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            raise StoreError("file_size_invalid")
        data = bytearray()
        while len(data) <= limit:
            part = os.read(fd, min(65536, limit + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        if len(data) > limit:
            raise StoreError("file_size_invalid")
        return bytes(data)
    finally:
        os.close(fd)


def _write_new_at(parent_fd: int, name: str, content: bytes) -> None:
    if name in ("", ".", "..") or "/" in name or "\x00" in name:
        raise StoreError("file_name_invalid")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
    try:
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_snapshot_file_at(root_fd: int, relative_path: str, content: bytes) -> None:
    """Write one file while retaining at most one descriptor per path level."""
    parts = relative_path.split("/")
    current_fd = root_fd
    opened = []
    try:
        for part in parts[:-1]:
            try:
                child_fd = os.open(part, _dir_flags(), dir_fd=current_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=current_fd)
                except FileExistsError:
                    pass
                _fsync_fd(current_fd)
                child_fd = os.open(part, _dir_flags(), dir_fd=current_fd)
            opened.append(child_fd)
            current_fd = child_fd
        _write_new_at(current_fd, parts[-1], content)
        _fsync_fd(current_fd)
    finally:
        for fd in reversed(opened):
            os.close(fd)


def _remove_tree_at(parent_fd: int, name: str) -> None:
    """Remove an unpublished tree without following symlinks."""
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(info.st_mode):
        os.unlink(name, dir_fd=parent_fd)
    else:
        child_fd = os.open(name, _dir_flags(), dir_fd=parent_fd)
        try:
            for child in os.listdir(child_fd):
                _remove_tree_at(child_fd, child)
            _fsync_fd(child_fd)
        finally:
            os.close(child_fd)
        os.rmdir(name, dir_fd=parent_fd)
    _fsync_fd(parent_fd)


def _recover_uncommitted_generations(generations_fd: int, conn: sqlite3.Connection) -> None:
    """Reclaim staging/renamed directories absent from committed publication state."""
    committed = {row[0] for row in conn.execute("SELECT generation_id FROM publication_audit")}
    current = conn.execute("SELECT generation_id FROM current_reference WHERE singleton=1").fetchone()
    if current is not None:
        committed.add(current[0])
    for name in os.listdir(generations_fd):
        if name.startswith(".stage-") or (_GENERATION_RE.fullmatch(name) and name not in committed):
            _remove_tree_at(generations_fd, name)


def _capture_tree_at(root_fd: int) -> dict[str, bytes]:
    captured: dict[str, bytes] = {}
    entries = 0

    def walk(directory_fd: int, prefix: str, depth: int) -> None:
        nonlocal entries
        if depth > MAX_DIRECTORY_DEPTH:
            raise StoreError("snapshot_directory_depth_invalid")
        with os.scandir(directory_fd) as children:
            for child in children:
                name = child.name
                entries += 1
                if entries > MAX_TREE_ENTRIES:
                    raise StoreError("snapshot_entry_count_invalid")
                rel = _validated_path(f"{prefix}/{name}" if prefix else name)
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child_fd = _open_child_dir(directory_fd, name)
                    try:
                        walk(child_fd, rel, depth + 1)
                    finally:
                        os.close(child_fd)
                elif stat.S_ISREG(info.st_mode):
                    if len(captured) >= _MAX_FILES or rel in captured:
                        raise StoreError("snapshot_file_count_invalid")
                    data = _read_file_at(directory_fd, name, _MAX_FILE_BYTES)
                    captured[rel] = data
                    if sum(map(len, captured.values())) > _MAX_TOTAL_BYTES:
                        raise StoreError("snapshot_total_size_invalid")
                else:
                    raise StoreError("snapshot_special_file_rejected")

    walk(root_fd, "", 0)
    return captured


def _fsync_fd(fd: int) -> None:
    os.fsync(fd)


def _rename_noreplace(parent_fd: int, source: str, destination: str) -> None:
    renameat2 = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if renameat2 is None:
        raise StoreError("atomic_noreplace_rename_unavailable")
    result = renameat2(parent_fd, os.fsencode(source), parent_fd,
                       os.fsencode(destination), 1)  # RENAME_NOREPLACE
    if result != 0:
        err = ctypes.get_errno()
        if err == 17:
            raise StoreError("generation_collision")
        raise OSError(err, os.strerror(err))


def _validated_path(value: object) -> str:
    return _path(value)


def _capture_files(files) -> dict[str, bytes]:
    if type(files) is not dict or len(files) > _MAX_FILES:
        raise ValueError("snapshot_file_count_invalid")
    captured: dict[str, bytes] = {}
    total = 0
    for path, value in files.items():
        path = _validated_path(path)
        if path in captured:
            raise ValueError("snapshot_path_duplicate")
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise ValueError("snapshot_bytes_invalid")
        data = memoryview(value).tobytes()
        if len(data) > _MAX_FILE_BYTES:
            raise ValueError("snapshot_file_size_invalid")
        total += len(data)
        if total > _MAX_TOTAL_BYTES:
            raise ValueError("snapshot_total_size_invalid")
        captured[path] = data
    return captured


def _outcome(outcome: str, reason: str, **fields) -> dict:
    return {"kind": "cpr-experimental-receiver-store-result", "version": 1,
            "outcome": outcome, "reason_codes": [reason], **fields}


class ReceiverStore:
    """Receiver with immutable policy and an independently retained reference."""

    def __init__(self, data_root, trust_db, *, context, scope, trusted_public_key,
                 max_age_seconds=3600, receiver_profile=None):
        if (os.name != "posix" or not hasattr(os, "O_NOFOLLOW")
                or not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NONBLOCK")
                or os.open not in os.supports_dir_fd or os.scandir not in os.supports_fd):
            raise ValueError("receiver_platform_unsupported")
        self.data_root = _absolute(data_root)
        self.trust_db = _absolute(trust_db)
        if not isinstance(trusted_public_key, Ed25519PublicKey):
            raise ValueError("trusted_public_key_invalid")
        if not isinstance(context, str) or not context or len(context) > 512 or "\x00" in context:
            raise ValueError("context_invalid")
        if not isinstance(scope, str) or not scope or len(scope) > 512 or "\x00" in scope:
            raise ValueError("scope_invalid")
        if type(max_age_seconds) is not int or not 1 <= max_age_seconds <= 31_536_000:
            raise ValueError("freshness_invalid")
        _check_components(self.data_root)
        _check_components(self.trust_db)
        try:
            if os.path.commonpath((str(self.data_root.resolve()), str(self.trust_db.resolve()))) == str(self.data_root.resolve()):
                raise ValueError("trust_db_inside_data_root")
        except ValueError as exc:
            if str(exc) == "trust_db_inside_data_root":
                raise
        self.context = context
        self.scope = scope
        self.trusted_public_key = trusted_public_key
        self.max_age_seconds = max_age_seconds
        self.receiver_profile = None
        if receiver_profile is not None:
            from .receiver_profile import validate_profile
            self.receiver_profile = validate_profile(
                receiver_profile, context=context, scope=scope,
                public_key_bytes=raw_pubkey_bytes(trusted_public_key))
        policy_value = {
            "context": context, "scope": scope,
            "trusted_public_key": raw_pubkey_bytes(trusted_public_key).hex(),
            "max_age_seconds": max_age_seconds,
        }
        if receiver_profile is not None:
            policy_value["receiver_profile"] = receiver_profile
        self._policy = canonical_bytes(policy_value)

    def _connect(self, *, create=False):
        _check_components(self.trust_db)
        if create:
            _ensure_directory(self.trust_db.parent)
            if not _regular_file(self.trust_db, missing_ok=True):
                fd = os.open(self.trust_db, os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                os.close(fd)
        elif not _regular_file(self.trust_db, missing_ok=True):
            return None
        conn = sqlite3.connect(self.trust_db, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def _policy_check(self, conn):
        row = conn.execute("SELECT value FROM receiver_policy WHERE singleton=1").fetchone()
        if row is None:
            raise StoreError("receiver_not_initialized")
        if bytes(row[0]) != self._policy:
            raise StoreError("receiver_policy_mismatch")

    def initialize(self) -> dict:
        """Create the data root and bind the separate trust DB to this policy."""
        _ensure_directory(self.data_root)
        generations = self.data_root / "generations"
        _ensure_directory(generations)
        conn = self._connect(create=True)
        try:
            conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("CREATE TABLE IF NOT EXISTS receiver_policy (singleton INTEGER PRIMARY KEY CHECK(singleton=1), value BLOB NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS current_reference (singleton INTEGER PRIMARY KEY CHECK(singleton=1), generation_id TEXT NOT NULL, sequence INTEGER NOT NULL, checkpoint_digest TEXT NOT NULL, bundle_digest TEXT NOT NULL, manifest_digest TEXT NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS publication_audit (sequence INTEGER PRIMARY KEY, generation_id TEXT UNIQUE NOT NULL, checkpoint_digest TEXT NOT NULL, bundle_digest TEXT NOT NULL, manifest_digest TEXT NOT NULL)")
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT value FROM receiver_policy WHERE singleton=1").fetchone()
            if row is None:
                conn.execute("INSERT INTO receiver_policy(singleton,value) VALUES(1,?)", (self._policy,))
            elif bytes(row[0]) != self._policy:
                conn.rollback()
                return _outcome("REJECT", "receiver_policy_mismatch")
            conn.commit()
            return _outcome("ACCEPT", "receiver_initialized")
        finally:
            conn.close()

    @staticmethod
    def _reference(row):
        if row is None:
            return None
        return {"generation_id": row["generation_id"], "sequence": row["sequence"],
                "checkpoint_digest": row["checkpoint_digest"], "bundle_digest": row["bundle_digest"],
                "manifest_digest": row["manifest_digest"]}

    def current_reference(self) -> dict | None:
        conn = self._connect()
        if conn is None:
            return None
        try:
            self._policy_check(conn)
            return self._reference(conn.execute("SELECT * FROM current_reference WHERE singleton=1").fetchone())
        finally:
            conn.close()

    def publish(self, files, *, private_key, expected_checkpoint_digest, now, fault_hook=None) -> dict:
        """Capture, sign, verify, durably store, and atomically select a generation."""
        if not isinstance(private_key, Ed25519PrivateKey) or raw_pubkey_bytes(private_key.public_key()) != raw_pubkey_bytes(self.trusted_public_key):
            return _outcome("REJECT", "writer_key_mismatch")
        try:
            captured = _capture_files(files)
            if self.receiver_profile is not None and (
                    not set(self.receiver_profile["inventory"]) - set(self.receiver_profile["optional"]) <= set(captured) or
                    not set(captured) <= set(self.receiver_profile["inventory"])):
                return _outcome("REJECT", "receiver_profile_inventory_mismatch")
            from .memory_snapshot import build_bundle, build_manifest
            manifest_bytes = build_manifest(captured)
            bundle_bytes = build_bundle(manifest_bytes, scope=self.scope, private_key=private_key, issued_at=now)
            checkpoint = issue_checkpoint(bundle_bytes, context=self.context, issued_at=now,
                                           max_age_seconds=self.max_age_seconds, private_key=private_key)
            checkpoint_bytes = canonical_bytes(checkpoint)
            checkpoint_ref = sha256_prefixed(checkpoint_bytes)
            assessment = self._assess(bundle_bytes, checkpoint_bytes, manifest_bytes, captured, now, checkpoint_ref)
            if assessment.outcome != "ACCEPT":
                return _outcome(assessment.outcome, assessment.reason_codes[0], assessment=assessment.as_dict())
        except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError) as exc:
            return _outcome("REJECT", str(exc) if str(exc) else "publication_input_invalid")

        conn = self._connect()
        if conn is None:
            return _outcome("NEEDS_EVIDENCE", "receiver_not_initialized")
        generation_id = secrets.token_hex(16)
        stage_name = ".stage-" + generation_id
        directory_fds = []
        generations_fd = None
        try:
            self._policy_check(conn)
            conn.execute("BEGIN IMMEDIATE")
            old = self._reference(conn.execute("SELECT * FROM current_reference WHERE singleton=1").fetchone())
            actual_expected = old["checkpoint_digest"] if old else None
            if expected_checkpoint_digest != actual_expected:
                conn.rollback()
                return _outcome("REJECT", "reference_conflict", reference=old)
            root_fd = _open_directory_path(self.data_root, create=True)
            directory_fds.append(root_fd)
            generations_fd = _open_child_dir(root_fd, "generations", create=True)
            directory_fds.append(generations_fd)
            _recover_uncommitted_generations(generations_fd, conn)
            os.mkdir(stage_name, mode=0o700, dir_fd=generations_fd)
            stage_fd = _open_child_dir(generations_fd, stage_name)
            directory_fds.append(stage_fd)
            files_fd = _open_child_dir(stage_fd, "files", create=True)
            directory_fds.append(files_fd)
            _write_new_at(stage_fd, "bundle.json", bundle_bytes)
            _write_new_at(stage_fd, "checkpoint.json", checkpoint_bytes)
            _write_new_at(stage_fd, "manifest.json", manifest_bytes)
            for rel, data in captured.items():
                _write_snapshot_file_at(files_fd, rel, data)
            for directory_fd in reversed(directory_fds):
                _fsync_fd(directory_fd)
            self._fault(fault_hook, "after_stage")
            _rename_noreplace(generations_fd, stage_name, generation_id)
            _fsync_fd(generations_fd)
            self._fault(fault_hook, "after_rename")
            sequence = old["sequence"] + 1 if old else 1
            bundle_ref = sha256_prefixed(bundle_bytes)
            manifest_ref = sha256_prefixed(manifest_bytes)
            reference = {"generation_id": generation_id, "sequence": sequence,
                         "checkpoint_digest": checkpoint_ref, "bundle_digest": bundle_ref,
                         "manifest_digest": manifest_ref}
            conn.execute("INSERT INTO publication_audit VALUES(?,?,?,?,?)",
                         (sequence, generation_id, checkpoint_ref, bundle_ref, manifest_ref))
            conn.execute("INSERT INTO current_reference(singleton,generation_id,sequence,checkpoint_digest,bundle_digest,manifest_digest) VALUES(1,?,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET generation_id=excluded.generation_id, sequence=excluded.sequence, checkpoint_digest=excluded.checkpoint_digest, bundle_digest=excluded.bundle_digest, manifest_digest=excluded.manifest_digest",
                         (generation_id, sequence, checkpoint_ref, bundle_ref, manifest_ref))
            self._fault(fault_hook, "before_commit")
            conn.commit()
            self._fault(fault_hook, "after_commit")
            return _outcome("ACCEPT", "published", reference=reference, assessment=assessment.as_dict())
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            if generations_fd is not None:
                try:
                    committed = conn.execute(
                        "SELECT 1 FROM publication_audit WHERE generation_id=?", (generation_id,)
                    ).fetchone()
                except sqlite3.Error:
                    committed = True  # Preserve data if commit state cannot be determined.
                if not committed:
                    for abandoned in (stage_name, generation_id):
                        try:
                            _remove_tree_at(generations_fd, abandoned)
                        except OSError:
                            pass  # A later serialized publish retries safe orphan recovery.
            raise
        finally:
            for directory_fd in reversed(directory_fds):
                try:
                    os.close(directory_fd)
                except OSError:
                    pass
            conn.close()

    @staticmethod
    def _fault(hook, boundary):
        if hook is not None:
            hook(boundary)

    def _assess(self, bundle, checkpoint, manifest, files, now, checkpoint_ref):
        from .memory_snapshot import assess_snapshot
        return assess_snapshot(bundle, checkpoint, manifest, files,
                               expected_scope=self.scope,
                               trusted_public_key=self.trusted_public_key,
                               expected_context=self.context,
                               accepted_checkpoint_digest=checkpoint_ref,
                               now=now, max_age_seconds=self.max_age_seconds)

    def recall(self, *, now, sink=None) -> dict:
        conn = self._connect()
        if conn is None:
            return _outcome("NEEDS_EVIDENCE", "receiver_database_missing", files=None, reference=None)
        reference = None
        directory_fds = []
        try:
            self._policy_check(conn)
            conn.execute("BEGIN IMMEDIATE")
            reference = self._reference(conn.execute("SELECT * FROM current_reference WHERE singleton=1").fetchone())
            if reference is None:
                conn.rollback()
                return _outcome("NEEDS_EVIDENCE", "accepted_reference_missing", files=None, reference=None)
            if not _GENERATION_RE.fullmatch(reference["generation_id"]):
                conn.rollback()
                return _outcome("REJECT", "generation_id_invalid", files=None, reference=reference)
            root_fd = _open_directory_path(self.data_root)
            directory_fds.append(root_fd)
            generations_fd = _open_child_dir(root_fd, "generations")
            directory_fds.append(generations_fd)
            generation_fd = _open_child_dir(generations_fd, reference["generation_id"])
            directory_fds.append(generation_fd)
            bundle_bytes = _read_file_at(generation_fd, "bundle.json", MAX_BUNDLE_BYTES)
            checkpoint_bytes = _read_file_at(generation_fd, "checkpoint.json", MAX_CHECKPOINT_BYTES)
            manifest_bytes = _read_file_at(generation_fd, "manifest.json", _MAX_MANIFEST_BYTES)
            if sha256_prefixed(bundle_bytes) != reference["bundle_digest"] or sha256_prefixed(manifest_bytes) != reference["manifest_digest"]:
                conn.rollback()
                return _outcome("REJECT", "generation_digest_mismatch", files=None, reference=reference)
            files_fd = _open_child_dir(generation_fd, "files")
            directory_fds.append(files_fd)
            captured = _capture_tree_at(files_fd)
            if self.receiver_profile is not None and (
                    not set(self.receiver_profile["inventory"]) - set(self.receiver_profile["optional"]) <= set(captured) or
                    not set(captured) <= set(self.receiver_profile["inventory"])):
                conn.rollback()
                return _outcome("REJECT", "receiver_profile_inventory_mismatch", files=None, reference=reference)
            assessment = self._assess(bundle_bytes, checkpoint_bytes, manifest_bytes,
                                      captured, now, reference["checkpoint_digest"])
            if assessment.outcome != "ACCEPT":
                conn.rollback()
                return {**_outcome(assessment.outcome, assessment.reason_codes[0],
                                   files=None, reference=reference), "assessment": assessment.as_dict()}
            if sink is not None:
                sink(dict(captured))
            conn.commit()
            return {**_outcome("ACCEPT", "snapshot_current", files=captured,
                               reference=reference), "assessment": assessment.as_dict()}
        except (OSError, sqlite3.Error, StoreError, ValueError, TypeError, UnicodeError, OverflowError, RecursionError) as exc:
            if conn.in_transaction:
                conn.rollback()
            reason = str(exc) if isinstance(exc, (StoreError, ValueError)) and str(exc) else "generation_unavailable"
            return _outcome("REJECT", reason, files=None, reference=reference)
        finally:
            for directory_fd in reversed(directory_fds):
                try:
                    os.close(directory_fd)
                except OSError:
                    pass
            conn.close()
