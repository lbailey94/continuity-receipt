"""Bounded local witness-file I/O and cooperating publisher coordination.

A file outside the receiver tree is still caller-retained evidence, not an
independent service. SQLite publication and this file update are separate
durable steps; callers must report an update failure after the local commit.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import time

MAX_WITNESS_BYTES = 16 * 1024
_LOCK_TIMEOUT_SECONDS = 10


def _flags() -> int:
    return getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def _open_parent(path) -> tuple[int, str]:
    absolute = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    if absolute == Path(absolute.anchor):
        raise ValueError("witness_path_invalid")
    fd = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY | _flags())
    try:
        for component in absolute.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | _flags(), dir_fd=fd)
            os.close(fd)
            fd = child
        return fd, absolute.name
    except BaseException:
        os.close(fd)
        raise


def _read_at(parent_fd: int, name: str, limit: int) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | _flags(), dir_fd=parent_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("witness_not_bounded_regular_file")
        captured = bytearray()
        while len(captured) <= limit:
            part = os.read(fd, min(65536, limit + 1 - len(captured)))
            if not part:
                break
            captured.extend(part)
        if len(captured) > limit:
            raise ValueError("witness_not_bounded_regular_file")
        return bytes(captured)
    finally:
        os.close(fd)


def read_bounded_regular(path, limit: int = MAX_WITNESS_BYTES) -> bytes:
    """Read through pinned, no-follow directory components and a bounded leaf."""
    parent = None
    try:
        parent, name = _open_parent(path)
        return _read_at(parent, name, limit)
    except FileNotFoundError as exc:
        raise ValueError("off_host_witness_missing") from exc
    finally:
        if parent is not None:
            os.close(parent)


def _parse_witness(raw: bytes, *, expected_checkpoint_digest=None):
    from . import strict_json
    from .witness import OffHostWitness
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("off_host_witness_invalid_json")
    return OffHostWitness.from_dict(strict_json.loads(raw.decode("utf-8")),
                                    expected_checkpoint_digest=expected_checkpoint_digest)


def load_witness(path, *, expected_checkpoint_digest=None):
    """Configured evidence must exist and validate; no missing-file fallback."""
    return _parse_witness(read_bounded_regular(path),
                          expected_checkpoint_digest=expected_checkpoint_digest)


class WitnessPublication:
    """Prepare a safe local file update before the receiver commits.

    The stable sidecar lock coordinates publishers using this helper and target.
    Other writers and independent witness custody remain caller obligations.
    """

    def __init__(self, path):
        self.path = os.fspath(path)
        self.parent_fd = None
        self.lock_fd = None
        self.temp_fd = None
        self.temp_name = None
        self.name = None
        self.existing = None

    def __enter__(self):
        try:
            self.parent_fd, self.name = _open_parent(self.path)
            lock_name = ".cpr-witness-" + hashlib.sha256(self.name.encode()).hexdigest()[:24] + ".lock"
            self.lock_fd = os.open(lock_name, os.O_RDWR | os.O_CREAT | os.O_NONBLOCK | _flags(),
                                   0o600, dir_fd=self.parent_fd)
            lock_info = os.fstat(self.lock_fd)
            if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1:
                raise ValueError("witness_lock_not_regular")
            deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise ValueError("witness_publication_lock_timeout")
                    time.sleep(0.01)
            self.existing = self._existing()
            self.temp_name = ".cpr-witness-stage-" + secrets.token_hex(16)
            self.temp_fd = os.open(self.temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _flags(),
                                   0o600, dir_fd=self.parent_fd)
            os.fsync(self.temp_fd)
            os.fsync(self.parent_fd)
            return self
        except BaseException:
            self._close()
            raise

    def _existing(self):
        try:
            return _parse_witness(_read_at(self.parent_fd, self.name, MAX_WITNESS_BYTES))
        except FileNotFoundError:
            return None

    def ensure_not_ahead(self, reference):
        """Refuse publication from a local store already behind/forked from witness."""
        if self.existing is None:
            return
        if reference is None or self.existing.min_sequence > reference["sequence"]:
            raise ValueError("witness_ahead_of_local_reference")
        if self.existing.min_sequence == reference["sequence"]:
            if self.existing.latest_checkpoint != reference["checkpoint_digest"]:
                raise ValueError("witness_local_reference_conflict")
            if (self.existing.generation_id is not None and
                    self.existing.generation_id != reference["generation_id"]):
                raise ValueError("witness_local_reference_conflict")

    def commit(self, reference):
        """Replace the complete witness atomically, then sync its directory."""
        from .witness import OffHostWitness
        data = {key: reference[key] for key in ("sequence", "checkpoint_digest", "generation_id")}
        incoming = OffHostWitness.from_dict(data)
        # The lock protects cooperating writers; also re-read for explicit drift.
        existing = self._existing()
        if existing is not None:
            if existing.min_sequence > incoming.min_sequence:
                raise ValueError("witness_sequence_regression")
            if existing.min_sequence == incoming.min_sequence and (
                    existing.latest_checkpoint != incoming.latest_checkpoint or
                    (existing.generation_id is not None and existing.generation_id != incoming.generation_id)):
                raise ValueError("witness_checkpoint_conflict")
        raw = (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode()
        view = memoryview(raw)
        while view:
            count = os.write(self.temp_fd, view)
            if count == 0:
                raise OSError("witness_file_write_incomplete")
            view = view[count:]
        os.fsync(self.temp_fd)
        os.close(self.temp_fd)
        self.temp_fd = None
        os.replace(self.temp_name, self.name, src_dir_fd=self.parent_fd, dst_dir_fd=self.parent_fd)
        self.temp_name = None
        os.fsync(self.parent_fd)

    def _close(self):
        if self.temp_fd is not None:
            os.close(self.temp_fd)
            self.temp_fd = None
        if self.temp_name is not None and self.parent_fd is not None:
            try:
                os.unlink(self.temp_name, dir_fd=self.parent_fd)
            except FileNotFoundError:
                pass
            self.temp_name = None
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None
        if self.parent_fd is not None:
            os.close(self.parent_fd)
            self.parent_fd = None

    def __exit__(self, exc_type, exc_value, traceback):
        self._close()
        return False
