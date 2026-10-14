#!/usr/bin/env python3
"""Disposable rehearsal of state backup/restore and assertion-key rotation.

Uses temporary directories, synthetic keys, one synthetic owner, and the
candidate authd/API helpers. It never reads operator state or writes outside
the temporary directory. Output contains statuses and artifact hashes only.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import pathlib
import secrets
import shutil
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parents[1]))


def load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load candidate module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def keyring(active: str, keys: dict[str, bytes]) -> bytes:
    return (json.dumps({"active_kid": active,
                        "keys": {kid: b64u(key) for kid, key in keys.items()}},
                       sort_keys=True, separators=(",", ":")) + "\n").encode()


def file_hashes(root: pathlib.Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*")) if path.is_file()
    }


def main() -> int:
    authd = load_module("rollout_rehearsal_authd", ROOT / "src" / "authd.py")
    api = load_module("rollout_rehearsal_api", ROOT / "src" / "receipt-api.py")
    with tempfile.TemporaryDirectory(prefix="crystal-rollout-rehearsal-") as temp:
        base = pathlib.Path(temp)
        state = base / "state"
        backup = base / "backup"
        state.mkdir(mode=0o700)
        old_key = secrets.token_bytes(32)
        new_key = secrets.token_bytes(32)
        owner_id = secrets.token_hex(32)
        state.joinpath("crystal_assertion.keys.json").write_bytes(keyring("old", {"old": old_key}))
        state.joinpath("synthetic-crystal.marker").write_bytes(b"synthetic-only; no crystal payload")
        state.joinpath("crystal_assertion.keys.json").chmod(0o600)
        api.STATE_DIR = state
        api.CRYSTAL_ASSERTION_KEYS_PATH = state / "crystal_assertion.keys.json"
        api.CRYSTAL_ASSERTION_SECRET_PATH = state / "crystal_assertion.secret"
        api.CRYSTAL_ASSERTION_REPLAY_PATH = state / "crystal_assertion_replay.sqlite3"

        active_kid, issuer_key = authd._load_crystal_issuer_key(state)
        assert active_kid == "old" and issuer_key == old_key
        old_replayed = authd._make_crystal_assertion(old_key, owner_id, "GET",
                                                      "/crystals/owner-locator", b"", kid="old")
        api.verify_crystal_assertion(old_replayed, "GET", "/crystals/owner-locator", b"")
        shutil.copytree(state, backup, copy_function=shutil.copy2)
        backup.chmod(0o700)
        snapshot_hashes = file_hashes(backup)

        # During overlap the issuer switches to new while the verifier retains old.
        overlap_bytes = keyring("new", {"old": old_key, "new": new_key})
        api.CRYSTAL_ASSERTION_KEYS_PATH.write_bytes(overlap_bytes)
        api.CRYSTAL_ASSERTION_KEYS_PATH.chmod(0o600)
        active_kid, issuer_key = authd._load_crystal_issuer_key(state)
        assert active_kid == "new" and issuer_key == new_key
        old_during_overlap = authd._make_crystal_assertion(old_key, owner_id, "GET",
                                                           "/crystals/owner-locator", b"", kid="old")
        api.verify_crystal_assertion(old_during_overlap, "GET", "/crystals/owner-locator", b"")
        new_assertion = authd._make_crystal_assertion(issuer_key, owner_id, "GET",
                                                     "/crystals/owner-locator", b"", kid=active_kid)
        api.verify_crystal_assertion(new_assertion, "GET", "/crystals/owner-locator", b"")

        # Retiring old verifier material rejects any newly presented old-key assertion.
        revoked_assertion = authd._make_crystal_assertion(old_key, owner_id, "GET",
                                                          "/crystals/owner-locator", b"", kid="old")
        api.CRYSTAL_ASSERTION_KEYS_PATH.write_bytes(keyring("new", {"new": new_key}))
        api.CRYSTAL_ASSERTION_KEYS_PATH.chmod(0o600)
        try:
            api.verify_crystal_assertion(revoked_assertion, "GET", "/crystals/owner-locator", b"")
        except api.CrystalAssertionError as error:
            old_after_retirement = str(error)
        else:
            raise AssertionError("retired assertion key was accepted")

        # Restore the captured snapshot and prove both byte restoration and
        # preservation of the pre-backup replay marker.
        shutil.rmtree(state)
        shutil.copytree(backup, state, copy_function=shutil.copy2)
        restored = file_hashes(state) == snapshot_hashes
        try:
            api.verify_crystal_assertion(old_replayed, "GET", "/crystals/owner-locator", b"")
        except api.CrystalAssertionError as error:
            restored_replay = str(error)
        else:
            raise AssertionError("restored replay ledger forgot the pre-backup nonce")

        report = {
            "backup_hashes_match_after_restore": restored,
            "old_key_accepted_during_overlap": True,
            "new_active_key_accepted": True,
            "old_key_after_retirement": old_after_retirement,
            "pre_backup_nonce_after_restore": restored_replay,
            "temporary_state_removed_on_exit": True,
            "external_state_read_or_modified": False,
        }
        assert restored and old_after_retirement == "unknown assertion key id"
        assert restored_replay == "assertion replay"
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
