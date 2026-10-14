#!/usr/bin/env python3
"""Synthetic-only rehearsal for a controlled Crystal recovery copy.

This module never contacts a service. Callers must provide disposable paths;
the accompanying CLI always creates those paths under TemporaryDirectory.
It copies opaque bytes and does not parse or decrypt an envelope.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile


class RecoveryRefused(RuntimeError):
    """Recovery was refused because a required control or byte check failed."""


def _load_quarantine_api():
    repo_root = Path(__file__).resolve().parents[2]
    import sys
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    source = repo_root / "ops/crystal-ownership-candidate/src/receipt-api.py"
    spec = importlib.util.spec_from_file_location("crystal_recovery_quarantine_api", source)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the reviewed quarantine primitive")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    directory_fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def restore_copy(
    *,
    quarantine_file: Path,
    destination_file: Path,
    expected_sha256: str,
    legacy_locator: str,
    mapped_owner_id: str,
    approved_owner_id: str,
    registry_mapping_conflict: bool,
    prior_binding_verified: bool,
    consent_verified: bool,
    independent_review_complete: bool,
    crash_failpoint: str | None = None,
) -> str:
    """Make an idempotent synthetic ciphertext copy after explicit approvals.

    The operation deliberately leaves the quarantine source in place. It uses
    an exclusive temporary file and a no-overwrite hard link for publication.
    """
    if crash_failpoint not in (None, "after-stage", "after-publish"):
        raise ValueError("unknown synthetic crash failpoint")
    if not prior_binding_verified or not consent_verified or not independent_review_complete:
        raise RecoveryRefused("required ownership, consent, or review evidence is absent")
    if not mapped_owner_id or mapped_owner_id != approved_owner_id:
        raise RecoveryRefused("approved owner does not match the explicit owner mapping")
    if registry_mapping_conflict:
        raise RecoveryRefused("owner ID is already mapped to a different principal")
    if not isinstance(legacy_locator, str) or not legacy_locator.startswith("sha256:"):
        raise RecoveryRefused("legacy locator must be sha256:<64 lowercase hex>")
    locator_digest = legacy_locator.removeprefix("sha256:")
    if len(locator_digest) != 64 or any(c not in "0123456789abcdef" for c in locator_digest):
        raise RecoveryRefused("invalid legacy locator digest")
    if approved_owner_id != locator_digest:
        raise RecoveryRefused("wm-crystal/1.0 locator does not match the approved owner ID")
    if len(expected_sha256) != 64 or any(c not in "0123456789abcdef" for c in expected_sha256):
        raise RecoveryRefused("invalid expected ciphertext digest")
    if quarantine_file.is_symlink() or not quarantine_file.is_file():
        raise RecoveryRefused("quarantine source must be a regular non-symlink file")
    if sha256_file(quarantine_file) != expected_sha256:
        raise RecoveryRefused("quarantine ciphertext digest changed")

    destination_file.parent.mkdir(parents=True, exist_ok=True)
    if destination_file.is_symlink():
        raise RecoveryRefused("destination must not be a symlink")
    temporary = destination_file.with_name(destination_file.name + ".recovery-tmp")
    if destination_file.exists():
        if not destination_file.is_file() or sha256_file(destination_file) != expected_sha256:
            raise RecoveryRefused("destination exists with different or invalid bytes")
        if temporary.is_symlink() or (temporary.exists() and (not temporary.is_file() or sha256_file(temporary) != expected_sha256)):
            raise RecoveryRefused("stale recovery temporary conflicts with the published copy")
        if temporary.exists():
            temporary.unlink()
            _fsync_directory(destination_file.parent)
        return "already-restored-identical"

    if temporary.exists() or temporary.is_symlink():
        raise RecoveryRefused("stale recovery temporary exists; inspect before retry")
    try:
        # This test fixture writes only opaque synthetic bytes. Production
        # procedure must likewise copy bytes without parsing or decrypting.
        with quarantine_file.open("rb") as source, temporary.open("xb") as target:
            os.chmod(temporary, 0o600)
            while True:
                block = source.read(65536)
                if not block:
                    break
                target.write(block)
            target.flush()
            os.fsync(target.fileno())
        if sha256_file(temporary) != expected_sha256:
            raise RecoveryRefused("staged ciphertext digest mismatch")
        _fsync_directory(destination_file.parent)
        if crash_failpoint == "after-stage":
            os._exit(86)  # Test-only abrupt process death; finally must not run.
        try:
            # Same-filesystem link publishes atomically and refuses overwrite.
            os.link(temporary, destination_file, follow_symlinks=False)
        except FileExistsError:
            if destination_file.is_file() and sha256_file(destination_file) == expected_sha256:
                return "already-restored-identical"
            raise RecoveryRefused("destination appeared with different or invalid bytes")
        _fsync_directory(destination_file.parent)
        if crash_failpoint == "after-publish":
            os._exit(87)  # Test-only abrupt process death after the directory fsync.
        if sha256_file(destination_file) != expected_sha256:
            raise RecoveryRefused("published ciphertext digest mismatch")
        return "restored-identical"
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def run_synthetic_rehearsal() -> dict:
    """Quarantine one fake unmapped envelope and rehearse recovery outcomes."""
    api = _load_quarantine_api()
    legacy_locator_digest = "c" * 64
    legacy_locator = f"sha256:{legacy_locator_digest}"
    # JSON-shaped synthetic input lets the existing helper classify an
    # unmapped v1 locator. It is not a real envelope and is never decrypted.
    synthetic_ciphertext = json.dumps(
        {"tenant_hash": legacy_locator, "ciphertext": "SYNTHETIC-OPAQUE-BYTES"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(synthetic_ciphertext).hexdigest()
    owner = legacy_locator_digest
    wrong_owner = "b" * 64
    with tempfile.TemporaryDirectory(prefix="crystal-recovery-synthetic-") as scratch:
        root = Path(scratch)
        # Keep the fixture path construction explicit; no production paths are accepted.
        source_file = root / "legacy" / "tenant" / "crystals" / "ab" / ("ab" + "1" * 62 + ".crystal")
        source_file.parent.mkdir(parents=True)
        source_file.write_bytes(synthetic_ciphertext)
        storage = root / "legacy"
        quarantine = root / "quarantine"
        plan = api.plan_legacy_crystal_quarantine(storage, quarantine)
        if len(plan["entries"]) != 1 or plan["entries"][0]["source_sha256"] != digest:
            raise AssertionError("synthetic quarantine plan did not bind the fixture bytes")
        api.apply_legacy_crystal_quarantine_plan(plan)
        quarantined = quarantine / plan["entries"][0]["destination"]
        if sha256_file(quarantined) != digest or source_file.exists():
            raise AssertionError("synthetic quarantine move did not preserve exact bytes")

        destination = root / "restored" / "tenant" / "crystals" / "ab" / quarantined.name
        common = dict(
            quarantine_file=quarantined,
            destination_file=destination,
            expected_sha256=digest,
            legacy_locator=legacy_locator,
            mapped_owner_id=owner,
            approved_owner_id=owner,
            registry_mapping_conflict=False,
            prior_binding_verified=True,
            consent_verified=True,
            independent_review_complete=True,
        )
        outcomes = {}
        try:
            restore_copy(**{**common, "mapped_owner_id": owner, "approved_owner_id": wrong_owner})
        except RecoveryRefused:
            outcomes["wrong_owner_refused"] = True
        else:
            raise AssertionError("wrong-owner recovery was not refused")
        try:
            restore_copy(**{**common, "legacy_locator": f"sha256:{wrong_owner}"})
        except RecoveryRefused:
            outcomes["locator_mismatch_refused"] = True
        else:
            raise AssertionError("wm-crystal/1.0 locator mismatch was not refused")
        if destination.exists():
            raise AssertionError("ownership refusal created a destination")

        # Abrupt subprocess death after fsync leaves a stale stage. Automatic
        # retry refuses it; this parent reconciles exact bytes before retry.
        stale_stage = destination.with_name(destination.name + ".recovery-tmp")
        _run_crash_worker(common, "after-stage")
        outcomes["staged_interruption_kept_quarantine"] = (
            quarantined.exists() and not destination.exists() and stale_stage.exists()
        )
        if not outcomes["staged_interruption_kept_quarantine"]:
            raise AssertionError("abrupt pre-publication exit did not leave the expected state")
        outcomes["prepublish_blind_retry_refused"] = False
        try:
            restore_copy(**common)
        except RecoveryRefused:
            outcomes["prepublish_blind_retry_refused"] = True
        if not outcomes["prepublish_blind_retry_refused"]:
            raise AssertionError("pre-publication stale stage did not block blind retry")
        if sha256_file(stale_stage) != digest or sha256_file(quarantined) != digest:
            raise AssertionError("pre-publication stage/source digest mismatch")
        stale_stage.unlink()  # synthetic operator reconciliation after digest review
        outcomes["retry_after_stage_reconciliation"] = restore_copy(**common)

        # Abrupt exit after publication + directory fsync models a lost process
        # response. Retry recognizes the exact destination and cleans only an
        # identical stale hard-link stage.
        second = root / "restored-after-publish" / quarantined.name
        common_second = {**common, "destination_file": second}
        _run_crash_worker(common_second, "after-publish")
        second_stage = second.with_name(second.name + ".recovery-tmp")
        if not (quarantined.exists() and second.exists() and second_stage.exists()):
            raise AssertionError("abrupt post-publication exit did not preserve expected files")
        outcomes["postpublish_stage_matches"] = sha256_file(second_stage) == digest
        common_second = {**common, "destination_file": second}
        outcomes["retry_after_publish"] = restore_copy(**common_second)
        outcomes["postpublish_stage_cleaned"] = not second_stage.exists()
        outcomes["quarantine_retained"] = quarantined.exists()
        outcomes["all_copies_match"] = all(
            sha256_file(path) == digest for path in (destination, second, quarantined)
        )
        if not outcomes["quarantine_retained"] or not outcomes["all_copies_match"]:
            raise AssertionError("recovery rehearsal did not preserve byte identity")

        try:
            restore_copy(**{**common, "registry_mapping_conflict": True})
        except RecoveryRefused:
            outcomes["registry_mapping_conflict_refused"] = True
        else:
            raise AssertionError("simulated registry mapping conflict was not refused")

        altered = root / "tampered.crystal"
        altered.write_bytes(synthetic_ciphertext + b"tamper")
        try:
            restore_copy(**{**common, "quarantine_file": altered, "destination_file": root / "tampered-out.crystal"})
        except RecoveryRefused:
            outcomes["tampered_source_refused"] = True
        else:
            raise AssertionError("tampered source was not refused")
        if (root / "tampered-out.crystal").exists():
            raise AssertionError("tampered source created a destination")
        return {"result": "PASS", "synthetic_only": True, "ciphertext_sha256": digest, "outcomes": outcomes}


def _run_crash_worker(arguments: dict, failpoint: str) -> None:
    """Run a synthetic restore in a child that exits without Python cleanup."""
    import subprocess
    import sys

    module_path = Path(__file__).resolve()
    script = r"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]).parent))
from recovery_harness import restore_copy
restore_copy(
    quarantine_file=Path(sys.argv[2]), destination_file=Path(sys.argv[3]),
    expected_sha256=sys.argv[4], legacy_locator=sys.argv[5],
    mapped_owner_id=sys.argv[6], approved_owner_id=sys.argv[7],
    registry_mapping_conflict=False, prior_binding_verified=True,
    consent_verified=True, independent_review_complete=True,
    crash_failpoint=sys.argv[8],
)
raise SystemExit(0)
"""
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(module_path),
            str(arguments["quarantine_file"]),
            str(arguments["destination_file"]),
            arguments["expected_sha256"],
            arguments["legacy_locator"],
            arguments["mapped_owner_id"],
            arguments["approved_owner_id"],
            failpoint,
        ],
        check=False,
    )
    expected_code = 86 if failpoint == "after-stage" else 87
    if completed.returncode != expected_code:
        raise AssertionError(f"crash worker exited {completed.returncode}, expected {expected_code}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    print(json.dumps(run_synthetic_rehearsal(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
