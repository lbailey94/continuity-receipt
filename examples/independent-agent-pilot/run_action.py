#!/usr/bin/env python3
"""Write one fixed local assessment record after explicit caller checks.

This is an opt-in relying-agent action: it records the actual consumer result
to a fixed JSON filename in an operator-selected local directory. It never
executes receipt text, invokes tools, or uses the network. Freshness is checked
against an explicit caller-supplied UTC time and maximum age, not a trusted
time oracle.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import sqlite3
import stat
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = Path(__file__).resolve().parent
OUTPUT_NAME = "assessment.json"
STATE_NAME = "replay-state.sqlite3"
TEMP_NAME = ".assessment.json.tmp"
MAX_INPUT_BYTES = 1024 * 1024
SOURCE_MODULES = (
    "continuity_receipt.consumer", "continuity_receipt.verify",
    "continuity_receipt.canon", "continuity_receipt.strict_json",
    "continuity_receipt.records", "continuity_receipt.keys",
    "continuity_receipt.agreements", "continuity_receipt.bundle",
    "continuity_receipt.revocations",
)
_IMPORT_LOCK = threading.RLock()


class ActionRefused(RuntimeError):
    pass


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _within_checkout(path: str | Path) -> bool:
    try:
        Path(path).resolve().relative_to(ROOT)
        return True
    except (OSError, ValueError):
        return False


def load_consumer(*, installed_package: bool):
    """Load the requested consumer without mutating sys.path.

    Source mode loads the checkout package by its explicit package location and
    rejects any already-cached Continuity Receipt module imported from outside
    the checkout. Installed mode rejects a cached or resolved checkout import.
    """
    with _IMPORT_LOCK:
        cached = {
            name: module for name, module in tuple(sys.modules.items())
            if name == "continuity_receipt" or name.startswith("continuity_receipt.")
        }
        if installed_package:
            consumer = importlib.import_module("continuity_receipt.consumer")
            if not _within_checkout(consumer.__file__):
                return consumer
            raise ActionRefused("installed_consumer_resolves_to_source_checkout")

        for name, module in cached.items():
            module_path = getattr(module, "__file__", None)
            if module_path is None:
                locations = getattr(module, "__path__", None)
                if locations:
                    if any(not _within_checkout(location) for location in locations):
                        raise ActionRefused(f"source_import_cached_outside_checkout:{name}")
                    continue
                raise ActionRefused(f"source_import_cached_without_path:{name}")
            if not _within_checkout(module_path):
                raise ActionRefused(f"source_import_cached_outside_checkout:{name}")

        if "continuity_receipt" not in sys.modules:
            package_path = ROOT / "continuity_receipt" / "__init__.py"
            package_spec = importlib.util.spec_from_file_location(
                "continuity_receipt", package_path,
                submodule_search_locations=[str(package_path.parent)],
            )
            if package_spec is None or package_spec.loader is None:
                raise ActionRefused("source_package_spec_unavailable")
            package = importlib.util.module_from_spec(package_spec)
            sys.modules["continuity_receipt"] = package
            try:
                package_spec.loader.exec_module(package)
            except Exception:
                sys.modules.pop("continuity_receipt", None)
                raise

        consumer = importlib.import_module("continuity_receipt.consumer")
        for name in SOURCE_MODULES:
            module = importlib.import_module(name)
            module_path = getattr(module, "__file__", None)
            if module_path is None or not _within_checkout(module_path):
                raise ActionRefused(f"source_import_resolved_outside_checkout:{name}")
        return consumer


def read_pinned(path: Path, expected: str, label: str) -> bytes:
    with path.open("rb") as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise ActionRefused(f"{label}_too_large")
        if stream.read(1):
            raise ActionRefused(f"{label}_too_large")
    if len(raw) > MAX_INPUT_BYTES:
        raise ActionRefused(f"{label}_too_large")
    observed = digest(raw)
    if observed != expected:
        raise ActionRefused(f"{label}_raw_pin_mismatch:{observed}")
    return raw


def source_pins(consumer) -> dict:
    files = {}
    for module_name in SOURCE_MODULES:
        module = importlib.import_module(module_name)
        path = Path(module.__file__).resolve()
        files[str(path)] = digest(path.read_bytes())
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
            text=True, check=True, timeout=5,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain", "--", "continuity_receipt"],
            cwd=ROOT, capture_output=True, text=True, check=True, timeout=5,
        ).stdout
        dirty = bool(status.strip())
    except (OSError, subprocess.SubprocessError):
        head, dirty = None, None
    return {
        "repository_head_observed": head,
        "runtime_sources_dirty": dirty,
        "consumer_module_path": str(Path(consumer.__file__).resolve()),
        "imported_module_file_sha256": files,
        "python": sys.version.split()[0],
        "operating_system": platform.platform(),
        "cryptography_version": importlib.metadata.version("cryptography"),
        "source_status_is_not_a_signature_or_independence_claim": True,
    }


def _paths(output_dir: Path) -> tuple[Path, Path, Path]:
    return output_dir / OUTPUT_NAME, output_dir / STATE_NAME, output_dir / TEMP_NAME


def _ensure_operator_dir(output_dir: Path) -> None:
    if output_dir.is_symlink() or not output_dir.is_dir():
        raise ActionRefused("operator_directory_not_a_plain_directory")
    if stat.S_IMODE(output_dir.stat().st_mode) & 0o077:
        raise ActionRefused("operator_directory_permissions_must_be_owner_only")
    for path in _paths(output_dir):
        if path.is_symlink():
            raise ActionRefused(f"symlink_refused:{path.name}")


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(output_dir: Path, raw: bytes) -> None:
    output_path, _, temp_path = _paths(output_dir)
    if temp_path.exists():
        raise ActionRefused("stale_temporary_output_refused")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(temp_path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # Hard-link creation is atomic and fails if any path already exists;
        # unlike replace(), it cannot overwrite an operator's concurrent file.
        os.link(temp_path, output_path)
        temp_path.unlink()
        _fsync_directory(output_dir)
    except Exception:
        try:
            temp_path.unlink()
        except OSError:
            pass
        raise


def _connect_state(output_dir: Path) -> sqlite3.Connection:
    _, state_path, _ = _paths(output_dir)
    if state_path.exists() and not stat.S_ISREG(state_path.lstat().st_mode):
        raise ActionRefused("state_path_not_regular_file")
    if not state_path.exists():
        try:
            fd = os.open(state_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        except FileExistsError:
            pass
    os.chmod(state_path, 0o600)
    db = sqlite3.connect(state_path, timeout=5, isolation_level=None)
    db.execute("PRAGMA journal_mode=DELETE")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("""CREATE TABLE IF NOT EXISTS operations (
        operation_id TEXT PRIMARY KEY,
        bundle_raw_sha256 TEXT NOT NULL,
        policy_raw_sha256 TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('PREPARED','COMPLETE')),
        output_sha256 TEXT,
        UNIQUE(bundle_raw_sha256, policy_raw_sha256)
    )""")
    check = db.execute("PRAGMA integrity_check").fetchone()
    if not check or check[0] != "ok":
        db.close()
        raise ActionRefused("replay_state_integrity_check_failed")
    return db


def _prepare(db: sqlite3.Connection, output_dir: Path, operation_id: str,
             bundle_pin: str, policy_pin: str) -> None:
    output_path, _, temp_path = _paths(output_dir)
    db.execute("BEGIN IMMEDIATE")
    try:
        rows = db.execute("SELECT state, output_sha256 FROM operations").fetchall()
        if rows:
            if len(rows) != 1:
                raise ActionRefused("unexpected_replay_state_rows")
            state, saved_output_hash = rows[0]
            if state == "PREPARED":
                raise ActionRefused("interrupted_prepared_operation_fail_closed")
            if state != "COMPLETE":
                raise ActionRefused("unknown_replay_state_fail_closed")
            if not output_path.is_file():
                raise ActionRefused("completed_output_missing_fail_closed")
            if digest(output_path.read_bytes()) != saved_output_hash:
                raise ActionRefused("completed_output_tampered_fail_closed")
            raise ActionRefused("assessment_replay_refused")
        if output_path.exists() or temp_path.exists():
            raise ActionRefused("untracked_existing_output_refused")
        db.execute(
            "INSERT INTO operations(operation_id,bundle_raw_sha256,policy_raw_sha256,state) VALUES(?,?,?,'PREPARED')",
            (operation_id, bundle_pin, policy_pin),
        )
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise


def _parse_now(value: str) -> datetime:
    if not isinstance(value, str):
        raise ActionRefused("now_must_be_utc_rfc3339_seconds")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ActionRefused("now_must_be_utc_rfc3339_seconds") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ActionRefused("now_must_be_utc_rfc3339_seconds")
    return parsed


def check_caller_freshness(bundle: dict, *, now_utc: str, max_age_seconds: int) -> dict:
    """Apply caller-supplied time and max age; neither is a trusted oracle."""
    if not isinstance(max_age_seconds, int) or isinstance(max_age_seconds, bool) or not 1 <= max_age_seconds <= 86400:
        raise ActionRefused("max_age_seconds_out_of_bounds")
    now = _parse_now(now_utc)
    receipts = bundle.get("receipts")
    if not isinstance(receipts, list) or not receipts:
        raise ActionRefused("freshness_receipts_missing")
    for index, receipt in enumerate(receipts):
        issued = receipt.get("issued_at") if isinstance(receipt, dict) else None
        if not isinstance(issued, str):
            raise ActionRefused(f"freshness_issued_at_missing:{index}")
        try:
            issued_dt = datetime.fromisoformat(issued.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ActionRefused(f"freshness_issued_at_invalid:{index}") from exc
        if issued_dt.tzinfo is None or issued_dt.utcoffset().total_seconds() != 0:
            raise ActionRefused(f"freshness_issued_at_not_utc:{index}")
        age = (now - issued_dt).total_seconds()
        if age < 0:
            raise ActionRefused(f"freshness_issued_in_future:{index}")
        if age > max_age_seconds:
            raise ActionRefused(f"freshness_max_age_exceeded:{index}")
        body = receipt.get("body", {})
        record_type = receipt.get("type")
        expiry_key = "expires_at" if record_type == "session.pass.created" else "valid_until" if record_type == "agreement.offer" else None
        if expiry_key:
            expiry = body.get(expiry_key) if isinstance(body, dict) else None
            if not isinstance(expiry, str):
                raise ActionRefused(f"freshness_expiry_missing:{index}")
            try:
                expiry_dt = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ActionRefused(f"freshness_expiry_invalid:{index}") from exc
            if expiry_dt.tzinfo is None or expiry_dt.utcoffset().total_seconds() != 0 or expiry_dt <= now:
                raise ActionRefused(f"freshness_expired:{index}")
    return {
        "id": "caller-now-utc-max-age-v1",
        "now_utc_supplied_by_operator": now_utc,
        "max_age_seconds": max_age_seconds,
        "validation": "all receipt issued_at values are at or before supplied time and within max age; session pass and agreement offer expiries are after supplied time",
        "trusted_time_oracle_used": False,
    }


def record_assessment(*, bundle_raw: bytes, policy_raw: bytes, now_utc: str,
                      max_age_seconds: int, output_dir: Path,
                      expected_bundle_sha256: str, expected_policy_sha256: str,
                      interrupt_after_prepare: bool = False,
                      installed_package: bool = False) -> dict:
    """Assess pinned bytes and durably record exactly one fixed JSON result."""
    if len(bundle_raw) > MAX_INPUT_BYTES or len(policy_raw) > MAX_INPUT_BYTES:
        raise ActionRefused("raw_input_too_large")
    observed_bundle_pin = digest(bundle_raw)
    observed_policy_pin = digest(policy_raw)
    if observed_bundle_pin != expected_bundle_sha256:
        raise ActionRefused(f"bundle_raw_pin_mismatch:{observed_bundle_pin}")
    if observed_policy_pin != expected_policy_sha256:
        raise ActionRefused(f"policy_raw_pin_mismatch:{observed_policy_pin}")
    consumer = load_consumer(installed_package=installed_package)
    bundle = consumer._parse_raw(bundle_raw, "bundle")
    policy = consumer._parse_raw(policy_raw, "policy")
    freshness = check_caller_freshness(bundle, now_utc=now_utc, max_age_seconds=max_age_seconds)
    assessment = consumer.assess_bundle(bundle, policy).as_dict()
    if assessment.get("outcome") != "ACCEPT":
        raise ActionRefused("consumer_assessment_not_accept")
    if not isinstance(assessment.get("bundle_digest"), str) or not assessment["bundle_digest"].startswith("sha256:"):
        raise ActionRefused("consumer_bundle_digest_missing")
    if not isinstance(assessment.get("policy", {}).get("digest"), str) or not assessment["policy"]["digest"].startswith("sha256:"):
        raise ActionRefused("consumer_policy_digest_missing")

    report = {
        "format": "continuity-receipt-independent-agent-assessment-record/1",
        "result": "LOCAL_ASSESSMENT_RECORDED_NOT_AUTHORIZATION",
        "local_action": "write_fixed_local_assessment_json",
        "local_action_performed": True,
        "receipt_claimed_action_executed": False,
        "consumer_assessment": assessment,
        "input_pins": {
            "bundle_bytes": len(bundle_raw), "bundle_raw_sha256": observed_bundle_pin,
            "bundle_canonical_sha256": assessment["bundle_digest"],
            "policy_bytes": len(policy_raw), "policy_raw_sha256": observed_policy_pin,
            "policy_canonical_sha256": assessment["policy"]["digest"],
        },
        "caller_freshness_policy": freshness,
        "source_pins_observed_locally": source_pins(consumer),
        "limitations": [
            "The output write is the only action; no receipt-described action, tool, command, payment, or network request is executed.",
            "ACCEPT is the local verifier plus caller policy result and does not establish identity, authority, currentness, revocation, execution, complete history, or independent adoption.",
            "The SQLite journal prevents repeat recording in this local directory and fails closed after an interrupted PREPARED operation; it is not a multi-host ledger.",
        ],
    }
    output_raw = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    output_dir = Path(output_dir).expanduser().absolute()
    _ensure_operator_dir(output_dir)
    op_id = digest((observed_bundle_pin + "\n" + observed_policy_pin).encode("ascii"))
    db = _connect_state(output_dir)
    try:
        _prepare(db, output_dir, op_id, observed_bundle_pin, observed_policy_pin)
        if interrupt_after_prepare:
            raise ActionRefused("test_interruption_after_prepare")
        _atomic_write(output_dir, output_raw)
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute(
                "UPDATE operations SET state='COMPLETE', output_sha256=? WHERE operation_id=? AND state='PREPARED'",
                (digest(output_raw), op_id),
            )
            if db.execute("SELECT changes()").fetchone()[0] != 1:
                raise ActionRefused("prepared_operation_transition_failed")
            db.execute("COMMIT")
        except Exception:
            db.execute("ROLLBACK")
            raise
    finally:
        db.close()
    _fsync_directory(output_dir)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record-assessment", action="store_true", required=True,
                        help="opt in to writing the single fixed local JSON assessment")
    parser.add_argument("--bundle-sha256", required=True, help="expected raw bundle sha256:<hex>")
    parser.add_argument("--policy-sha256", required=True, help="expected raw policy sha256:<hex>")
    parser.add_argument("--bundle", type=Path, default=EXAMPLE / "bundle.json", help="raw bundle JSON input")
    parser.add_argument("--policy", type=Path, default=EXAMPLE / "policy.json", help="raw caller policy JSON input")
    parser.add_argument("--now-utc", required=True, help="caller-supplied UTC RFC3339 time; not a trusted oracle")
    parser.add_argument("--max-age-seconds", required=True, type=int, help="maximum allowed receipt age, 1..86400")
    parser.add_argument("--output-dir", required=True, help="operator-selected local evidence directory")
    parser.add_argument("--installed-package", action="store_true",
                        help="use the installed package and fail if it resolves to this source checkout")
    args = parser.parse_args(argv)
    try:
        bundle_raw = read_pinned(args.bundle, args.bundle_sha256, "bundle")
        policy_raw = read_pinned(args.policy, args.policy_sha256, "policy")
        report = record_assessment(
            bundle_raw=bundle_raw, policy_raw=policy_raw, now_utc=args.now_utc,
            max_age_seconds=args.max_age_seconds, output_dir=Path(args.output_dir),
            expected_bundle_sha256=args.bundle_sha256, expected_policy_sha256=args.policy_sha256,
            installed_package=args.installed_package,
        )
        print(json.dumps({"status": "RECORDED", "path": str(Path(args.output_dir).expanduser().absolute() / OUTPUT_NAME), "result": report["result"]}, sort_keys=True))
        return 0
    except (OSError, sqlite3.Error, ValueError, ImportError, ActionRefused) as exc:
        print(json.dumps({"status": "REFUSED", "reason": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
