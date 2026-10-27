"""Fresh-process crash and hostile restore probes for the local receiver.

These exercise process termination and SQLite restart recovery on the current
filesystem. They do not simulate loss of power, torn sectors, or device-cache
failure.
"""
from __future__ import annotations

import json
import hashlib
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
WORKTREE = ROOT.parent
sys.path.insert(0, str(ROOT))

from continuity_receipt.receiver_store import ReceiverStore  # noqa: E402

NOW = "2026-10-23T12:00:00Z"
CONTEXT = "crash-test"
SCOPE = "memory:crash-test"
KEY_BYTES = bytes(range(32))


def make_store(base: Path) -> tuple[ReceiverStore, Ed25519PrivateKey]:
    key = Ed25519PrivateKey.from_private_bytes(KEY_BYTES)
    store = ReceiverStore(base / "data", base / "trust" / "receiver.sqlite3",
                          context=CONTEXT, scope=SCOPE,
                          trusted_public_key=key.public_key(), max_age_seconds=3600)
    initialized = store.initialize()
    if initialized["outcome"] != "ACCEPT":
        raise AssertionError(initialized)
    return store, key


def audit_rows(db: Path) -> list[tuple]:
    with sqlite3.connect(db, timeout=3) as conn:
        return conn.execute(
            "SELECT sequence,generation_id,checkpoint_digest,bundle_digest,manifest_digest "
            "FROM publication_audit ORDER BY sequence"
        ).fetchall()


def save_probe(name: str, value: dict) -> None:
    path = WORKTREE / "evidence" / f"crash-{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


class ReceiverCrashRecoveryTests(unittest.TestCase):
    def test_fresh_process_exit_at_each_publish_boundary_recovers_reference(self):
        for boundary in ("after_stage", "after_rename", "before_commit", "after_commit"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temp:
                base = Path(temp)
                store, key = make_store(base)
                first = store.publish({"nested/notes.txt": b"previous"},
                                      private_key=key, expected_checkpoint_digest=None, now=NOW)
                self.assertEqual(first["outcome"], "ACCEPT", first)
                previous = first["reference"]

                child = r'''
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from continuity_receipt.receiver_store import ReceiverStore
base = Path(sys.argv[2]); boundary = sys.argv[3]
key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
store = ReceiverStore(base / "data", base / "trust" / "receiver.sqlite3",
    context="crash-test", scope="memory:crash-test",
    trusted_public_key=key.public_key(), max_age_seconds=3600)
def stop(where):
    if where == boundary:
        os._exit(73)
store.publish({"nested/notes.txt": b"replacement"}, private_key=key,
    expected_checkpoint_digest=sys.argv[4], now="2026-10-23T12:00:00Z", fault_hook=stop)
os._exit(74)
'''
                try:
                    proc = subprocess.run(
                        [sys.executable, "-c", child, str(ROOT), str(base), boundary,
                         previous["checkpoint_digest"]],
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True, timeout=15,
                        env={**os.environ, "PYTHONPATH": str(ROOT)},
                    )
                    current = store.current_reference()
                    recalled = store.recall(now=NOW)
                    audits = audit_rows(base / "trust" / "receiver.sqlite3")
                    selected_is_audited = bool(current) and any(
                        row[1] == current["generation_id"] and row[0] == current["sequence"]
                        for row in audits
                    )
                    record = {
                        "boundary": boundary,
                        "child_returncode": proc.returncode,
                        "child_stdout": proc.stdout,
                        "child_stderr": proc.stderr,
                        "expected_exit": 73,
                        "reference": current,
                        "audit_sequences": [row[0] for row in audits],
                        "selected_reference_in_audit": selected_is_audited,
                        "recall_outcome": recalled["outcome"],
                        "recall_reason_codes": recalled["reason_codes"],
                        "recalled_files": ({p: v.decode("utf-8") for p, v in recalled["files"].items()}
                                           if recalled.get("files") is not None else None),
                    }
                    save_probe(boundary.replace("_", "-"), record)
                except subprocess.TimeoutExpired as exc:
                    save_probe(boundary.replace("_", "-"), {
                        "boundary": boundary, "timeout_seconds": 15,
                        "stdout": (exc.stdout or "").decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout,
                        "stderr": (exc.stderr or "").decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr,
                    })
                    self.fail(f"child process timed out at {boundary}")

                self.assertEqual(proc.returncode, 73, record)
                self.assertTrue(selected_is_audited, record)
                self.assertEqual(recalled["outcome"], "ACCEPT", record)
                self.assertEqual(len(audits), 2 if boundary == "after_commit" else 1, record)
                if boundary == "after_commit":
                    self.assertNotEqual(current, previous, record)
                    self.assertEqual(recalled["files"], {"nested/notes.txt": b"replacement"}, record)
                else:
                    self.assertEqual(current, previous, record)
                    self.assertEqual(recalled["files"], {"nested/notes.txt": b"previous"}, record)

    def test_data_only_restore_cannot_select_old_generation(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            store, key = make_store(base)
            first = store.publish({"nested/state.txt": b"old"}, private_key=key,
                                  expected_checkpoint_digest=None, now=NOW)
            old_id = first["reference"]["generation_id"]
            old_copy = base / "old-generation-copy"
            import shutil
            shutil.copytree(base / "data" / "generations" / old_id, old_copy)
            second = store.publish({"nested/state.txt": b"new"}, private_key=key,
                                   expected_checkpoint_digest=first["reference"]["checkpoint_digest"], now=NOW)
            self.assertEqual(second["outcome"], "ACCEPT", second)
            selected = base / "data" / "generations" / second["reference"]["generation_id"]
            import shutil
            shutil.rmtree(selected)
            shutil.copytree(old_copy, selected)
            received = []
            result = store.recall(now=NOW, sink=received.append)
            record = {"old_generation_id": old_id, "selected_generation_id": second["reference"]["generation_id"],
                      "trusted_reference": store.current_reference(), "outcome": result["outcome"],
                      "reason_codes": result["reason_codes"], "sink_calls": len(received)}
            save_probe("data-only-restore", record)
            self.assertEqual(result["outcome"], "REJECT", record)
            self.assertIsNone(result["files"])
            self.assertEqual(received, [])
            self.assertEqual(store.current_reference(), second["reference"])

    def test_missing_generation_is_rejected_without_sink(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            store, key = make_store(base)
            published = store.publish({"nested/state.txt": b"saved"}, private_key=key,
                                      expected_checkpoint_digest=None, now=NOW)
            generation = base / "data" / "generations" / published["reference"]["generation_id"]
            import shutil
            shutil.rmtree(generation)
            received = []
            result = store.recall(now=NOW, sink=received.append)
            record = {"reference": published["reference"], "outcome": result["outcome"],
                      "reason_codes": result["reason_codes"], "sink_calls": len(received)}
            save_probe("missing-generation", record)
            self.assertEqual(result["outcome"], "REJECT", record)
            self.assertIsNone(result["files"])
            self.assertEqual(received, [])

    def test_corrupted_selected_bundle_is_rejected_without_sink(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            store, key = make_store(base)
            published = store.publish({"nested/state.txt": b"saved"}, private_key=key,
                                      expected_checkpoint_digest=None, now=NOW)
            bundle = (base / "data" / "generations" / published["reference"]["generation_id"]
                      / "bundle.json")
            original = bundle.read_bytes()
            bundle.write_bytes(original[:-1] + (b" " if original[-1:] != b" " else b"!"))
            received = []
            result = store.recall(now=NOW, sink=received.append)
            record = {"outcome": result["outcome"], "reason_codes": result["reason_codes"],
                      "sink_calls": len(received)}
            save_probe("corrupted-generation", record)
            self.assertEqual(result["outcome"], "REJECT", record)
            self.assertIsNone(result["files"])
            self.assertEqual(received, [])

    def test_malformed_manifest_and_fifo_are_rejected_without_sink(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            store, key = make_store(base)
            published = store.publish({"nested/state.txt": b"saved"}, private_key=key,
                                      expected_checkpoint_digest=None, now=NOW)
            generation = base / "data" / "generations" / published["reference"]["generation_id"]
            manifest = generation / "manifest.json"
            original_manifest = manifest.read_bytes()
            malformed_bytes = b'{"files":[],"files":[]}'
            manifest.write_bytes(malformed_bytes)
            # Keep the trusted digest aligned so this reaches strict manifest
            # parsing instead of stopping at the earlier generation hash gate.
            with sqlite3.connect(base / "trust" / "receiver.sqlite3") as conn:
                conn.execute("UPDATE current_reference SET manifest_digest=? WHERE singleton=1",
                             ("sha256:" + hashlib.sha256(malformed_bytes).hexdigest(),))
            received = []
            malformed = store.recall(now=NOW, sink=received.append)
            manifest.write_bytes(original_manifest)
            with sqlite3.connect(base / "trust" / "receiver.sqlite3") as conn:
                conn.execute("UPDATE current_reference SET manifest_digest=? WHERE singleton=1",
                             ("sha256:" + hashlib.sha256(original_manifest).hexdigest(),))

            files = generation / "files"
            (files / "nested" / "state.txt").unlink()
            os.mkfifo(files / "nested" / "state.txt")
            fifo = store.recall(now=NOW, sink=received.append)
            record = {
                "malformed_manifest": {"outcome": malformed["outcome"], "reason_codes": malformed["reason_codes"]},
                "fifo": {"outcome": fifo["outcome"], "reason_codes": fifo["reason_codes"]},
                "sink_calls": len(received),
            }
            save_probe("hostile-restore", record)
            for label, result in (("malformed manifest", malformed), ("FIFO", fifo)):
                with self.subTest(case=label):
                    self.assertEqual(result["outcome"], "REJECT", record)
                    self.assertIsNone(result["files"])
            self.assertEqual(received, [])


if __name__ == "__main__":
    unittest.main()
