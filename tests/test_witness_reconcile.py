"""Pinned witness-only recovery, including process restart and partial writes."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import fcntl
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from continuity_receipt.memory_resume import main
from continuity_receipt.receiver_store import ReceiverStore
from continuity_receipt.witness_file import WitnessPublication


class WitnessReconcileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cpr-witness-reconcile-")
        self.root = Path(self.temporary.name)
        self.data = self.root / "data"
        self.witness = self.root / "witness.json"
        self.input = self.root / "input"
        self.input.mkdir()
        self.secret = "approved S2 retained memory; do not print during repair\n"
        self.private = self.root / "private.pem"
        self.public = self.root / "public.pem"
        key = Ed25519PrivateKey.generate()
        self.private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        self.common = ["--data-root", str(self.data), "--trust-db", str(self.root / "trust.sqlite3"),
                       "--context", "reconcile-test", "--scope", "user:test",
                       "--public-key", str(self.public), "--now", "2026-11-01T12:00:00Z"]
        self.assertEqual(self.invoke("init")[0], 0)
        (self.input / "memory.txt").write_text("accepted S1 memory\n")
        code, self.first = self.invoke("publish", "--key-pem", str(self.private),
            "--input-root", str(self.input), "--expected-reference", "none",
            "--witness-file", str(self.witness))
        self.assertEqual(code, 0, self.first)
        self.old_witness = self.witness.read_bytes()
        (self.input / "memory.txt").write_text(self.secret)
        code, self.second = self.invoke("publish", "--key-pem", str(self.private),
            "--input-root", str(self.input), "--expected-reference", self.first["reference"]["checkpoint_digest"])
        self.assertEqual(code, 0, self.second)
        self.reference = self.second["reference"]
        self.pin = self.reference["checkpoint_digest"]

    def tearDown(self):
        self.temporary.cleanup()

    def invoke(self, command, *options, common=None):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main([command, *(self.common if common is None else common), *options])
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(len(out.getvalue().splitlines()), 1, out.getvalue())
        self.assertNotIn(self.secret.strip(), out.getvalue())
        return code, json.loads(out.getvalue())

    def reconcile(self, pin=None, witness=None, common=None):
        return self.invoke("witness-reconcile", "--witness-file", str(witness or self.witness),
                           "--expected-reference", self.pin if pin is None else pin, common=common)

    def generations(self):
        return sorted(path.name for path in (self.data / "generations").iterdir())

    def subprocess_cli(self, *args):
        # -I ignores inherited Python paths; this subprocess deliberately tests
        # the checkout. The separate acceptance runner tests the installed wheel.
        bridge = ("import runpy,sys;sys.path.insert(0,sys.argv.pop(1));"
                  "runpy.run_module('continuity_receipt.memory_resume',run_name='__main__')")
        return subprocess.run([sys.executable, "-I", "-B", "-c", bridge,
            str(Path(__file__).resolve().parents[1]), *args], cwd=self.root,
            capture_output=True, text=True, timeout=20, check=False)

    def assert_no_local_change(self, generations):
        self.assertEqual(self.invoke("status")[1]["reference"], self.reference)
        self.assertEqual(self.generations(), generations)

    def test_stale_witness_repair_and_retry_do_not_publish_or_deliver(self):
        generations = self.generations()
        with mock.patch.object(ReceiverStore, "publish", side_effect=AssertionError("repair published")):
            code, result = self.reconcile()
            self.assertEqual(code, 0, result)
            repaired = self.witness.read_bytes()
            code, again = self.reconcile()
        self.assertEqual(code, 0, again)
        self.assertEqual(result, again)
        self.assertEqual(result["operation"], "witness-reconcile")
        self.assertIs(result["local_publication_performed"], False)
        self.assertEqual(result["verified_reference"], self.reference)
        self.assertEqual(result["witness_publication"]["outcome"], "COMPLETE")
        self.assertEqual(result["policy"]["id"], "cpr-memory-witness-reconcile")
        self.assertEqual(result["policy"]["version"], "1")
        self.assertRegex(result["policy"]["digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertNotIn("files", result)
        self.assertEqual(self.witness.read_bytes(), repaired)
        self.assert_no_local_change(generations)

    def test_missing_witness_is_created_from_verified_independent_pin(self):
        self.witness.unlink()
        generations = self.generations()
        code, result = self.reconcile()
        self.assertEqual(code, 0, result)
        self.assertEqual(json.loads(self.witness.read_bytes())["checkpoint_digest"], self.pin)
        self.assert_no_local_change(generations)

    def test_historical_pin_and_invalid_pin_refuse_without_changing_evidence(self):
        generations = self.generations()
        for pin in (self.first["reference"]["checkpoint_digest"], "none", "", "sha256:" + "A" * 64):
            with self.subTest(pin=pin):
                code, result = self.reconcile(pin=pin)
                self.assertEqual(code, 2, result)
                self.assertEqual(result["outcome"], "REJECT")
                self.assertIs(result["local_publication_performed"], False)
                self.assertNotIn("verified_reference", result)
                self.assertEqual(self.witness.read_bytes(), self.old_witness)
        self.assert_no_local_change(generations)

    def test_policy_digest_changes_with_expected_pin(self):
        code, rejected = self.reconcile(pin=self.first["reference"]["checkpoint_digest"])
        self.assertEqual(code, 2)
        code, accepted = self.reconcile()
        self.assertEqual(code, 0)
        self.assertNotEqual(rejected["policy"]["digest"], accepted["policy"]["digest"])

    def test_ahead_fork_and_generation_conflict_preserve_existing_witness(self):
        for edits in ({"sequence": 3}, {"checkpoint_digest": "sha256:" + "f" * 64},
                      {"generation_id": "f" * 32}):
            with self.subTest(edits=edits):
                witness = {key: self.reference[key] for key in ("sequence", "checkpoint_digest", "generation_id")}
                witness.update(edits)
                raw = (json.dumps(witness) + "\n").encode()
                self.witness.write_bytes(raw)
                code, result = self.reconcile()
                self.assertEqual(code, 2, result)
                self.assertEqual(result["verified_reference"], self.reference)
                self.assertEqual(self.witness.read_bytes(), raw)

    def test_malformed_target_and_symlink_components_are_not_replaced(self):
        self.witness.write_bytes(b'{"sequence":true,"checkpoint_digest":"invalid"}\n')
        bad = self.witness.read_bytes()
        self.assertEqual(self.reconcile()[0], 2)
        self.assertEqual(self.witness.read_bytes(), bad)
        self.witness.unlink()
        outside = self.root / "outside.json"
        outside.write_bytes(self.old_witness)
        self.witness.symlink_to(outside)
        self.assertEqual(self.reconcile()[0], 2)
        self.assertTrue(self.witness.is_symlink())
        self.assertEqual(outside.read_bytes(), self.old_witness)
        directory = self.root / "directory"
        directory.mkdir()
        (directory / "witness.json").write_bytes(self.old_witness)
        link = self.root / "linked-directory"
        link.symlink_to(directory, target_is_directory=True)
        self.assertEqual(self.reconcile(witness=link / "witness.json")[0], 2)
        self.assertEqual((directory / "witness.json").read_bytes(), self.old_witness)

    def test_wrong_key_context_scope_and_expired_snapshot_refuse(self):
        alternate = self.root / "alternate-public.pem"
        alternate.write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        for option, value in (("--public-key", str(alternate)), ("--context", "wrong-context"),
                              ("--scope", "wrong-scope"), ("--now", "2026-11-02T12:00:00Z")):
            with self.subTest(option=option):
                common = self.common.copy()
                common[common.index(option) + 1] = value
                code, result = self.reconcile(common=common)
                self.assertNotEqual(code, 0, result)
                self.assertNotIn("verified_reference", result)
                self.assertEqual(self.witness.read_bytes(), self.old_witness)

    def test_tampered_retained_snapshot_refuses_and_preserves_witness(self):
        retained = self.data / "generations" / self.reference["generation_id"] / "files" / "memory.txt"
        retained.write_text("tampered bytes\n")
        code, result = self.reconcile()
        self.assertEqual(code, 2, result)
        self.assertNotIn("verified_reference", result)
        self.assertEqual(self.witness.read_bytes(), self.old_witness)

    def test_cooperating_lock_is_held_during_verified_read(self):
        original = ReceiverStore.recall_with_decision

        def checked_read(store, **kwargs):
            lock = next(self.root.glob(".cpr-witness-*.lock"))
            with lock.open("rb") as descriptor:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(descriptor.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return original(store, **kwargs)

        with mock.patch.object(ReceiverStore, "recall_with_decision", checked_read):
            self.assertEqual(self.reconcile()[0], 0)

    def test_read_commit_failure_never_updates_witness(self):
        import sqlite3
        original = ReceiverStore._connect

        class FailedCommit:
            def __init__(self, connection):
                self.connection = connection

            def __getattr__(self, name):
                return getattr(self.connection, name)

            def commit(self):
                raise sqlite3.OperationalError("injected read commit failure")

        with mock.patch.object(ReceiverStore, "_connect", lambda store: FailedCommit(original(store))):
            code, result = self.reconcile()
        self.assertEqual(code, 2, result)
        self.assertNotIn("verified_reference", result)
        self.assertEqual(self.witness.read_bytes(), self.old_witness)

    def test_reconcile_write_failure_before_and_after_replacement_is_retryable(self):
        generations = self.generations()
        original = WitnessPublication.commit
        for replace_first in (False, True):
            with self.subTest(replace_first=replace_first):
                self.witness.write_bytes(self.old_witness)

                def fail(publication, reference):
                    if replace_first:
                        original(publication, reference)
                    raise OSError("injected witness completion failure")

                with mock.patch.object(WitnessPublication, "commit", fail):
                    code, result = self.reconcile()
                self.assertEqual(code, 2, result)
                self.assertIs(result["local_publication_performed"], False)
                self.assertNotIn("local_committed", result)
                self.assertEqual(result["verified_reference"], self.reference)
                self.assertEqual(result["witness_publication"]["outcome"], "INCOMPLETE")
                visible = json.loads(self.witness.read_bytes())
                self.assertEqual(visible["sequence"], 2 if replace_first else 1)
                self.assert_no_local_change(generations)
                self.assertEqual(self.reconcile()[0], 0)
                self.assert_no_local_change(generations)

    def test_cleanup_failure_emits_one_final_rejection_after_completed_write(self):
        original = WitnessPublication.__exit__

        def fail(publication, *args):
            original(publication, *args)
            raise OSError("injected cleanup failure")

        with mock.patch.object(WitnessPublication, "__exit__", fail):
            code, result = self.reconcile()
        self.assertEqual(code, 2, result)
        self.assertEqual(result["outcome"], "REJECT")
        self.assertEqual(result["witness_publication"]["outcome"], "COMPLETE")
        self.assertEqual(result["verified_reference"], self.reference)
        self.assertEqual(self.reconcile()[0], 0)

    def test_actual_partial_publication_recovers_in_fresh_process_then_strict_resume(self):
        (self.input / "memory.txt").write_text("accepted S3 after partial publication\n")
        with mock.patch.object(WitnessPublication, "commit", side_effect=OSError("injected postcommit witness failure")):
            code, partial = self.invoke("publish", "--key-pem", str(self.private),
                "--input-root", str(self.input), "--expected-reference", self.pin,
                "--witness-file", str(self.witness))
        self.assertEqual(code, 2, partial)
        self.assertIs(partial["local_committed"], True)
        self.assertEqual(partial["witness_publication"]["outcome"], "INCOMPLETE")
        self.reference = partial["reference"]
        self.pin = self.reference["checkpoint_digest"]
        self.assertEqual(self.reference["sequence"], 3)
        generations = self.generations()
        repair_args = ["witness-reconcile", *self.common, "--witness-file", str(self.witness),
                       "--expected-reference", self.pin]
        repaired = self.subprocess_cli(*repair_args)
        self.assertEqual(repaired.returncode, 0, repaired.stderr + repaired.stdout)
        self.assertEqual(repaired.stderr, "")
        self.assertEqual(len(repaired.stdout.splitlines()), 1)
        self.assertNotIn("accepted S3", repaired.stdout)
        self.assertEqual(json.loads(repaired.stdout)["verified_reference"], self.reference)
        witness_bytes = self.witness.read_bytes()
        repeated = self.subprocess_cli(*repair_args)
        self.assertEqual(repeated.returncode, 0, repeated.stdout)
        self.assertEqual(self.witness.read_bytes(), witness_bytes)
        resumed = self.subprocess_cli("resume", *self.common, "--witness-file", str(self.witness),
            "--require-witness", "--expected-witness-checkpoint", self.pin, "--memory-path", "memory.txt")
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual(resumed.stdout, "accepted S3 after partial publication\n")
        self.assertEqual(json.loads(resumed.stderr)["reference"], self.reference)
        self.assert_no_local_change(generations)


if __name__ == "__main__":
    unittest.main()
