"""Native-process witness enforcement and honest publication-fault regressions."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from continuity_receipt import memory_resume, witness_file

ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-11-01T13:15:00Z"
SCOPE = "test:witness-hardening"
CONTEXT = "witness-cli-regression"


class WitnessCLIHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cpr-witness-cli-")
        self.root = Path(self.temporary.name)
        self.data = self.root / "runtime" / "data"
        self.trust = self.root / "runtime" / "trust" / "receiver.sqlite3"
        self.inputs = self.root / "input"
        self.inputs.mkdir()
        self.witness = self.root / "witness.json"
        self.private = self.root / "operator.pem"
        self.public = self.root / "operator-public.pem"
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()))
        self.private.chmod(0o600)
        self.public.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.common = ["--data-root", str(self.data), "--trust-db", str(self.trust),
                       "--context", CONTEXT, "--scope", SCOPE,
                       "--public-key", str(self.public), "--now", NOW]
        self.assertEqual(self.native(["init"]).returncode, 0)
        self.s1 = self.publish("S1\n", "none")["reference"]
        backup = self.root / "s1-backup"
        shutil.copytree(self.data, backup / "data")
        shutil.copytree(self.trust.parent, backup / "trust")
        self.s2 = self.publish("S2\n", self.s1["checkpoint_digest"])["reference"]

    def tearDown(self):
        self.temporary.cleanup()

    def native(self, command):
        # -I avoids ambient module selection; the only injected path is this
        # checkout, and every command is a newly started Python process.
        bridge = ("import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); "
                  "runpy.run_module('continuity_receipt.memory_resume',run_name='__main__')")
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.root), "LC_ALL": "C.UTF-8"}
        return subprocess.run([sys.executable, "-I", "-B", "-c", bridge, str(ROOT),
                               *command, *self.common], capture_output=True,
                              text=True, env=env, cwd=self.root, timeout=20)

    def in_process(self, command):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = memory_resume.main([*command, *self.common])
        return code, stdout.getvalue(), stderr.getvalue()

    def publish_args(self, text, expected, *extra):
        (self.inputs / "notes.txt").write_text(text)
        return ["publish", "--input-root", str(self.inputs), "--key-pem", str(self.private),
                "--expected-reference", expected, *extra]

    def publish(self, text, expected, *extra):
        process = self.native(self.publish_args(text, expected, *extra))
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(len(process.stdout.splitlines()), 1)
        payload = json.loads(process.stdout)
        self.assertEqual(payload["outcome"], "ACCEPT", payload)
        return payload

    def status(self):
        process = self.native(["status"])
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        return json.loads(process.stdout)["reference"]

    def write_witness(self, reference):
        self.witness.write_text(json.dumps({name: reference[name] for name in
                                ("sequence", "checkpoint_digest", "generation_id")}))

    def restore_s1(self):
        self.data.rename(self.root / "displaced-data")
        self.trust.parent.rename(self.root / "displaced-trust")
        shutil.copytree(self.root / "s1-backup" / "data", self.data)
        shutil.copytree(self.root / "s1-backup" / "trust", self.trust.parent)

    def resume(self, *extra):
        return self.native(["resume", "--memory-path", "notes.txt", *extra])

    def assert_refused(self, process):
        self.assertNotEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(process.stdout, "", "refused recall emitted bytes")
        report = json.loads(process.stderr)
        self.assertIn(report["outcome"], ("REJECT", "NEEDS_EVIDENCE"))
        return report

    def assert_partial_publication(self, code, stdout, expected_sequence):
        self.assertNotEqual(code, 0)
        self.assertEqual(len(stdout.splitlines()), 1, "publication emitted multiple final records")
        report = json.loads(stdout)
        self.assertNotEqual(report["outcome"], "ACCEPT")
        self.assertIs(report["local_committed"], True)
        self.assertEqual(report["reference"]["sequence"], expected_sequence)
        self.assertEqual(report["witness_publication"]["outcome"], "INCOMPLETE")
        self.assertEqual(self.status()["sequence"], expected_sequence)
        return report

    def test_legacy_no_witness_is_explicitly_optional(self):
        process = self.resume()
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stdout, "S2\n")

    def test_configured_invalid_witness_never_releases_restored_content(self):
        self.restore_s1()
        invalid = [None, b"{}", b"[]", b"not-json", b"\xef\xbb\xbf{}",
                   json.dumps({"min_sequence": 2, "checkpoint_digest": self.s2["checkpoint_digest"]}).encode(),
                   json.dumps({"sequence": True, "checkpoint_digest": self.s2["checkpoint_digest"]}).encode(),
                   json.dumps({"sequence": 2, "checkpoint_digest": self.s2["checkpoint_digest"], "observed_at": NOW}).encode()]
        for content in invalid:
            with self.subTest(content=content):
                self.witness.unlink(missing_ok=True)
                if content is not None:
                    self.witness.write_bytes(content)
                self.assert_refused(self.resume("--witness-file", str(self.witness)))

    def test_configured_directory_fifo_and_oversized_file_refuse_without_memory(self):
        directory = self.root / "witness-directory"
        directory.mkdir()
        fifo = self.root / "witness-fifo"
        os.mkfifo(fifo)
        oversized = self.root / "oversized.json"
        oversized.write_bytes(b" " * (witness_file.MAX_WITNESS_BYTES + 1))
        for path in (directory, fifo, oversized):
            with self.subTest(path=path.name):
                self.assert_refused(self.resume("--witness-file", str(path)))

    def test_witness_leaf_and_parent_symlinks_are_not_followed(self):
        outside = self.root / "outside"
        outside.mkdir()
        external = outside / "witness.json"
        raw = json.dumps({name: self.s2[name] for name in ("sequence", "checkpoint_digest", "generation_id")})
        external.write_text(raw)
        self.witness.symlink_to(external)
        self.assert_refused(self.resume("--witness-file", str(self.witness)))
        linked_parent = self.root / "linked-parent"
        linked_parent.symlink_to(outside, target_is_directory=True)
        self.assert_refused(self.resume("--witness-file", str(linked_parent / "witness.json")))
        self.assertEqual(external.read_text(), raw)

    def test_permission_failure_does_not_fall_back_to_unwitnessed_recall(self):
        self.write_witness(self.s2)
        with mock.patch.object(witness_file, "read_bounded_regular", side_effect=PermissionError("injected unreadable witness")):
            code, stdout, stderr = self.in_process(["resume", "--memory-path", "notes.txt",
                                                  "--witness-file", str(self.witness)])
        self.assertNotEqual(code, 0)
        self.assertEqual(stdout, "")
        self.assertEqual(json.loads(stderr)["outcome"], "REJECT")

    def test_required_witness_requires_both_file_and_independent_pin(self):
        self.write_witness(self.s2)
        for options in (("--require-witness",),
                        ("--require-witness", "--witness-file", str(self.witness)),
                        ("--expected-witness-checkpoint", self.s2["checkpoint_digest"])):
            with self.subTest(options=options):
                self.assert_refused(self.resume(*options))

    def test_empty_explicit_read_options_never_silently_disable_checks(self):
        self.write_witness(self.s2)
        cases = [
            (("--witness-file", ""), "off_host_witness_path_invalid"),
            (("--expected-witness-checkpoint", ""), "off_host_witness_expected_reference_invalid"),
            (("--witness-file", str(self.witness), "--expected-witness-checkpoint", ""),
             "off_host_witness_expected_reference_invalid"),
            (("--predicate-file", ""), "semantic_predicate_path_invalid"),
            (("--profile", ""), "receiver_profile_path_invalid"),
        ]
        for options, reason in cases:
            with self.subTest(options=options):
                report = self.assert_refused(self.resume(*options))
                self.assertIn(reason, report["reason_codes"])

    def test_empty_explicit_witness_publish_fails_before_local_commit(self):
        process = self.native(self.publish_args("S3\n", self.s2["checkpoint_digest"],
                                               "--witness-file", ""))
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(len(process.stdout.splitlines()), 1)
        report = json.loads(process.stdout)
        self.assertIs(report["local_committed"], False)
        self.assertIn("off_host_witness_path_invalid", report["reason_codes"])
        self.assertEqual(self.status(), self.s2)

    def test_matching_current_witness_pin_accepts_healthy_state(self):
        self.write_witness(self.s2)
        process = self.resume("--witness-file", str(self.witness), "--require-witness",
                              "--expected-witness-checkpoint", self.s2["checkpoint_digest"])
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stdout, "S2\n")

    def test_authentic_old_witness_cannot_satisfy_separately_retained_new_pin(self):
        self.write_witness(self.s1)
        self.restore_s1()
        report = self.assert_refused(self.resume("--witness-file", str(self.witness), "--require-witness",
                                    "--expected-witness-checkpoint", self.s2["checkpoint_digest"]))
        self.assertIn("off_host_witness_reference_mismatch", report["reason_codes"])

    def test_current_witness_pin_rejects_joint_restore_before_delivery(self):
        self.write_witness(self.s2)
        self.restore_s1()
        self.assert_refused(self.resume("--witness-file", str(self.witness), "--require-witness",
                            "--expected-witness-checkpoint", self.s2["checkpoint_digest"]))

    def test_authentic_old_witness_without_independent_pin_remains_only_a_floor(self):
        self.write_witness(self.s1)
        self.restore_s1()
        process = self.resume("--witness-file", str(self.witness))
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stdout, "S1\n")
        # This is an explicit limit, not a secure-currentness success. Adding
        # the independently retained S2 pin must refuse the identical inputs.
        self.assert_refused(self.resume("--witness-file", str(self.witness), "--require-witness",
                            "--expected-witness-checkpoint", self.s2["checkpoint_digest"]))

    def test_required_pin_is_bound_into_the_approved_policy_digest(self):
        self.write_witness(self.s2)
        weak = self.resume("--witness-file", str(self.witness))
        strict = self.resume("--witness-file", str(self.witness), "--require-witness",
                             "--expected-witness-checkpoint", self.s2["checkpoint_digest"])
        for process in (weak, strict):
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(process.stdout, "S2\n")
        weak_report, strict_report = json.loads(weak.stderr), json.loads(strict.stderr)
        self.assertEqual(weak_report["policy"]["version"], "2")
        self.assertEqual(strict_report["policy"]["version"], "2")
        self.assertNotEqual(weak_report["policy"]["digest"], strict_report["policy"]["digest"])
        self.assertEqual(weak_report["decision"]["approved_output_digest"],
                         strict_report["decision"]["approved_output_digest"])

    def test_successful_publication_has_one_final_record_and_atomic_mode600_witness(self):
        self.write_witness(self.s2)
        result = self.publish("S3\n", self.s2["checkpoint_digest"], "--witness-file", str(self.witness))
        self.assertIs(result["local_committed"], True)
        self.assertEqual(json.loads(self.witness.read_text()), {name: result["reference"][name]
                         for name in ("sequence", "checkpoint_digest", "generation_id")})
        self.assertEqual(stat.S_IMODE(self.witness.stat().st_mode), 0o600)
        self.assertEqual(self.status(), result["reference"])

    def test_missing_witness_parent_fails_before_local_commit(self):
        missing = self.root / "uncreated-parent" / "witness.json"
        process = self.native(self.publish_args("S3\n", self.s2["checkpoint_digest"],
                                               "--witness-file", str(missing)))
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(len(process.stdout.splitlines()), 1)
        report = json.loads(process.stdout)
        self.assertIs(report["local_committed"], False)
        self.assertEqual(self.status(), self.s2)
        self.assertFalse(missing.exists())

    def test_postcommit_failure_reports_actual_committed_state_in_one_record(self):
        self.write_witness(self.s2)
        old = self.witness.read_bytes()
        with mock.patch.object(witness_file.WitnessPublication, "commit", side_effect=OSError("injected postcommit witness failure")):
            code, stdout, _ = self.in_process(self.publish_args("S3\n", self.s2["checkpoint_digest"],
                                               "--witness-file", str(self.witness)))
        self.assert_partial_publication(code, stdout, 3)
        self.assertEqual(self.witness.read_bytes(), old)

    def test_cleanup_failure_after_complete_witness_write_has_one_honest_final_record(self):
        self.write_witness(self.s2)
        original_exit = witness_file.WitnessPublication.__exit__

        def fail_after_cleanup(publication, exc_type, exc_value, traceback):
            original_exit(publication, exc_type, exc_value, traceback)
            raise OSError("injected cleanup failure after completed witness write")

        with mock.patch.object(witness_file.WitnessPublication, "__exit__", new=fail_after_cleanup):
            code, stdout, _ = self.in_process(self.publish_args("S3\n", self.s2["checkpoint_digest"],
                                               "--witness-file", str(self.witness)))
        self.assertNotEqual(code, 0)
        self.assertEqual(len(stdout.splitlines()), 1)
        report = json.loads(stdout)
        self.assertNotEqual(report["outcome"], "ACCEPT")
        self.assertIs(report["local_committed"], True)
        self.assertEqual(report["reference"]["sequence"], 3)
        self.assertIn(report["witness_publication"]["outcome"], ("COMPLETE", "INCOMPLETE"))
        self.assertEqual(self.status(), report["reference"])
        self.assertEqual(json.loads(self.witness.read_text())["checkpoint_digest"],
                         report["reference"]["checkpoint_digest"])

    def test_atomic_replace_failure_preserves_previous_witness_after_local_commit(self):
        self.write_witness(self.s2)
        old = self.witness.read_bytes()
        with mock.patch.object(witness_file.os, "replace", side_effect=OSError("injected replace failure")):
            code, stdout, _ = self.in_process(self.publish_args("S3\n", self.s2["checkpoint_digest"],
                                               "--witness-file", str(self.witness)))
        self.assert_partial_publication(code, stdout, 3)
        self.assertEqual(self.witness.read_bytes(), old)

    def test_directory_sync_failure_does_not_claim_witness_rollback(self):
        self.write_witness(self.s2)
        original_commit = witness_file.WitnessPublication.commit
        original_fsync = witness_file.os.fsync

        def fail_directory_sync(publication, reference):
            def fsync(fd):
                if fd == publication.parent_fd and publication.temp_name is None:
                    raise OSError("injected directory sync failure")
                return original_fsync(fd)
            with mock.patch.object(witness_file.os, "fsync", side_effect=fsync):
                return original_commit(publication, reference)

        with mock.patch.object(witness_file.WitnessPublication, "commit", new=fail_directory_sync):
            code, stdout, _ = self.in_process(self.publish_args("S3\n", self.s2["checkpoint_digest"],
                                               "--witness-file", str(self.witness)))
        result = self.assert_partial_publication(code, stdout, 3)
        # Replacement happened; durability is uncertain. Reporting failure must
        # not pretend the new witness was removed or the local commit undone.
        self.assertEqual(json.loads(self.witness.read_text())["checkpoint_digest"], result["reference"]["checkpoint_digest"])

    def test_publication_does_not_downgrade_ahead_witness_after_joint_restore(self):
        self.write_witness(self.s2)
        old = self.witness.read_bytes()
        self.restore_s1()
        process = self.native(self.publish_args("forked S2\n", self.s1["checkpoint_digest"],
                                               "--witness-file", str(self.witness)))
        self.assertNotEqual(process.returncode, 0)
        report = json.loads(process.stdout)
        self.assertIs(report["local_committed"], False)
        self.assertEqual(self.status(), self.s1)
        self.assertEqual(self.witness.read_bytes(), old)

    def test_equal_sequence_conflicting_witness_blocks_publication_before_commit(self):
        self.write_witness({**self.s2, "checkpoint_digest": "sha256:" + "0" * 64})
        old = self.witness.read_bytes()
        process = self.native(self.publish_args("S3\n", self.s2["checkpoint_digest"],
                                               "--witness-file", str(self.witness)))
        self.assertNotEqual(process.returncode, 0)
        self.assertIs(json.loads(process.stdout)["local_committed"], False)
        self.assertEqual(self.status(), self.s2)
        self.assertEqual(self.witness.read_bytes(), old)

    def test_publication_refuses_symlink_target_without_writing_outside(self):
        outside = self.root / "outside.json"
        outside.write_text("outside remains unchanged\n")
        self.witness.symlink_to(outside)
        process = self.native(self.publish_args("S3\n", self.s2["checkpoint_digest"],
                                               "--witness-file", str(self.witness)))
        self.assertNotEqual(process.returncode, 0)
        self.assertIs(json.loads(process.stdout)["local_committed"], False)
        self.assertEqual(self.status(), self.s2)
        self.assertEqual(outside.read_text(), "outside remains unchanged\n")


if __name__ == "__main__":
    unittest.main()
