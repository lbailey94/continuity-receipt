import resource
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from continuity_receipt.receiver_store import ReceiverStore  # noqa: E402
from continuity_receipt.receiver_store import ReceiverDecision  # noqa: E402


class ReceiverStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.data = self.base / "data"
        self.db = self.base / "trust" / "receiver.sqlite3"
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.store = ReceiverStore(self.data, self.db, context="local:test",
                                   scope="memory:test", trusted_public_key=self.key.public_key(),
                                   max_age_seconds=3600)
        self.now = "2026-10-23T12:00:00Z"
        self.store.initialize()

    def tearDown(self):
        self.tmp.cleanup()

    def publish(self, files=None, expected=None, **kwargs):
        return self.store.publish(files if files is not None else {"notes.txt": b"one"},
                                  private_key=self.key, expected_checkpoint_digest=expected,
                                  now=self.now, **kwargs)

    def test_publish_and_recall_release_exact_captured_bytes(self):
        payload = {"notes.txt": bytearray(b"first"), "sub/empty": b"", "sub/other": b"also"}
        published = self.publish(payload)
        self.assertEqual(published["outcome"], "ACCEPT", published)
        reference = published["reference"]
        payload["notes.txt"][:] = b"later"
        self.assertEqual(self.store.current_reference(), reference)
        released = []
        result = self.store.recall(now=self.now, sink=released.append)
        self.assertEqual(result["outcome"], "ACCEPT", result)
        self.assertEqual(result["files"], {"notes.txt": b"first", "sub/empty": b"", "sub/other": b"also"})
        self.assertEqual(released, [result["files"]])
        self.assertEqual(result["reference"], reference)

    def test_decision_api_binds_immutable_capture_and_releases_only_after_commit(self):
        first = self.publish({"notes.txt": b"checked bytes"})
        seen = {}
        generation_file = self.data / "generations" / first["reference"]["generation_id"] / "files" / "notes.txt"
        def approve(files, reference):
            seen["reference"] = reference
            self.assertEqual(files["notes.txt"], b"checked bytes")
            with self.assertRaises(TypeError):
                files["notes.txt"] = b"substituted"
            generation_file.write_bytes(b"mutated after capture")
            return ReceiverDecision(True, "allowed", "test-policy", "1", "sha256:" + "a" * 64)
        result = self.store.recall_with_decision(now=self.now, decision_policy=approve)
        self.assertEqual(result["outcome"], "ACCEPT")
        self.assertEqual(result["files"]["notes.txt"], b"checked bytes")
        self.assertEqual(result["policy"], {"id": "test-policy", "version": "1", "digest": "sha256:" + "a" * 64})
        from continuity_receipt.canon import canonical_bytes, sha256_prefixed
        expected_files_digest = sha256_prefixed(canonical_bytes({
            "notes.txt": sha256_prefixed(b"checked bytes")
        }))
        self.assertEqual(result["decision"]["approved_output_digest"], expected_files_digest)
        self.assertEqual(result["decision"]["reference"], first["reference"])
        self.assertEqual(result["decision"]["reference"]["manifest_digest"], first["reference"]["manifest_digest"])
        self.assertEqual(dict(seen["reference"]), first["reference"])

    def test_decision_rejection_exception_and_commit_failure_return_no_payload(self):
        self.publish({"notes.txt": b"secret"})
        rejected = self.store.recall_with_decision(
            now=self.now, decision_policy=lambda files, ref: ReceiverDecision(False, "forbidden", "p", "1"))
        self.assertEqual(rejected["outcome"], "REJECT")
        self.assertIsNone(rejected["files"])
        failed = self.store.recall_with_decision(now=self.now,
            decision_policy=lambda files, ref: (_ for _ in ()).throw(RuntimeError("policy boom")))
        self.assertEqual(failed["outcome"], "REJECT")
        self.assertEqual(failed["reason_codes"], ["receiver_policy_failed:RuntimeError"])
        self.assertIsNone(failed["files"])
        for malformed in (object(), {"approved": True}, ReceiverDecision(False)):
            bad = self.store.recall_with_decision(now=self.now,
                decision_policy=lambda files, ref, value=malformed: value)
            self.assertEqual(bad["outcome"], "REJECT")
            self.assertIsNone(bad["files"])
        with self.assertRaisesRegex(TypeError, "receiver_decision_shape_invalid"):
            ReceiverDecision(1, "allowed", "p", "1", "sha256:" + "d" * 64)
        ambiguous = self.store.recall_with_decision(now=self.now,
            decision_policy=lambda files, ref: ReceiverDecision(True, "allowed", "", "", "sha256:" + "d" * 64))
        self.assertEqual(ambiguous["reason_codes"], ["receiver_policy_binding_missing"])
        self.assertIsNone(ambiguous["files"])

        original_connect = self.store._connect
        class CommitFailure:
            def __init__(self, conn): self.conn = conn
            def __getattr__(self, name): return getattr(self.conn, name)
            def commit(self): raise sqlite3.OperationalError("injected commit failure")
        import sqlite3
        with patch.object(self.store, "_connect", side_effect=lambda: CommitFailure(original_connect())):
            failed_commit = self.store.recall_with_decision(now=self.now,
                decision_policy=lambda files, ref: ReceiverDecision(True, "allowed", "p", "1", "sha256:" + "b" * 64))
        self.assertEqual(failed_commit["outcome"], "REJECT")
        self.assertIsNone(failed_commit["files"])

    def test_reads_never_initialize_missing_database_or_release_content(self):
        self.tmp.cleanup()
        absent = self.base / "absent" / "trust.sqlite3"
        store = ReceiverStore(self.base / "absent-data", absent, context="local:test",
                              scope="memory:test", trusted_public_key=self.key.public_key())
        self.assertIsNone(store.current_reference())
        self.assertFalse(absent.exists())
        received = []
        result = store.recall(now=self.now, sink=received.append)
        self.assertEqual(result["outcome"], "NEEDS_EVIDENCE")
        self.assertIsNone(result["files"])
        self.assertEqual(received, [])
        self.assertFalse(absent.exists())

    def test_database_must_be_outside_data_root_and_policy_is_immutable(self):
        with self.assertRaisesRegex(ValueError, "trust_db_inside_data_root"):
            ReceiverStore(self.data, self.data / "trust.sqlite3", context="local:test",
                          scope="memory:test", trusted_public_key=self.key.public_key())
        changed = ReceiverStore(self.data, self.db, context="local:other", scope="memory:test",
                                trusted_public_key=self.key.public_key())
        self.assertEqual(changed.initialize()["reason_codes"], ["receiver_policy_mismatch"])
        self.assertIsNone(self.store.current_reference())

    def test_writer_key_capture_limits_and_expected_reference_cas(self):
        wrong = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
        result = self.store.publish({"notes.txt": b"x"}, private_key=wrong,
                                    expected_checkpoint_digest=None, now=self.now)
        self.assertEqual(result["reason_codes"], ["writer_key_mismatch"])
        for files in ({"../escape": b"x"}, {"a\\b": b"x"}, {"empty": "not bytes"},
                      {"large": b"x" * (1024 * 1024 + 1)}):
            with self.subTest(files=list(files)):
                result = self.publish(files)
                self.assertEqual(result["outcome"], "REJECT")
                self.assertIsNone(self.store.current_reference())
        first = self.publish()
        self.assertEqual(first["outcome"], "ACCEPT", first)
        conflict = self.publish({"notes.txt": b"two"}, expected=None)
        self.assertEqual(conflict["reason_codes"], ["reference_conflict"])
        self.assertEqual(self.store.current_reference(), first["reference"])
        second = self.publish({"notes.txt": b"two"}, expected=first["reference"]["checkpoint_digest"])
        self.assertEqual(second["outcome"], "ACCEPT", second)
        self.assertEqual(second["reference"]["sequence"], 2)

    def test_fault_boundaries_leave_reference_at_the_durable_commit_point(self):
        first = self.publish()
        old = first["reference"]
        for boundary in ("after_stage", "after_rename", "before_commit"):
            def crash(where, target=boundary):
                if where == target:
                    raise RuntimeError("simulated crash")
            with self.subTest(boundary=boundary):
                with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                    self.publish({"notes.txt": boundary.encode()}, expected=old["checkpoint_digest"],
                                 fault_hook=crash)
                self.assertEqual(self.store.current_reference(), old)
                self.assertEqual(self.store.recall(now=self.now)["files"], {"notes.txt": b"one"})
                generations = {p.name for p in (self.data / "generations").iterdir()}
                self.assertEqual(generations, {old["generation_id"]})
        def crash_after_commit(where):
            if where == "after_commit":
                raise RuntimeError("simulated crash")
        with self.assertRaisesRegex(RuntimeError, "simulated crash"):
            self.publish({"notes.txt": b"committed"}, expected=old["checkpoint_digest"],
                         fault_hook=crash_after_commit)
        current = self.store.current_reference()
        self.assertNotEqual(current, old)
        self.assertEqual(self.store.recall(now=self.now)["files"], {"notes.txt": b"committed"})
        self.assertTrue((self.data / "generations" / current["generation_id"]).is_dir())

    def test_publish_reclaims_uncommitted_crash_orphans_but_keeps_audited_generations(self):
        first = self.publish()
        generations = self.data / "generations"
        (generations / (".stage-" + "f" * 32)).mkdir()
        orphan = "e" * 32
        (generations / orphan).mkdir()
        result = self.publish({"notes.txt": b"next"}, expected=first["reference"]["checkpoint_digest"])
        self.assertEqual(result["outcome"], "ACCEPT", result)
        names = {p.name for p in generations.iterdir()}
        self.assertEqual(names, {first["reference"]["generation_id"], result["reference"]["generation_id"]})

    def test_deep_valid_snapshot_stays_within_a_bounded_descriptor_budget(self):
        depth = "/".join(f"d{i}" for i in range(16))
        files = {f"{depth}/file-{i}.txt": str(i).encode() for i in range(64)}
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard < 64:
            self.skipTest("host descriptor limit is below the bounded test budget")
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(64, hard), hard))
        try:
            result = self.publish(files)
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
        self.assertEqual(result["outcome"], "ACCEPT", result)

    def test_recall_rejects_symlinked_snapshot_file_without_sink_release(self):
        published = self.publish()
        selected = self.data / "generations" / published["reference"]["generation_id"] / "files" / "notes.txt"
        selected.unlink()
        external = self.base / "outside.txt"
        external.write_bytes(b"outside")
        selected.symlink_to(external)
        received = []
        result = self.store.recall(now=self.now, sink=received.append)
        self.assertEqual(result["outcome"], "REJECT")
        self.assertIsNone(result["files"])
        self.assertEqual(received, [])

    def test_recall_rejects_extra_unmanifested_files(self):
        published = self.publish()
        files = self.data / "generations" / published["reference"]["generation_id"] / "files"
        (files / "extra.txt").write_bytes(b"unlisted")
        received = []
        result = self.store.recall(now=self.now, sink=received.append)
        self.assertEqual(result["outcome"], "REJECT")
        self.assertIsNone(result["files"])
        self.assertEqual(received, [])

    def test_rejects_symlinked_database_and_data_directory(self):
        with tempfile.TemporaryDirectory() as other:
            link_db = self.base / "linked.sqlite3"
            link_db.symlink_to(self.db)
            with self.assertRaisesRegex(ValueError, "symlink_path_rejected"):
                ReceiverStore(self.data, link_db, context="local:test", scope="memory:test",
                              trusted_public_key=self.key.public_key())
            link_data = self.base / "linked-data"
            link_data.symlink_to(other, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink_path_rejected"):
                ReceiverStore(link_data, self.base / "other.sqlite3", context="local:test",
                              scope="memory:test", trusted_public_key=self.key.public_key())


if __name__ == "__main__":
    unittest.main()
