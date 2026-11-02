"""File custody and cooperating-writer regressions for supplied witnesses."""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from continuity_receipt.witness_file import WitnessPublication, load_witness
from continuity_receipt.witness import OffHostWitness


def reference(sequence):
    digit = format(sequence, "x")
    return {"sequence": sequence, "checkpoint_digest": "sha256:" + digit * 64,
            "generation_id": digit * 32}


class WitnessFileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cpr-witness-file-")
        self.root = Path(self.temporary.name)
        self.target = self.root / "witness.json"
        self.target.write_text(json.dumps(reference(2)))

    def tearDown(self):
        self.temporary.cleanup()

    def test_readers_observe_old_complete_file_until_atomic_replacement(self):
        with WitnessPublication(self.target) as publication:
            publication.ensure_not_ahead(reference(2))
            self.assertEqual(load_witness(self.target).min_sequence, 2)
            publication.commit(reference(3))
            self.assertEqual(load_witness(self.target).min_sequence, 3)
        self.assertEqual(load_witness(self.target).latest_checkpoint,
                         reference(3)["checkpoint_digest"])
        self.assertEqual(list(self.root.glob(".cpr-witness-stage-*")), [])

    def test_inverted_cooperating_publishers_cannot_regress_witness(self):
        newer_entered = threading.Event()
        older_started = threading.Event()
        release_newer = threading.Event()
        older_done = threading.Event()
        failures = []

        def newer():
            try:
                with WitnessPublication(self.target) as publication:
                    publication.ensure_not_ahead(reference(2))
                    newer_entered.set()
                    if not release_newer.wait(5):
                        raise RuntimeError("test_release_timeout")
                    publication.commit(reference(3))
            except Exception as exc:
                failures.append(("newer", str(exc)))
                newer_entered.set()

        def older():
            older_started.set()
            try:
                with WitnessPublication(self.target) as publication:
                    publication.ensure_not_ahead(reference(2))
                    publication.commit(reference(2))
            except ValueError as exc:
                failures.append(("older", str(exc)))
            except Exception as exc:
                failures.append(("unexpected", str(exc)))
            finally:
                older_done.set()

        first = threading.Thread(target=newer, daemon=True)
        second = threading.Thread(target=older, daemon=True)
        first.start()
        try:
            self.assertTrue(newer_entered.wait(5))
            second.start()
            self.assertTrue(older_started.wait(5))
            self.assertFalse(older_done.wait(0.1), "publisher bypassed the cooperating lock")
        finally:
            release_newer.set()
            first.join(5)
            if second.ident is not None:
                second.join(5)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(failures, [("older", "witness_ahead_of_local_reference")])
        self.assertEqual(load_witness(self.target).min_sequence, 3)

    def test_preflight_sync_failure_preserves_target_and_removes_staging_file(self):
        original = self.target.read_bytes()
        with mock.patch("continuity_receipt.witness_file.os.fsync", side_effect=OSError("injected preflight sync failure")):
            with self.assertRaises(OSError):
                with WitnessPublication(self.target):
                    self.fail("preflight failure reached publication body")
        self.assertEqual(self.target.read_bytes(), original)
        self.assertEqual(list(self.root.glob(".cpr-witness-stage-*")), [])

    def test_malformed_existing_reference_cannot_be_silently_replaced(self):
        self.target.write_text("{}\n")
        with self.assertRaisesRegex(ValueError, "off_host_witness_invalid"):
            with WitnessPublication(self.target):
                self.fail("invalid existing evidence reached publication body")
        self.assertEqual(self.target.read_text(), "{}\n")

    def test_unlink_failure_still_closes_descriptors_and_releases_lock(self):
        publication = WitnessPublication(self.target)
        publication.__enter__()
        descriptors = (publication.temp_fd, publication.lock_fd, publication.parent_fd)
        stage = publication.temp_name
        with mock.patch("continuity_receipt.witness_file.os.unlink", side_effect=PermissionError("injected unlink failure")):
            with self.assertRaisesRegex(PermissionError, "injected unlink failure"):
                publication.__exit__(None, None, None)
        for descriptor in descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)
        # A failed removal may leave a stage file, but must not retain the lock.
        with WitnessPublication(self.target) as retry:
            retry.ensure_not_ahead(reference(2))
        (self.root / stage).unlink()

    def test_cleanup_failure_does_not_mask_primary_publication_failure(self):
        with mock.patch("continuity_receipt.witness_file.os.unlink", side_effect=PermissionError("secondary cleanup failure")):
            with self.assertRaisesRegex(RuntimeError, "primary publication failure") as caught:
                with WitnessPublication(self.target):
                    raise RuntimeError("primary publication failure")
        self.assertTrue(any("secondary cleanup failure" in note for note in caught.exception.__notes__))
        with WitnessPublication(self.target):
            pass

    def test_implementation_witness_policy_vectors(self):
        directory = Path(__file__).resolve().parents[1] / "vectors"
        manifest = json.loads((directory / "receiver-witness-policy-manifest-v1.json").read_text())
        raw = (directory / manifest["file"]).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), manifest["sha256"])
        cases = json.loads(raw)["cases"]
        self.assertEqual(len(cases), manifest["cases"])
        for case in cases:
            with self.subTest(case=case["id"]):
                if case["expected"] == "REJECT":
                    with self.assertRaises(ValueError):
                        OffHostWitness.from_dict(case["witness"], expected_checkpoint_digest=case.get("expected_pin"))
                else:
                    witness = OffHostWitness.from_dict(case["witness"], expected_checkpoint_digest=case.get("expected_pin"))
                    self.assertEqual(witness.min_sequence, case["witness"]["sequence"])


if __name__ == "__main__":
    unittest.main()
