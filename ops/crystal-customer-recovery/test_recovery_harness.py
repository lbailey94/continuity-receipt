from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

from recovery_harness import RecoveryRefused, restore_copy, run_synthetic_rehearsal


class SyntheticRecoveryTests(unittest.TestCase):
    def test_end_to_end_synthetic_quarantine_and_recovery(self):
        result = run_synthetic_rehearsal()
        self.assertEqual(result["result"], "PASS")
        self.assertTrue(result["synthetic_only"])
        self.assertEqual(result["outcomes"]["retry_after_stage_reconciliation"], "restored-identical")
        self.assertEqual(result["outcomes"]["retry_after_publish"], "already-restored-identical")
        for key in (
            "wrong_owner_refused",
            "locator_mismatch_refused",
            "staged_interruption_kept_quarantine",
            "prepublish_blind_retry_refused",
            "postpublish_stage_matches",
            "postpublish_stage_cleaned",
            "registry_mapping_conflict_refused",
            "quarantine_retained",
            "all_copies_match",
            "tampered_source_refused",
        ):
            self.assertTrue(result["outcomes"][key], key)

    def test_missing_any_required_approval_refuses_before_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "quarantine.crystal"
            source.write_bytes(b"opaque synthetic bytes")
            target = root / "target.crystal"
            kwargs = dict(
                quarantine_file=source,
                destination_file=target,
                expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                legacy_locator="sha256:" + "a" * 64,
                mapped_owner_id="a" * 64,
                approved_owner_id="a" * 64,
                registry_mapping_conflict=False,
                prior_binding_verified=True,
                consent_verified=True,
                independent_review_complete=True,
            )
            for field in ("prior_binding_verified", "consent_verified", "independent_review_complete"):
                altered = {**kwargs, field: False}
                with self.subTest(field=field), self.assertRaises(RecoveryRefused):
                    restore_copy(**altered)
            with self.assertRaises(RecoveryRefused):
                restore_copy(**{**kwargs, "legacy_locator": "sha256:" + "b" * 64})
            with self.assertRaises(RecoveryRefused):
                restore_copy(**{**kwargs, "registry_mapping_conflict": True})
            self.assertFalse(target.exists())

    def test_conflicting_existing_destination_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "quarantine.crystal"
            target = root / "target.crystal"
            source.write_bytes(b"original opaque synthetic bytes")
            target.write_bytes(b"different existing bytes")
            kwargs = dict(
                quarantine_file=source,
                destination_file=target,
                expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                legacy_locator="sha256:" + "a" * 64,
                mapped_owner_id="a" * 64,
                approved_owner_id="a" * 64,
                registry_mapping_conflict=False,
                prior_binding_verified=True,
                consent_verified=True,
                independent_review_complete=True,
            )
            with self.assertRaises(RecoveryRefused):
                restore_copy(**kwargs)
            self.assertEqual(target.read_bytes(), b"different existing bytes")


if __name__ == "__main__":
    unittest.main()
