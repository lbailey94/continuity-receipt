"""Witness validation and the boundary between a floor and trusted currency."""
from dataclasses import FrozenInstanceError
import unittest

from continuity_receipt.witness import OffHostWitness


S1 = "sha256:" + "1" * 64
S2 = "sha256:" + "2" * 64
G1 = "a" * 32
G2 = "b" * 32


class OffHostWitnessTests(unittest.TestCase):
    def test_constructor_requires_nonvacuous_reference(self):
        with self.assertRaises(TypeError):
            OffHostWitness()
        with self.assertRaises(TypeError):
            OffHostWitness(min_sequence=1)
        for sequence in (None, False, True, 0, -1, 1.0, "1"):
            with self.subTest(sequence=sequence):
                with self.assertRaisesRegex(ValueError, "off_host_witness_sequence_invalid"):
                    OffHostWitness(min_sequence=sequence, latest_checkpoint=S1)
        for checkpoint in (None, "", 1, "sha256:" + "A" * 64, "sha256:" + "1" * 63, S1 + "\n"):
            with self.subTest(checkpoint=checkpoint):
                with self.assertRaisesRegex(ValueError, "off_host_witness_checkpoint_invalid"):
                    OffHostWitness(min_sequence=1, latest_checkpoint=checkpoint)

    def test_json_shape_cannot_silently_select_defaults(self):
        for value in (None, [], "witness", {}, {"sequence": 2},
                      {"checkpoint_digest": S2}, {"min_sequence": 2, "checkpoint_digest": S2},
                      {"sequence": 2, "checkpoint_digest": S2, "observed_at": "2026-11-01T13:15:00Z"},
                      {"sequence": 2, "checkpoint_digest": S2, "unknown": None}):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "off_host_witness_invalid"):
                    OffHostWitness.from_dict(value)
        for sequence in (False, True, 0, -1, 2.0, "2"):
            with self.subTest(sequence=sequence):
                with self.assertRaises(ValueError):
                    OffHostWitness.from_dict({"sequence": sequence, "checkpoint_digest": S2})

    def test_reference_is_immutable_after_validation(self):
        witness = OffHostWitness(min_sequence=2, latest_checkpoint=S2)
        with self.assertRaises(FrozenInstanceError):
            witness.min_sequence = 0

    def test_current_reference_refuses_authentic_historical_state(self):
        witness = OffHostWitness.from_dict({"sequence": 2, "checkpoint_digest": S2,
                                           "generation_id": G2})
        self.assertEqual(witness.verify(sequence=1, checkpoint_digest=S1, generation_id=G1),
                         {"trusted": False, "reason": "joint_rollback_detected:sequence_1_below_witness_2"})
        self.assertTrue(witness.verify(sequence=2, checkpoint_digest=S2, generation_id=G2)["trusted"])

    def test_equal_sequence_binds_checkpoint_and_optional_generation(self):
        witness = OffHostWitness(min_sequence=2, latest_checkpoint=S2, generation_id=G2)
        mismatch = witness.verify(sequence=2, checkpoint_digest=S1, generation_id=G2)
        self.assertEqual(mismatch["reason"], "joint_rollback_detected:checkpoint_mismatch_at_sequence_2")
        for generation in (None, G1):
            with self.subTest(generation=generation):
                mismatch = witness.verify(sequence=2, checkpoint_digest=S2, generation_id=generation)
                self.assertEqual(mismatch["reason"], "joint_rollback_detected:generation_mismatch_at_sequence_2")
        # The API deliberately represents a floor, not an assertion of latestness.
        self.assertTrue(witness.verify(sequence=3, checkpoint_digest=S1, generation_id=G1)["trusted"])

    def test_missing_generation_is_allowed_only_when_not_bound_by_witness(self):
        witness = OffHostWitness.from_dict({"sequence": 2, "checkpoint_digest": S2})
        self.assertTrue(witness.verify(sequence=2, checkpoint_digest=S2)["trusted"])
        for generation in ("", "a" * 31, "A" * 32, 123, False):
            with self.subTest(generation=generation):
                with self.assertRaisesRegex(ValueError, "off_host_witness_generation_invalid"):
                    OffHostWitness(min_sequence=2, latest_checkpoint=S2, generation_id=generation)

    def test_independent_pin_rejects_old_witness_even_when_it_matches_old_state(self):
        historical = {"sequence": 1, "checkpoint_digest": S1, "generation_id": G1}
        unpinned = OffHostWitness.from_dict(historical)
        self.assertTrue(unpinned.verify(sequence=1, checkpoint_digest=S1, generation_id=G1)["trusted"])
        with self.assertRaisesRegex(ValueError, "off_host_witness_reference_mismatch"):
            OffHostWitness.from_dict(historical, expected_checkpoint_digest=S2)
        with self.assertRaisesRegex(ValueError, "off_host_witness_reference_mismatch"):
            OffHostWitness(min_sequence=1, latest_checkpoint=S1, expected_checkpoint_digest=S2)
        pinned = OffHostWitness.from_dict({"sequence": 2, "checkpoint_digest": S2},
                                         expected_checkpoint_digest=S2)
        self.assertTrue(pinned.verify(sequence=2, checkpoint_digest=S2)["trusted"])

    def test_invalid_independent_pin_is_not_ignored(self):
        for pin in (False, 2, "", "sha256:" + "F" * 64, S2 + "\n"):
            with self.subTest(pin=pin):
                with self.assertRaisesRegex(ValueError, "off_host_witness_expected_reference_invalid"):
                    OffHostWitness.from_dict({"sequence": 2, "checkpoint_digest": S2},
                                             expected_checkpoint_digest=pin)

    def test_invalid_verification_inputs_are_explicit_refusals(self):
        witness = OffHostWitness(min_sequence=2, latest_checkpoint=S2)
        for sequence in (None, True, False, 0, -1, 2.0, "2"):
            with self.subTest(sequence=sequence):
                self.assertEqual(witness.verify(sequence=sequence, checkpoint_digest=S2),
                                 {"trusted": False, "reason": "off_host_witness_sequence_invalid"})
        for checkpoint in (None, 2, "", S2 + "\n"):
            with self.subTest(checkpoint=checkpoint):
                self.assertEqual(witness.verify(sequence=2, checkpoint_digest=checkpoint),
                                 {"trusted": False, "reason": "off_host_witness_checkpoint_invalid"})
        self.assertEqual(witness.verify(sequence=2, checkpoint_digest=S2, generation_id="bad"),
                         {"trusted": False, "reason": "off_host_witness_generation_invalid"})


if __name__ == "__main__":
    unittest.main()
