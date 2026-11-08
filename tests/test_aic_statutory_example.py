"""Conformance check for the AIC statutory rollback-freshness example."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from continuity_receipt import verify_bundle  # noqa: E402

EXAMPLE = ROOT / "examples" / "04_aic_statutory_bundle"


def load(name: str) -> dict:
    return json.loads((EXAMPLE / name).read_text(encoding="utf-8"))


class TestAicStatutoryExample(unittest.TestCase):
    def test_anchored_bundle_is_trusted(self):
        result = verify_bundle(load("aic_activity_bundle.json"))
        self.assertEqual(result.verdict, "TRUSTED", result.errors)
        self.assertEqual(
            result.summary.get("chain_head", {}).get("anchored"), "opentimestamps"
        )

    def test_unanchored_head_is_provisional_under_require_anchor(self):
        result = verify_bundle(load("aic_activity_unanchored.json"), require_anchor=True)
        self.assertEqual(result.verdict, "PROVISIONAL")
        self.assertIn("head_anchor_missing", result.provisional_reasons)

    def test_rollback_head_is_refused(self):
        result = verify_bundle(load("aic_activity_rollback.json"))
        self.assertEqual(result.verdict, "UNTRUSTED")
        self.assertIn("head_mismatch", result.codes())

    def test_aic_disclosure_fields_are_signed_body_claims(self):
        bundle = load("aic_activity_bundle.json")
        commitment = next(
            r for r in bundle["receipts"] if r.get("type") == "state.commitment"
        )
        aic = commitment["body"].get("aic", {})
        self.assertEqual(aic.get("aic_registered_name"), "WhiteMagic Autonomous Commons, A.I.C.")
        self.assertTrue(aic.get("sandbox_disclosure"))
        self.assertTrue(aic.get("capitalization_floor_ok"))


if __name__ == "__main__":
    unittest.main()
