"""Tests for W3C PACMI / AGMI conformance evaluator."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from continuity_receipt import pacmi, strict_json

VECTORS_DIR = Path(__file__).resolve().parents[1] / "vectors"


class TestPACMIConformance(unittest.TestCase):
    def setUp(self):
        with open(VECTORS_DIR / "01_happy_minimal.json", "r", encoding="utf-8") as f:
            self.happy_bundle = strict_json.loads(f.read())
        with open(VECTORS_DIR / "22_local_state_commitment.json", "r", encoding="utf-8") as f:
            self.state_bundle = strict_json.loads(f.read())

    def test_happy_bundle_evaluates_t1_through_t8_safe(self):
        report = pacmi.evaluate_pacmi(self.happy_bundle)
        self.assertIsNotNone(report.bundle_digest)
        self.assertTrue(report.scitt_envelope_compliant)

        # In-store default without off-store anchor: T01-T08 safe; T09 and T10 vulnerable
        threat_map = {t.code: t.status for t in report.threats}
        for code in ["T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08"]:
            self.assertEqual(threat_map[code], pacmi.STATUS_SAFE, f"Expected {code} to be SAFE")

        self.assertEqual(threat_map["T09"], pacmi.STATUS_VULNERABLE)
        self.assertEqual(threat_map["T10"], pacmi.STATUS_VULNERABLE)
        self.assertEqual(report.score, "8/10")
        self.assertEqual(report.verdict, "PARTIAL")

    def test_state_commitment_bundle_with_offstore_anchor(self):
        # 22_local_state_commitment carries state.commitment
        report_no_anchor = pacmi.evaluate_pacmi(self.state_bundle)
        self.assertFalse(report_no_anchor.offstore_anchor_present)
        threat_map_no_anchor = {t.code: t.status for t in report_no_anchor.threats}
        self.assertEqual(threat_map_no_anchor["T09"], pacmi.STATUS_VULNERABLE)

        # Now pass an external offstore anchor
        offstore_anchor = {
            "anchor_kind": "scitt_receipt",
            "registered_at": "2026-09-24T18:00:05Z",
            "ledger_digest": "sha256:" + "c" * 64,
        }
        report_anchored = pacmi.evaluate_pacmi(self.state_bundle, offstore_anchor=offstore_anchor)
        self.assertTrue(report_anchored.offstore_anchor_present)
        threat_map_anchored = {t.code: t.status for t in report_anchored.threats}
        self.assertEqual(threat_map_anchored["T09"], pacmi.STATUS_SAFE)

    def test_cli_formatting(self):
        report = pacmi.evaluate_pacmi(self.happy_bundle)
        output = pacmi.format_report_cli(report, show_table=True)
        self.assertIn("W3C PACMI / AGMI", output)
        self.assertIn("T01", output)
        self.assertIn("T10", output)
        self.assertIn("W3C 4-FIELD RESULT SCHEMA", output)
        self.assertIn("| Property | Evidence | Result | Detection point and treatment |", output)
        self.assertIn("FINAL VERDICT", output)

    def test_vectors_26_pacmi_threat_matrix_and_counterfactuals(self):
        # 1. Vector 26: 10/10 CONFORMANT
        with open(VECTORS_DIR / "26_pacmi_erasure_resurrection.json", "r", encoding="utf-8") as f:
            v26 = strict_json.loads(f.read())
        r26 = pacmi.evaluate_pacmi(v26)
        self.assertEqual(r26.verdict, "CONFORMANT")
        self.assertEqual(r26.score, "10/10")
        self.assertTrue(r26.offstore_anchor_present)
        self.assertTrue(r26.erasure_commitment_present)

        # 2. Vector 26b: 9/10 PARTIAL (T10 counterfactual with high-water only)
        with open(VECTORS_DIR / "26b_pacmi_high_water_counterfactual.json", "r", encoding="utf-8") as f:
            v26b = strict_json.loads(f.read())
        r26b = pacmi.evaluate_pacmi(v26b)
        self.assertEqual(r26b.verdict, "PARTIAL")
        self.assertEqual(r26b.score, "9/10")
        self.assertTrue(r26b.offstore_anchor_present)
        self.assertFalse(r26b.erasure_commitment_present)
        threat_map_b = {t.code: t.status for t in r26b.threats}
        self.assertEqual(threat_map_b["T09"], pacmi.STATUS_SAFE)
        self.assertEqual(threat_map_b["T10"], pacmi.STATUS_VULNERABLE)

        # 3. Vector 26c: 8/10 PARTIAL (in-store baseline without anchor)
        with open(VECTORS_DIR / "26c_pacmi_in_store_no_anchor.json", "r", encoding="utf-8") as f:
            v26c = strict_json.loads(f.read())
        r26c = pacmi.evaluate_pacmi(v26c)
        self.assertEqual(r26c.verdict, "PARTIAL")
        self.assertEqual(r26c.score, "8/10")
        self.assertFalse(r26c.offstore_anchor_present)
        self.assertTrue(r26c.erasure_commitment_present)
        threat_map_c = {t.code: t.status for t in r26c.threats}
        self.assertEqual(threat_map_c["T09"], pacmi.STATUS_VULNERABLE)
        self.assertEqual(threat_map_c["T10"], pacmi.STATUS_VULNERABLE)


if __name__ == "__main__":
    unittest.main()
