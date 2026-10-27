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
        output = pacmi.format_report_cli(report)
        self.assertIn("W3C PACMI / AGMI", output)
        self.assertIn("T01", output)
        self.assertIn("T10", output)
        self.assertIn("FINAL VERDICT", output)


if __name__ == "__main__":
    unittest.main()
