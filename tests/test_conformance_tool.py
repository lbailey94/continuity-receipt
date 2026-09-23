"""Conformance tool: report verification (shape, signature, tampering)."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import conformance_submit as cs  # noqa: E402

from continuity_receipt import keys  # noqa: E402
from continuity_receipt.canon import canonical_bytes  # noqa: E402


class TestConformanceReport(unittest.TestCase):
    def setUp(self):
        self.did, self.key = keys.generate(keys.deterministic_seed("referee"))
        self.report = {
            "kind": "continuity-receipt-conformance",
            "version": 1,
            "implementation": {
                "name": "continuity-receipt",
                "version": "0.3.3",
                "language": "rust",
            },
            "submission_digest": "sha256:" + "0" * 64,
            "corpus": {
                "bundles": {"vectors": 26, "manifest_digest": "sha256:" + "1" * 64},
                "verification_receipts": {"vectors": 20, "manifest_digest": "sha256:" + "2" * 64},
            },
            "results": {
                "bundles": {"matched": 26, "total": 26, "mismatches": []},
                "verification_receipts": {"matched": 20, "total": 20, "mismatches": []},
            },
            "verdict": "CONFORMANT",
            "issued_at": "2026-09-23T21:00:00Z",
            "issuer": self.did,
        }
        self.report["sig"] = {
            "alg": "ed25519",
            "key": self.did,
            "value": keys.sign(self.key, canonical_bytes(self.report)),
        }

    def test_valid_report(self):
        result = cs.verify_report(self.report)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["verdict"], "CONFORMANT")

    def test_tampered_report(self):
        tampered = json.loads(json.dumps(self.report))
        tampered["verdict"] = "NONCONFORMANT"
        self.assertFalse(cs.verify_report(tampered)["valid"])

    def test_bad_kind_and_shape(self):
        bad = json.loads(json.dumps(self.report))
        bad["kind"] = "other"
        self.assertIn("bad_kind", cs.verify_report(bad)["errors"])
        self.assertEqual(cs.verify_report([])["errors"], ["not_an_object"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
