"""Consistency tests for the machine-readable capability disclosure.

These do not re-test verification behavior (the vector suite and
`test_revocations.py` do that); they pin the disclosure against the code so
the published capabilities cannot silently drift.
"""

import json
import tomllib
import unittest
from pathlib import Path

from continuity_receipt import records
from continuity_receipt import revocations as revocations_mod

ROOT = Path(__file__).resolve().parent.parent


class TestCapabilityDisclosure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.caps = json.loads((ROOT / "verifier-capabilities.json").read_text("utf-8"))
        cls.verify_src = (ROOT / "continuity_receipt" / "verify.py").read_text("utf-8")
        cls.revocations_src = (ROOT / "continuity_receipt" / "revocations.py").read_text("utf-8")
        cls.anchor_src = (ROOT / "continuity_receipt" / "anchor.py").read_text("utf-8")
        cls.scripts = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))[
            "project"
        ]["scripts"]

    def test_document_identity(self):
        self.assertEqual(self.caps["kind"], "continuity-receipt-verifier-capabilities")
        self.assertEqual(self.caps["version"], 1)

    def test_spec_versions_match_code(self):
        self.assertEqual(self.caps["spec_versions"], list(records.SUPPORTED_SPECS))

    def test_verdicts_match_spec(self):
        self.assertEqual(
            self.caps["verdicts"],
            ["TRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE", "UNTRUSTED"],
        )
        for verdict in self.caps["verdicts"]:
            self.assertIn(verdict, self.verify_src)

    def test_error_codes_exist_in_verifier(self):
        for code in self.caps["error_codes"]:
            self.assertIn(f'"{code}"', self.verify_src, code)

    def test_reason_prefixes_exist_in_verifier(self):
        for reason in self.caps["provisional_reasons"] + self.caps["insufficient_reasons"]:
            self.assertIn(reason.split(":")[0], self.verify_src, reason)

    def test_revocation_list_constants_match_code(self):
        lists = self.caps["revocation_lists"]
        self.assertEqual(lists["document_kind"], revocations_mod.DOCUMENT_KIND)
        self.assertEqual(lists["document_version"], revocations_mod.DOCUMENT_VERSION)
        self.assertEqual(lists["max_document_bytes"], revocations_mod.MAX_DOCUMENT_BYTES)
        for code in lists["error_codes"]:
            self.assertIn(f'"{code}"', self.revocations_src, code)

    def test_cli_surface_matches_pyproject(self):
        self.assertEqual(set(self.caps["cli"].values()), set(self.scripts.keys()))

    def test_anchor_companion_is_declared_and_present(self):
        anchors = self.caps["anchors"]
        self.assertEqual(anchors["proof_verification"], "companion")
        self.assertIn(anchors["companion_cli"], self.scripts)
        for code in ("anchor_verified", "header_mismatch", "unsupported_op"):
            self.assertIn(f'"{code}"', self.anchor_src, code)
        self.assertTrue((ROOT / "vectors" / "anchor").is_dir())

    def test_conformance_doc_links_the_json(self):
        doc = (ROOT / "CONFORMANCE.md").read_text("utf-8")
        self.assertIn("verifier-capabilities.json", doc)


if __name__ == "__main__":
    unittest.main()
