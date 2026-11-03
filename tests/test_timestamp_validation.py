"""Calendar validation at the signed receipt, revocation and CLI boundaries."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from continuity_receipt import records, verification
from continuity_receipt.revocations import verify_statements
from continuity_receipt.verify import verify_bundle

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
TIMES = json.loads((FIXTURES / "timestamp-boundaries.json").read_text())
SIGNED = json.loads((FIXTURES / "signed-timestamp-boundaries.json").read_text())


class TestTimestampBoundaries(unittest.TestCase):
    def test_calendar_and_wire_spelling(self):
        for value in TIMES["valid"]:
            with self.subTest(valid=value):
                self.assertTrue(records.validate_timestamp(value))
                self.assertIsNotNone(records.parse_timestamp(value))
        for value in TIMES["invalid"] + [None, True, 2026, {}, []]:
            with self.subTest(invalid=value):
                self.assertFalse(records.validate_timestamp(value))

    def test_signed_dates_do_not_override_calendar_validation(self):
        good = verify_bundle(SIGNED["valid_bundle"])
        self.assertEqual(good.verdict, "TRUSTED", good.as_dict())
        bad = verify_bundle(SIGNED["invalid_bundle"])
        self.assertEqual(bad.verdict, "UNTRUSTED")
        self.assertEqual(set(bad.codes()), {"malformed"})
        self.assertTrue(verification.verify_verification_receipt(SIGNED["valid_receipt"]).valid)
        bad_receipt = verification.verify_verification_receipt(SIGNED["invalid_receipt"])
        self.assertFalse(bad_receipt.valid)
        self.assertEqual(bad_receipt.errors, ["bad_verified_at"])

    def test_invalid_signed_revocation_is_structured(self):
        revoked, errors = verify_statements([SIGNED["invalid_revocation"]])
        self.assertEqual(revoked, [])
        self.assertEqual([code for code, _ in errors], ["bad_revocation"])
        result = verify_bundle(SIGNED["valid_bundle"], external_revocations=[SIGNED["invalid_revocation"]])
        self.assertEqual(result.verdict, "UNTRUSTED")
        self.assertEqual(set(result.codes()), {"bad_revocation"})

    def test_impossible_calendar_date_cli_is_structured(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "signed-invalid-date.json"
            path.write_text(json.dumps(SIGNED["invalid_bundle"]))
            result = subprocess.run(
                [sys.executable, "-m", "continuity_receipt.verify", str(path)],
                cwd=ROOT, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(json.loads(result.stdout)["verdict"], "UNTRUSTED")
            self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
