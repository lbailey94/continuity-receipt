"""Validate every schema-valid vector against the schema for its spec version."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    import jsonschema
except ImportError:  # pragma: no cover - CI installs jsonschema
    jsonschema = None

VECTORS = ROOT / "vectors"
SCHEMA_DIR = ROOT / "schema"
MANIFEST = json.loads((VECTORS / "manifest.json").read_text(encoding="utf-8"))
MANIFEST["vectors"] += json.loads((VECTORS / "manifest-0.5.json").read_text(encoding="utf-8"))["vectors"]
SCHEMA_FOR_SPEC = {
    "continuity-receipt/0.1": "continuity-receipt-0.2.schema.json",
    "continuity-receipt/0.2": "continuity-receipt-0.2.schema.json",
    "continuity-receipt/0.3": "continuity-receipt-0.3.schema.json",
    "continuity-receipt/0.4": "continuity-receipt-0.4.schema.json",
    "continuity-receipt/0.5": "continuity-receipt-0.5.schema.json",
}


def validator_for(bundle: dict):
    schema_name = SCHEMA_FOR_SPEC[bundle["spec"]]
    schema = json.loads((SCHEMA_DIR / schema_name).read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator(schema)


class TestSchema(unittest.TestCase):
    @unittest.skipIf(jsonschema is None, "jsonschema not installed")
    def test_schema_valid_vectors(self):
        checked = 0
        for entry in MANIFEST["vectors"]:
            if not entry.get("schema_valid", True):
                continue
            bundle = json.loads((VECTORS / entry["file"]).read_text(encoding="utf-8"))
            validator = validator_for(bundle)
            errors = sorted(validator.iter_errors(bundle), key=lambda e: list(e.path))
            self.assertEqual(
                errors,
                [],
                f"{entry['file']}: {[e.message for e in errors][:3]}",
            )
            checked += 1
        self.assertGreater(checked, 0)

    @unittest.skipIf(jsonschema is None, "jsonschema not installed")
    def test_negative_vectors_are_schema_invalid(self):
        for entry in MANIFEST["vectors"]:
            if entry.get("schema_valid", True):
                continue
            bundle = json.loads((VECTORS / entry["file"]).read_text(encoding="utf-8"))
            validator = validator_for(bundle)
            self.assertTrue(list(validator.iter_errors(bundle)), f"{entry['file']} should fail schema")

    @unittest.skipIf(jsonschema is None, "jsonschema not installed")
    def test_bwrap_profile_requirement_is_scoped_to_spec_05(self):
        bundle = json.loads((VECTORS / "02_happy_full.json").read_text(encoding="utf-8"))
        bundle["spec"] = "continuity-receipt/0.4"
        for receipt in bundle["receipts"]:
            receipt["spec"] = "continuity-receipt/0.4"
            if receipt.get("type") == "task.execution":
                receipt["body"]["sandbox_class"] = "bwrap"
                receipt["body"].pop("runner_profile", None)
        validator = validator_for(bundle)
        self.assertEqual(list(validator.iter_errors(bundle)), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
