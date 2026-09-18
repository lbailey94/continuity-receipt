"""Validate every schema-valid vector against the JSON Schema."""
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
SCHEMA_PATH = ROOT / "schema" / "continuity-receipt-0.2.schema.json"
MANIFEST = json.loads((VECTORS / "manifest.json").read_text(encoding="utf-8"))


class TestSchema(unittest.TestCase):
    @unittest.skipIf(jsonschema is None, "jsonschema not installed")
    def test_schema_valid_vectors(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)
        checked = 0
        for entry in MANIFEST["vectors"]:
            if not entry.get("schema_valid", True):
                continue
            bundle = json.loads((VECTORS / entry["file"]).read_text(encoding="utf-8"))
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
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)
        for entry in MANIFEST["vectors"]:
            if entry.get("schema_valid", True):
                continue
            bundle = json.loads((VECTORS / entry["file"]).read_text(encoding="utf-8"))
            self.assertTrue(list(validator.iter_errors(bundle)), f"{entry['file']} should fail schema")


if __name__ == "__main__":
    unittest.main(verbosity=2)
