"""Hostile-input regression tests.

Every malformed input must produce a structured `VerifyResult` — never an
exception — and the documented reproductions must carry their expected codes.
These pin the whole-shape validation pass that runs before semantic checks.
"""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from continuity_receipt import verify_bundle
from continuity_receipt.verify import MAX_BUNDLE_BYTES, MAX_RECEIPTS

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "vectors"
VERDICTS = ("TRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE", "UNTRUSTED")


def load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def leaf_paths(node, prefix=()):
    """Paths to every scalar leaf."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield from leaf_paths(value, prefix + (key,))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from leaf_paths(value, prefix + (index,))
    else:
        yield prefix


def get_path(node, path):
    for part in path:
        node = node[part]
    return node


def set_path(node, path, value):
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value


def key_paths(node, prefix=()):
    """Paths to every dict key and list index (structural deletion sites)."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield prefix + (key,)
            yield from key_paths(value, prefix + (key,))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield prefix + (index,)
            yield from key_paths(value, prefix + (index,))


def delete_path(node, path):
    for part in path[:-1]:
        node = node[part]
    del node[path[-1]]


def structured(result) -> bool:
    return (
        result.verdict in VERDICTS
        and isinstance(result.errors, list)
        and all(isinstance(entry, dict) and isinstance(entry.get("code"), str) for entry in result.errors)
    )


class TestDocumentedReproductions(unittest.TestCase):
    """The four cases from the independent review; none may raise."""

    def setUp(self):
        self.base = load("02_happy_full.json")

    def test_receipt_entry_null(self):
        bundle = copy.deepcopy(self.base)
        bundle["receipts"][0] = None
        result = verify_bundle(bundle)
        self.assertTrue(structured(result))
        self.assertIn("malformed", result.codes())

    def test_issuer_null(self):
        bundle = copy.deepcopy(self.base)
        bundle["receipts"][0]["issuer"] = None
        result = verify_bundle(bundle)
        self.assertTrue(structured(result))
        self.assertIn("malformed", result.codes())
        self.assertIn("bad_signature", result.codes())

    def test_settlement_amount_null(self):
        bundle = copy.deepcopy(self.base)
        for receipt in bundle["receipts"]:
            if receipt.get("type") == "settlement":
                receipt["body"]["amount"] = None
        result = verify_bundle(bundle)
        self.assertTrue(structured(result))
        self.assertIn("malformed", result.codes())

    def test_anchor_entry_null(self):
        bundle = copy.deepcopy(self.base)
        bundle["anchors"] = [None]
        result = verify_bundle(bundle)
        self.assertTrue(structured(result))
        self.assertIn("anchor_invalid", result.codes())


class TestMutationSweep(unittest.TestCase):
    """Every scalar leaf replaced by hostile values must stay structured."""

    MUTATIONS = (None, {}, [], 0, "x", True)
    VECTOR_FILES = (
        "02_happy_full.json",
        "08_redacted_disclosed.json",
        "13_attestation_valid.json",
        "16_offer_accept.json",
    )

    def test_every_leaf_mutation_is_structured(self):
        cases = 0
        for name in self.VECTOR_FILES:
            base = load(name)
            for path in leaf_paths(base):
                for value in self.MUTATIONS:
                    bundle = copy.deepcopy(base)
                    set_path(bundle, path, value)
                    try:
                        result = verify_bundle(bundle)
                    except Exception as exc:  # noqa: BLE001 - the point of the test
                        self.fail(f"{name} {path} -> {value!r} raised {type(exc).__name__}: {exc}")
                    self.assertTrue(
                        structured(result), f"{name} {path} -> {value!r} not structured"
                    )
                    cases += 1
        self.assertGreater(cases, 500)

    def test_deleted_key_sweep_is_structured(self):
        cases = 0
        for name in self.VECTOR_FILES:
            base = load(name)
            for path in key_paths(base):
                bundle = copy.deepcopy(base)
                delete_path(bundle, path)
                try:
                    result = verify_bundle(bundle)
                except Exception as exc:  # noqa: BLE001 - the point of the test
                    self.fail(f"{name} delete {path} raised {type(exc).__name__}: {exc}")
                self.assertTrue(structured(result), f"{name} delete {path} not structured")
                cases += 1
        self.assertGreater(cases, 200)

    def test_non_canonical_float_is_structured(self):
        bundle = load("02_happy_full.json")
        for receipt in bundle["receipts"]:
            if receipt.get("type") == "settlement":
                receipt["body"]["amount"]["minor"] = 1.5
        result = verify_bundle(bundle)
        self.assertTrue(structured(result))
        self.assertIn("malformed", result.codes())


class TestInputBoundaries(unittest.TestCase):
    def test_too_many_receipts(self):
        bundle = {
            "spec": "continuity-receipt/0.3",
            "task_id": "urn:uuid:00000000-0000-7000-8000-000000000000",
            "receipts": [{}] * (MAX_RECEIPTS + 1),
        }
        result = verify_bundle(bundle)
        self.assertTrue(structured(result))
        self.assertIn("too_many_receipts", result.codes())

    def test_nesting_too_deep(self):
        deep = "leaf"
        for _ in range(100):
            deep = {"next": deep}
        bundle = load("02_happy_full.json")
        bundle["receipts"][0]["body"]["deep"] = deep
        result = verify_bundle(bundle)
        self.assertTrue(structured(result))
        self.assertIn("nesting_too_deep", result.codes())


class TestCliBoundaries(unittest.TestCase):
    def run_cli(self, path):
        proc = subprocess.run(
            [sys.executable, "-m", "continuity_receipt.verify", str(path)],
            capture_output=True,
            text=True,
            cwd=ROOT,
        )
        return proc

    def test_invalid_json_is_structured(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            handle.write("{not json")
            path = handle.name
        proc = self.run_cli(path)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "UNTRUSTED")
        self.assertEqual(payload["errors"][0]["code"], "malformed")

    def test_deep_json_is_structured(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            handle.write('{"a":' * 5000 + "1" + "}" * 5000)
            path = handle.name
        proc = self.run_cli(path)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["errors"][0]["code"], "nesting_too_deep")

    def test_oversized_file_is_structured(self):
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as handle:
            handle.truncate(MAX_BUNDLE_BYTES + 1)
            path = handle.name
        proc = self.run_cli(path)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["errors"][0]["code"], "bundle_too_large")


if __name__ == "__main__":
    unittest.main()
