#!/usr/bin/env python3
"""Isolated ERC adapter semantics checks for a Phase 4B receipt-api.py candidate.

Usage: python3 ops/test_hosted_erc_candidate.py --source /path/to/receipt-api.py
The tested module uses a fresh temporary WM_RECEIPT_API_STATE and loopback port.
Published receipt vectors are read-only fixtures; no key material is copied.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
SOURCE: pathlib.Path | None = None


def _request(url: str, payload: dict | None = None):
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"} if data is not None else {},
        method="POST" if data is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


class HostedERCCandidate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SOURCE is None:
            raise unittest.SkipTest(
                "standalone hosted ERC candidate harness; run with --source PATH"
            )
        if not SOURCE.is_file():
            raise RuntimeError(f"candidate source does not exist: {SOURCE}")

        cls.tempdir = tempfile.TemporaryDirectory(prefix="receipt-api-erc-candidate-")
        cls.state = pathlib.Path(cls.tempdir.name) / "state"
        cls.previous_state_env = os.environ.get("WM_RECEIPT_API_STATE")
        os.environ["WM_RECEIPT_API_STATE"] = str(cls.state)

        spec = importlib.util.spec_from_file_location("receipt_api_erc_candidate", SOURCE)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"could not load candidate source: {SOURCE}")
        cls.api = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.api
        spec.loader.exec_module(cls.api)

        cls.server = cls.api.ThreadingHTTPServer(("127.0.0.1", 0), cls.api.Handler)
        cls.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "server"):
            cls.server.shutdown()
            cls.server.server_close()
            cls.server_thread.join(timeout=5)
        if hasattr(cls, "tempdir"):
            cls.tempdir.cleanup()
        if getattr(cls, "previous_state_env", None) is None:
            os.environ.pop("WM_RECEIPT_API_STATE", None)
        elif hasattr(cls, "previous_state_env"):
            os.environ["WM_RECEIPT_API_STATE"] = cls.previous_state_env
        sys.modules.pop("receipt_api_erc_candidate", None)

    def _fixture(self, name: str) -> dict:
        return json.loads((REPO_ROOT / "vectors" / name).read_text(encoding="utf-8"))

    def _post(self, bundle: dict, task_hash: str):
        payload = {
            "request_id": "0x" + "11" * 32,
            "task_hash": task_hash,
            "bundle": bundle,
        }
        return _request(f"{self.base_url}/erc8004/validate", payload)

    def _assert_evidence_is_unclaimed(self, response: dict, binding: str):
        checks = response["checks"]
        for field in (
            "chain_integrity",
            "signatures_valid",
            "policy_compliant",
            "resource_caps_respected",
            "anchors_verified",
        ):
            self.assertIsNone(checks[field], field)
        self.assertFalse(checks["issuer_policy_evaluated"])
        self.assertFalse(checks["anchors_required"])
        scope = response["evaluation_scope"]
        self.assertEqual(scope["core_verdict"], response["cr_verdict"])
        self.assertEqual(scope["task_binding"], binding)
        self.assertEqual(scope["issuer_policy"], "not_evaluated")
        self.assertEqual(
            scope["anchors"], "not_required; no_independent_status_reported"
        )
        self.assertEqual(scope["individual_checks"], "not_reported_by_adapter")
        self.assertEqual(scope["attestation"], "ed25519_signature_over_canonical_json_message")
        self.assertEqual(scope["evm_relay"], "not_performed")
        self.assertEqual(response["onchain"], {"relayed": False, "tx_hash": None})

        from continuity_receipt import keys
        from continuity_receipt.canon import canonical_bytes

        attestation = response["attestation"]
        self.assertTrue(keys.verify(
            attestation["signer"],
            canonical_bytes(attestation["message"]),
            attestation["signature"],
        ))

    def test_info_describes_distinct_evaluation_and_signature_boundaries(self):
        status, info = _request(f"{self.base_url}/info")
        self.assertEqual(status, 200)
        desc = info["endpoints"]["POST /erc8004/validate"].lower()
        self.assertIn("core verifier verdict", desc)
        self.assertIn("task binding", desc)
        self.assertIn("issuer policy is not evaluated", desc)
        self.assertIn("anchors are not required", desc)
        self.assertIn("ed25519-signed", desc)
        self.assertIn("does not relay it onchain", desc)
        erc = info["erc8004"]
        self.assertIn("not reported as per-check successes", erc["checks"].lower())
        self.assertIn("type exactly task.termination", erc["checks"].lower())
        self.assertIn("not evaluated", erc["issuer_policy"].lower())
        self.assertIn("not required for the adapter outcome", erc["anchors"].lower())
        self.assertIn("core verifier may inspect", erc["anchors"].lower())
        self.assertIn("no evm-compatible signature or onchain relay", erc["attestation"].lower())

    def test_valid_signed_fixtures_preserve_outcomes_without_inferred_policy_or_anchor_success(self):
        expected = (
            ("01_happy_minimal.json", "TRUSTED", 1, "ACCEPT"),
            ("07_redacted_no_disclosure.json", "PROVISIONAL", 2, "NEEDS_EVIDENCE"),
            ("04_missing_termination.json", "UNTRUSTED", 0, "REJECT"),
        )
        for filename, verdict, outcome, label in expected:
            with self.subTest(fixture=filename):
                bundle = self._fixture(filename)
                core = self.api.Handler._verify_one(bundle, require_anchor=False)
                self.assertEqual(core["verdict"], verdict)
                self.assertNotIn("bad_signature", {error.get("code") for error in core.get("errors", [])})
                status, response = self._post(bundle, bundle["task_id"])
                self.assertEqual(status, 200, response)
                self.assertEqual(response["cr_verdict"], verdict)
                self.assertEqual(response["outcome"], outcome)
                self.assertEqual(response["outcome_label"], label)
                self.assertTrue(response["checks"]["task_bound"])
                if filename != "04_missing_termination.json":
                    self.assertTrue(response["checks"]["termination_present"])
                else:
                    self.assertFalse(response["checks"]["termination_present"])
                self._assert_evidence_is_unclaimed(response, "matched")


    def test_malformed_receipts_and_early_core_failures_do_not_infer_check_success(self):
        base = self._fixture("01_happy_minimal.json")
        malformed_receipts = json.loads(json.dumps(base))
        malformed_receipts["receipts"] = "not-a-list"
        malformed_record = json.loads(json.dumps(base))
        malformed_record["receipts"] = ["not-a-receipt-object"]
        shape_invalid = json.loads(json.dumps(base))
        shape_invalid["receipts"][0]["body"] = ["wrong", "body", "shape"]
        deep = json.loads(json.dumps(base))
        node = {}
        deep["extra_depth_probe"] = node
        for _ in range(68):
            child = {}
            node["child"] = child
            node = child

        for name, bundle in (
            ("receipts-string", malformed_receipts),
            ("receipts-bad-record", malformed_record),
            ("shape-invalid", shape_invalid),
            ("core-depth-failure", deep),
        ):
            with self.subTest(case=name):
                status, response = self._post(bundle, bundle["task_id"])
                self.assertEqual(status, 200, response)
                self.assertEqual(response["outcome"], 0 if response["cr_verdict"] == "UNTRUSTED" else 2)
                if name.startswith("receipts-"):
                    self.assertFalse(response["checks"]["termination_present"])
                self._assert_evidence_is_unclaimed(response, "matched")

    def test_task_mismatch_keeps_reject_outcome_and_does_not_claim_policy_or_anchor_checks(self):
        bundle = self._fixture("01_happy_minimal.json")
        status, response = self._post(bundle, "did:task:mismatch")
        self.assertEqual(status, 422, response)
        self.assertEqual(response["error"], "task_mismatch")
        self.assertEqual(response["cr_verdict"], "TRUSTED")
        self.assertEqual(response["outcome"], 0)
        self.assertEqual(response["outcome_label"], "REJECT")
        self.assertFalse(response["checks"]["task_bound"])
        self._assert_evidence_is_unclaimed(response, "mismatch")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run isolated loopback tests against an ERC adapter candidate."
    )
    parser.add_argument("--source", required=True, type=pathlib.Path)
    args, unittest_args = parser.parse_known_args()
    SOURCE = args.source.resolve()
    unittest.main(argv=[sys.argv[0], *unittest_args], verbosity=2)
