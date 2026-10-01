#!/usr/bin/env python3
"""Isolated loopback regression checks for a Phase 4A receipt-api.py candidate.

Usage: python3 ops/test_hosted_api_candidate.py --source /path/to/receipt-api.py
The source must be the reviewed candidate. This harness never reads host state
or credentials and injects a fresh temporary WM_RECEIPT_API_STATE before import.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import socket
import sys
import tempfile
import threading
import urllib.error
import urllib.request
import os
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
SOURCE: pathlib.Path | None = None


def _response(url: str, data: bytes | None = None):
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"} if data is not None else {},
        method="POST" if data is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


class CandidateQualification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SOURCE is None:
            raise unittest.SkipTest(
                "standalone hosted API candidate harness; run with --source PATH"
            )
        source = SOURCE
        if not source.is_file():
            raise RuntimeError(f"candidate source does not exist: {source}")

        cls.tempdir = tempfile.TemporaryDirectory(prefix="receipt-api-phase4a-")
        cls.state = pathlib.Path(cls.tempdir.name) / "state"
        cls.previous_state_env = os.environ.get("WM_RECEIPT_API_STATE")
        os.environ["WM_RECEIPT_API_STATE"] = str(cls.state)

        spec = importlib.util.spec_from_file_location("receipt_api_phase4a_candidate", source)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"could not load candidate source: {source}")
        cls.api = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.api
        spec.loader.exec_module(cls.api)

        cls.server = cls.api.ThreadingHTTPServer(("127.0.0.1", 0), cls.api.Handler)
        cls.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=5)
        cls.tempdir.cleanup()
        if cls.previous_state_env is None:
            os.environ.pop("WM_RECEIPT_API_STATE", None)
        else:
            os.environ["WM_RECEIPT_API_STATE"] = cls.previous_state_env
        sys.modules.pop("receipt_api_phase4a_candidate", None)

    def _post(self, raw: bytes):
        if len(raw) > self.api.MAX_BODY:
            with socket.create_connection(("127.0.0.1", self.server.server_address[1]), timeout=5) as connection:
                headers = (
                    f"POST /notarize HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{self.server.server_address[1]}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(raw)}\r\n"
                    "Connection: close\r\n\r\n"
                )
                connection.sendall(headers.encode("ascii"))
                chunks = []
                while True:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
            response = b"".join(chunks)
            head, body = response.split(b"\r\n\r\n", 1)
            status = int(head.split(b"\r\n", 1)[0].split()[1])
            return status, body
        return _response(f"{self.base_url}/notarize", raw)

    def _assert_no_state_writes(self):
        if self.state.exists():
            self.assertEqual(list(self.state.iterdir()), [])

    def test_01_descriptor_describes_caller_claims_and_keyless_locator(self):
        status, raw = _response(f"{self.base_url}/notarize")
        self.assertEqual(status, 200)
        description = json.loads(raw)["description"].lower()
        self.assertIn("caller-supplied", description)
        self.assertIn("does not observe", description)
        status, raw = _response(f"{self.base_url}/crystals")
        self.assertEqual(status, 200)
        self.assertIn("caller-supplied tenant-hash locator", json.loads(raw)["access_model"])
        self._assert_no_state_writes()

    def test_00_rejected_inputs_are_structured_and_do_not_create_key_or_receipt(self):
        digest = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
        deep_value = b"[" * 1600 + b"0" + b"]" * 1600
        cases: list[tuple[str, bytes, int]] = [
            ("float", b'{"context_digest":"' + digest.encode() + b'","metadata":{"x":1.5}}', 400),
            ("nan", b'{"context_digest":"' + digest.encode() + b'","metadata":{"x":NaN}}', 400),
            ("infinity", b'{"context_digest":"' + digest.encode() + b'","metadata":{"x":Infinity}}', 400),
            ("duplicate top level", b'{"context_digest":"' + digest.encode() + b'","context_digest":"' + digest.encode() + b'"}', 400),
            ("duplicate nested", b'{"context_digest":"' + digest.encode() + b'","metadata":{"x":1,"x":2}}', 400),
            ("BOM", b"\xef\xbb\xbf" + b'{"context_digest":"' + digest.encode() + b'"}', 400),
            ("UTF-16", json.dumps({"context_digest": digest}).encode("utf-16"), 400),
            ("deep nesting", b'{"context_digest":"' + digest.encode() + b'","metadata":{"x":' + deep_value + b"}}", 400),
            ("digest type", json.dumps({"context_digest": 7}).encode(), 400),
            ("prompt hash type", json.dumps({"prompt_hash": True}).encode(), 400),
            ("action type", json.dumps({"context_digest": digest, "action": 4}).encode(), 400),
            ("action too long", json.dumps({"context_digest": digest, "action": "a" * 121}).encode(), 400),
            ("metadata array", json.dumps({"context_digest": digest, "metadata": [1]}).encode(), 400),
            ("nested metadata", json.dumps({"context_digest": digest, "metadata": {"x": {"y": 1}}}).encode(), 400),
            ("metadata key too long", json.dumps({"context_digest": digest, "metadata": {"k" * 65: 1}}).encode(), 400),
            ("metadata truncation collision", json.dumps({"context_digest": digest, "metadata": {"k" * 64 + "a": 1, "k" * 64 + "b": 2}}).encode(), 400),
            ("metadata oversized integer", json.dumps({"context_digest": digest, "metadata": {"x": 2**53}}).encode(), 400),
            ("metadata value too long", json.dumps({"context_digest": digest, "metadata": {"x": "v" * 257}}).encode(), 400),
            ("too many metadata entries", json.dumps({"context_digest": digest, "metadata": {f"k{i}": i for i in range(17)}}).encode(), 400),
            ("unsupported field", json.dumps({"context_digest": digest, "unexpected": "x"}).encode(), 400),
            ("lone surrogate", b'{"context_digest":"' + digest.encode() + b'","action":"\\ud800"}', 400),
            ("maximum body valid JSON missing digest", b'{"metadata":{}}' + b" " * (self.api.MAX_BODY - len(b'{"metadata":{}}')), 400),
            ("oversize body", b" " * (self.api.MAX_BODY + 1), 413),
        ]

        for label, raw, expected_status in cases:
            with self.subTest(case=label):
                status, body = self._post(raw)
                self.assertEqual(status, expected_status, body[:500])
                if expected_status == 400:
                    response = json.loads(body)
                    self.assertIn("error", response)
                    if label == "maximum body valid JSON missing digest":
                        self.assertEqual(response["error"], "missing_required_digest")
                self._assert_no_state_writes()

    def test_02_valid_metadata_is_stored_retrieved_and_cryptographically_verified(self):
        from continuity_receipt import keys
        from continuity_receipt.canon import canonical_bytes, sha256_prefixed

        digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        submitted = {
            "context_digest": digest,
            "action": "agent.decision",
            "model": "local-test-model",
            "agent_id": "agent-test-1",
            "metadata": {"step": 42, "approved": True, "optional": None, "note": "kept"},
        }
        status, raw = self._post(json.dumps(submitted, separators=(",", ":")).encode())
        self.assertEqual(status, 200, raw)
        response = json.loads(raw)
        receipt = response["receipt"]
        sig = receipt.pop("sig")
        canonical = canonical_bytes(receipt)
        self.assertEqual(response["digest"], sha256_prefixed(canonical))
        self.assertTrue(keys.verify(sig["key"], canonical, sig["value"]))
        self.assertEqual(receipt["metadata"], submitted["metadata"])
        self.assertEqual(receipt["action"], submitted["action"])

        status, stored_raw = _response(f"{self.base_url}/notarize/{response['digest'].split(':', 1)[1]}")
        self.assertEqual(status, 200)
        stored = json.loads(stored_raw)
        self.assertIn("caller-supplied digests and claims", stored["note"])
        stored_receipt = stored["notarization"]
        stored_sig = stored_receipt.pop("sig")
        stored_canonical = canonical_bytes(stored_receipt)
        self.assertEqual(stored["notarization_digest"], sha256_prefixed(stored_canonical))
        self.assertTrue(keys.verify(stored_sig["key"], stored_canonical, stored_sig["value"]))

    def test_03_info_describes_persistence_and_erc_adapter_limits(self):
        status, raw = _response(f"{self.base_url}/info")
        self.assertEqual(status, 200)
        info = json.loads(raw)
        privacy = info["privacy"].lower()
        for item in ("payment receipts", "notarizations", "crystals", "anchors", "signing key"):
            self.assertIn(item, privacy)
        self.assertIn("caller-supplied tenant-hash locator", privacy)
        self.assertIn("no authenticated tenant isolation", info["crystals"]["isolation"])
        self.assertIn("issuer_policy", info["erc8004"])
        self.assertIn("anchors", info["erc8004"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run isolated loopback tests against a hosted receipt-api.py candidate."
    )
    parser.add_argument("--source", required=True, type=pathlib.Path)
    args, unittest_args = parser.parse_known_args()
    SOURCE = args.source.resolve()
    unittest.main(argv=[sys.argv[0], *unittest_args], verbosity=2)
