#!/usr/bin/env python3
"""Offline baseline characterization of the hosted Crystal access boundary.

Opt in explicitly with:
  RUN_CRYSTAL_ACCESS_CHARACTERIZATION=1 python3 -m unittest \
    ops.test_crystal_access_boundary -v

This harness intentionally asserts that the current keyless locator access is
reproducible. A passing test means the gap was confirmed, not that access
control passed. It uses one synthetic encrypted crystal and disposable state.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

REPO = pathlib.Path(__file__).resolve().parents[1]
KIT = pathlib.Path("/home/lucas/Desktop/WHITEMAGIC/planning/private/hosted-kit")
API_SOURCE = KIT / "receipt-api.py"
CLIENT_SOURCE = pathlib.Path("/home/lucas/Desktop/WHITEMAGIC/WMv9/scripts/crystal_client.py")
sys.path.insert(0, str(REPO))


def request(url: str, method: str, payload: dict | None = None):
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if data is not None else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read(), dict(error.headers)


class CrystalAccessBaseline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("RUN_CRYSTAL_ACCESS_CHARACTERIZATION") != "1":
            raise unittest.SkipTest(
                "opt-in baseline gap characterization; set RUN_CRYSTAL_ACCESS_CHARACTERIZATION=1"
            )
        if not API_SOURCE.is_file() or not CLIENT_SOURCE.is_file():
            raise RuntimeError("canonical hosted API or Crystal client source is missing")

        cls.tempdir = tempfile.TemporaryDirectory(prefix="crystal-access-baseline-")
        cls.previous_state_env = os.environ.get("WM_RECEIPT_API_STATE")
        os.environ["WM_RECEIPT_API_STATE"] = str(pathlib.Path(cls.tempdir.name) / "api-state")

        api_spec = importlib.util.spec_from_file_location("receipt_api_crystal_baseline", API_SOURCE)
        if api_spec is None or api_spec.loader is None:
            raise RuntimeError("could not load canonical hosted API source")
        cls.api = importlib.util.module_from_spec(api_spec)
        sys.modules[api_spec.name] = cls.api
        api_spec.loader.exec_module(cls.api)

        client_spec = importlib.util.spec_from_file_location("crystal_client_baseline", CLIENT_SOURCE)
        if client_spec is None or client_spec.loader is None:
            raise RuntimeError("could not load Crystal client source")
        cls.client = importlib.util.module_from_spec(client_spec)
        sys.modules[client_spec.name] = cls.client
        client_spec.loader.exec_module(cls.client)

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
        sys.modules.pop("receipt_api_crystal_baseline", None)
        sys.modules.pop("crystal_client_baseline", None)

    def test_baseline_gap_outsider_with_locator_reads_ciphertext_not_plaintext(self):
        # All values are synthetic and exist only in the temp state directory.
        owner_key = os.urandom(32)
        outsider_key = os.urandom(32)
        owner_name = "synthetic-owner-for-baseline-only"
        plaintext = b"synthetic private Crystal payload; never real user data"
        envelope = self.client.seal_crystal(
            plaintext,
            owner_key,
            owner_name,
            metadata_public={"synthetic": True, "label": "baseline-only"},
            cipher="chacha20-poly1305",
        )
        tenant_locator = envelope["tenant_hash"]
        crystal_id = envelope["crystal_id"]
        path_id = crystal_id.removeprefix("sha256:")

        status, store_raw, _ = request(self.base_url + "/crystals", "POST", envelope)
        self.assertEqual(status, 201, store_raw)
        self.assertTrue(json.loads(store_raw)["stored"])

        # This mirrors configured keyless GET behavior: the caller supplies
        # X-Tenant-Hash / ?tenant. No gateway or authenticated principal is used.
        outsider_url = (
            f"{self.base_url}/crystals/{path_id}"
            f"?tenant={urllib.parse.quote(tenant_locator)}"
        )
        status, body, _ = request(outsider_url, "GET")
        self.assertEqual(status, 200, body)
        disclosed = json.loads(body)
        self.assertEqual(disclosed["crystal_id"], crystal_id)
        self.assertEqual(disclosed["tenant_hash"], tenant_locator)
        self.assertEqual(disclosed["ciphertext"], envelope["ciphertext"])
        self.assertEqual(disclosed["metadata_public"], envelope["metadata_public"])

        # Ciphertext disclosure is not plaintext decryption: only the owner key
        # opens the authenticated envelope; the synthetic outsider key fails.
        self.assertEqual(self.client.unseal_crystal(disclosed, owner_key), plaintext)
        with self.assertRaises(Exception, msg="outsider key must not decrypt ciphertext"):
            self.client.unseal_crystal(disclosed, outsider_key)

        lineage_url = (
            f"{self.base_url}/crystals/lineage?tenant={urllib.parse.quote(tenant_locator)}"
        )
        status, lineage_raw, _ = request(lineage_url, "GET")
        self.assertEqual(status, 200, lineage_raw)
        lineage = json.loads(lineage_raw)
        self.assertEqual(lineage["count"], 1)
        self.assertEqual(lineage["crystals"][0]["crystal_id"], crystal_id)
        self.assertEqual(lineage["crystals"][0]["metadata_public"], envelope["metadata_public"])

        print(
            "BASELINE GAP REPRODUCED (not a security pass): unauthenticated caller "
            "with locator retrieved synthetic ciphertext and public lineage metadata; "
            "only the owner key decrypted it."
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
