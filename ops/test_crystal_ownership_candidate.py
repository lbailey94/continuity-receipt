#!/usr/bin/env python3
"""Isolated loopback checks for the Phase 4C owner-bound crystal candidate.

Runs the candidate authd (trusted gateway) and receipt-api together on
loopback with synthetic principals, keys, secrets, and crystals. It never
reads host state or credentials; fresh temporary state directories are
injected for both processes. The harness intentionally crafts adversarial
assertions (wrong secret, expired, replayed, retargeted) with the shared
synthetic secret.

Opt in explicitly:

  python3 ops/test_crystal_ownership_candidate.py \
      --authd ops/crystal-ownership-candidate/src/authd.py \
      --api ops/crystal-ownership-candidate/src/receipt-api.py
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import importlib.util
import json
import os
import pathlib
import secrets
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

AUTHD_SOURCE: pathlib.Path | None = None
API_SOURCE: pathlib.Path | None = None

OWNER_A = "a1" * 32
OWNER_B = "b2" * 32
TOKEN_A = "wm_test_key_owner_a"
TOKEN_B = "wm_test_key_owner_b"
TOKEN_UNMAPPED = "wm_test_key_unmapped"
CRYSTAL_SECRET = hashlib.sha256(b"phase4c-loopback-synthetic-secret").digest()


def _load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load candidate source: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _response(url: str, method: str = "GET", token: str | None = None,
              data: bytes | None = None, headers: dict | None = None,
              timeout: int = 10):
    request_headers = dict(headers or {})
    if token:
        request_headers["Authorization"] = f"Bearer {token}"
    if data is not None:
        request_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(url, data=data, headers=request_headers,
                                     method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


class OwnershipCandidateLoopback(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if AUTHD_SOURCE is None or API_SOURCE is None:
            raise unittest.SkipTest(
                "standalone phase 4C harness; run with --authd PATH --api PATH"
            )
        for path in (AUTHD_SOURCE, API_SOURCE):
            if not path.is_file():
                raise RuntimeError(f"candidate source does not exist: {path}")

        cls.tempdir = tempfile.TemporaryDirectory(prefix="crystal-ownership-phase4c-")
        root = pathlib.Path(cls.tempdir.name)
        cls.gateway_state = root / "gateway-state"
        cls.api_state = root / "api-state"
        cls.gateway_state.mkdir(parents=True)
        cls.api_state.mkdir(parents=True)

        for target in ("crystal_assertion.secret",):
            (cls.gateway_state / target).write_bytes(CRYSTAL_SECRET)
            (cls.api_state / target).write_bytes(CRYSTAL_SECRET)
        (cls.gateway_state / "keys.json").write_text(json.dumps({"keys": [
            {"name": "owner-a", "token": TOKEN_A, "owner_id": OWNER_A, "daily_cap": 1000},
            {"name": "owner-b", "token": TOKEN_B, "owner_id": OWNER_B, "daily_cap": 1000},
            {"name": "unmapped", "token": TOKEN_UNMAPPED, "daily_cap": 1000},
        ]}) + "\n", encoding="utf-8")

        previous_state_env = os.environ.get("WM_RECEIPT_API_STATE")
        os.environ["WM_RECEIPT_API_STATE"] = str(cls.api_state)
        try:
            cls.api = _load_module("receipt_api_phase4c_candidate", API_SOURCE)
            cls.authd = _load_module("authd_phase4c_candidate", AUTHD_SOURCE)
        finally:
            if previous_state_env is None:
                os.environ.pop("WM_RECEIPT_API_STATE", None)
            else:
                os.environ["WM_RECEIPT_API_STATE"] = previous_state_env

        cls.api_server = cls.api.ThreadingHTTPServer(("127.0.0.1", 0), cls.api.Handler)
        cls.api_url = f"http://127.0.0.1:{cls.api_server.server_address[1]}"
        cls._thread(cls.api_server)

        class GatewayServer(ThreadingHTTPServer):
            request_queue_size = 128
            state_dir = cls.gateway_state
            upstream = cls.api_url
            anon_daily_cap = 2000
            keyless_paths = ["/crystals/*"]
            x402_enabled = False
            x402_version = 2
            x402_facilitator = "https://x402.org/facilitator"
            x402_pay_to = ""
            x402_asset = ""
            x402_daily_cap = 1000
            x402_network = "base-sepolia"
            x402_price = 3000
            x402_resource = "http://127.0.0.1/"
            x402_nonce_lock = threading.Lock()
            payment_receipts_url = ""
            payment_receipts_public_base_url = ""
            internal_token_file = ""
            trial_per_ip = 0
            oauth_state = ""
            oauth_resource_metadata = ""

        cls.gateway_server = GatewayServer(("127.0.0.1", 0), cls.authd.Gateway)
        cls.gateway_url = f"http://127.0.0.1:{cls.gateway_server.server_address[1]}"
        cls._thread(cls.gateway_server)

    @classmethod
    def _thread(cls, server):
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        if not hasattr(cls, "server_threads"):
            cls.server_threads = []
        cls.server_threads.append((server, thread))

    @classmethod
    def tearDownClass(cls):
        for server, thread in getattr(cls, "server_threads", []):
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        cls.tempdir.cleanup()
        sys.modules.pop("receipt_api_phase4c_candidate", None)
        sys.modules.pop("authd_phase4c_candidate", None)

    # ── helpers ─────────────────────────────────────────────────────────
    def _seal(self, tenant_hash: str, plaintext: bytes = b"synthetic memory envelope"):
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        created_at = dt.datetime.now(dt.timezone.utc).isoformat()
        aad = self.api.build_aad("chacha20-poly1305", tenant_hash, None, created_at)
        ciphertext = self.api.ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
        crystal = self.api.MemoryCrystal(
            crystal_id="sha256:" + hashlib.sha256(ciphertext).hexdigest(),
            parent_crystal_id=None,
            tenant_hash=tenant_hash,
            cipher="chacha20-poly1305",
            nonce=nonce,
            ciphertext=ciphertext,
            size_bytes=len(ciphertext),
            created_at=created_at,
        )
        return crystal, key, plaintext, aad

    @staticmethod
    def _sign_claims(claims: dict, secret: bytes = CRYSTAL_SECRET) -> str:
        """Adversarial crafting helper: the same wire format authd emits."""
        encoded = base64.urlsafe_b64encode(json.dumps(
            claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).rstrip(b"=").decode("ascii")
        signature = base64.urlsafe_b64encode(hmac.new(
            secret, b"wm-crystal-assertion-v1." + encoded.encode("ascii"),
            hashlib.sha256).digest()).rstrip(b"=").decode("ascii")
        return encoded + "." + signature

    def _claims(self, method: str, target: str, body: bytes, **overrides) -> dict:
        now = int(time.time())
        claims = {
            "v": 1,
            "owner_id": OWNER_A,
            "method": method,
            "target": target,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "iat": now,
            "exp": now + 30,
            "nonce": secrets.token_hex(16),
        }
        claims.update(overrides)
        return claims

    # ── gateway-level tests ─────────────────────────────────────────────
    def test_01_owner_write_then_read_roundtrip(self):
        evidence = self._owner_a_crystal()
        crystal_hex = evidence["hex"]
        status, raw = _response(f"{self.gateway_url}/crystals/{crystal_hex}",
                                token=TOKEN_A)
        self.assertEqual(status, 200, raw)
        stored = json.loads(raw)
        self.assertEqual(stored["tenant_hash"], f"sha256:{OWNER_A}")
        recovered = self.api.ChaCha20Poly1305(evidence["key"]).decrypt(
            base64.urlsafe_b64decode(stored["nonce"]),
            base64.urlsafe_b64decode(stored["ciphertext"]),
            evidence["aad"],
        )
        self.assertEqual(recovered, evidence["plaintext"])

    def test_02_keyless_read_fails_closed(self):
        crystal_hex = self._owner_a_crystal()["hex"]
        status, raw = _response(f"{self.gateway_url}/crystals/{crystal_hex}")
        self.assertEqual(status, 403, raw)
        self.assertIn("crystal_owner_not_mapped", raw.decode())

    def test_03_unmapped_key_denied(self):
        crystal_hex = self._owner_a_crystal()["hex"]
        status, raw = _response(f"{self.gateway_url}/crystals/{crystal_hex}",
                                token=TOKEN_UNMAPPED)
        self.assertEqual(status, 403, raw)
        self.assertIn("crystal_owner_not_mapped", raw.decode())

    def test_04_cross_owner_read_uniform_miss(self):
        crystal_hex = self._owner_a_crystal()["hex"]
        status, raw = _response(f"{self.gateway_url}/crystals/{crystal_hex}",
                                token=TOKEN_B)
        self.assertEqual(status, 404, raw)
        self.assertNotIn(b"ciphertext", raw)

    def test_05_spoofed_internal_headers_stripped(self):
        crystal_hex = self._owner_a_crystal()["hex"]
        status, raw = _response(
            f"{self.gateway_url}/crystals/{crystal_hex}",
            token=TOKEN_A,
            headers={
                "X-WM-Crystal-Assertion": "forged.payload",
                "X-WM-Crystal-Owner": OWNER_B,
                "X-WM-Principal": "forged-principal",
                "X-Tenant-Hash": f"sha256:{OWNER_B}",
            },
        )
        self.assertEqual(status, 200, raw)
        self.assertEqual(json.loads(raw)["tenant_hash"], f"sha256:{OWNER_A}")

    def test_06_tenant_selector_mismatch_uniform_miss(self):
        crystal_hex = self._owner_a_crystal()["hex"]
        status, raw = _response(
            f"{self.gateway_url}/crystals/{crystal_hex}?tenant=sha256:{OWNER_B}",
            token=TOKEN_A,
        )
        self.assertEqual(status, 404, raw)
        status, raw = _response(
            f"{self.gateway_url}/crystals/{OWNER_B}/{crystal_hex}", token=TOKEN_A
        )
        self.assertEqual(status, 404, raw)

    def test_07_owner_cannot_write_foreign_envelope(self):
        foreign, _, _, _ = self._seal(f"sha256:{OWNER_A}")
        status, raw = _response(f"{self.gateway_url}/crystals", method="POST",
                                token=TOKEN_B, data=foreign.to_json().encode())
        self.assertEqual(status, 403, raw)
        self.assertIn("crystal owner mismatch", raw.decode())

        own, _, _, _ = self._seal(f"sha256:{OWNER_B}")
        status, raw = _response(f"{self.gateway_url}/crystals", method="POST",
                                token=TOKEN_B, data=own.to_json().encode())
        self.assertEqual(status, 201, raw)

    def test_08_lineage_scoped_to_owner(self):
        status, raw = _response(f"{self.gateway_url}/crystals/lineage", token=TOKEN_A)
        self.assertEqual(status, 200, raw)
        payload = json.loads(raw)
        self.assertEqual(payload["tenant_hash"], f"sha256:{OWNER_A}")
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["crystals"][0]["crystal_id"],
                         f"sha256:{self._owner_a_crystal()['hex']}")

        status, raw = _response(
            f"{self.gateway_url}/crystals/lineage?tenant=sha256:{OWNER_B}",
            token=TOKEN_A,
        )
        self.assertEqual(status, 404, raw)

    # ── direct-to-API tests (assertion is the only credential) ──────────
    def test_09_direct_api_requires_valid_assertion(self):
        crystal_hex = self._owner_a_crystal()["hex"]
        path = f"/crystals/{crystal_hex}"
        status, raw = _response(f"{self.api_url}{path}")
        self.assertEqual(status, 401, raw)

        forged = self._sign_claims(
            self._claims("GET", path, b""),
            secret=hashlib.sha256(b"wrong-secret").digest(),
        )
        status, raw = _response(f"{self.api_url}{path}",
                                headers={"X-WM-Crystal-Assertion": forged})
        self.assertEqual(status, 401, raw)

    def test_10_direct_api_accepts_valid_assertion_then_rejects_replay(self):
        crystal_hex = self._owner_a_crystal()["hex"]
        path = f"/crystals/{crystal_hex}"
        assertion = self.authd._make_crystal_assertion(
            CRYSTAL_SECRET, OWNER_A, "GET", path, b"")
        headers = {"X-WM-Crystal-Assertion": assertion}
        status, raw = _response(f"{self.api_url}{path}", headers=headers)
        self.assertEqual(status, 200, raw)
        status, raw = _response(f"{self.api_url}{path}", headers=headers)
        self.assertEqual(status, 401, raw)
        self.assertIn("crystal access denied", raw.decode())

    def test_11_lifetime_bounds(self):
        crystal_hex = self._owner_a_crystal()["hex"]
        path = f"/crystals/{crystal_hex}"
        now = int(time.time())
        variants = {
            "expired": {"iat": now - 120, "exp": now - 60},
            "future": {"iat": now + 60, "exp": now + 90},
            "too_long": {"iat": now, "exp": now + 3600},
        }
        for label, override in variants.items():
            with self.subTest(label=label):
                assertion = self._sign_claims(self._claims("GET", path, b"", **override))
                status, raw = _response(
                    f"{self.api_url}{path}", headers={"X-WM-Crystal-Assertion": assertion}
                )
                self.assertEqual(status, 401, raw)

    def test_12_method_target_body_binding(self):
        crystal_hex = self._owner_a_crystal()["hex"]
        path = f"/crystals/{crystal_hex}"

        assertion = self._sign_claims(self._claims("GET", path + "?x=1", b""))
        status, raw = _response(f"{self.api_url}{path}",
                                headers={"X-WM-Crystal-Assertion": assertion})
        self.assertEqual(status, 401, raw)

        assertion = self._sign_claims(self._claims("GET", path, b"different-body"))
        status, raw = _response(f"{self.api_url}{path}",
                                headers={"X-WM-Crystal-Assertion": assertion})
        self.assertEqual(status, 401, raw)

        crystal, _, _, _ = self._seal(f"sha256:{OWNER_A}")
        other = crystal.to_json().encode()
        assertion = self._sign_claims(self._claims("GET", "/crystals", b""))
        status, raw = _response(f"{self.api_url}/crystals", method="POST",
                                data=other,
                                headers={"X-WM-Crystal-Assertion": assertion})
        self.assertEqual(status, 401, raw)

    def _owner_a_crystal(self) -> dict:
        evidence = getattr(self.__class__, "_crystal_a", None)
        if evidence:
            return evidence
        tenant = f"sha256:{OWNER_A}"
        crystal, key, plaintext, aad = self._seal(tenant)
        status, raw = _response(f"{self.gateway_url}/crystals", method="POST",
                                token=TOKEN_A, data=crystal.to_json().encode())
        self.assertEqual(status, 201, raw)
        evidence = {
            "hex": crystal.crystal_id.removeprefix("sha256:"),
            "key": key,
            "plaintext": plaintext,
            "aad": aad,
        }
        self.__class__._crystal_a = evidence
        return evidence


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run isolated loopback evidence for the Phase 4C ownership candidate."
    )
    parser.add_argument("--authd", required=True, type=pathlib.Path)
    parser.add_argument("--api", required=True, type=pathlib.Path)
    args, unittest_args = parser.parse_known_args()
    AUTHD_SOURCE = args.authd.resolve()
    API_SOURCE = args.api.resolve()
    unittest.main(argv=[sys.argv[0], *unittest_args], verbosity=2)
