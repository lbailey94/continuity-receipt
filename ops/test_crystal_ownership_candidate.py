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
import concurrent.futures
import datetime as dt
import hashlib
import hmac
import importlib.util
import json
import multiprocessing
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
CRYSTAL_OLD_SECRET = hashlib.sha256(b"phase4c-loopback-old-secret").digest()


def _load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load candidate source: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _subprocess_reserve(api_path: str, state_path: str, assertion: str,
                        method: str, target: str, now: int,
                        start_event, result_queue):
    """Independent process used to exercise SQLite replay serialization."""
    module = _load_module(f"receipt_api_replay_worker_{os.getpid()}", pathlib.Path(api_path))
    state = pathlib.Path(state_path)
    module.STATE_DIR = state
    module.CRYSTAL_ASSERTION_SECRET_PATH = state / "crystal_assertion.secret"
    module.CRYSTAL_ASSERTION_KEYS_PATH = state / "crystal_assertion.keys.json"
    module.CRYSTAL_ASSERTION_REPLAY_PATH = state / "crystal_assertion_replay.sqlite3"
    start_event.wait(timeout=10)
    try:
        module.verify_crystal_assertion(assertion, method, target, b"", now=now)
        result_queue.put("accepted")
    except module.CrystalAssertionError as error:
        result_queue.put("rejected:" + str(error))


def _response(url: str, method: str = "GET", token: str | None = None,
              data: bytes | None = None, headers: dict | None = None,
              timeout: int = 10, with_headers: bool = False):
    request_headers = dict(headers or {})
    if token:
        request_headers["Authorization"] = f"Bearer {token}"
    if data is not None:
        request_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(url, data=data, headers=request_headers,
                                     method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            result = (response.status, response.read())
            return (*result, response.headers) if with_headers else result
    except urllib.error.HTTPError as error:
        result = (error.code, error.read())
        return (*result, error.headers) if with_headers else result


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

        ring = {
            "active_kid": "test-current",
            "keys": {
                "test-current": base64.urlsafe_b64encode(CRYSTAL_SECRET).decode().rstrip("="),
                "test-previous": base64.urlsafe_b64encode(CRYSTAL_OLD_SECRET).decode().rstrip("="),
            },
        }
        for state in (cls.gateway_state, cls.api_state):
            (state / "crystal_assertion.keys.json").write_text(json.dumps(ring), encoding="utf-8")
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
            "kid": "test-current",
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

    def test_malformed_gateway_keyring_fails_closed_and_is_restored(self):
        keyring_path = self.gateway_state / "crystal_assertion.keys.json"
        valid = keyring_path.read_bytes()
        malformed_documents = [
            b"[]\n",
            b'{"active_kid":"test-current","keys":{},"keys":{"test-current":"' +
            base64.urlsafe_b64encode(CRYSTAL_SECRET).rstrip(b"=") + b'"}}\n',
        ]
        try:
            for malformed in malformed_documents:
                with self.subTest(malformed=malformed[:24]):
                    keyring_path.write_bytes(malformed)
                    status, raw = _response(
                        f"{self.gateway_url}/crystals/owner-locator", token=TOKEN_A)
                    self.assertEqual(status, 503, raw)
                    self.assertIn(b"crystal_internal_auth_unavailable", raw)
        finally:
            keyring_path.write_bytes(valid)
        status, raw = _response(f"{self.gateway_url}/crystals/owner-locator", token=TOKEN_A)
        self.assertEqual(status, 200, raw)
        self.assertEqual(json.loads(raw)["owner_locator"], f"sha256:{OWNER_A}")

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
            CRYSTAL_SECRET, OWNER_A, "GET", path, b"", kid="test-current")
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

    def test_13_replay_persists_across_module_reload_and_skew_window(self):
        path = "/crystals/" + self._owner_a_crystal()["hex"]
        claims = self._claims("GET", path, b"")
        claims["iat"] = 10_000
        claims["exp"] = 10_030
        assertion = self._sign_claims(claims)
        owner = self.api.verify_crystal_assertion(assertion, "GET", path, b"", now=10_029)
        self.assertEqual(owner, OWNER_A)
        # A fresh module instance models a worker restart; SQLite remains the shared authority.
        reloaded = _load_module("receipt_api_phase4c_reloaded", API_SOURCE)
        reloaded.STATE_DIR = self.api_state
        reloaded.CRYSTAL_ASSERTION_SECRET_PATH = self.api_state / "crystal_assertion.secret"
        reloaded.CRYSTAL_ASSERTION_KEYS_PATH = self.api_state / "crystal_assertion.keys.json"
        reloaded.CRYSTAL_ASSERTION_REPLAY_PATH = self.api_state / "crystal_assertion_replay.sqlite3"
        with self.assertRaises(reloaded.CrystalAssertionError):
            reloaded.verify_crystal_assertion(assertion, "GET", path, b"", now=10_031)
        sys.modules.pop("receipt_api_phase4c_reloaded", None)

        boundary = self._claims("GET", path, b"")
        boundary["iat"] = 20_000
        boundary["exp"] = 20_030
        boundary_assertion = self._sign_claims(boundary)
        self.assertEqual(self.api.verify_crystal_assertion(
            boundary_assertion, "GET", path, b"", now=20_035), OWNER_A)
        with self.assertRaises(self.api.CrystalAssertionError):
            self.api.verify_crystal_assertion(
                self._sign_claims({**boundary, "nonce": secrets.token_hex(16)}),
                "GET", path, b"", now=20_036)

    def test_14_cross_process_replay_race_and_restart(self):
        path = "/crystals/" + self._owner_a_crystal()["hex"]
        now = int(time.time())
        claims = self._claims("GET", path, b"")
        claims["iat"] = now
        claims["exp"] = now + 20
        assertion = self._sign_claims(claims)
        context = multiprocessing.get_context("spawn")
        start_event = context.Event()
        result_queue = context.Queue()
        workers = [context.Process(
            target=_subprocess_reserve,
            args=(str(API_SOURCE), str(self.api_state), assertion, "GET", path,
                  now + 19, start_event, result_queue),
        ) for _ in range(4)]
        for worker in workers:
            worker.start()
        start_event.set()
        outcomes = [result_queue.get(timeout=10) for _ in workers]
        for worker in workers:
            worker.join(timeout=10)
            self.assertEqual(worker.exitcode, 0)
        self.assertEqual(outcomes.count("accepted"), 1, outcomes)
        self.assertEqual(outcomes.count("rejected:assertion replay"), 3, outcomes)

        # A new process after all contenders exit still sees the durable marker.
        restart_event = context.Event()
        restart_queue = context.Queue()
        restart = context.Process(
            target=_subprocess_reserve,
            args=(str(API_SOURCE), str(self.api_state), assertion, "GET", path,
                  now + 21, restart_event, restart_queue),
        )
        restart.start()
        restart_event.set()
        outcome = restart_queue.get(timeout=10)
        restart.join(timeout=10)
        self.assertEqual(restart.exitcode, 0)
        self.assertEqual(outcome, "rejected:assertion replay")

    def test_15_lifetime_ordering_and_non_bool_integers(self):
        path = "/crystals/" + self._owner_a_crystal()["hex"]
        now = int(time.time())
        cases = [
            {"iat": now, "exp": now},
            {"iat": now + 1, "exp": now},
            {"iat": True, "exp": now + 30},
            {"iat": now, "exp": False},
        ]
        for claims_override in cases:
            with self.subTest(claims=claims_override):
                assertion = self._sign_claims(self._claims("GET", path, b"", **claims_override))
                with self.assertRaises(self.api.CrystalAssertionError):
                    self.api.verify_crystal_assertion(assertion, "GET", path, b"")

    def test_16_concurrent_replay_reservation_is_single_use(self):
        path = "/crystals/" + self._owner_a_crystal()["hex"]
        assertion = self._sign_claims(self._claims("GET", path, b""))

        def reserve(_):
            try:
                self.api.verify_crystal_assertion(assertion, "GET", path, b"")
                return True
            except self.api.CrystalAssertionError:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(reserve, range(8)))
        self.assertEqual(sum(outcomes), 1)

    def test_17_assertion_key_rotation_overlap_and_revocation(self):
        path = "/crystals/" + self._owner_a_crystal()["hex"]
        claims = self._claims("GET", path, b"", kid="test-previous")
        assertion = self._sign_claims(claims, CRYSTAL_OLD_SECRET)
        self.assertEqual(self.api.verify_crystal_assertion(assertion, "GET", path, b""), OWNER_A)
        ring = {"active_kid": "test-current", "keys": {
            "test-current": base64.urlsafe_b64encode(CRYSTAL_SECRET).decode().rstrip("=")
        }}
        (self.api_state / "crystal_assertion.keys.json").write_text(json.dumps(ring), encoding="utf-8")
        revoked = self._sign_claims(self._claims("GET", path, b"", kid="test-previous"), CRYSTAL_OLD_SECRET)
        with self.assertRaises(self.api.CrystalAssertionError):
            self.api.verify_crystal_assertion(revoked, "GET", path, b"")

    def test_18_owner_locator_bootstrap_and_client_sealing(self):
        status, raw = _response(f"{self.gateway_url}/crystals/owner-locator", token=TOKEN_A)
        self.assertEqual(status, 200, raw)
        locator = json.loads(raw)["owner_locator"]
        self.assertEqual(locator, f"sha256:{OWNER_A}")
        client = _load_module("crystal_client_phase4c_candidate", API_SOURCE.parent / "crystal_client.py")
        envelope = client.seal_crystal("synthetic", b"k" * 32, "unused", owner_locator=locator)
        self.assertEqual(envelope["tenant_hash"], locator)
        self.assertEqual(envelope["spec"], "wm-crystal/1.0")

    def test_19_ownerless_legacy_locator_is_quarantined(self):
        legacy_locator = self.api.compute_tenant_hash("synthetic-unmapped-legacy")
        crystal, _, _, _ = self._seal(legacy_locator)
        source = self.api.TenantCrystalStore(self.api.CRYSTALS_DIR).store_crystal(crystal)
        original = source.read_bytes()
        crystal_hex = crystal.crystal_id.removeprefix("sha256:")
        plan = self.api.plan_legacy_crystal_quarantine(
            self.api.CRYSTALS_DIR, self.api.CRYSTAL_QUARANTINE_DIR,
            registered_owner_ids=[OWNER_A, OWNER_B])
        entry = next(item for item in plan["entries"] if item["source_sha256"] == hashlib.sha256(original).hexdigest())
        self.assertEqual(entry["disposition"], "quarantine_unmapped_legacy_owner")
        self.assertNotIn("owner_id", entry, "a locator must never become an owner claim")
        manifest_path = self.api_state / "legacy-quarantine-dry-run.json"
        manifest_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
        self.assertTrue(source.exists(), "dry-run must not move or alter source bytes")
        applied = self.api.apply_legacy_crystal_quarantine_plan(json.loads(manifest_path.read_text()))
        quarantine_file = self.api.CRYSTAL_QUARANTINE_DIR / entry["destination"]
        self.assertFalse(source.exists())
        self.assertEqual(quarantine_file.read_bytes(), original)
        self.assertEqual(applied["entries"][0]["status"], "quarantined")
        self.assertEqual(self.api.CRYSTAL_QUARANTINE_DIR.stat().st_mode & 0o777, 0o700)
        self.assertEqual(quarantine_file.parent.stat().st_mode & 0o077, 0)

        owner_path = f"/crystals/{crystal_hex}"
        assertion = self.authd._make_crystal_assertion(
            CRYSTAL_SECRET, OWNER_A, "GET", owner_path, b"", kid="test-current")
        status, raw = _response(f"{self.api_url}{owner_path}",
                                headers={"X-WM-Crystal-Assertion": assertion})
        self.assertEqual(status, 404, raw)
        status, raw = _response(f"{self.gateway_url}/crystals/lineage", token=TOKEN_A)
        self.assertEqual(status, 200, raw)
        self.assertNotIn(crystal_hex, raw.decode())

    def test_20_quarantine_manifest_preflights_all_sources(self):
        source_root = pathlib.Path(self.tempdir.name) / "preflight-source"
        target_root = pathlib.Path(self.tempdir.name) / "preflight-quarantine"
        # Use regular synthetic bytes; plan hashes exact source bytes.
        file_a = source_root / "a" / "crystals" / "aa" / "a.crystal"
        file_b = source_root / "b" / "crystals" / "bb" / "b.crystal"
        file_a.parent.mkdir(parents=True)
        file_b.parent.mkdir(parents=True)
        file_a.write_bytes(b'{"tenant_hash":"sha256:' + b"a" * 64 + b'"}')
        file_b.write_bytes(b'{"tenant_hash":"sha256:' + b"b" * 64 + b'"}')
        plan = self.api.plan_legacy_crystal_quarantine(source_root, target_root)
        file_b.write_bytes(b"changed after dry run")
        with self.assertRaises(ValueError):
            self.api.apply_legacy_crystal_quarantine_plan(plan)
        self.assertTrue(file_a.exists(), "whole-manifest preflight prevents partial moves")
        self.assertFalse(target_root.exists())

    def test_21_quarantine_permissions_preflight_prevents_partial_moves(self):
        source_root = pathlib.Path(self.tempdir.name) / "permissions-source"
        target_root = pathlib.Path(self.tempdir.name) / "permissions-quarantine"
        source_a = source_root / "a" / "crystals" / "aa" / "a.crystal"
        source_b = source_root / "b" / "crystals" / "bb" / "b.crystal"
        source_a.parent.mkdir(parents=True)
        source_b.parent.mkdir(parents=True)
        source_a.write_bytes(b"synthetic-a")
        source_b.write_bytes(b"synthetic-b")
        plan = self.api.plan_legacy_crystal_quarantine(source_root, target_root)

        # First row would otherwise create a private path. A later preexisting
        # permissive path must be caught before any row is linked or unlinked.
        permissive = target_root / "b" / "crystals" / "bb"
        permissive.mkdir(parents=True, mode=0o755)
        permissive.chmod(0o755)
        with self.assertRaises(PermissionError):
            self.api.apply_legacy_crystal_quarantine_plan(plan)

        self.assertTrue(source_a.exists())
        self.assertTrue(source_b.exists())
        self.assertEqual(list(target_root.rglob("*.crystal")), [])
        self.assertFalse((target_root / "a").exists(), "preflight must precede directory creation")

    def test_22_quarantine_manifest_rejects_duplicate_source_before_moves(self):
        source_root = pathlib.Path(self.tempdir.name) / "duplicate-source"
        target_root = pathlib.Path(self.tempdir.name) / "duplicate-quarantine"
        source = source_root / "legacy" / "crystals" / "cc" / "c.crystal"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"synthetic-legacy")
        plan = self.api.plan_legacy_crystal_quarantine(source_root, target_root)
        self.assertEqual(len(plan["entries"]), 1)
        plan["entries"].append(dict(plan["entries"][0]))

        with self.assertRaisesRegex(ValueError, "duplicate source or destination"):
            self.api.apply_legacy_crystal_quarantine_plan(plan)

        self.assertTrue(source.exists())
        self.assertFalse(target_root.exists())

    def test_23_candidate_info_has_no_stale_keyless_crystal_claims(self):
        status, raw = _response(f"{self.api_url}/info")
        self.assertEqual(status, 200, raw)
        info = json.loads(raw)
        rendered = json.dumps(info["crystals"]) + json.dumps(info["privacy"])
        self.assertIn("owner-locator", rendered)
        self.assertIn("authenticated owner assertion", rendered)
        self.assertNotIn("keyless reads have no authenticated", rendered)
        status, raw = _response(f"{self.api_url}/crystals")
        self.assertEqual(status, 200, raw)
        crystal_info = json.loads(raw)
        self.assertEqual(crystal_info["access_model"], info["crystals"]["access_model"])

    def test_24_crystal_responses_are_never_shared_cached(self):
        def check(response_headers):
            self.assertEqual(response_headers.get("Cache-Control"), "private, no-store")
            vary = {part.strip().lower() for part in response_headers.get("Vary", "").split(",")}
            self.assertTrue({"authorization", "x-api-key", "x-session-pass"}.issubset(vary))

        evidence = self._owner_a_crystal()
        url = f"{self.gateway_url}/crystals/{evidence['hex']}"
        status, raw, headers = _response(url, token=TOKEN_A, with_headers=True)
        self.assertEqual(status, 200, raw)
        check(headers)

        etag = headers.get("ETag")
        self.assertTrue(etag)
        status, _, headers = _response(url, token=TOKEN_A,
                                       headers={"If-None-Match": etag}, with_headers=True)
        self.assertEqual(status, 304)
        check(headers)

        for request_url, token, expected in (
            (url, None, 403),
            (url, TOKEN_UNMAPPED, 403),
            (url, TOKEN_B, 404),
            (f"{self.gateway_url}/crystals", TOKEN_A, 200),
            (f"{self.gateway_url}/crystals/owner-locator", TOKEN_A, 200),
            (f"{self.gateway_url}/crystals/lineage", TOKEN_A, 200),
        ):
            with self.subTest(url=request_url, token=token, status=expected):
                status, _, headers = _response(request_url, token=token, with_headers=True)
                self.assertEqual(status, expected)
                check(headers)

        status, _, headers = _response(f"{self.api_url}/crystals/{evidence['hex']}",
                                       with_headers=True)
        self.assertEqual(status, 401)
        check(headers)

        direct_path = f"/crystals/{evidence['hex']}"
        direct_assertion = self.authd._make_crystal_assertion(
            CRYSTAL_SECRET, OWNER_A, "GET", direct_path, b"", kid="test-current")
        status, _, headers = _response(f"{self.api_url}{direct_path}",
                                       headers={"X-WM-Crystal-Assertion": direct_assertion},
                                       with_headers=True)
        self.assertEqual(status, 200)
        check(headers)
        direct_etag = headers.get("ETag")
        direct_assertion = self.authd._make_crystal_assertion(
            CRYSTAL_SECRET, OWNER_A, "GET", direct_path, b"", kid="test-current")
        status, _, headers = _response(
            f"{self.api_url}{direct_path}",
            headers={"X-WM-Crystal-Assertion": direct_assertion,
                     "If-None-Match": direct_etag}, with_headers=True)
        self.assertEqual(status, 304)
        check(headers)

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
