"""Local-only tests for crystal envelope encryption and integrity checks."""

import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.request import Request

try:
    from cryptography.exceptions import InvalidTag
except ImportError:  # Keep the test module importable when the optional package is absent.
    InvalidTag = ValueError

_PARENT = Path(__file__).resolve().parents[1]
SCRIPTS = _PARENT / "src" if (_PARENT / "src" / "crystal_client.py").is_file() else _PARENT
sys.path.insert(0, str(SCRIPTS))
import crystal_client as cc  # noqa: E402


@unittest.skipIf(cc.AESGCM is None or cc.ChaCha20Poly1305 is None, "cryptography is optional")
class CrystalClientTest(unittest.TestCase):
    def test_round_trip_for_each_supported_cipher(self) -> None:
        key = bytes(range(32))
        plaintext = b"local crystal round trip"
        for cipher in ("aes-256-gcm", "chacha20-poly1305"):
            with self.subTest(cipher=cipher):
                envelope = cc.seal_crystal(plaintext, key, "test-tenant", cipher=cipher)
                self.assertEqual(cc.unseal_crystal(envelope, key), plaintext)

    def test_authenticated_fields_reject_tampering(self) -> None:
        key = bytes(range(32))
        envelope = cc.seal_crystal(
            b"tamper check", key, "test-tenant", parent_crystal_id="sha256:parent"
        )
        for field, value in (
            ("tenant_hash", "sha256:" + "0" * 64),
            ("parent_crystal_id", "sha256:other-parent"),
            ("created_at", "2030-01-01T00:00:00Z"),
            ("cipher", "chacha20-poly1305"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(envelope)
                changed[field] = value
                # Keep content-address verification from masking the AAD check.
                if field == "cipher":
                    ciphertext = cc.base64.urlsafe_b64decode(changed["ciphertext"])
                    changed["crystal_id"] = f"sha256:{hashlib.sha256(ciphertext).hexdigest()}"
                with self.assertRaises((ValueError, InvalidTag)):
                    cc.unseal_crystal(changed, key)

    def test_public_metadata_is_not_aad_bound(self) -> None:
        key = bytes(range(32))
        envelope = cc.seal_crystal(b"public metadata", key, "test-tenant", metadata_public={"label": "a"})
        envelope["metadata_public"] = {"label": "changed"}
        self.assertEqual(cc.unseal_crystal(envelope, key), b"public metadata")

    def test_api_urls_require_https_and_reject_embedded_secrets(self) -> None:
        for url in (
            "http://example.test",
            "https://user:pass@example.test",
            "https://example.test/path",
            "https://example.test?x=1",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                cc._require_https_api(url)

    def test_pull_rejects_malformed_ids_before_network_access(self) -> None:
        with self.assertRaises(ValueError):
            cc.pull_crystal("../../other-path", auth_token="dummy-token")

    def test_push_fails_closed_on_redirect(self) -> None:
        fake_opener = Mock()
        fake_opener.open.side_effect = HTTPError(
            "https://api.whitemagic.dev/crystals",
            307,
            "temporary redirect",
            {},
            BytesIO(b"secret-test-token reflected by endpoint"),
        )
        with patch.object(cc.urllib.request, "build_opener", return_value=fake_opener) as build_opener:
            with self.assertRaisesRegex(RuntimeError, "HTTP 307") as raised:
                cc.push_crystal({"ciphertext": "opaque"}, auth_token="secret-test-token")
        self.assertNotIn("secret-test-token", str(raised.exception))

        build_opener.assert_called_once_with(cc._NoRedirectHandler)
        fake_opener.open.assert_called_once()
        handler = cc._NoRedirectHandler()
        request = Request("https://api.whitemagic.dev/crystals", data=b"{}", method="POST")
        with self.assertRaises(HTTPError) as raised:
            handler.redirect_request(
                request,
                BytesIO(b""),
                307,
                "temporary redirect",
                {},
                "http://attacker.invalid/collect",
            )
        self.assertEqual(raised.exception.code, 307)

    def test_all_owner_requests_are_authenticated_and_use_fixed_paths(self) -> None:
        locator = "sha256:" + "a" * 64

        class Response:
            def __init__(self, value):
                self.payload = json.dumps(value).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def read(self):
                return self.payload

        opener = Mock()
        opener.open.side_effect = [
            Response({"stored": True}),
            Response({"crystal_id": "sha256:" + "b" * 64}),
            Response({"crystals": []}),
            Response({"owner_locator": locator}),
        ]
        token = "dummy-owner-token"
        with patch.object(cc.urllib.request, "build_opener", return_value=opener) as build:
            cc.push_crystal({"ciphertext": "fixture"}, auth_token=token)
            cc.pull_crystal("sha256:" + "b" * 64, auth_token=token)
            self.assertEqual(cc.pull_lineage(auth_token=token), [])
            self.assertEqual(cc.fetch_owner_locator(auth_token=token), locator)

        requests = [call.args[0] for call in opener.open.call_args_list]
        self.assertEqual([request.get_method() for request in requests], ["POST", "GET", "GET", "GET"])
        self.assertTrue(all(request.get_header("Authorization") == f"Bearer {token}" for request in requests))
        self.assertEqual(requests[0].full_url, "https://api.whitemagic.dev/crystals")
        self.assertEqual(requests[1].full_url, f"https://api.whitemagic.dev/crystals/{'b' * 64}")
        self.assertEqual(requests[2].full_url, "https://api.whitemagic.dev/crystals/lineage")
        self.assertEqual(requests[3].full_url, "https://api.whitemagic.dev/crystals/owner-locator")
        self.assertTrue(all("tenant=" not in request.full_url for request in requests))
        self.assertEqual(build.call_count, 4)
        self.assertTrue(all(call.args == (cc._NoRedirectHandler,) for call in build.call_args_list))

    def test_invalid_id_and_origins_fail_before_network_for_all_owner_requests(self) -> None:
        invalid_origins = (
            "http://example.test",
            "https://user:pass@example.test",
            "https://example.test/path",
            "https://example.test?x=1",
            "https://example.test:bad",
        )
        with patch.object(cc.urllib.request, "build_opener") as build:
            for origin in invalid_origins:
                calls = (
                    lambda: cc.push_crystal({}, api_url=origin, auth_token="dummy"),
                    lambda: cc.pull_crystal("b" * 64, api_url=origin, auth_token="dummy"),
                    lambda: cc.pull_lineage(api_url=origin, auth_token="dummy"),
                    lambda: cc.fetch_owner_locator(api_url=origin, auth_token="dummy"),
                )
                for call in calls:
                    with self.subTest(origin=origin), self.assertRaises(ValueError):
                        call()
            for malformed in ("../escape", "g" * 64, "a" * 63, "a" * 64 + "/x"):
                with self.assertRaises(ValueError):
                    cc.pull_crystal(malformed, auth_token="dummy")
            build.assert_not_called()

    def test_redirects_are_refused_for_all_owner_requests_without_echoing_token(self) -> None:
        token = "dummy-owner-token"
        calls = (
            lambda: cc.push_crystal({}, auth_token=token),
            lambda: cc.pull_crystal("a" * 64, auth_token=token),
            lambda: cc.pull_lineage(auth_token=token),
            lambda: cc.fetch_owner_locator(auth_token=token),
        )
        for call in calls:
            fake_opener = Mock()
            fake_opener.open.side_effect = HTTPError(
                "https://api.whitemagic.dev/crystals", 302, "Found", {},
                BytesIO(token.encode()),
            )
            with patch.object(cc.urllib.request, "build_opener", return_value=fake_opener) as build:
                with self.assertRaisesRegex(RuntimeError, "redirect refused") as raised:
                    call()
            self.assertNotIn(token, str(raised.exception))
            build.assert_called_once_with(cc._NoRedirectHandler)

    def test_owner_calls_require_keyword_auth_and_token_file_is_protected(self) -> None:
        with self.assertRaises(TypeError):
            cc.pull_crystal("a" * 64, "legacy-tenant")
        with self.assertRaises(TypeError):
            cc.pull_lineage("legacy-tenant")

        with tempfile.TemporaryDirectory() as td:
            token_path = Path(td) / "token"
            token_path.write_text("dummy-token\n", encoding="utf-8")
            os.chmod(token_path, 0o600)
            self.assertEqual(cc._token_from_inputs("UNSET_WM_CRYSTAL_TOKEN", str(token_path)), "dummy-token")
            if os.name == "posix":
                os.chmod(token_path, 0o644)
                with self.assertRaises(ValueError):
                    cc._token_from_inputs("UNSET_WM_CRYSTAL_TOKEN", str(token_path))
            link_path = Path(td) / "token-link"
            link_path.symlink_to(token_path)
            with self.assertRaises((OSError, ValueError)):
                cc._token_from_inputs("UNSET_WM_CRYSTAL_TOKEN", str(link_path))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO support required")
    def test_fifo_token_path_is_rejected_without_blocking(self) -> None:
        import subprocess

        with tempfile.TemporaryDirectory() as td:
            fifo = Path(td) / "token-fifo"
            os.mkfifo(fifo)
            code = (
                "import importlib.util,sys; "
                "s=importlib.util.spec_from_file_location('cc',sys.argv[1]); "
                "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                "\ntry: m._token_from_inputs('UNSET',sys.argv[2])\n"
                "except (ValueError,OSError): raise SystemExit(0)\n"
                "raise SystemExit(4)"
            )
            result = subprocess.run(
                [sys.executable, "-c", code, str(SCRIPTS / "crystal_client.py"), str(fifo)],
                capture_output=True, timeout=3, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

    def test_cli_uses_env_or_file_credentials_and_no_tenant_or_token_arguments(self) -> None:
        import contextlib
        import io

        original_argv = sys.argv
        output = io.StringIO()
        try:
            for command in ("seal", "push", "pull", "lineage"):
                sys.argv = [str(SCRIPTS / "crystal_client.py"), command, "--help"]
                with contextlib.redirect_stdout(output), self.assertRaises(SystemExit):
                    cc.main()
                help_text = output.getvalue()
                self.assertIn("--token-env", help_text)
                self.assertIn("--token-file", help_text)
                self.assertNotIn("--token ", help_text)
                if command in ("seal", "pull", "lineage"):
                    self.assertNotIn("--tenant", help_text)
                output.seek(0)
                output.truncate(0)
        finally:
            sys.argv = original_argv

    def test_i1_i2_kek_version_cell_id_binding_rotation_and_dek_erasure(self) -> None:
        kek_v1 = bytes(range(32))
        kek_v2 = bytes(reversed(range(32)))
        plaintext = b"SAIHM-aligned non-custodial crystal payload"

        env = cc.seal_crystal(plaintext, kek_v1, "test-tenant", cipher="chacha20-poly1305", kek_version=1)
        self.assertEqual(env["kek_version"], 1)
        self.assertEqual(env["id_kek_version"], 1)
        self.assertIsNotNone(env["wrapped_dek"])
        self.assertEqual(cc.unseal_crystal(env, kek_v1), plaintext)

        # I1: mutating nonce or id_kek_version must fail content-address verification before AEAD
        tampered_nonce = copy.deepcopy(env)
        tampered_nonce["nonce"] = cc.base64.urlsafe_b64encode(b"0" * 12).decode("ascii")
        with self.assertRaisesRegex(ValueError, "content-address verification failed"):
            cc.unseal_crystal(tampered_nonce, kek_v1)

        # I2: KEK rotation re-wraps DEK under kek_v2 (version 2) without changing crystal_id
        rotated = cc.rotate_crystal_kek(env, kek_v1, kek_v2, 2)
        self.assertEqual(rotated["crystal_id"], env["crystal_id"])
        self.assertEqual(rotated["id_kek_version"], 1)
        self.assertEqual(rotated["kek_version"], 2)
        self.assertNotEqual(rotated["wrapped_dek"], env["wrapped_dek"])
        with self.assertRaises((ValueError, InvalidTag)):
            cc.unseal_crystal(rotated, kek_v1)
        self.assertEqual(cc.unseal_crystal(rotated, kek_v2), plaintext)

        # I2/I3: destroying the wrapped DEK renders the crystal permanently undecryptable
        erased = cc.destroy_crystal_dek(rotated)
        self.assertIsNone(erased["wrapped_dek"])
        self.assertTrue(erased["dek_destroyed"])
        with self.assertRaisesRegex(ValueError, "cryptographically destroyed"):
            cc.unseal_crystal(erased, kek_v2)

    def test_i4_i6_client_sig_and_set_commitment_read_path(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        kek = bytes(range(32))
        ed_seed = b"test-ed25519-crystal-seed-32byte"
        anchor_seed = b"test-ed25519-anchor-seed-32bytes"
        anchor_pub = Ed25519PrivateKey.from_private_bytes(anchor_seed).public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        tenant_hash = cc.compute_tenant_hash("tenant-i6")

        c1 = cc.seal_crystal(b"step 1", kek, "tenant-i6", kek_version=1)
        c1 = cc.sign_crystal_envelope(c1, ed_seed)
        c2 = cc.seal_crystal(b"step 2", kek, "tenant-i6", parent_crystal_id=c1["crystal_id"], kek_version=1)
        c2 = cc.sign_crystal_envelope(c2, ed_seed, pq_alg="ml-dsa-65", pq_public_key_b64="cHFfcHVi", pq_sig_b64="cHFfc2ln")

        self.assertTrue(cc.verify_crystal_client_sig(c1))
        self.assertTrue(cc.verify_crystal_client_sig(c2, pq_verifier=lambda pub, msg, sig: sig == "cHFfc2ln"))

        comm = cc.compute_crystal_set_commitment([c1, c2], tenant_hash, signing_key=anchor_seed)
        pts = cc.verify_and_unseal_crystal_set(
            [c1, c2], kek, tenant_hash, expected_commitment=comm, anchor_public_key=anchor_pub
        )
        self.assertEqual(pts, [b"step 1", b"step 2"])

        # Rollback / truncation to [c1] must raise CrystalRollbackError against comm
        with self.assertRaises(cc.CrystalRollbackError):
            cc.verify_and_unseal_crystal_set(
                [c1], kek, tenant_hash, expected_commitment=comm, anchor_public_key=anchor_pub
            )

    def test_l5_third_party_zero_knowledge_verifier_rejects_all_t1_t9_without_kek(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        kek = bytes(range(32))
        ed_seed = b"l5-holder-ed25519-seed-32-bytes!"
        ed_pub = Ed25519PrivateKey.from_private_bytes(ed_seed).public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        tenant_hash = cc.compute_tenant_hash("tenant-l5")

        crystals = []
        parent = None
        for idx in range(3):
            env = cc.seal_crystal(
                f"confidential memory #{idx}".encode(),
                kek,
                "tenant-l5",
                parent_crystal_id=parent,
                metadata_public={"step": idx},
                kek_version=1,
            )
            env = cc.sign_crystal_envelope(env, ed_seed)
            parent = env["crystal_id"]
            crystals.append(env)

        comm_v2 = cc.compute_crystal_set_commitment(crystals[:2], tenant_hash, signing_key=ed_seed)
        comm_v3 = cc.compute_crystal_set_commitment(crystals, tenant_hash, signing_key=ed_seed)
        notary = {
            "receipt": {
                "kind": "wm.context-notarization",
                "context_digest": comm_v3["commitment_digest"],
            }
        }

        # Happy path: third party verifies [c0, c1, c2] WITHOUT kek
        res = cc.verify_crystal_set_third_party(
            crystals,
            tenant_hash,
            expected_commitment=comm_v3,
            signer_public_key=ed_pub,
            notarization=notary,
        )
        self.assertTrue(res["verified"])
        self.assertEqual(res["level"], "L5-third-party-zero-knowledge")
        self.assertEqual(res["count"], 3)
        self.assertTrue(res["notarized"])

        # T1 (tamper ciphertext) -> rejected without KEK
        t1 = copy.deepcopy(crystals)
        raw_ct = bytearray(cc.base64.urlsafe_b64decode(t1[1]["ciphertext"]))
        raw_ct[0] ^= 0xFF
        t1[1]["ciphertext"] = cc.base64.urlsafe_b64encode(bytes(raw_ct)).decode("ascii")
        with self.assertRaises((cc.CrystalVerificationError, ValueError)):
            cc.verify_crystal_set_third_party(
                t1, tenant_hash, expected_commitment=comm_v3, signer_public_key=ed_pub
            )

        # T2 (truncate tail) -> rejected without KEK
        with self.assertRaises(cc.CrystalRollbackError):
            cc.verify_crystal_set_third_party(
                crystals[:2], tenant_hash, expected_commitment=comm_v3, signer_public_key=ed_pub
            )

        # T3 (delete middle) -> rejected without KEK
        with self.assertRaises(cc.CrystalLineageError):
            cc.verify_crystal_set_third_party(
                [crystals[0], crystals[2]], tenant_hash, expected_commitment=comm_v3, signer_public_key=ed_pub
            )

        # T4 (reorder) -> rejected without KEK
        with self.assertRaises(cc.CrystalLineageError):
            cc.verify_crystal_set_third_party(
                [crystals[0], crystals[2], crystals[1]],
                tenant_hash,
                expected_commitment=comm_v3,
                signer_public_key=ed_pub,
            )

        # T5 (forge by attacker without holder's Ed25519 key) -> rejected without KEK
        attacker_seed = b"attacker-ed25519-seed-32-bytes!!"
        forged = cc.seal_crystal(
            b"forged", os.urandom(32), "tenant-l5", parent_crystal_id=crystals[2]["crystal_id"], kek_version=1
        )
        forged = cc.sign_crystal_envelope(forged, attacker_seed)
        with self.assertRaises(cc.CrystalVerificationError):
            cc.verify_crystal_set_third_party(
                crystals + [forged], tenant_hash, expected_commitment=comm_v3, signer_public_key=ed_pub
            )

        # T6 (cross_replay from another tenant) -> rejected without KEK
        other = cc.seal_crystal(b"other", kek, "other-tenant", parent_crystal_id=crystals[2]["crystal_id"], kek_version=1)
        other = cc.sign_crystal_envelope(other, ed_seed)
        with self.assertRaises(cc.CrystalContextError):
            cc.verify_crystal_set_third_party(
                crystals + [other], tenant_hash, expected_commitment=comm_v3, signer_public_key=ed_pub
            )

        # T7 (rollback_replay duplicate crystal) -> rejected without KEK
        with self.assertRaises(cc.CrystalLineageError):
            cc.verify_crystal_set_third_party(
                crystals + [crystals[1]], tenant_hash, expected_commitment=comm_v3, signer_public_key=ed_pub
            )

        # T8 (metadata_tamper) -> rejected without KEK via client_sig
        t8 = copy.deepcopy(crystals)
        t8[1]["metadata_public"] = {"step": 999}
        with self.assertRaises(ValueError):
            cc.verify_crystal_set_third_party(
                t8, tenant_hash, expected_commitment=comm_v3, signer_public_key=ed_pub
            )

        # T9 (snapshot_rollback to older valid snapshot [c0, c1] + comm_v2 when notary/anchor is at comm_v3)
        with self.assertRaises(cc.CrystalRollbackError):
            cc.verify_crystal_set_third_party(
                crystals[:2],
                tenant_hash,
                expected_commitment=comm_v2,
                signer_public_key=ed_pub,
                notarization=notary,
            )


if __name__ == "__main__":
    unittest.main()
