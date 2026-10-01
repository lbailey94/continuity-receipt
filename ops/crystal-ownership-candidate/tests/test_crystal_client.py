import importlib.util
import json
import os
import pathlib
import unittest
import urllib.error
from unittest.mock import patch


CLIENT_PATH = pathlib.Path(__file__).parents[1] / "src" / "crystal_client.py"
spec = importlib.util.spec_from_file_location("crystal_client_candidate", CLIENT_PATH)
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class Response:
    def __init__(self, value):
        self.data = json.dumps(value).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return self.data


class Opener:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.calls = response, error, []

    def open(self, req, timeout):
        self.calls.append((req, timeout))
        if self.error:
            raise self.error
        return self.response


class CrystalClientBoundaryTests(unittest.TestCase):
    token = "dummy-credential-never-real"
    locator = "sha256:" + "a" * 64
    cid = "sha256:" + "b" * 64

    def invoke_all(self, opener):
        with patch.object(client.urllib.request, "build_opener", return_value=opener) as build:
            client.push_crystal({"spec": client.SPEC}, auth_token=self.token)
            client.pull_crystal(self.cid, auth_token=self.token)
            client.pull_lineage(auth_token=self.token)
            self.assertEqual(client.fetch_owner_locator(auth_token=self.token), self.locator)
        self.assertEqual(build.call_count, 4)
        for call in build.call_args_list:
            self.assertEqual(len(call.args), 1)
            self.assertIsInstance(call.args[0], client._NoRedirectHandler)

    def test_each_authenticated_request_has_expected_shape_and_no_redirect_handler(self):
        opener = Opener(Response({"owner_locator": self.locator, "crystals": []}))
        self.invoke_all(opener)
        self.assertEqual([call[0].get_method() for call in opener.calls], ["POST", "GET", "GET", "GET"])
        self.assertEqual([call[1] for call in opener.calls], [30] * 4)
        self.assertTrue(all(call[0].get_header("Authorization") == f"Bearer {self.token}" for call in opener.calls))
        self.assertEqual(opener.calls[0][0].full_url, "https://api.whitemagic.dev/crystals")
        self.assertEqual(opener.calls[0][0].get_header("Content-type"), "application/json")
        self.assertTrue(opener.calls[1][0].full_url.endswith("/crystals/" + "b" * 64))

    def test_session_pass_uses_both_supported_headers_and_empty_token_is_rejected(self):
        opener = Opener(Response({"crystals": []}))
        with patch.object(client.urllib.request, "build_opener", return_value=opener):
            client.pull_lineage(auth_token="wm_pass_dummy")
        req = opener.calls[0][0]
        self.assertEqual(req.get_header("Authorization"), "Bearer wm_pass_dummy")
        self.assertEqual(req.get_header("X-session-pass"), "wm_pass_dummy")
        with patch.object(client.urllib.request, "build_opener") as build:
            with self.assertRaises(ValueError):
                client.pull_lineage(auth_token="  ")
            build.assert_not_called()

    def test_bad_id_and_bad_origins_fail_before_opener(self):
        with patch.object(client.urllib.request, "build_opener") as build:
            for bad_id in ("../x", "b" * 63, "sha256:" + "g" * 64, "x" * 64 + "/z"):
                with self.assertRaises(ValueError):
                    client.pull_crystal(bad_id, auth_token=self.token)
            for origin in ("http://api.example", "https://u:p@api.example", "https://api.example/path", "https://api.example?q=x"):
                for call in (
                    lambda: client.push_crystal({}, api_url=origin, auth_token=self.token),
                    lambda: client.pull_crystal(self.cid, api_url=origin, auth_token=self.token),
                    lambda: client.pull_lineage(api_url=origin, auth_token=self.token),
                    lambda: client.fetch_owner_locator(api_url=origin, auth_token=self.token),
                ):
                    with self.assertRaises(ValueError):
                        call()
            build.assert_not_called()

    def test_redirects_are_refused_for_every_authenticated_request_without_token_echo(self):
        with patch.object(client.urllib.request, "build_opener", side_effect=lambda *handlers: self.assertIsInstance(handlers[0], client._NoRedirectHandler)):
            handler = client._NoRedirectHandler()
            req = client.urllib.request.Request("https://api.example/crystals")
            with self.assertRaises(urllib.error.HTTPError) as raised:
                handler.redirect_request(req, None, 302, "Found", {}, "https://elsewhere.example/")
            self.assertNotIn(self.token, str(raised.exception))

        for operation in (
            lambda: client.push_crystal({}, auth_token=self.token),
            lambda: client.pull_crystal(self.cid, auth_token=self.token),
            lambda: client.pull_lineage(auth_token=self.token),
            lambda: client.fetch_owner_locator(auth_token=self.token),
        ):
            opener = Opener(error=urllib.error.HTTPError("https://api.example/x", 302, "Found", {}, None))
            with patch.object(client.urllib.request, "build_opener", return_value=opener):
                with self.assertRaises(RuntimeError) as raised:
                    operation()
                self.assertNotIn(self.token, str(raised.exception))

    def test_old_positional_tenant_is_not_reinterpreted_as_token(self):
        with self.assertRaises(TypeError):
            client.pull_crystal(self.cid, "legacy-tenant")
        with self.assertRaises(TypeError):
            client.pull_lineage("legacy-tenant")

    def test_token_file_requires_protected_regular_file(self):
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "token"
            path.write_text(self.token)
            os.chmod(path, 0o600)
            self.assertEqual(client._token_from_inputs("UNSET_CR_TOKEN", str(path)), self.token)
            if os.name == "posix":
                os.chmod(path, 0o644)
                with self.assertRaises(ValueError):
                    client._token_from_inputs("UNSET_CR_TOKEN", str(path))
            link = pathlib.Path(td) / "token-link"
            link.symlink_to(path)
            with self.assertRaises((OSError, ValueError)):
                client._token_from_inputs("UNSET_CR_TOKEN", str(link))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO support required")
    def test_fifo_token_path_is_rejected_without_blocking(self):
        import subprocess
        import sys
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            fifo = pathlib.Path(td) / "token-fifo"
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
                [sys.executable, "-c", code, str(CLIENT_PATH), str(fifo)],
                capture_output=True, timeout=3, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

    def test_seal_cli_preserves_binary_key_with_whitespace_edge_bytes(self):
        import contextlib
        import io
        import sys
        import tempfile

        raw_key = b" " + bytes(range(1, 31)) + b"\n"
        self.assertEqual(len(raw_key), 32)
        with tempfile.TemporaryDirectory() as td:
            key_path = pathlib.Path(td) / "key.bin"
            envelope_path = pathlib.Path(td) / "envelope.json"
            key_path.write_bytes(raw_key)
            previous_argv = sys.argv
            try:
                sys.argv = [str(CLIENT_PATH), "seal", "--key", str(key_path), "--content", "fixture", "--out", str(envelope_path)]
                with patch.dict(os.environ, {"WM_CRYSTAL_TOKEN": "dummy-token"}):
                    with patch.object(client, "fetch_owner_locator", return_value=self.locator):
                        with contextlib.redirect_stdout(io.StringIO()):
                            client.main()
            finally:
                sys.argv = previous_argv
            envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
            self.assertEqual(envelope["tenant_hash"], self.locator)

    def test_genkey_output_is_private_and_refuses_overwrite(self):
        import contextlib
        import io
        import os
        import sys
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            key_path = pathlib.Path(td) / "new-key"
            previous_argv = sys.argv
            try:
                sys.argv = [str(CLIENT_PATH), "genkey", "--out", str(key_path)]
                with contextlib.redirect_stdout(io.StringIO()):
                    client.main()
                self.assertEqual(len(key_path.read_bytes()), 32)
                if os.name == "posix":
                    self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
                original = b"keep-existing-key"
                key_path.write_bytes(original)
                with self.assertRaises(FileExistsError):
                    client.main()
                self.assertEqual(key_path.read_bytes(), original)
            finally:
                sys.argv = previous_argv

    def test_cli_does_not_accept_credentials_or_tenant_ids_in_argv(self):
        import contextlib
        import io
        import sys

        old_argv = sys.argv
        output = io.StringIO()
        try:
            for command in ("push", "pull", "lineage", "seal"):
                sys.argv = [str(CLIENT_PATH), command, "--help"]
                with contextlib.redirect_stdout(output), self.assertRaises(SystemExit):
                    client.main()
                help_text = output.getvalue()
                self.assertNotIn("--token ", help_text)
                self.assertNotIn("--owner-locator", help_text)
                self.assertIn("--token-env", help_text)
                if command in ("pull", "lineage", "seal"):
                    self.assertNotIn("--tenant", help_text)
                output.seek(0)
                output.truncate(0)
        finally:
            sys.argv = old_argv


if __name__ == "__main__":
    unittest.main()
