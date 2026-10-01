#!/usr/bin/env python3
"""Run the owner-bound candidate matrix through disposable Caddy TLS.

Uses synthetic state, loopback ephemeral ports, and a private disposable CA.
It does not bind a public interface or read live Caddy/state configuration.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request

spec = importlib.util.spec_from_file_location(
    "crystal_staging_base", Path(__file__).with_name("test_crystal_ownership_candidate.py")
)
base = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = base
spec.loader.exec_module(base)
CADDY = None


class OwnershipCandidateCaddyTLS(base.OwnershipCandidateLoopback):
    @classmethod
    def setUpClass(cls):
        if CADDY is None:
            raise unittest.SkipTest("explicit Caddy candidate staging only")
        super().setUpClass()
        root = Path(cls.tempdir.name)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        config = root / "Caddyfile"
        upstream = cls.gateway_url.removeprefix("http://")
        config.write_text(
            "{\n admin off\n auto_https disable_redirects\n skip_install_trust\n}\n"
            f"https://127.0.0.1:{port} {{\n tls internal\n"
            f" handle /crystals {{\n  reverse_proxy {upstream}\n }}\n"
            f" handle /crystals/* {{\n  reverse_proxy {upstream}\n }}\n"
            " respond 404\n}\n"
        )
        cls.caddy_log = (root / "caddy.log").open("w+")
        env = dict(os.environ, XDG_DATA_HOME=str(root / "data"),
                   XDG_CONFIG_HOME=str(root / "config"))
        cls.caddy = subprocess.Popen(
            [CADDY, "run", "--config", str(config), "--adapter", "caddyfile"],
            env=env, stdout=cls.caddy_log, stderr=subprocess.STDOUT,
        )
        cls.original_urlopen = urllib.request.urlopen
        try:
            ca = root / "data/caddy/pki/authorities/local/root.crt"
            for _ in range(100):
                if cls.caddy.poll() is not None:
                    cls.caddy_log.flush()
                    cls.caddy_log.seek(0)
                    raise RuntimeError("disposable Caddy exited: " + cls.caddy_log.read())
                if ca.is_file():
                    context = ssl.create_default_context(cafile=str(ca))
                    try:
                        cls.original_urlopen(f"https://127.0.0.1:{port}/", context=context,
                                             timeout=1).close()
                    except urllib.error.HTTPError:
                        break
                    except (OSError, urllib.error.URLError):
                        pass
                time.sleep(0.05)
            else:
                raise RuntimeError("disposable Caddy TLS startup timed out")
            cls.gateway_url = f"https://127.0.0.1:{port}"

            def trusted_urlopen(request, *args, **kwargs):
                url = request.full_url if hasattr(request, "full_url") else request
                if url.startswith(cls.gateway_url + "/"):
                    kwargs["context"] = context
                return cls.original_urlopen(request, *args, **kwargs)

            urllib.request.urlopen = trusted_urlopen
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "original_urlopen"):
            urllib.request.urlopen = cls.original_urlopen
        if hasattr(cls, "caddy"):
            cls.caddy.terminate()
            try:
                cls.caddy.wait(timeout=10)
            except subprocess.TimeoutExpired:
                cls.caddy.kill()
                cls.caddy.wait(timeout=5)
        if hasattr(cls, "caddy_log"):
            cls.caddy_log.close()
        super().tearDownClass()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authd", type=Path, required=True)
    parser.add_argument("--api", type=Path, required=True)
    parser.add_argument("--caddy", required=True)
    args = parser.parse_args()
    base.AUTHD_SOURCE, base.API_SOURCE = args.authd.resolve(), args.api.resolve()
    CADDY = args.caddy
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(OwnershipCandidateCaddyTLS)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
