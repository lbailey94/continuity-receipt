import os
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from continuity_receipt.memory_resume import capture_input_tree, main


class MemoryResumeCaptureTests(unittest.TestCase):
    def test_captures_regular_files_and_empty_directories_are_not_entries(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "notes", "empty-dir"))
            with open(os.path.join(root, "notes", "today.txt"), "wb") as stream:
                stream.write(b"exact\n")
            self.assertEqual(capture_input_tree(root), {"notes/today.txt": b"exact\n"})

    def test_refuses_symlinks_and_special_files(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            with open(os.path.join(outside, "secret"), "wb") as stream:
                stream.write(b"not captured")
            os.symlink(os.path.join(outside, "secret"), os.path.join(root, "link"))
            with self.assertRaises((OSError, ValueError)):
                capture_input_tree(root)

    def test_cli_publishes_recalls_and_emits_only_accepted_selected_text(self):
        with tempfile.TemporaryDirectory() as root:
            data_root = os.path.join(root, "receiver")
            trust_db = os.path.join(root, "trust.sqlite")
            input_root = os.path.join(root, "input")
            os.mkdir(input_root)
            os.makedirs(os.path.join(input_root, "notes"))
            with open(os.path.join(input_root, "notes", "today.txt"), "wb") as stream:
                stream.write(b"resume this exact text\n")
            private = Ed25519PrivateKey.generate()
            private_path = os.path.join(root, "private.pem")
            public_path = os.path.join(root, "public.pem")
            with open(private_path, "wb") as stream:
                stream.write(private.private_bytes(serialization.Encoding.PEM,
                                                   serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
            with open(public_path, "wb") as stream:
                stream.write(private.public_key().public_bytes(serialization.Encoding.PEM,
                                                               serialization.PublicFormat.SubjectPublicKeyInfo))
            from continuity_receipt.canon import sha256_prefixed
            from continuity_receipt.keys import raw_pubkey_bytes
            profile_path = os.path.join(root, "receiver-profile.json")
            profile = {
                "kind": "cpr-experimental-local-receiver-profile", "version": 1,
                "id": "test-local-note", "export": {"scope": "user:local", "inventory": ["notes/today.txt", "notes/absent.txt"], "optional": ["notes/absent.txt"], "memory_paths": ["notes/today.txt", "notes/absent.txt"]},
                "trust": {"context": "cli-test", "key_sha256": sha256_prefixed(raw_pubkey_bytes(private.public_key())),
                          "reference": "receiver-trust-db/current_reference; advanced only by explicit local publish", "clock": "system-utc"},
                "authority": {"status": "operator-asserted", "basis": "outside this verifier"},
                "consent": {"status": "operator-asserted", "subject_consent_verified": False},
                "retention": {"mode": "retain current generation until explicit replacement; prior generations may remain on disk", "deletion": "operator-managed"},
                "refusal": ["missing policy or reference", "untrusted or stale evidence", "inventory mismatch", "selected memory file missing or invalid UTF-8"],
            }
            with open(profile_path, "w", encoding="utf-8") as stream:
                json.dump(profile, stream)
            common = ["--data-root", data_root, "--trust-db", trust_db,
                      "--context", "cli-test", "--scope", "user:local",
                      "--public-key", public_path, "--profile", profile_path]

            def invoke(command):
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    code = main(command + common)
                return code, out.getvalue(), err.getvalue()

            # JSON numbers compare equal to booleans in Python; the profile
            # contract requires the exact false value before any policy pin.
            profile["consent"]["subject_consent_verified"] = 0
            with open(profile_path, "w", encoding="utf-8") as stream:
                json.dump(profile, stream)
            bad_code, bad_out, _ = invoke(["init"])
            self.assertEqual(bad_code, 2)
            self.assertIn("receiver_profile_consent_invalid", bad_out)
            profile["consent"]["subject_consent_verified"] = False
            with open(profile_path, "w", encoding="utf-8") as stream:
                json.dump(profile, stream)
            self.assertEqual(invoke(["init"])[0], 0)
            clock_code, clock_out, _ = invoke(["status", "--now", "2026-10-23T12:00:00Z"])
            self.assertEqual(clock_code, 2)
            self.assertIn("receiver_profile_clock_override_forbidden", clock_out)
            profile["id"] = "silently-changed"
            with open(profile_path, "w", encoding="utf-8") as stream:
                json.dump(profile, stream)
            changed_code, changed_out, _ = invoke(["init"])
            self.assertEqual(changed_code, 2)
            self.assertIn("receiver_policy_mismatch", changed_out)
            profile["id"] = "test-local-note"
            with open(profile_path, "w", encoding="utf-8") as stream:
                json.dump(profile, stream)
            witness_path = os.path.join(root, "published-witness.json")
            code, published, _ = invoke(["publish", "--key-pem", private_path,
                                         "--expected-reference", "none", "--input-root", input_root,
                                         "--witness-file", witness_path])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(published)["outcome"], "ACCEPT")
            with open(witness_path, encoding="utf-8") as wf:
                witness_json = json.load(wf)
            self.assertEqual(witness_json,
                             {"sequence": 1, "checkpoint_digest": json.loads(published)["reference"]["checkpoint_digest"],
                              "generation_id": json.loads(published)["reference"]["generation_id"]})
            with open(os.path.join(input_root, "extra.txt"), "w", encoding="utf-8") as stream:
                stream.write("outside declared inventory")
            reference = json.loads(published)["reference"]["checkpoint_digest"]
            code, rejected, _ = invoke(["publish", "--key-pem", private_path,
                                        "--expected-reference", reference, "--input-root", input_root])
            self.assertEqual(code, 2)
            self.assertIn("receiver_profile_inventory_mismatch", rejected)
            os.unlink(os.path.join(input_root, "extra.txt"))
            code, recalled, _ = invoke(["recall"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(recalled)["files"][0]["path"], "notes/today.txt")
            code, stdout, stderr = invoke(["resume", "--memory-path", "notes/absent.txt"])
            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("memory_path_missing", stderr)
            code, stdout, stderr = invoke(["resume", "--memory-path", "notes/today.txt",
                                          "--witness-file", witness_path])
            self.assertEqual(code, 0, stderr)
            self.assertEqual(stdout, "resume this exact text\n")
            self.assertIn('"outcome": "ACCEPT"', stderr)
            code, stdout, stderr = invoke(["resume", "--memory-path", "notes/today.txt",
                                          "--witness-file", os.path.join(root, "missing-witness.json")])
            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("off_host_witness_missing", stderr)
            empty_witness = os.path.join(root, "empty-witness.json")
            with open(empty_witness, "w", encoding="utf-8") as stream:
                json.dump({}, stream)
            code, stdout, stderr = invoke(["resume", "--memory-path", "notes/today.txt",
                                          "--witness-file", empty_witness])
            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("off_host_witness_invalid", stderr)
            from continuity_receipt.receiver_store import ReceiverStore
            import sqlite3
            original_connect = ReceiverStore._connect
            class CommitFailure:
                def __init__(self, conn): self.conn = conn
                def __getattr__(self, name): return getattr(self.conn, name)
                def commit(self): raise sqlite3.OperationalError("injected commit failure")
            with patch.object(ReceiverStore, "_connect", lambda self, **kw: CommitFailure(original_connect(self, **kw))):
                code, stdout, stderr = invoke(["resume", "--memory-path", "notes/today.txt"])
            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn('"outcome": "REJECT"', stderr)
            with open(os.path.join(input_root, "notes", "today.txt"), "wb") as stream:
                stream.write(b"\xff")
            current = json.loads(published)["reference"]["checkpoint_digest"]
            code, published_bad_text, _ = invoke(["publish", "--key-pem", private_path,
                "--expected-reference", current, "--input-root", input_root])
            self.assertEqual(code, 0, published_bad_text)
            code, stdout, stderr = invoke(["resume", "--memory-path", "notes/today.txt"])
            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("memory_text_invalid_utf8", stderr)
            code, stdout, stderr = invoke(["resume", "--memory-path", "missing.txt"])
            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("receiver_profile_memory_path_mismatch", stderr)


if __name__ == "__main__":
    unittest.main()
