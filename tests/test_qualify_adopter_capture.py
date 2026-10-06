import hashlib
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.qualify_adopter_capture import REPO_ROOT, assess, snapshot_commitment, strict_load
from continuity_receipt import keys
from continuity_receipt.bundle import TaskChain
from continuity_receipt.records import SPEC_ID


def _script(path: Path, verdict: str = "TRUSTED", code: str | None = None) -> Path:
    errors = [] if code is None else [{"code": code, "detail": "test stub"}]
    path.write_text(
        "#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps("
        + repr({"verdict": verdict, "errors": errors})
        + "))\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _case(tmp_path: Path, rust_verdict: str = "TRUSTED", artifact: bool = True, duplicate: bool = False):
    capture = tmp_path / "capture"
    capture.mkdir()
    root = capture / "artifacts"
    root.mkdir()
    content = b"captured bytes\n"
    (root / "state.bin").write_bytes(content)
    state = {
        "files": [
            {
                "path": "state.bin",
                "size": len(content),
                "sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
            }
        ]
    }
    count, head = snapshot_commitment(state)
    did, key = keys.generate(bytes(range(32)))
    chain = TaskChain(task_id="urn:uuid:11111111-1111-4111-8111-111111111111", spec="continuity-receipt/0.5")
    chain.add(
        "state.commitment",
        "agent",
        did,
        key,
        {"state_kind": "file-snapshot-v1", "scope": "test", "count": count, "head_digest": head},
        issued_at="2026-09-29T12:00:00Z",
    )
    bundle = chain.bundle()
    bundle_path = capture / "bundle.json"
    if duplicate:
        bundle_path.write_text('{"spec":"continuity-receipt/0.5","spec":"continuity-receipt/0.5"}', encoding="utf-8")
    else:
        bundle_path.write_text(json.dumps(bundle, separators=(",", ":")), encoding="utf-8")
    python_stub = _script(capture / "python-verifier")
    rust_stub = _script(capture / "rust-verifier", verdict=rust_verdict)
    raw_hash = "sha256:" + hashlib.sha256(bundle_path.read_bytes()).hexdigest()
    metadata = {
        "command": "test producer command",
        "host": "temp-test-host",
        "operator": "unit-test",
        "captured_bundle_sha256": raw_hash,
        "pins": {
            "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip(),
            "python_verifier_sha256": "sha256:" + hashlib.sha256(python_stub.read_bytes()).hexdigest(),
            "rust_verifier_sha256": "sha256:" + hashlib.sha256(rust_stub.read_bytes()).hexdigest(),
        },
    }
    metadata_path = capture / "metadata.json"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    state_path = capture / "state.json"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    if not artifact:
        (root / "state.bin").unlink()
    report = assess(bundle_path, state_path, metadata_path, root, [str(python_stub)], [str(rust_stub)])
    return report, root


class TestQualifyAdopterCapture(unittest.TestCase):
    def test_file_snapshot_v1_counts_entries_not_bytes(self):
        state = {"files": [{"path": "a.txt", "size": 4096, "sha256": "sha256:" + "a" * 64}]}
        count, digest = snapshot_commitment(state)
        encoded = json.dumps(state["files"], sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
        self.assertEqual(count, 1)
        self.assertEqual(
            digest,
            "sha256:"
            + hashlib.sha256(
                json.dumps(state, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
            ).hexdigest(),
        )
        self.assertNotEqual(len(encoded), count)

    def test_ambiguous_or_malformed_snapshot_rejected(self):
        cases = [
            {"files": [{"path": "../escape", "size": 0, "sha256": "sha256:" + "0" * 64}]},
            {"files": [{"path": "a", "size": True, "sha256": "sha256:" + "0" * 64}]},
            {
                "files": [
                    {"path": "a", "size": 0, "sha256": "sha256:" + "0" * 64},
                    {"path": "a", "size": 0, "sha256": "sha256:" + "0" * 64},
                ]
            },
            {
                "files": [
                    {"path": "z", "size": 0, "sha256": "sha256:" + "0" * 64},
                    {"path": "a", "size": 0, "sha256": "sha256:" + "0" * 64},
                ]
            },
        ]
        for state in cases:
            with self.subTest(state=state):
                with self.assertRaises(ValueError):
                    snapshot_commitment(state)

    def test_duplicate_json_members_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "duplicate.json"
            path.write_text('{"files": [], "files": []}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON member"):
                strict_load(path)

    def test_missing_inputs_are_incomplete_and_cannot_pass(self):
        report = assess(None, None, None, None, None, None)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertIn("file-snapshot-v1", report["caveats"][1])
        self.assertIn("does not establish", report["caveats"][1])

    def test_signed_bundle_and_stubs_pass_with_captured_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            report, _ = _case(Path(td))
            self.assertEqual(report["status"], "PASS")
            self.assertTrue(report["checks"]["source_pin"]["verified"])
            self.assertTrue(report["checks"]["snapshot_files"]["all_match"])

    def test_changed_underlying_artifact_fails(self):
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            report, root = _case(tmp_path)
            (root / "state.bin").write_bytes(b"changed")
            capture = tmp_path / "capture"
            report = assess(
                capture / "bundle.json",
                capture / "state.json",
                capture / "metadata.json",
                root,
                [str(capture / "python-verifier")],
                [str(capture / "rust-verifier")],
            )
            self.assertEqual(report["status"], "FAIL")

    def test_duplicate_bundle_members_fail(self):
        with tempfile.TemporaryDirectory() as td:
            report, _ = _case(Path(td), duplicate=True)
            self.assertEqual(report["status"], "FAIL")
            self.assertIn("duplicate JSON member", report["checks"]["input_validation"])

    def test_excessive_json_nesting_returns_structured_fail(self):
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            _case(tmp_path)
            capture = tmp_path / "capture"
            bundle_path = capture / "bundle.json"
            raw = b'{"spec":"continuity-receipt/0.5","nested":' + b"[" * 10_000 + b"]" * 10_000 + b"}"
            bundle_path.write_bytes(raw)
            metadata_path = capture / "metadata.json"
            metadata = json.loads(metadata_path.read_text())
            metadata["captured_bundle_sha256"] = "sha256:" + hashlib.sha256(raw).hexdigest()
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            report = assess(
                bundle_path,
                capture / "state.json",
                metadata_path,
                capture / "artifacts",
                [str(capture / "python-verifier")],
                [str(capture / "rust-verifier")],
            )
            self.assertEqual(report["status"], "FAIL")
            self.assertEqual(report["checks"]["input_validation"], "input_nesting_too_deep")

    def test_canonicalization_recursion_returns_structured_fail(self):
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            _case(tmp_path)
            capture = tmp_path / "capture"
            with patch("tools.qualify_adopter_capture.canonical", side_effect=RecursionError):
                report = assess(
                    capture / "bundle.json",
                    capture / "state.json",
                    capture / "metadata.json",
                    capture / "artifacts",
                    [str(capture / "python-verifier")],
                    [str(capture / "rust-verifier")],
                )
            self.assertEqual(report["status"], "FAIL")
            self.assertEqual(report["checks"]["input_validation"], "input_nesting_too_deep")

    def test_verifier_disagreement_fails(self):
        with tempfile.TemporaryDirectory() as td:
            report, _ = _case(Path(td), rust_verdict="UNTRUSTED")
            self.assertEqual(report["status"], "FAIL")
            self.assertFalse(report["checks"]["verifier_agreement"])

    def test_missing_referenced_artifact_is_incomplete(self):
        with tempfile.TemporaryDirectory() as td:
            report, _ = _case(Path(td), artifact=False)
            self.assertEqual(report["status"], "INCOMPLETE")

    def test_metadata_bundle_hash_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            report, _ = _case(tmp_path)
            capture = tmp_path / "capture"
            metadata_path = capture / "metadata.json"
            metadata = json.loads(metadata_path.read_text())
            metadata["captured_bundle_sha256"] = "sha256:" + "0" * 64
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            report = assess(
                capture / "bundle.json",
                capture / "state.json",
                metadata_path,
                capture / "artifacts",
                [str(capture / "python-verifier")],
                [str(capture / "rust-verifier")],
            )
            self.assertEqual(report["status"], "FAIL")
            self.assertIn("captured_bundle_sha256", report["checks"]["input_validation"])

    def test_documented_cli_command_string_parsing(self):
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            _case(tmp_path)
            capture = tmp_path / "capture"
            metadata_path = capture / "metadata.json"
            metadata = json.loads(metadata_path.read_text())
            python_path = shutil.which("python3")
            self.assertIsNotNone(python_path)
            metadata["pins"]["python_verifier_sha256"] = "sha256:" + hashlib.sha256(
                Path(python_path).read_bytes()
            ).hexdigest()
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            quoted_stub = (
                "python3 -c 'import json; print(json.dumps({\"verdict\": \"TRUSTED\", \"errors\": []}))'"
            )
            command = [
                sys.executable,
                str(REPO_ROOT / "tools/qualify_adopter_capture.py"),
                "--bundle",
                str(capture / "bundle.json"),
                "--state",
                str(capture / "state.json"),
                "--metadata",
                str(metadata_path),
                "--artifact-root",
                str(capture / "artifacts"),
                "--python-verifier-command",
                quoted_stub,
                "--rust-verifier-command",
                shlex.quote(str(capture / "rust-verifier")),
                "--output",
                "-",
            ]
            result = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(json.loads(result.stdout)["status"], "PASS")

    def test_real_python_and_rust_verifiers_accept_signed_file_snapshot_chain(self):
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            capture = tmp_path / "real-verifiers"
            artifact_root = capture / "artifacts"
            artifact_root.mkdir(parents=True)
            payload = b"real captured state\n"
            (artifact_root / "state.bin").write_bytes(payload)
            state = {
                "files": [
                    {
                        "path": "state.bin",
                        "size": len(payload),
                        "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
                    }
                ]
            }
            count, head = snapshot_commitment(state)
            did, key = keys.generate(bytes(range(32)))
            chain = TaskChain(task_id="urn:uuid:22222222-2222-4222-8222-222222222222", spec=SPEC_ID)
            chain.add(
                "session.pass.created",
                "agent",
                did,
                key,
                {
                    "gate_id": "test:gate",
                    "mandala_class": "gate-lite",
                    "quotas": {"cpu_ms": 1000, "mem_mb": 128, "disk_mb": 64, "wall_ms": 10000},
                    "expires_at": "2026-09-30T12:00:00Z",
                    "policy_version": "test-policy/1",
                    "mandate_ref": "sha256:" + "1" * 64,
                    "agent_id": "test-agent",
                },
                issued_at="2026-09-29T12:00:00Z",
            )
            chain.add(
                "task.decision",
                "agent",
                did,
                key,
                {
                    "action": "test.snapshot",
                    "action_args_hash": "sha256:" + "2" * 64,
                    "model": {"provider": "test", "id": "none"},
                    "input_provenance": {
                        "policy_id": "test-policy/1",
                        "allowed_sources": ["local"],
                        "observed_sources_hash": "sha256:" + "3" * 64,
                    },
                    "decision": "allow",
                    "policy_version": "test-policy/1",
                },
                issued_at="2026-09-29T12:00:01Z",
            )
            chain.add(
                "task.execution",
                "agent",
                did,
                key,
                {
                    "tool_calls": [],
                    "egress": [],
                    "resources": {"cpu_ms": 1, "mem_peak_mb": 2, "disk_peak_mb": 0},
                    "sandbox_class": "none",
                },
                issued_at="2026-09-29T12:00:02Z",
            )
            chain.add(
                "state.commitment",
                "agent",
                did,
                key,
                {
                    "state_kind": "file-snapshot-v1",
                    "scope": "test:snapshot",
                    "count": count,
                    "head_digest": head,
                },
                issued_at="2026-09-29T12:00:03Z",
            )
            chain.add(
                "task.termination",
                "agent",
                did,
                key,
                {
                    "reason": "completed",
                    "limits_at_stop": {
                        "cpu_ms": 1,
                        "wall_ms": 2,
                        "spend_minor": 0,
                        "currency": "USD",
                    },
                    "remaining": {},
                },
                issued_at="2026-09-29T12:00:04Z",
            )
            bundle_path = capture / "bundle.json"
            bundle_path.write_text(json.dumps(chain.bundle(), separators=(",", ":")), encoding="utf-8")
            python_cmd = ["python3", "-m", "continuity_receipt.verify"]
            rust_binary = REPO_ROOT / "rust/target/debug/continuity-receipt-verify"
            if not rust_binary.exists():
                build = subprocess.run(
                    [
                        "cargo",
                        "build",
                        "--locked",
                        "--manifest-path",
                        "rust/Cargo.toml",
                        "--bin",
                        "continuity-receipt-verify",
                    ],
                    cwd=REPO_ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(build.returncode, 0, build.stderr)
            rust_cmd = [str(rust_binary)]
            python_path = shutil.which("python3")
            self.assertIsNotNone(python_path)
            metadata = {
                "command": "test-only signed chain fixture",
                "host": "temporary-test-host",
                "operator": "unittest",
                "captured_bundle_sha256": "sha256:" + hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
                "pins": {
                    "source_commit": subprocess.check_output(
                        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True
                    ).strip(),
                    "python_verifier_sha256": "sha256:"
                    + hashlib.sha256(Path(python_path).read_bytes()).hexdigest(),
                    "rust_verifier_sha256": "sha256:" + hashlib.sha256(rust_binary.read_bytes()).hexdigest(),
                },
            }
            metadata_path = capture / "metadata.json"
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            state_path = capture / "state.json"
            state_path.write_text(json.dumps(state), encoding="utf-8")
            report = assess(bundle_path, state_path, metadata_path, artifact_root, python_cmd, rust_cmd)
            self.assertEqual(report["status"], "PASS", report)
            self.assertEqual(report["verifiers"]["python"]["verdict"], "TRUSTED")
            self.assertEqual(report["verifiers"]["rust"]["verdict"], "TRUSTED")


if __name__ == "__main__":
    unittest.main()
