import hashlib
import json
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tools.qualify_adopter_capture import REPO_ROOT, assess, snapshot_commitment, strict_load
from continuity_receipt import keys
from continuity_receipt.bundle import TaskChain
from continuity_receipt.records import SPEC_ID


def test_file_snapshot_v1_counts_entries_not_bytes():
    state = {"files": [{"path": "a.txt", "size": 4096, "sha256": "sha256:" + "a" * 64}]}
    count, digest = snapshot_commitment(state)
    encoded = json.dumps(state["files"], sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    assert count == 1
    assert digest == "sha256:" + hashlib.sha256(json.dumps(state, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    assert len(encoded) != count


@pytest.mark.parametrize("state", [
    {"files": [{"path": "../escape", "size": 0, "sha256": "sha256:" + "0" * 64}]},
    {"files": [{"path": "a", "size": True, "sha256": "sha256:" + "0" * 64}]},
    {"files": [{"path": "a", "size": 0, "sha256": "sha256:" + "0" * 64}, {"path": "a", "size": 0, "sha256": "sha256:" + "0" * 64}]},
    {"files": [{"path": "z", "size": 0, "sha256": "sha256:" + "0" * 64}, {"path": "a", "size": 0, "sha256": "sha256:" + "0" * 64}]},
])
def test_ambiguous_or_malformed_snapshot_rejected(state):
    with pytest.raises(ValueError):
        snapshot_commitment(state)


def test_duplicate_json_members_rejected(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"files": [], "files": []}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON member"):
        strict_load(path)


def test_missing_inputs_are_incomplete_and_cannot_pass():
    report = assess(None, None, None, None, None, None)
    assert report["status"] == "INCOMPLETE"
    assert "Current Mandala" in report["caveats"][1]


def _script(path, verdict="TRUSTED", code=None):
    errors = [] if code is None else [{"code": code, "detail": "test stub"}]
    path.write_text("#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps(" + repr({"verdict": verdict, "errors": errors}) + "))\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _case(tmp_path, rust_verdict="TRUSTED", artifact=True, duplicate=False):
    capture = tmp_path / "capture"
    capture.mkdir()
    root = capture / "artifacts"
    root.mkdir()
    content = b"captured bytes\n"
    (root / "state.bin").write_bytes(content)
    state = {"files": [{"path": "state.bin", "size": len(content), "sha256": "sha256:" + hashlib.sha256(content).hexdigest()}]}
    count, head = snapshot_commitment(state)
    did, key = keys.generate(bytes(range(32)))
    chain = TaskChain(task_id="urn:uuid:11111111-1111-4111-8111-111111111111", spec="continuity-receipt/0.5")
    chain.add("state.commitment", "agent", did, key, {"state_kind": "file-snapshot-v1", "scope": "test", "count": count, "head_digest": head}, issued_at="2026-09-29T12:00:00Z")
    bundle = chain.bundle()
    bundle_path = capture / "bundle.json"
    if duplicate:
        bundle_path.write_text('{"spec":"continuity-receipt/0.5","spec":"continuity-receipt/0.5"}', encoding="utf-8")
    else:
        bundle_path.write_text(json.dumps(bundle, separators=(",", ":")), encoding="utf-8")
    python_stub = _script(capture / "python-verifier")
    rust_stub = _script(capture / "rust-verifier", verdict=rust_verdict)
    raw_hash = "sha256:" + hashlib.sha256(bundle_path.read_bytes()).hexdigest()
    metadata = {"command": "test producer command", "host": "temp-test-host", "operator": "unit-test",
                "captured_bundle_sha256": raw_hash,
                "pins": {"source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip(),
                         "python_verifier_sha256": "sha256:" + hashlib.sha256(python_stub.read_bytes()).hexdigest(),
                         "rust_verifier_sha256": "sha256:" + hashlib.sha256(rust_stub.read_bytes()).hexdigest()}}
    metadata_path = capture / "metadata.json"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    state_path = capture / "state.json"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    if not artifact:
        (root / "state.bin").unlink()
    report = assess(bundle_path, state_path, metadata_path, root, [str(python_stub)], [str(rust_stub)])
    return report, root


def test_signed_bundle_and_stubs_pass_with_captured_artifact(tmp_path):
    report, _ = _case(tmp_path)
    assert report["status"] == "PASS"
    assert report["checks"]["source_pin"]["verified"] is True
    assert report["checks"]["snapshot_files"]["all_match"] is True


def test_changed_underlying_artifact_fails(tmp_path):
    report, root = _case(tmp_path)
    (root / "state.bin").write_bytes(b"changed")
    capture = tmp_path / "capture"
    report = assess(capture / "bundle.json", capture / "state.json", capture / "metadata.json", root,
                    [str(capture / "python-verifier")], [str(capture / "rust-verifier")])
    assert report["status"] == "FAIL"


def test_duplicate_bundle_members_fail(tmp_path):
    report, _ = _case(tmp_path, duplicate=True)
    assert report["status"] == "FAIL"
    assert "duplicate JSON member" in report["checks"]["input_validation"]


def test_verifier_disagreement_fails(tmp_path):
    report, _ = _case(tmp_path, rust_verdict="UNTRUSTED")
    assert report["status"] == "FAIL"
    assert report["checks"]["verifier_agreement"] is False


def test_missing_referenced_artifact_is_incomplete(tmp_path):
    report, _ = _case(tmp_path, artifact=False)
    assert report["status"] == "INCOMPLETE"


def test_metadata_bundle_hash_mismatch_fails(tmp_path):
    report, _ = _case(tmp_path)
    capture = tmp_path / "capture"
    metadata_path = capture / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["captured_bundle_sha256"] = "sha256:" + "0" * 64
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    report = assess(capture / "bundle.json", capture / "state.json", metadata_path,
                    capture / "artifacts", [str(capture / "python-verifier")],
                    [str(capture / "rust-verifier")])
    assert report["status"] == "FAIL"
    assert "captured_bundle_sha256" in report["checks"]["input_validation"]


def test_documented_cli_command_string_parsing(tmp_path):
    _case(tmp_path)
    capture = tmp_path / "capture"
    metadata_path = capture / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["pins"]["python_verifier_sha256"] = "sha256:" + hashlib.sha256(Path(shutil.which("python3")).read_bytes()).hexdigest()
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    quoted_stub = "python3 -c 'import json; print(json.dumps({\"verdict\": \"TRUSTED\", \"errors\": []}))'"
    command = [sys.executable, str(REPO_ROOT / "tools/qualify_adopter_capture.py"),
               "--bundle", str(capture / "bundle.json"), "--state", str(capture / "state.json"),
               "--metadata", str(metadata_path), "--artifact-root", str(capture / "artifacts"),
               "--python-verifier-command", quoted_stub,
               "--rust-verifier-command", shlex.quote(str(capture / "rust-verifier")), "--output", "-"]
    result = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr + result.stdout
    assert json.loads(result.stdout)["status"] == "PASS"


def test_real_python_and_rust_verifiers_accept_signed_file_snapshot_chain(tmp_path):
    capture = tmp_path / "real-verifiers"
    artifact_root = capture / "artifacts"
    artifact_root.mkdir(parents=True)
    payload = b"real captured state\n"
    (artifact_root / "state.bin").write_bytes(payload)
    state = {"files": [{"path": "state.bin", "size": len(payload),
                        "sha256": "sha256:" + hashlib.sha256(payload).hexdigest()}]}
    count, head = snapshot_commitment(state)
    did, key = keys.generate(bytes(range(32)))
    chain = TaskChain(task_id="urn:uuid:22222222-2222-4222-8222-222222222222", spec=SPEC_ID)
    chain.add("session.pass.created", "agent", did, key, {
        "gate_id": "test:gate", "mandala_class": "gate-lite",
        "quotas": {"cpu_ms": 1000, "mem_mb": 128, "disk_mb": 64, "wall_ms": 10000},
        "expires_at": "2026-09-30T12:00:00Z", "policy_version": "test-policy/1",
        "mandate_ref": "sha256:" + "1" * 64, "agent_id": "test-agent"},
        issued_at="2026-09-29T12:00:00Z")
    chain.add("task.decision", "agent", did, key, {
        "action": "test.snapshot", "action_args_hash": "sha256:" + "2" * 64,
        "model": {"provider": "test", "id": "none"},
        "input_provenance": {"policy_id": "test-policy/1", "allowed_sources": ["local"],
                             "observed_sources_hash": "sha256:" + "3" * 64},
        "decision": "allow", "policy_version": "test-policy/1"},
        issued_at="2026-09-29T12:00:01Z")
    chain.add("task.execution", "agent", did, key, {
        "tool_calls": [], "egress": [], "resources": {"cpu_ms": 1, "mem_peak_mb": 2, "disk_peak_mb": 0},
        "sandbox_class": "none"}, issued_at="2026-09-29T12:00:02Z")
    chain.add("state.commitment", "agent", did, key, {
        "state_kind": "file-snapshot-v1", "scope": "test:snapshot", "count": count, "head_digest": head},
        issued_at="2026-09-29T12:00:03Z")
    chain.add("task.termination", "agent", did, key, {
        "reason": "completed", "limits_at_stop": {"cpu_ms": 1, "wall_ms": 2, "spend_minor": 0, "currency": "USD"},
        "remaining": {}}, issued_at="2026-09-29T12:00:04Z")
    bundle_path = capture / "bundle.json"
    bundle_path.write_text(json.dumps(chain.bundle(), separators=(",", ":")), encoding="utf-8")
    python_cmd = ["python3", "-m", "continuity_receipt.verify"]
    rust_binary = REPO_ROOT / "rust/target/debug/continuity-receipt-verify"
    if not rust_binary.exists():
        build = subprocess.run(["cargo", "build", "--locked", "--manifest-path", "rust/Cargo.toml",
                                "--bin", "continuity-receipt-verify"], cwd=REPO_ROOT,
                               capture_output=True, text=True, check=False)
        assert build.returncode == 0, build.stderr
    rust_cmd = [str(rust_binary)]
    metadata = {"command": "test-only signed chain fixture", "host": "temporary-test-host", "operator": "pytest",
                "captured_bundle_sha256": "sha256:" + hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
                "pins": {"source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip(),
                         "python_verifier_sha256": "sha256:" + hashlib.sha256(Path(shutil.which("python3")).read_bytes()).hexdigest(),
                         "rust_verifier_sha256": "sha256:" + hashlib.sha256(rust_binary.read_bytes()).hexdigest()}}
    metadata_path = capture / "metadata.json"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    state_path = capture / "state.json"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    report = assess(bundle_path, state_path, metadata_path, artifact_root, python_cmd, rust_cmd)
    assert report["status"] == "PASS", report
    assert report["verifiers"]["python"]["verdict"] == "TRUSTED"
    assert report["verifiers"]["rust"]["verdict"] == "TRUSTED"
