#!/usr/bin/env python3
"""Reproduce a publication boundary, then recover with an installed candidate.

The before stage explicitly imports frozen 9b14d8a1 source. Every after-stage
CPR import uses the selected installed interpreter with -I, outside the checkout.
All stores, keys and fault injection are disposable and local to a new output.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time
from datetime import datetime, timezone
from urllib.parse import quote

NOW = "2026-11-01T13:15:00Z"
CONTEXT = "publication-boundary-reproducer"
SCOPE = "example:publication-boundary"
BEFORE_COMMIT = "9b14d8a1fb70cbcbb9d505fa4ef7d9cd7a1cce58"
BEFORE_ANCHORS = {
    "memory_resume.py": "12f903be8c56728d682f192ad367c5545395e7f0bf0c131963757ec924859c99",
    "witness.py": "4bf99698be4f01dc22d6b778e6c0bc3764b8ffef7ed80118d004806513766a1d",
}
BEFORE_BRIDGE = (
    "import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); "
    "runpy.run_module('continuity_receipt.memory_resume',run_name='__main__')"
)
FAULT_BRIDGE = """
import sys
from unittest import mock
from continuity_receipt import memory_resume, witness_file
with mock.patch.object(witness_file.os, 'replace', side_effect=OSError('controlled post-commit replacement failure')):
    code = memory_resume.main(sys.argv[1:])
raise SystemExit(code)
"""
IDENTITY = """
import hashlib,importlib.metadata,json,pathlib,sys
source = sys.argv[1] if len(sys.argv)>1 else None
if source:
    sys.path.insert(0,source)
import continuity_receipt
from continuity_receipt import memory_resume,receiver_store
prefix = pathlib.Path(sys.prefix).resolve()
modules = {}
for name,module in sorted(sys.modules.items()):
    if name.startswith('continuity_receipt') and getattr(module,'__file__',None):
        path = pathlib.Path(module.__file__).resolve()
        expected = pathlib.Path(source).resolve() if source else prefix
        if not path.is_relative_to(expected):
            raise RuntimeError('module_origin_outside_selected_boundary:'+name)
        modules[name]={'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
if not source and sys.prefix == sys.base_prefix:
    raise RuntimeError('after_interpreter_must_use_a_fresh_virtual_environment')
distribution = importlib.metadata.distribution('continuity-receipt')
installed_version = distribution.version
if not source and continuity_receipt.__version__ != installed_version:
    raise RuntimeError('installed_distribution_and_module_versions_differ')
direct = distribution.read_text('direct_url.json')
print(json.dumps({'mode':'explicit_before_source' if source else 'installed_after',
 'python':sys.executable,'prefix':str(prefix),'python_version':sys.version,
 'module_version':continuity_receipt.__version__,'installed_distribution_version':installed_version,
 'direct_url':json.loads(direct) if direct else None,'modules':modules},sort_keys=True))
"""
KEY_SETUP = """
import pathlib,sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
root=pathlib.Path(sys.argv[1])
key=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
(root/'fixture-private.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,
 serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
(root/'fixture-private.pem').chmod(0o600)
(root/'fixture-public.pem').write_bytes(key.public_key().public_bytes(
 serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
print('Disposable deterministic test key created; never use it for real data.')
"""


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


class Reproducer:
    def __init__(self, python, before, output):
        self.python, self.before, self.output = python, before, output
        self.calls = []
        for name in ("calls", "home", "tmp", "keys"):
            (output / name).mkdir(mode=0o700)
        self.env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8",
                    "HOME": str(output / "home"), "TMPDIR": str(output / "tmp"),
                    "XDG_CONFIG_HOME": str(output / "home" / "config"),
                    "XDG_DATA_HOME": str(output / "home" / "data")}

    def call(self, label, command):
        directory = self.output / "calls" / f"{len(self.calls)+1:03d}-{label}"
        directory.mkdir(mode=0o700)
        started = time.monotonic()
        try:
            process = subprocess.run(command, cwd=self.output, env=self.env,
                                     capture_output=True, timeout=30, check=False)
            stdout, stderr, code = process.stdout, process.stderr, process.returncode
        except subprocess.TimeoutExpired as exc:
            stdout, stderr, code = exc.stdout or b"", exc.stderr or b"", None
        except OSError as exc:
            stdout, stderr, code = b"", str(exc).encode(), None
        (directory / "stdout.bin").write_bytes(stdout)
        (directory / "stderr.bin").write_bytes(stderr)
        record = {"label": label, "command": command, "cwd": str(self.output),
                  "command_sha256": hashlib.sha256(json.dumps(command, separators=(",", ":")).encode()).hexdigest(),
                  "environment": self.env, "returncode": code,
                  "elapsed_seconds": time.monotonic() - started,
                  "stdout_sha256": digest(directory / "stdout.bin"),
                  "stderr_sha256": digest(directory / "stderr.bin")}
        write_json(directory / "receipt.json", record)
        self.calls.append(record)
        require(code is not None, "child_process_infrastructure_failure:" + label)
        return {"code": code, "stdout": stdout.decode("utf-8"), "stderr": stderr.decode("utf-8")}

    def cli(self, label, fixture, argv, *, before=False, fault=False):
        command = [str(self.python), "-I", "-B"]
        if before:
            command += ["-c", BEFORE_BRIDGE, str(self.before)]
        elif fault:
            command += ["-c", FAULT_BRIDGE]
        else:
            command += ["-m", "continuity_receipt.memory_resume"]
        common = ["--data-root", str(fixture / "data"),
                  "--trust-db", str(fixture / "trust" / "receiver.sqlite3"),
                  "--context", CONTEXT, "--scope", SCOPE,
                  "--public-key", str(self.output / "keys" / "fixture-public.pem"),
                  "--now", NOW]
        return self.call(label, command + argv + common)

    def fixture(self, name, *, before=False):
        root = self.output / name
        root.mkdir()
        (root / "input").mkdir()
        initialized = self.cli(name + "-init", root, ["init"], before=before)
        require(initialized["code"] == 0, name + ":initialization_failed")
        first = self.publish(name + "-s1", root, "S1\n", "none", before=before)
        require(first["code"] == 0, name + ":healthy_publication_failed")
        result = one_json(first["stdout"])
        require(result["outcome"] == "ACCEPT" and result["assessment"]["core"]["verdict"] == "TRUSTED",
                name + ":healthy_verification_not_accepted")
        return root, result["reference"]

    def publish(self, label, root, text, expected, *, witness=None, before=False, fault=False):
        (root / "input" / "notes.txt").write_text(text, encoding="utf-8")
        args = ["publish", "--input-root", str(root / "input"),
                "--key-pem", str(self.output / "keys" / "fixture-private.pem"),
                "--expected-reference", expected]
        if witness is not None:
            args += ["--witness-file", str(witness)]
        return self.cli(label, root, args, before=before, fault=fault)

    def status(self, label, root, *, before=False):
        result = self.cli(label, root, ["status"], before=before)
        require(result["code"] == 0, label + ":status_failed")
        return one_json(result["stdout"])["reference"]


def one_json(raw):
    lines = raw.splitlines()
    require(len(lines) == 1, "expected_exactly_one_json_record")
    return json.loads(lines[0])


def audit_count(root):
    database = root / "trust" / "receiver.sqlite3"
    connection = sqlite3.connect("file:" + quote(str(database), safe="/") + "?mode=ro", uri=True)
    try:
        return connection.execute("SELECT count(*) FROM publication_audit").fetchone()[0]
    finally:
        connection.close()


def seal(root):
    entries = [(p.relative_to(root).as_posix(), digest(p)) for p in sorted(root.rglob("*"))
               if p.is_file() and not p.is_symlink() and p != root / "SHA256SUMS"]
    with (root / "SHA256SUMS").open("x", encoding="utf-8") as stream:
        for name, sha256 in entries:
            stream.write(sha256 + "  " + name + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True, help="absolute Python path in the installed candidate venv")
    parser.add_argument("--before-source", required=True, help="frozen 9b14d8a1 package root, explicitly source-executed")
    parser.add_argument("--output", required=True, help="new absolute output directory outside source trees")
    args = parser.parse_args()
    python, before, output = Path(args.python), Path(args.before_source), Path(args.output)
    require(python.is_absolute() and python.is_file(), "absolute_installed_python_required")
    require(before.is_absolute() and before.is_dir(), "absolute_before_source_required")
    require(output.is_absolute() and not output.exists() and not output.is_symlink(), "new_absolute_output_required")
    require(output.parent.is_dir() and output.parent.resolve() == output.parent, "output_parent_must_exist_without_symlinks")
    require(not output.is_relative_to(before.resolve()) and not output.is_relative_to(Path(__file__).resolve().parents[1]),
            "output_must_be_outside_source_trees")
    anchors = {name: digest(before / "continuity_receipt" / name) for name in BEFORE_ANCHORS}
    require(anchors == BEFORE_ANCHORS, "before_source_does_not_match_declared_9b14d8a1_anchors")
    output.mkdir(mode=0o700)
    run = Reproducer(python, before, output)
    summary = {"status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
               "before_commit": BEFORE_COMMIT, "before_anchor_hashes": anchors,
               "runner_sha256": digest(__file__), "observations": {}, "limits": [
                   "Before stage imports declared frozen source; after stage uses the installed candidate.",
                   "Synthetic deterministic test key and disposable local stores; same operator.",
                   "Controlled os.replace fault is not power-loss qualification or an external witness service."]}
    try:
        after_identity = run.call("installed-origin", [str(python), "-I", "-B", "-c", IDENTITY])
        require(after_identity["code"] == 0, "installed_origin_check_failed")
        before_identity = run.call("before-origin", [str(python), "-I", "-B", "-c", IDENTITY, str(before)])
        require(before_identity["code"] == 0, "before_origin_check_failed")
        summary["installed_identity"] = json.loads(after_identity["stdout"])
        summary["before_identity"] = json.loads(before_identity["stdout"])
        setup = run.call("disposable-key", [str(python), "-I", "-B", "-c", KEY_SETUP, str(output / "keys")])
        require(setup["code"] == 0, "key_setup_failed")

        old, old_ref = run.fixture("before", before=True)
        old_target = old / "absent-parent" / "witness.json"
        failed = run.publish("before-publication-fault", old, "S2\n", old_ref["checkpoint_digest"],
                             witness=old_target, before=True)
        records = [json.loads(line) for line in failed["stdout"].splitlines()]
        old_current = run.status("before-postfault-status", old, before=True)
        require(failed["code"] == 2 and [r["outcome"] for r in records] == ["ACCEPT", "REJECT"],
                "before_mixed_publication_result_not_reproduced")
        require(old_current["sequence"] == 2 and not old_target.exists(), "before_partial_commit_not_reproduced")
        summary["observations"]["before"] = {"records": records, "exit": failed["code"],
                                               "actual_reference": old_current, "witness_exists": False}

        fresh, fresh_ref = run.fixture("after-preflight")
        target = fresh / "absent-parent" / "witness.json"
        refused = run.publish("after-preflight-refusal", fresh, "S2\n", fresh_ref["checkpoint_digest"], witness=target)
        refusal = one_json(refused["stdout"])
        current = run.status("after-preflight-status", fresh)
        require(refused["code"] == 2 and refusal["outcome"] == "REJECT" and
                refusal["local_committed"] is False and current == fresh_ref and not target.exists(),
                "after_preflight_did_not_preserve_local_state")
        summary["observations"]["after_preflight"] = {"result": refusal, "actual_reference": current}

        recovery, first = run.fixture("after-recovery")
        witness_parent = recovery / "retained"
        witness_parent.mkdir()
        witness = witness_parent / "witness.json"
        partial_call = run.publish("after-postcommit-fault", recovery, "S2\n", first["checkpoint_digest"],
                                   witness=witness, fault=True)
        partial = one_json(partial_call["stdout"])
        committed = run.status("after-postcommit-status", recovery)
        require(partial_call["code"] == 2 and partial["outcome"] == "REJECT" and partial["local_committed"] is True and
                partial["reference"] == committed and committed["sequence"] == 2 and
                partial["witness_publication"]["outcome"] == "INCOMPLETE" and not witness.exists(),
                "after_postcommit_truth_not_preserved")
        # Retain the returned checkpoint outside the runtime before recovery.
        pin = partial["reference"]["checkpoint_digest"]
        write_json(recovery / "independently-retained-receipt.json", partial)
        count_before = audit_count(recovery)
        wrong = run.cli("reconcile-old-pin-refusal", recovery, ["witness-reconcile", "--witness-file", str(witness),
                        "--expected-reference", first["checkpoint_digest"]])
        wrong_payload = one_json(wrong["stdout"])
        require(wrong["code"] == 2 and wrong_payload["outcome"] == "REJECT" and
                wrong_payload["local_publication_performed"] is False and not witness.exists(),
                "reconciliation_accepted_wrong_pin")
        reconciled = []
        witness_bytes = None
        for number in (1, 2):
            result = run.cli(f"reconcile-{number}", recovery, ["witness-reconcile", "--witness-file", str(witness),
                             "--expected-reference", pin])
            payload = one_json(result["stdout"])
            require(result["code"] == 0 and payload["outcome"] == "ACCEPT" and
                    payload["local_publication_performed"] is False and payload["verified_reference"] == committed and
                    payload["witness_publication"]["outcome"] == "COMPLETE", "reconciliation_failed")
            raw = witness.read_bytes()
            require(witness_bytes is None or raw == witness_bytes, "reconciliation_not_logically_idempotent")
            witness_bytes = raw
            reconciled.append(payload)
        final_reference = run.status("recovered-status", recovery)
        require(final_reference == committed and audit_count(recovery) == count_before == 2,
                "reconciliation_republished_or_advanced_local_state")
        resumed = run.cli("strict-resume", recovery, ["resume", "--memory-path", "notes.txt",
                          "--witness-file", str(witness), "--require-witness", "--expected-witness-checkpoint", pin])
        require(resumed["code"] == 0 and resumed["stdout"] == "S2\n", "recovered_strict_resume_failed")
        summary["observations"]["recovery"] = {"partial_result": partial, "wrong_pin_refusal": wrong_payload,
             "reconciliations": reconciled,
             "final_reference": final_reference, "publication_audit_rows_before_and_after": [count_before, audit_count(recovery)],
             "strict_stdout": resumed["stdout"], "witness_sha256": digest(witness)}
        summary["status"] = "COMPLETED"
    except Exception as exc:
        summary.update(status="FAILED", failure={"type": type(exc).__name__, "message": str(exc)})
    summary["finished_at"] = datetime.now(timezone.utc).isoformat()
    summary["process_calls"] = len(run.calls)
    write_json(output / "summary.json", summary)
    write_json(output / "calls.json", run.calls)
    seal(output)
    print(json.dumps({"status": summary["status"], "output": str(output), "process_calls": len(run.calls)}, sort_keys=True))
    return 0 if summary["status"] == "COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
