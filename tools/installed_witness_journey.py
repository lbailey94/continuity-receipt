#!/usr/bin/env python3
"""Qualify a supplied wheel through its installed CLI in a disposable directory.

This runner imports only the standard library. It never adds a checkout to a
child's import path. Install the candidate wheel into a fresh, private venv
first, then supply its Python, the exact wheel, the frozen source root, and a
new absolute output directory outside the source tree. All inputs, closed
store copies, native stdout/stderr, requests, receipts, and failed attempts are
retained. The fixture signing key is deliberately public and must never be
used for real evidence.
"""
from __future__ import annotations

import argparse
import base64
import configparser
import csv
from datetime import datetime, timezone
from email.parser import BytesParser
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import time
import traceback
import zipfile


NOW = "2026-11-01T13:15:00Z"
CONTEXT = "installed-witness-journey-20261101"
SCOPE = "test:installed-witness-journey"
TEXT = {n: f"Installed CPR witness journey: S{n}.\n".encode() for n in (1, 2, 3)}
REFERENCE_FIELDS = ("generation_id", "sequence", "checkpoint_digest", "bundle_digest", "manifest_digest")
LIMITS = [
    "Synthetic local fixture with a deliberately public signing key; no personal or production store is used.",
    "Qualification of one installed candidate wheel by one operator; not independent-operator reproduction or a deployed-service result.",
    "The retained pins are separate local fixture artifacts, not an independently operated witness service or authenticated currentness discovery.",
    "A valid old witness without a separately retained newer pin remains only a floor and can approve jointly restored old state.",
    "The forced os.replace failure is controlled fault injection in an installed module, not an observed production incident or a real power-loss durability test.",
    "witness-reconcile re-verifies the complete selected snapshot and updates only the witness; this does not demonstrate cheaper targeted evidence reassessment.",
    "Fixed --now is a synthetic trusted-clock override; these observations do not establish real-time freshness or evidence applicability across arbitrary releases.",
]


# Every Python helper runs under the supplied installed interpreter with -I -B.
# No helper receives the source-root path or imports this runner.
IDENTITY_CODE = r'''
import hashlib, importlib.metadata as md, json, pathlib, sys
import continuity_receipt as package
from continuity_receipt import memory_resume, receiver_store, witness, witness_file
import cryptography
dist = md.distribution("continuity-receipt")
root = pathlib.Path(package.__file__).resolve().parent
origins = {}
for name, module in sorted(sys.modules.items()):
    if name == "continuity_receipt" or name.startswith("continuity_receipt."):
        path = getattr(module, "__file__", None)
        origins[name] = {"path": str(pathlib.Path(path).resolve()),
                         "sha256": hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()} if path else {"path": None}
modules = {"continuity_receipt/" + str(p.relative_to(root)).replace("\\", "/"):
           {"path": str(p.resolve()), "size": p.stat().st_size,
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
           for p in sorted(root.rglob("*.py"))}
result = {"executable": sys.executable, "prefix": sys.prefix, "base_prefix": sys.base_prefix,
          "sys_path": sys.path, "isolated": sys.flags.isolated,
          "distribution": dist.metadata["Name"], "version": dist.version,
          "package_version": package.__version__, "package_root": str(root),
          "distribution_root": str(pathlib.Path(dist.locate_file("")).resolve()),
          "entry_points": {e.name: e.value for e in dist.entry_points if e.group == "console_scripts"},
          "metadata_sha256": hashlib.sha256(dist.read_text("METADATA").encode()).hexdigest(),
          "cryptography_version": cryptography.__version__, "cryptography_origin": cryptography.__file__,
          "loaded_module_origins": origins, "packaged_modules": modules}
print(json.dumps(result, sort_keys=True))
'''

KEY_CODE = r'''
import hashlib, json, pathlib, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
root = pathlib.Path(sys.argv[1])
key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
private = root / "fixture-private.pem"
public = root / "fixture-public.pem"
private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
private.chmod(0o600)
raw = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
public.write_bytes(raw)
public.chmod(0o600)
print(json.dumps({"fixture_key": True, "public_key_sha256": hashlib.sha256(raw).hexdigest(),
                  "seed": "bytes(range(32)); deliberately public, test-only"}, sort_keys=True))
'''

FAULT_CODE = r'''
import hashlib, json, pathlib, sys
from unittest.mock import patch
from continuity_receipt import memory_resume, witness_file
def origins():
    result = {}
    for name, module in sorted(sys.modules.items()):
        if name == "continuity_receipt" or name.startswith("continuity_receipt."):
            path = getattr(module, "__file__", None)
            result[name] = {"path": str(pathlib.Path(path).resolve()),
                            "sha256": hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()} if path else {"path": None}
    return result
code = None
try:
    with patch.object(witness_file.os, "replace", side_effect=OSError("installed-journey controlled postcommit os.replace failure")):
        code = memory_resume.main(sys.argv[2:])
finally:
    pathlib.Path(sys.argv[1]).write_text(json.dumps({"executable": sys.executable,
        "prefix": sys.prefix, "isolated": sys.flags.isolated,
        "loaded_module_origins": origins()}, sort_keys=True) + "\n")
raise SystemExit(code)
'''


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def inventory(root: Path) -> list[dict]:
    """Capture content and modes, not timestamps; never follow fixture symlinks."""
    result = []
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        item = {"path": path.relative_to(root).as_posix(), "mode": oct(stat.S_IMODE(info.st_mode))}
        if path.is_symlink():
            item.update(kind="symlink", target=os.readlink(path))
        elif path.is_dir():
            item["kind"] = "directory"
        elif path.is_file():
            raw = path.read_bytes()
            item.update(kind="file", size=len(raw), sha256=digest(raw))
        else:
            item["kind"] = "special"
        result.append(item)
    return result


def module_origins_ok(value: dict, prefix: Path, modules: dict) -> None:
    for name, item in value["loaded_module_origins"].items():
        require(item.get("path") is not None, f"{name}: absent installed module origin")
        origin = Path(item["path"]).resolve()
        require(within(origin, prefix), f"{name}: origin outside selected venv: {origin}")
        rel = "continuity_receipt/" + ("__init__.py" if name == "continuity_receipt" else name.split(".", 1)[1].replace(".", "/") + ".py")
        require(rel in modules and item["sha256"] == modules[rel]["sha256"], f"{name}: origin bytes differ from supplied wheel")


def wheel_binding(wheel: Path, source: Path) -> dict:
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "wheel contains duplicate member names")
        for name in names:
            path = PurePosixPath(name)
            require(not path.is_absolute() and ".." not in path.parts and "\\" not in name, "wheel contains unsafe member path")
        files = {name: archive.read(name) for name in names if not name.endswith("/")}
    records = [name for name in files if name.endswith(".dist-info/RECORD")]
    require(len(records) == 1, "wheel must contain exactly one RECORD")
    rows = list(csv.reader(io.StringIO(files[records[0]].decode("utf-8"))))
    require(all(len(row) == 3 for row in rows), "wheel RECORD has invalid row width")
    recorded = {row[0]: row for row in rows}
    require(len(recorded) == len(rows), "wheel RECORD contains duplicate paths")
    require(set(recorded) == set(files), "wheel member inventory and RECORD differ")
    for name, hash_value, size in rows:
        raw = files[name]
        if name == records[0]:
            require(not hash_value and not size, "RECORD must leave its own hash/size empty")
            continue
        require(hash_value.startswith("sha256=") and size == str(len(raw)), f"{name}: missing sha256 or incorrect RECORD size")
        expected = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
        require(hash_value == "sha256=" + expected, f"{name}: wheel RECORD digest mismatch")
    dist_info = records[0].rsplit("/", 1)[0]
    metadata_raw = files[dist_info + "/METADATA"]
    metadata = BytesParser().parsebytes(metadata_raw)
    require(metadata["Name"] == "continuity-receipt", "unexpected wheel distribution")
    entry = configparser.ConfigParser()
    entry.read_string(files[dist_info + "/entry_points.txt"].decode())
    require(entry["console_scripts"]["cpr-memory"] == "continuity_receipt.memory_resume:main", "wheel cpr-memory entry point mismatch")
    modules = {name: {"size": len(raw), "sha256": digest(raw)} for name, raw in sorted(files.items())
               if name.startswith("continuity_receipt/") and name.endswith(".py")}
    require(bool(modules), "wheel contains no package Python modules")
    source_modules = {"continuity_receipt/" + p.relative_to(source / "continuity_receipt").as_posix():
                      {"size": p.stat().st_size, "sha256": digest(p.read_bytes())}
                      for p in sorted((source / "continuity_receipt").rglob("*.py"))}
    require(modules == source_modules, "frozen source Python module inventory/bytes differ from supplied wheel")
    source_inputs = {}
    for name in ("pyproject.toml", "MANIFEST.in", "LICENSE", "tools/installed_witness_journey.py"):
        path = source / name
        if path.is_file():
            source_inputs[name] = {"size": path.stat().st_size, "sha256": digest(path.read_bytes())}
    licenses = [name for name in files if name.startswith(dist_info + "/licenses/")]
    require(any(Path(name).name == "LICENSE" for name in licenses), "candidate wheel lacks LICENSE")
    return {"distribution": metadata["Name"], "version": metadata["Version"],
            "wheel_path": str(wheel), "wheel_size": wheel.stat().st_size, "wheel_sha256": digest(wheel.read_bytes()),
            "record_path": records[0], "record_validated": True,
            "metadata_sha256": digest(metadata_raw), "modules": modules,
            "module_inventory_sha256": digest(json.dumps(modules, sort_keys=True, separators=(",", ":")).encode()),
            "source_root": str(source), "source_inputs": source_inputs,
            "source_modules_match_wheel": True, "licenses": licenses,
            "wheel_files": [{"path": name, "size": len(raw), "sha256": digest(raw)} for name, raw in sorted(files.items())]}


class Journey:
    def __init__(self, python: Path, wheel: Path, source: Path, output: Path):
        self.python, self.wheel, self.source, self.output = python, wheel, source, output
        self.prefix = python.parent.parent.resolve()
        self.entry = python.parent / "cpr-memory"
        self.events: list[dict] = []
        self.cases: list[dict] = []
        self.references: dict[str, dict] = {}
        self.binding = {}
        self.identity = {}
        for name in ("calls", "home", "tmp", "keys", "input", "retained", "archives", "baseline", "cases"):
            (output / name).mkdir(mode=0o700)
        self.env = {"PATH": "/usr/bin:/bin", "HOME": str(output / "home"),
                    "XDG_CONFIG_HOME": str(output / "home" / "config"),
                    "XDG_DATA_HOME": str(output / "home" / "data"),
                    "XDG_CACHE_HOME": str(output / "home" / "cache"),
                    "TMPDIR": str(output / "tmp"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                    "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}
        self.private = output / "keys" / "fixture-private.pem"
        self.public = output / "keys" / "fixture-public.pem"
        self.inputs = output / "input"

    def run(self, label: str, command: list[str], *, request: dict | None = None) -> dict:
        require(label and all(c.isalnum() or c in "-_" for c in label), "unsafe call label")
        call = self.output / "calls" / f"{len(self.events) + 1:03d}-{label}"
        call.mkdir(mode=0o700)
        payload = {"label": label, "command": command, "cwd": str(self.output),
                   "environment": self.env, "timeout_seconds": 40,
                   "request": request or {}, "started_utc": datetime.now(timezone.utc).isoformat()}
        write_json(call / "request.json", payload)
        started = time.monotonic()
        try:
            result = subprocess.run(command, cwd=self.output, env=self.env, capture_output=True,
                                    timeout=40, check=False)
            stdout, stderr, rc, error = result.stdout, result.stderr, result.returncode, None
        except subprocess.TimeoutExpired as exc:
            stdout, stderr, rc, error = exc.stdout or b"", exc.stderr or b"", None, "timeout"
        except OSError as exc:
            stdout, stderr, rc, error = b"", str(exc).encode(), None, type(exc).__name__
        (call / "stdout.txt").write_bytes(stdout)
        (call / "stderr.txt").write_bytes(stderr)
        receipt = {**payload, "returncode": rc, "infrastructure_error": error,
                   "elapsed_seconds": round(time.monotonic() - started, 6),
                   "stdout_size": len(stdout), "stdout_sha256": digest(stdout),
                   "stderr_size": len(stderr), "stderr_sha256": digest(stderr),
                   "stdout": stdout.decode("utf-8", errors="backslashreplace"),
                   "stderr": stderr.decode("utf-8", errors="backslashreplace")}
        write_json(call / "receipt.json", receipt)
        event = {"label": label, "directory": call.relative_to(self.output).as_posix(),
                 "returncode": rc, "infrastructure_error": error,
                 "stdout_size": len(stdout), "stdout_sha256": digest(stdout),
                 "stderr_size": len(stderr), "stderr_sha256": digest(stderr)}
        self.events.append(event)
        write_json(self.output / "call-ledger.json", self.events)
        require(error is None, f"{label}: subprocess infrastructure failure ({error})")
        return {**event, "stdout_raw": stdout, "stderr_raw": stderr, "call_path": call}

    def helper(self, label: str, code: str, *args: str) -> dict:
        return self.run(label, [str(self.python), "-I", "-B", "-c", code, *args],
                        request={"kind": "installed-python-helper", "source_path_injection": False})

    def common(self, case: Path) -> list[str]:
        return ["--data-root", str(case / "runtime" / "data"),
                "--trust-db", str(case / "runtime" / "trust" / "receiver.sqlite3"),
                "--context", CONTEXT, "--scope", SCOPE, "--public-key", str(self.public), "--now", NOW]

    def native(self, label: str, case: Path, operation: str, *args: str) -> dict:
        return self.run(label, [str(self.entry), operation, *args, *self.common(case)],
                        request={"kind": "native-installed-console-entrypoint", "operation": operation,
                                 "case": str(case), "source_path_injection": False})

    @staticmethod
    def report(event: dict, stream: str = "stdout", *, rc: int = 0) -> dict:
        require(event["returncode"] == rc, f"{event['label']}: rc {event['returncode']} != {rc}; see {event['directory']}")
        raw = event[stream + "_raw"]
        require(len(raw.splitlines()) == 1, f"{event['label']}: expected one final JSON record on {stream}")
        value = json.loads(raw)
        require(isinstance(value, dict), f"{event['label']}: report is not an object")
        return value

    def observed(self, label: str, event: dict, report: dict, **extra) -> None:
        self.cases.append({"case": label, "call": event["directory"], "returncode": event["returncode"],
                           "observed_report": report, "stdout_size": event["stdout_size"],
                           "stdout_sha256": event["stdout_sha256"], "checks_passed": True, **extra})
        write_json(self.output / "case-ledger.json", self.cases)

    def status(self, label: str, case: Path, expected: dict | None = None) -> dict:
        event = self.native(label, case, "status")
        value = self.report(event)
        require(value.get("outcome") == "ACCEPT", f"{label}: status did not accept")
        reference = value["reference"]
        require(set(reference) == set(REFERENCE_FIELDS), f"{label}: unexpected reference fields")
        if expected is not None:
            require(reference == expected, f"{label}: selected reference changed")
        self.observed(label, event, value)
        return reference

    def resume(self, label: str, case: Path, *, expected: bytes | None, options: list[str]) -> dict:
        event = self.native(label, case, "resume", "--memory-path", "notes.txt", *options)
        report = self.report(event, "stderr", rc=0 if expected is not None else 2)
        require(event["stdout_raw"] == (expected if expected is not None else b""), f"{label}: selected bytes differ or refused operation delivered bytes")
        require(report.get("outcome") == ("ACCEPT" if expected is not None else "REJECT"), f"{label}: unexpected decision")
        if expected is not None:
            require(report.get("policy", {}).get("version") == "2", f"{label}: resume policy is not version 2")
        self.observed(label, event, report, selected_bytes_sha256=digest(expected) if expected is not None else None)
        return report

    @staticmethod
    def strict(case: Path, reference: dict) -> list[str]:
        return ["--witness-file", str(case / "witness.json"), "--require-witness",
                "--expected-witness-checkpoint", reference["checkpoint_digest"]]

    def publication(self, label: str, case: Path, text: bytes, expected: str, *, witness: Path | None = None) -> dict:
        (self.inputs / "notes.txt").write_bytes(text)
        args = ["--input-root", str(self.inputs), "--key-pem", str(self.private), "--expected-reference", expected]
        if witness is not None:
            args += ["--witness-file", str(witness)]
        return self.native(label, case, "publish", *args)

    def clone(self, label: str, *, restore: bool = False, old_witness: bool = False) -> Path:
        case = self.output / "cases" / label
        case.mkdir(mode=0o700)
        shutil.copytree(self.output / "archives" / "S2" / "runtime", case / "runtime")
        shutil.copy2(self.output / "archives" / ("S1" if old_witness else "S2") / "witness.json", case / "witness.json")
        if restore:
            (case / "runtime").rename(case / "displaced-S2-runtime")
            shutil.copytree(self.output / "archives" / "S1" / "runtime", case / "runtime")
        write_json(case / "before-runtime.json", inventory(case / "runtime"))
        return case

    def reconcile(self, label: str, case: Path, reference: dict, *, accepted: bool) -> dict:
        before = inventory(case / "runtime")
        witness = case / "witness.json"
        old = witness.read_bytes() if witness.is_file() and not witness.is_symlink() else None
        event = self.native(label, case, "witness-reconcile", "--witness-file", str(witness),
                            "--expected-reference", reference["checkpoint_digest"])
        report = self.report(event, rc=0 if accepted else 2)
        require(event["stderr_raw"] == b"", f"{label}: reconciliation emitted unexpected stderr")
        require(report.get("operation") == "witness-reconcile", f"{label}: operation identity missing")
        require(report.get("outcome") == ("ACCEPT" if accepted else "REJECT"), f"{label}: unexpected reconcile outcome")
        require(report.get("local_publication_performed") is False, f"{label}: reconciliation claims local publication")
        after = inventory(case / "runtime")
        require(after == before, f"{label}: reconciliation changed local store/payload bytes or modes")
        if accepted:
            require(report.get("verified_reference") == reference, f"{label}: verified reference mismatch")
            require(report.get("witness_publication", {}).get("outcome") == "COMPLETE", f"{label}: witness repair incomplete")
            require(json.loads(witness.read_bytes()) == {k: reference[k] for k in ("sequence", "checkpoint_digest", "generation_id")}, f"{label}: repaired witness mismatch")
            require(stat.S_IMODE(witness.stat().st_mode) == 0o600, f"{label}: repaired witness is not mode 600")
        elif old is not None:
            require(witness.read_bytes() == old, f"{label}: refused reconciliation changed witness bytes")
        write_json(case / (label + "-runtime-after.json"), after)
        self.observed(label, event, report, runtime_unchanged=True)
        return report

    def verify_identity(self, label: str) -> dict:
        event = self.helper(label, IDENTITY_CODE)
        value = self.report(event)
        require(value["prefix"] != value["base_prefix"] and Path(value["prefix"]).resolve() == self.prefix, "selected Python is not the supplied venv")
        require(Path(value["executable"]).absolute() == self.python, "helper executable differs from supplied Python")
        require(value["isolated"] == 1, "identity helper is not isolated")
        require(value["version"] == self.binding["version"] == value["package_version"], "wheel/distribution/package versions differ")
        require(value["metadata_sha256"] == self.binding["metadata_sha256"], "installed METADATA differs from wheel")
        require(value["entry_points"]["cpr-memory"] == "continuity_receipt.memory_resume:main", "installed entry point mapping differs")
        require(within(Path(value["distribution_root"]), self.prefix), "installed distribution is outside selected venv")
        require(within(Path(value["cryptography_origin"]).resolve(), self.prefix), "cryptography dependency is outside selected venv")
        require(set(value["packaged_modules"]) == set(self.binding["modules"]), "installed module inventory differs from wheel")
        for name, item in value["packaged_modules"].items():
            require(within(Path(item["path"]), self.prefix), f"{name}: installed module outside venv")
            require({k: item[k] for k in ("size", "sha256")} == self.binding["modules"][name], f"{name}: installed bytes differ from wheel")
        for path in value["sys_path"]:
            require(path and not within(Path(path).resolve(), self.source), "isolated child contains an empty/check-out import path")
        module_origins_ok(value, self.prefix, self.binding["modules"])
        write_json(self.output / (label + ".json"), value)
        return value

    def execute(self) -> None:
        self.binding = wheel_binding(self.wheel, self.source)
        write_json(self.output / "wheel-source-binding.json", self.binding)
        cfg = self.prefix / "pyvenv.cfg"
        require(cfg.is_file() and "include-system-site-packages = false" in cfg.read_text().lower(), "venv must exclude global site packages")
        require(self.entry.is_file() and os.access(self.entry, os.X_OK), "installed cpr-memory entry point is absent/not executable")
        entry = self.entry.read_bytes()
        require(str(self.python).encode() in entry, "entry script does not name selected venv Python")
        write_json(self.output / "entrypoint-identity.json", {"path": str(self.entry), "size": len(entry),
                   "sha256": digest(entry), "header": entry.decode("utf-8").splitlines()[:8],
                   "entry_point": "continuity_receipt.memory_resume:main", "pyvenv_cfg": cfg.read_text()})
        self.identity = self.verify_identity("installed-identity-before")
        keys = self.helper("create-public-fixture-key", KEY_CODE, str(self.output / "keys"))
        require(self.report(keys).get("fixture_key") is True, "fixture key helper did not finish")
        baseline = self.output / "baseline"
        init = self.native("baseline-init", baseline, "init")
        require(self.report(init).get("outcome") == "ACCEPT", "installed initialization failed")
        self.observed("baseline-init", init, self.report(init))
        previous = "none"
        for number in (1, 2):
            event = self.publication(f"baseline-publish-S{number}", baseline, TEXT[number], previous, witness=baseline / "witness.json")
            report = self.report(event)
            require(report.get("outcome") == "ACCEPT" and report.get("local_committed") is True, f"S{number}: publication not committed")
            require(report.get("witness_publication", {}).get("outcome") == "COMPLETE", f"S{number}: witness not complete")
            reference = report["reference"]
            require(reference["sequence"] == number, f"S{number}: unexpected sequence")
            self.references[f"S{number}"] = reference
            write_json(self.output / "retained" / f"S{number}-reference.json", {"source_call": event["directory"], "reference": reference})
            self.observed(f"baseline-publish-S{number}", event, report)
            self.status(f"baseline-status-S{number}", baseline, reference)
            self.resume(f"healthy-strict-S{number}", baseline, expected=TEXT[number], options=self.strict(baseline, reference))
            # All CLI processes have exited before these SQLite/data copies.
            shutil.copytree(baseline / "runtime", self.output / "archives" / f"S{number}" / "runtime")
            shutil.copy2(baseline / "witness.json", self.output / "archives" / f"S{number}" / "witness.json")
            previous = reference["checkpoint_digest"]
        s1, s2 = self.references["S1"], self.references["S2"]
        weak = self.resume("healthy-file-only-S2", baseline, expected=TEXT[2], options=["--witness-file", str(baseline / "witness.json")])
        strict = self.resume("healthy-pin-policy-S2", baseline, expected=TEXT[2], options=self.strict(baseline, s2))
        require(weak["policy"]["digest"] != strict["policy"]["digest"], "required pin is absent from policy digest")
        require(weak["decision"]["approved_output_digest"] == strict["decision"]["approved_output_digest"], "same selected bytes have different approved output digest")
        write_json(self.output / "policy-binding-comparison.json", {"file_only": weak["policy"], "required_separate_pin": strict["policy"],
                   "different_policy_digests": True, "same_approved_output_digest": True})

        current = self.clone("joint-restore-current-witness", restore=True)
        self.resume("restored-S1-current-S2-witness-refuses", current, expected=None, options=self.strict(current, s2))
        old = self.clone("joint-restore-old-witness", restore=True, old_witness=True)
        self.resume("restored-S1-old-S1-witness-S2-pin-refuses", old, expected=None, options=self.strict(old, s2))
        self.resume("negative-control-old-floor-without-pin-accepts-S1", old, expected=TEXT[1], options=["--witness-file", str(old / "witness.json")])
        self.resume("identical-old-floor-with-new-pin-refuses", old, expected=None, options=self.strict(old, s2))

        invalid = [("missing", None), ("empty", b""), ("empty-object", b"{}"), ("invalid-json", b"not-json"),
                   ("wrong-field", json.dumps({"min_sequence": 2, "checkpoint_digest": s2["checkpoint_digest"]}).encode()),
                   ("boolean-sequence", json.dumps({"sequence": True, "checkpoint_digest": s2["checkpoint_digest"]}).encode()),
                   ("unknown-field", json.dumps({"sequence": 2, "checkpoint_digest": s2["checkpoint_digest"], "observed_at": NOW}).encode())]
        for name, raw in invalid:
            case = self.clone("invalid-witness-" + name, restore=True)
            (case / "witness.json").unlink()
            if raw is not None:
                (case / "witness.json").write_bytes(raw)
            self.resume("configured-" + name + "-witness-refuses", case, expected=None, options=self.strict(case, s2))
        case = self.clone("missing-and-empty-options", restore=True)
        option_cases = [
            ("required-witness-without-file", ["--require-witness"]),
            ("required-witness-without-pin", ["--require-witness", "--witness-file", str(case / "witness.json")]),
            ("pin-without-witness-file", ["--expected-witness-checkpoint", s2["checkpoint_digest"]]),
            ("empty-witness-path", ["--witness-file", ""]),
            ("empty-pin", ["--witness-file", str(case / "witness.json"), "--expected-witness-checkpoint", ""]),
            ("empty-predicate-path", ["--predicate-file", ""]), ("empty-profile-path", ["--profile", ""])]
        for name, options in option_cases:
            self.resume(name + "-refuses", case, expected=None, options=options)

        preflight = self.clone("publication-missing-witness-parent")
        before = inventory(preflight / "runtime")
        missing = preflight / "absent-parent" / "witness.json"
        event = self.publication("missing-parent-publication-refuses", preflight, TEXT[3], s2["checkpoint_digest"], witness=missing)
        report = self.report(event, rc=2)
        require(report.get("outcome") == "REJECT" and report.get("local_committed") is False, "preflight failure claimed local commit")
        require(report.get("witness_publication", {}).get("outcome") == "NOT_ATTEMPTED", "preflight failure claimed witness attempt")
        require(inventory(preflight / "runtime") == before and not missing.parent.exists(), "preflight failure mutated store or created missing parent")
        self.observed("missing-parent-publication-refuses", event, report, runtime_unchanged=True)
        self.status("missing-parent-fresh-status-remains-S2", preflight, s2)

        partial = self.clone("partial-publication-and-recovery")
        witness_before = (partial / "witness.json").read_bytes()
        (self.inputs / "notes.txt").write_bytes(TEXT[3])
        origin_path = partial / "fault-helper-module-origins.json"
        args = ["publish", "--input-root", str(self.inputs), "--key-pem", str(self.private),
                "--expected-reference", s2["checkpoint_digest"], "--witness-file", str(partial / "witness.json"), *self.common(partial)]
        event = self.helper("forced-installed-postcommit-replace-failure", FAULT_CODE, str(origin_path), *args)
        report = self.report(event, rc=2)
        require(report.get("outcome") == "REJECT" and report.get("local_committed") is True, "postcommit fault did not truthfully retain local commit")
        require(report.get("witness_publication", {}).get("outcome") == "INCOMPLETE", "postcommit fault did not retain incomplete witness status")
        require(report.get("reference", {}).get("sequence") == 3, "postcommit fault lost actual new reference")
        require((partial / "witness.json").read_bytes() == witness_before, "failed replacement changed previous witness bytes")
        origins = json.loads(origin_path.read_bytes())
        require(origins["isolated"] == 1 and Path(origins["prefix"]).resolve() == self.prefix, "fault helper was not isolated inside supplied venv")
        module_origins_ok(origins, self.prefix, self.binding["modules"])
        s3 = report["reference"]
        self.references["S3-partial"] = s3
        write_json(self.output / "retained" / "S3-partial-reference.json", {"source_call": event["directory"], "reference": s3,
                   "custody": "separate local artifact, same operator; not an independent service"})
        self.observed("forced-installed-postcommit-replace-failure", event, report, previous_witness_unchanged=True,
                      fault="controlled OSError from installed witness_file.os.replace")
        self.status("postfault-fresh-status-is-committed-S3", partial, s3)
        self.resume("postfault-old-S2-file-with-S3-pin-refuses", partial, expected=None, options=self.strict(partial, s3))
        self.reconcile("repair-wrong-retained-S2-pin-refuses", partial, s2, accepted=False)
        self.status("wrong-pin-fresh-status-remains-S3", partial, s3)
        self.reconcile("repair-with-retained-S3-pin", partial, s3, accepted=True)
        self.status("repaired-fresh-status-remains-S3", partial, s3)
        witness_repaired = (partial / "witness.json").read_bytes()
        self.reconcile("repeat-repair-is-idempotent", partial, s3, accepted=True)
        require((partial / "witness.json").read_bytes() == witness_repaired, "repeat repair changed witness bytes")
        self.resume("repaired-strict-resume-emits-exact-S3", partial, expected=TEXT[3], options=self.strict(partial, s3))

        missing_case = self.clone("repair-missing-witness")
        (missing_case / "witness.json").unlink()
        self.reconcile("repair-missing-witness-with-retained-S2-pin", missing_case, s2, accepted=True)
        self.resume("missing-witness-repaired-strict-S2", missing_case, expected=TEXT[2], options=self.strict(missing_case, s2))
        for name, witness_value in (("ahead", {**s2, "sequence": 3}),
                                    ("fork", {**s2, "checkpoint_digest": "sha256:" + "0" * 64}),
                                    ("malformed", {})):
            case = self.clone("repair-refuses-" + name)
            (case / "witness.json").write_text(json.dumps({k: witness_value[k] for k in ("sequence", "checkpoint_digest", "generation_id") if k in witness_value}))
            self.reconcile("repair-refuses-" + name, case, s2, accepted=False)
        case = self.clone("repair-refuses-symlink")
        target = case / "retained-external-witness.json"
        (case / "witness.json").rename(target)
        raw = target.read_bytes()
        (case / "witness.json").symlink_to(target)
        self.reconcile("repair-refuses-symlink", case, s2, accepted=False)
        require(target.read_bytes() == raw and (case / "witness.json").is_symlink(), "symlink refusal changed external target")

        final_identity = self.verify_identity("installed-identity-after")
        require(final_identity == self.identity, "installed package/runtime identity changed during journey")
        require(self.entry.read_bytes() == entry, "installed console entry point changed during journey")
        require(wheel_binding(self.wheel, self.source) == self.binding, "source/wheel binding changed during journey")

    def finish(self, failure: dict | None) -> dict:
        summary = {"kind": "installed-cpr-witness-journey", "outcome": "PASS" if failure is None else "FAIL",
                   "output": str(self.output), "python": str(self.python), "source_root": str(self.source),
                   "wheel": str(self.wheel), "candidate_version": self.binding.get("version"),
                   "wheel_sha256": self.binding.get("wheel_sha256"), "native_entrypoint": str(self.entry),
                   "source_import_path_injection": False, "call_count": len(self.events),
                   "case_checks_passed": len(self.cases),
                   "nonzero_calls_retained": [e for e in self.events if e["returncode"] != 0],
                   "references": self.references, "failure": failure, "limits": LIMITS}
        write_json(self.output / "summary.json", summary)
        # Capture the list before opening the manifest, and exclude the manifest
        # itself. A manifest cannot meaningfully contain its own changing hash.
        manifest = self.output / "SHA256SUMS"
        files = [p for p in sorted(self.output.rglob("*")) if p.is_file() and not p.is_symlink() and p != manifest]
        lines = [f"{digest(p.read_bytes())}  {p.relative_to(self.output).as_posix()}\n" for p in files]
        manifest.write_text("".join(lines), encoding="utf-8")
        return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--python", required=True, type=Path, help="absolute fresh-venv/bin/python; candidate already installed")
    parser.add_argument("--wheel", required=True, type=Path, help="absolute path of exact installed candidate wheel")
    parser.add_argument("--source-root", required=True, type=Path, help="absolute frozen source root, used only for parent-side byte comparisons")
    parser.add_argument("--output", required=True, type=Path, help="new absolute output directory outside the checkout and venv")
    args = parser.parse_args()
    try:
        for name in ("python", "wheel", "source_root", "output"):
            require(getattr(args, name).is_absolute(), f"--{name.replace('_', '-')} must be absolute")
        # Preserve the venv/bin/python spelling; resolving that symlink would
        # select the system interpreter instead of the venv.
        python = args.python.absolute()
        wheel, source = args.wheel.resolve(strict=True), args.source_root.resolve(strict=True)
        require(python.is_file() and os.access(python, os.X_OK), "supplied Python is not executable")
        require(wheel.is_file() and wheel.suffix == ".whl", "supplied wheel is not a wheel file")
        require((source / "continuity_receipt").is_dir(), "source root lacks package directory")
        require(args.output.parent.resolve(strict=True) == args.output.parent, "output parent must use a real canonical path without symlinks")
        output = args.output
        require(not output.exists() and not output.is_symlink(), "output must be new; existing attempts are never overwritten")
        require(not within(output, source) and not within(output, python.parent.parent.resolve()), "output must be outside checkout and venv")
        output.mkdir(mode=0o700)
    except Exception as exc:
        print(f"installed witness journey input error: {exc}", file=sys.stderr)
        return 2
    journey = Journey(python, wheel, source, output)
    failure = None
    try:
        journey.execute()
    except Exception as exc:
        failure = {"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}
        write_json(output / "failure.json", failure)
    summary = journey.finish(failure)
    print(json.dumps({"outcome": summary["outcome"], "candidate_version": summary["candidate_version"],
                      "calls": summary["call_count"], "case_checks_passed": summary["case_checks_passed"],
                      "summary": str(output / "summary.json"), "manifest": str(output / "SHA256SUMS"),
                      "failure": failure["message"] if failure else None}, sort_keys=True))
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
