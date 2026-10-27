#!/usr/bin/env python3
"""Run a disposable, subprocess-level CPR memory receiver journey.

Every CLI operation is a fresh ``python -m continuity_receipt.memory_resume``
process. The fixed Ed25519 fixture key is written only inside the temporary
journey root and is never copied into evidence. Optional WhiteMagic integration
uses the caller-supplied binary against another disposable store.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

CPR_ROOT = Path(__file__).resolve().parents[1]
FIXED_NOW = "2026-10-23T12:00:00Z"
FIXED_SEED = bytes(range(32))
CONTEXT = "lane07-full-journey"
SCOPE = "whitemagic.memory.resume.v1"
INITIAL = "Journey starts with the red block in bay 3.\n"
APPENDED = INITIAL + " Next action: verify the local receiver.\n"
ERASED = "This selected note must never be emitted after erasure.\n"
QUERY = "lane07_receiver_journey_unique_red_block_bay_3"


def require(condition: bool, message: str) -> None:
    """A journey gate that remains active under ``python -O``."""
    if not condition:
        raise RuntimeError(message)


def _key_files(root: Path) -> tuple[Path, Path]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(FIXED_SEED)
    private = root / "fixture-private.pem"
    public = root / "fixture-public.pem"
    private.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    private.chmod(0o600)
    public.chmod(0o600)
    return private, public


def _child_env(journal: Path) -> tuple[dict[str, str], list[str]]:
    env = os.environ.copy()
    removed = []
    for name in tuple(env):
        if name.startswith(("WM_GEN3_STORE", "WM_STORE", "WM_DATABASE")):
            env.pop(name, None)
            removed.append(name)
    env["WM_GEN3_JOURNAL"] = str(journal)
    env["PYTHONPATH"] = str(CPR_ROOT) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    return env, sorted(removed)


class Journey:
    def __init__(self, root: Path, evidence_dir: Path):
        self.root = root
        self.evidence_dir = evidence_dir
        self.events: list[dict] = []
        self.private, self.public = _key_files(root)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from continuity_receipt.canon import sha256_prefixed
        from continuity_receipt.keys import raw_pubkey_bytes
        key = Ed25519PrivateKey.from_private_bytes(FIXED_SEED)
        self.profile = root / "receiver-profile.json"
        profile = {
            "kind": "cpr-experimental-local-receiver-profile", "version": 1,
            "id": "journey-two-file-v1",
            "export": {"scope": SCOPE, "inventory": ["memory/resume.txt", "memory/retained.txt", "memory/erased.txt"], "optional": ["memory/erased.txt"], "memory_paths": ["memory/resume.txt", "memory/erased.txt"]},
            "trust": {"context": CONTEXT, "key_sha256": sha256_prefixed(raw_pubkey_bytes(key.public_key())),
                      "reference": "receiver-trust-db/current_reference; advanced only by explicit local publish", "clock": "system-utc"},
            "authority": {"status": "operator-asserted", "basis": "outside this verifier"},
            "consent": {"status": "operator-asserted", "subject_consent_verified": False},
            "retention": {"mode": "retain current generation until explicit replacement; prior generations may remain on disk", "deletion": "operator-managed"},
            "refusal": ["missing policy or reference", "untrusted or stale evidence", "inventory mismatch", "selected memory file missing or invalid UTF-8"],
        }
        self.profile.write_text(json.dumps(profile), encoding="utf-8")
        self.data = root / "receiver-data"
        self.trust = root / "receiver-trust.sqlite"
        self.input = root / "input"
        self.input.mkdir()
        self.common = [
            "--data-root", str(self.data), "--trust-db", str(self.trust),
            "--context", CONTEXT, "--scope", SCOPE,
            "--public-key", str(self.public), "--profile", str(self.profile),
        ]
        self.env, self.removed_env = _child_env(root / "wm-gen3-disposable.journal")

    def run(self, label: str, args: list[str], *, code: int, stdout: str | None = None,
            stderr_contains: str | None = None, env: dict[str, str] | None = None) -> dict:
        command = [sys.executable, "-m", "continuity_receipt.memory_resume", *args, *self.common]
        proc = subprocess.run(command, cwd=CPR_ROOT, env=env or self.env,
                              text=True, capture_output=True, timeout=20, check=False)
        event = {
            "label": label, "command": command,
            "returncode": proc.returncode, "stdout": proc.stdout,
            "stderr": proc.stderr, "stdout_sha256": hashlib.sha256(proc.stdout.encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256(proc.stderr.encode()).hexdigest(),
        }
        self.events.append(event)
        require(proc.returncode == code,
                f"{label}: rc={proc.returncode}, expected={code}; stdout={proc.stdout!r}; stderr={proc.stderr!r}")
        if stdout is not None:
            require(proc.stdout == stdout,
                    f"{label}: stdout differed; got {proc.stdout!r}, expected {stdout!r}")
        if stderr_contains is not None:
            require(stderr_contains in proc.stderr,
                    f"{label}: missing {stderr_contains!r} in stderr {proc.stderr!r}")
        return event

    def init(self):
        self.run("initialize-trust", ["init"], code=0)

    def publish(self, label: str, files: dict[str, str], expected: str):
        if self.input.exists():
            shutil.rmtree(self.input)
        self.input.mkdir()
        for rel, text in files.items():
            target = self.input / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8", newline="")
        return self.run(label, ["publish", "--key-pem", str(self.private),
                                "--expected-reference", expected,
                                "--input-root", str(self.input)], code=0)

    def reference(self) -> dict:
        event = self.run("read-current-reference", ["status"], code=0)
        payload = json.loads(event["stdout"])
        require(payload["outcome"] == "ACCEPT" and payload.get("reference"),
                "status did not return an accepted current reference")
        return payload["reference"]

    def resume(self, label: str, path: str, expected: str | None, *, accepted: bool):
        command = [sys.executable, "-m", "continuity_receipt.memory_resume", "resume",
                   "--memory-path", path, *self.common]
        proc = subprocess.run(command, cwd=CPR_ROOT, env=self.env, text=True,
                              capture_output=True, timeout=20, check=False)
        event = {"label": label, "command": command, "returncode": proc.returncode,
                 "stdout": proc.stdout, "stderr": proc.stderr,
                 "stdout_sha256": hashlib.sha256(proc.stdout.encode()).hexdigest(),
                 "stderr_sha256": hashlib.sha256(proc.stderr.encode()).hexdigest()}
        self.events.append(event)
        if accepted:
            require(proc.returncode == 0 and proc.stdout == expected,
                    f"{label}: expected exact accepted text, got rc={proc.returncode}, stdout={proc.stdout!r}")
            require('"outcome": "ACCEPT"' in proc.stderr,
                    f"{label}: expected an ACCEPT assessment on stderr")
        else:
            require(proc.returncode in (1, 2) and proc.stdout == "",
                    f"{label}: expected refusal with empty stdout, got rc={proc.returncode}, stdout={proc.stdout!r}")
        return event


def _copy_pair(data: Path, trust: Path, destination: Path, *, include_trust: bool) -> tuple[Path, Path]:
    target_data = destination / "data"
    target_trust = destination / "trust.sqlite"
    shutil.copytree(data, target_data)
    if include_trust:
        shutil.copy2(trust, target_trust)
    return target_data, target_trust


def _assert_rejected(root: Path, data: Path, trust: Path, public: Path, *, label: str,
                     generation_id: str, path: str, tamper: str) -> dict:
    target_data, target_trust = _copy_pair(data, trust, root / label, include_trust=True)
    generation = target_data / "generations" / generation_id
    require(generation.is_dir(), f"selected generation missing in {label}")
    if tamper == "payload":
        payload = generation / "files" / path
        payload.write_text("CORRUPTED: " + ERASED, encoding="utf-8")
    elif tamper == "checkpoint":
        checkpoint = generation / "checkpoint.json"
        value = json.loads(checkpoint.read_text(encoding="utf-8"))
        value["context"] = value["context"] + ".different"
        checkpoint.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    else:
        raise ValueError(f"unknown_tamper_case:{tamper}")
    command = [sys.executable, "-m", "continuity_receipt.memory_resume", "resume",
               "--data-root", str(target_data), "--trust-db", str(target_trust),
               "--context", CONTEXT, "--scope", SCOPE, "--public-key", str(public),
               "--profile", str(root / "receiver-profile.json"), "--memory-path", path]
    env, _ = _child_env(root / f"{label}.journal")
    proc = subprocess.run(command, cwd=CPR_ROOT, env=env, text=True, capture_output=True,
                          timeout=20, check=False)
    event = {"label": label, "command": command, "returncode": proc.returncode,
             "stdout": proc.stdout, "stderr": proc.stderr,
             "stdout_sha256": hashlib.sha256(proc.stdout.encode()).hexdigest(),
             "stderr_sha256": hashlib.sha256(proc.stderr.encode()).hexdigest()}
    require(proc.returncode in (1, 2) and proc.stdout == "",
            f"{label} leaked/released: rc={proc.returncode}, stdout={proc.stdout!r}")
    return event


def _wm_integration(binary: Path, journey: Journey, accepted_text: str, bundle_digest: str,
                    evidence: dict) -> None:
    binary = binary.resolve(strict=True)
    if not os.access(binary, os.X_OK) or not binary.is_file():
        raise ValueError("wm_binary_must_be_executable_regular_file")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    version = subprocess.run([str(binary), "--version"], cwd=CPR_ROOT, env=journey.env,
                             text=True, capture_output=True, timeout=8, check=False)
    evidence["wm_core"] = {
        "path": str(binary), "sha256": digest,
        "version_probe_returncode": version.returncode,
        "version_probe_stdout": version.stdout[:500],
        "version_probe_stderr_sha256": hashlib.sha256(version.stderr.encode()).hexdigest(),
        "version_probe_supported": version.returncode == 0,
        "source_build_relation": "unknown; no source-to-binary build attestation was collected",
        "journal_path": str(journey.root / "wm-gen3-disposable.journal"),
        "removed_inherited_store_environment_names": journey.removed_env,
    }
    store = journey.root / "wm-store-disposable"
    remember = subprocess.run(
        [str(binary), "--store", str(store), "remember", accepted_text,
         "--source", f"cpr:{bundle_digest}", "--kind", "reported"],
        cwd=CPR_ROOT, env=journey.env, text=True, capture_output=True, timeout=30, check=False,
    )
    remember_event = {"label": "wm-remember-accepted-resume", "returncode": remember.returncode,
                      "stdout": remember.stdout, "stderr": remember.stderr,
                      "stdout_sha256": hashlib.sha256(remember.stdout.encode()).hexdigest(),
                      "stderr_sha256": hashlib.sha256(remember.stderr.encode()).hexdigest()}
    evidence["events"].append(remember_event)
    require(remember.returncode == 0, f"wm remember failed: {remember.stderr!r}")
    recall = subprocess.run(
        [str(binary), "--store", str(store), "recall", QUERY],
        cwd=CPR_ROOT, env=journey.env, text=True, capture_output=True, timeout=30, check=False,
    )
    recall_event = {"label": "wm-recall-imported-resume", "returncode": recall.returncode,
                    "stdout": recall.stdout, "stderr": recall.stderr,
                    "stdout_sha256": hashlib.sha256(recall.stdout.encode()).hexdigest(),
                    "stderr_sha256": hashlib.sha256(recall.stderr.encode()).hexdigest()}
    evidence["events"].append(recall_event)
    require(recall.returncode == 0 and accepted_text.strip() in recall.stdout,
            f"wm recall did not return the imported accepted text: rc={recall.returncode}, stdout={recall.stdout!r}")


def run_journey(output_dir: Path, wm_binary: Path | None = None) -> dict:
    output_dir.mkdir(parents=True, exist_ok=False)
    events = []
    with tempfile.TemporaryDirectory(prefix="cpr-memory-journey-") as temp:
        root = Path(temp)
        journey = Journey(root, output_dir)
        journey.resume("missing-trust-releases-no-output", "memory/resume.txt", None, accepted=False)
        journey.init()
        first = journey.publish("publish-initial-exact-files", {
            "memory/resume.txt": INITIAL, "memory/retained.txt": "Retained control note.\n",
            "memory/erased.txt": ERASED,
        }, "none")
        initial = journey.reference()
        journey.resume("resume-initial-exact-text", "memory/resume.txt", INITIAL, accepted=True)

        second = journey.publish("append-published-by-cas", {
            "memory/resume.txt": APPENDED, "memory/retained.txt": "Retained control note.\n",
            "memory/erased.txt": ERASED,
        }, initial["checkpoint_digest"])
        current = journey.reference()
        journey.resume("resume-appended-exact-text", "memory/resume.txt", APPENDED, accepted=True)

        # Capture a legitimate, mutually consistent current backup before the erasure update.
        trusted_backup_data, trusted_backup_db = _copy_pair(journey.data, journey.trust,
                                                              root / "legitimate-backup", include_trust=True)
        restored_data, restored_db = _copy_pair(trusted_backup_data, trusted_backup_db,
                                                root / "legitimate-restore", include_trust=True)
        restore_command = [sys.executable, "-m", "continuity_receipt.memory_resume", "resume",
                           "--data-root", str(restored_data), "--trust-db", str(restored_db),
                           "--context", CONTEXT, "--scope", SCOPE, "--public-key", str(journey.public),
                           "--profile", str(journey.profile), "--memory-path", "memory/resume.txt"]
        restore_env, _ = _child_env(root / "legitimate-restore.journal")
        restored = subprocess.run(restore_command, cwd=CPR_ROOT, env=restore_env, text=True,
                                  capture_output=True, timeout=20, check=False)
        require(restored.returncode == 0 and restored.stdout == APPENDED,
                f"trusted current-generation restore failed: rc={restored.returncode}, stdout={restored.stdout!r}")
        require('"outcome": "ACCEPT"' in restored.stderr,
                "trusted current-generation restore lacked ACCEPT assessment")
        events.append({"label": "restore-trusted-current-generation-recovers",
                       "command": restore_command, "returncode": restored.returncode,
                       "stdout": restored.stdout, "stderr": restored.stderr,
                       "stdout_sha256": hashlib.sha256(restored.stdout.encode()).hexdigest(),
                       "stderr_sha256": hashlib.sha256(restored.stderr.encode()).hexdigest()})
        data_only_root = root / "data-only-restore"
        data_only, missing_db = _copy_pair(journey.data, journey.trust, data_only_root, include_trust=False)
        command = [sys.executable, "-m", "continuity_receipt.memory_resume", "resume",
                   "--data-root", str(data_only), "--trust-db", str(missing_db),
                   "--context", CONTEXT, "--scope", SCOPE, "--public-key", str(journey.public),
                   "--profile", str(journey.profile), "--memory-path", "memory/resume.txt"]
        env, _ = _child_env(root / "data-only.journal")
        proc = subprocess.run(command, cwd=CPR_ROOT, env=env, text=True, capture_output=True,
                              timeout=20, check=False)
        events.append({"label": "restore-data-without-trust-releases-no-output", "command": command,
                       "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr,
                       "stdout_sha256": hashlib.sha256(proc.stdout.encode()).hexdigest(),
                       "stderr_sha256": hashlib.sha256(proc.stderr.encode()).hexdigest()})
        require(proc.returncode in (1, 2) and proc.stdout == "",
                "data-only restore emitted memory")

        # Restore the full trusted checkpoint into two separate disposable copies.
        events.append(_assert_rejected(root, trusted_backup_data, trusted_backup_db, journey.public,
                                       label="restore-corrupt-payload-releases-no-output",
                                       generation_id=current["generation_id"],
                                       path="memory/resume.txt", tamper="payload"))
        events.append(_assert_rejected(root, trusted_backup_data, trusted_backup_db, journey.public,
                                       label="restore-different-checkpoint-releases-no-output",
                                       generation_id=current["generation_id"],
                                       path="memory/resume.txt", tamper="checkpoint"))

        erased = journey.publish("erase-one-file-by-cas", {
            "memory/resume.txt": APPENDED, "memory/retained.txt": "Retained control note.\n",
        }, current["checkpoint_digest"])
        journey.resume("erased-selected-path-releases-no-output", "memory/erased.txt", None,
                       accepted=False)
        journey.resume("current-selected-path-still-recovers", "memory/resume.txt", APPENDED,
                       accepted=True)

        # Keep the post-erasure reference while restoring pre-erasure data.
        # The opposite control restores both data and trust and demonstrates
        # the explicitly excluded joint-rollback attacker.
        for label, trust_source, expected_text in (
            ("pre-erasure-data-current-trust-releases-no-output", journey.trust, None),
            ("joint-old-data-and-trust-can-resurrect-erased-text", trusted_backup_db, ERASED),
        ):
            restored_data, restored_trust = _copy_pair(
                trusted_backup_data, trust_source, root / label, include_trust=True)
            command = [sys.executable, "-m", "continuity_receipt.memory_resume", "resume",
                       "--data-root", str(restored_data), "--trust-db", str(restored_trust),
                       "--context", CONTEXT, "--scope", SCOPE, "--public-key", str(journey.public),
                       "--profile", str(journey.profile), "--memory-path", "memory/erased.txt"]
            proc = subprocess.run(command, cwd=CPR_ROOT, env=journey.env, text=True,
                                  capture_output=True, timeout=20, check=False)
            require(proc.returncode == (2 if expected_text is None else 0)
                    and proc.stdout == (expected_text or ""),
                    f"{label}: unexpected release rc={proc.returncode}, stdout={proc.stdout!r}")
            events.append({"label": label, "command": command, "returncode": proc.returncode,
                           "stdout": proc.stdout, "stderr": proc.stderr,
                           "stdout_sha256": hashlib.sha256(proc.stdout.encode()).hexdigest(),
                           "stderr_sha256": hashlib.sha256(proc.stderr.encode()).hexdigest()})

        wm_evidence = {"events": []}
        if wm_binary is not None:
            bundle_digest = json.loads(second["stdout"])["reference"]["bundle_digest"]
            _wm_integration(wm_binary, journey, APPENDED, bundle_digest, wm_evidence)

        optimized_probe_dir = root / "optimized-fail-closed-probe"
        optimized_probe = subprocess.run(
            [sys.executable, "-O", str(Path(__file__).resolve()), "--probe-fail-closed",
             "--output-dir", str(optimized_probe_dir)],
            cwd=CPR_ROOT, env=journey.env, text=True, capture_output=True,
            timeout=10, check=False,
        )
        require(optimized_probe.returncode == 1 and optimized_probe.stdout == "" and
                "intentional fail-closed probe" in optimized_probe.stderr and
                not optimized_probe_dir.exists(),
                "optimized-mode failed gate did not stop before PASS or evidence creation")

        evidence = {
            "schema": "cpr-memory-receiver-journey-evidence-v1",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "fixed_case_time": FIXED_NOW,
            "case": "synthetic-local-receiver-journey",
            "same_operator": True,
            "answers_visible": True,
            "operator_visibility": "Each subprocess stdout/stderr and return code is recorded below; accepted resume stdout is exact fixture text, and every refusal asserts empty stdout.",
            "limitations": ["same local operator controls receiver trust and runner", "synthetic fixture text and disposable state", "not a second-operator or adversarial host qualification", "does not prove semantic truth or completeness of captured memory", "joint rollback of trust DB and data can resurrect erased text; this expected control is recorded"],
            "key_material": "fixture PEM files existed only in the temporary root and were not copied into this packet",
            "optimized_mode_negative_probe": {
                "command": [sys.executable, "-O", str(Path(__file__).resolve()),
                            "--probe-fail-closed", "--output-dir", "<temporary probe path>"],
                "returncode": optimized_probe.returncode,
                "stdout": optimized_probe.stdout,
                "stderr": optimized_probe.stderr,
                "output_directory_created": optimized_probe_dir.exists(),
            },
            "events": events,
            "wm_events": wm_evidence["events"],
            **{key: value for key, value in wm_evidence.items() if key != "events"},
            "references": {"initial_checkpoint_digest": initial["checkpoint_digest"],
                           "appended_checkpoint_digest": current["checkpoint_digest"],
                           "erase_checkpoint_digest": json.loads(erased["stdout"])["reference"]["checkpoint_digest"]},
        }
        # Include accepted CLI events already accumulated, omitting paths that point at the temporary key files.
        for event in journey.events:
            event["command"] = ["<fixture-key-path>" if part in (str(journey.private), str(journey.public)) else part
                                 for part in event["command"]]
            evidence["events"].append(event)
        return evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=CPR_ROOT.parent / "evidence" / "journey-luna")
    parser.add_argument("--wm-binary", type=Path, help="optional local WhiteMagic wm-core executable")
    parser.add_argument("--probe-fail-closed", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if args.probe_fail_closed:
            require(False, "intentional fail-closed probe")
        evidence = run_journey(args.output_dir, args.wm_binary)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "journey.json").write_text(
            json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps({"outcome": "PASS", "evidence": str(args.output_dir / "journey.json"),
                          "events": len(evidence["events"]),
                          "wm_integration": args.wm_binary is not None}, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"outcome": "FAIL", "reason": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
