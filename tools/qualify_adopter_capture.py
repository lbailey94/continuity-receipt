#!/usr/bin/env python3
"""Offline assessor for a real adopter's Continuity Receipt 0.5 capture.

This reports artifact and verifier agreement only. It cannot establish who
administered the host or whether a sandbox actually enforced restrictions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


def strict_load(path: Path):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError(f"duplicate JSON member: {key}")
            out[key] = value
        return out

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"invalid constant {value}")))


def canonical(value) -> bytes:
    # The profile is intentionally ASCII-keyed JSON and forbids floats.
    def check(node):
        if isinstance(node, float):
            raise ValueError("floats are not allowed")
        if isinstance(node, dict):
            if any(not isinstance(k, str) for k in node):
                raise ValueError("object keys must be strings")
            for child in node.values(): check(child)
        elif isinstance(node, list):
            for child in node: check(child)
    check(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def snapshot_commitment(state):
    """file-snapshot-v1: {files:[{path,size,sha256}...]}, sorted unique paths."""
    if not isinstance(state, dict) or set(state) != {"files"} or not isinstance(state["files"], list):
        raise ValueError("state must be exactly an object with a files array")
    entries, seen = [], set()
    for item in state["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
            raise ValueError("each file entry must contain exactly path, size, sha256")
        path, size, digest = item["path"], item["size"], item["sha256"]
        if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path or any(p in ("", ".", "..") for p in path.split("/")):
            raise ValueError("file paths must be unique normalized relative POSIX paths")
        if path in seen: raise ValueError("duplicate file path")
        seen.add(path)
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ValueError("file size must be a nonnegative integer")
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("sha256 must be lowercase sha256:<64 hex>")
        entries.append({"path": path, "size": size, "sha256": digest})
    if [e["path"] for e in entries] != sorted(seen):
        raise ValueError("file entries must be sorted by path")
    return len(entries), "sha256:" + hashlib.sha256(canonical({"files": entries})).hexdigest()


REPO_ROOT = Path(__file__).resolve().parent.parent


def run_verifier(argv, bundle):
    result = {"command": argv, "exit_code": None, "verdict": None, "error_codes": [], "error": None}
    try:
        proc = subprocess.run([*argv, str(bundle)], capture_output=True, text=True,
                              timeout=120, check=False, cwd=REPO_ROOT)
        result["exit_code"] = proc.returncode
        try:
            payload = json.loads(proc.stdout)
            result["verdict"] = payload.get("verdict")
            result["error_codes"] = sorted(e.get("code", "") for e in payload.get("errors", []) if isinstance(e, dict))
            if not isinstance(result["verdict"], str): raise ValueError("missing verdict")
        except (ValueError, AttributeError, TypeError) as exc:
            result["error"] = f"invalid verifier JSON output: {exc}; stderr={proc.stderr[-1000:]}"
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["error"] = str(exc)
    return result


def command_digest(argv):
    candidate = Path(argv[0])
    if not candidate.is_absolute():
        candidate = REPO_ROOT / candidate
    executable = str(candidate) if candidate.is_file() else shutil.which(argv[0])
    if not executable:
        raise ValueError(f"verifier executable not found: {argv[0]}")
    return "sha256:" + hashlib.sha256(Path(executable).read_bytes()).hexdigest()


def verify_source_pin(expected):
    """Require the verifier source tree used by Python and Rust to be at HEAD and clean."""
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    verifier_paths = ["continuity_receipt/verify.py", "continuity_receipt/verification.py",
                      "continuity_receipt/strict_json.py", "continuity_receipt/records.py",
                      "continuity_receipt/keys.py", "continuity_receipt/agreements.py",
                      "continuity_receipt/bundle.py", "continuity_receipt/canon.py",
                      "continuity_receipt/revocations.py", "rust/src", "rust/Cargo.toml",
                      "rust/Cargo.lock"]
    diff = subprocess.run(["git", "diff", "--quiet", "HEAD", "--", *verifier_paths],
                          cwd=REPO_ROOT, check=False)
    untracked = subprocess.run(["git", "ls-files", "--others", "--exclude-standard", "--",
                                "rust/src"], cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    actual = head.stdout.strip() if head.returncode == 0 else None
    clean = diff.returncode == 0 and untracked.returncode == 0 and not untracked.stdout.strip()
    return {"expected": expected, "measured_head": actual,
            "verifier_source_tree_clean": clean,
            "verified": actual == expected and clean}


def verify_snapshot_files(state, artifact_root):
    """Hash every file named by the profile, resolving symlinks under the root."""
    results, missing = [], []
    root = artifact_root.resolve(strict=True)
    for entry in state["files"]:
        relative = Path(*entry["path"].split("/"))
        lexical = root / relative
        try:
            actual = lexical.resolve(strict=True)
        except FileNotFoundError:
            missing.append(entry["path"])
            results.append({"path": entry["path"], "available": False})
            continue
        try:
            actual.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"snapshot path escapes artifact root through symlink: {entry['path']}") from exc
        if not actual.is_file():
            raise ValueError(f"snapshot path is not a regular file: {entry['path']}")
        content = actual.read_bytes()
        observed_size = len(content)
        observed_hash = "sha256:" + hashlib.sha256(content).hexdigest()
        matches = observed_size == entry["size"] and observed_hash == entry["sha256"]
        results.append({"path": entry["path"], "available": True, "size": observed_size,
                        "sha256": observed_hash, "match": matches})
        if not matches:
            raise ValueError(f"captured artifact size or digest mismatch: {entry['path']}")
    return {"root": str(root), "files": results, "missing": missing,
            "all_match": not missing and all(item.get("match", False) for item in results)}


def assess(bundle_path, state_path, metadata_path, artifact_root, python_cmd, rust_cmd):
    report = {"format": "continuity-receipt-other-host-assessment/1", "status": "INCOMPLETE",
              "evidence_class": "candidate only until a real independent-host capture is reviewed",
              "checks": {}, "caveats": ["Does not prove independent administration, sandbox enforcement, or live-network safety.",
              "The packet is specifically for a 0.5 capture with a file-snapshot-v1 state.commitment; this local assessment does not establish that a producer or independent host emitted it. Existing same-host evidence is not independent qualification."]}
    required = (bundle_path, state_path, metadata_path, artifact_root, python_cmd, rust_cmd)
    if any(x is None for x in required):
        report["checks"]["inputs"] = "missing required input; supply bundle, referenced state, metadata, artifact root, and both verifier commands"
        return report
    try:
        bundle_path, state_path, metadata_path = (Path(p).resolve(strict=True)
                                                   for p in (bundle_path, state_path, metadata_path))
        artifact_root = Path(artifact_root).resolve(strict=True)
        if not artifact_root.is_dir():
            raise ValueError("artifact root must be an existing directory")
        raw_bundle = bundle_path.read_bytes()
        bundle_hash = "sha256:" + hashlib.sha256(raw_bundle).hexdigest()
        bundle = strict_load(bundle_path)
        state = strict_load(state_path)
        meta = strict_load(metadata_path)
        required_meta = {"command", "pins", "host", "operator", "captured_bundle_sha256"}
        if not isinstance(meta, dict) or not required_meta <= set(meta): raise ValueError("metadata must include command, pins, host, operator, captured_bundle_sha256")
        if not all(isinstance(meta[k], str) and meta[k].strip() for k in ("command", "host", "operator")): raise ValueError("command, host, and operator must be nonempty strings")
        if meta["captured_bundle_sha256"] != bundle_hash:
            raise ValueError("captured_bundle_sha256 does not match raw bundle bytes")
        pins = meta["pins"]
        if not isinstance(pins, dict) or not all(isinstance(pins.get(k), str) and pins[k] for k in ("source_commit", "python_verifier_sha256", "rust_verifier_sha256")):
            raise ValueError("pins must include source_commit and both verifier SHA-256 pins")
        if not re.fullmatch(r"[0-9a-f]{40,64}", pins["source_commit"]):
            raise ValueError("source_commit must be a full lowercase Git object id")
        for key in ("python_verifier_sha256", "rust_verifier_sha256"):
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", pins[key]):
                raise ValueError(f"{key} must be sha256:<lowercase hex>")
        actual_python = command_digest(python_cmd)
        actual_rust = command_digest(rust_cmd)
        if actual_python != pins["python_verifier_sha256"] or actual_rust != pins["rust_verifier_sha256"]:
            raise ValueError("verifier executable hash does not match recorded pin")
        source_pin = verify_source_pin(pins["source_commit"])
        report["checks"]["source_pin"] = source_pin
        if not source_pin["verified"]:
            raise ValueError("source_commit does not match a clean verifier source checkout")
        if not isinstance(bundle, dict) or bundle.get("spec") != "continuity-receipt/0.5": raise ValueError("bundle is not spec continuity-receipt/0.5")
        receipts = bundle.get("receipts")
        if not isinstance(receipts, list): raise ValueError("bundle receipts must be an array")
        commitments = [r.get("body") for r in receipts if isinstance(r, dict) and r.get("type") == "state.commitment"]
        if len(commitments) != 1: raise ValueError("bundle must contain exactly one state.commitment")
        commitment = commitments[0]
        if commitment.get("state_kind") != "file-snapshot-v1": raise ValueError("state_kind must explicitly be file-snapshot-v1")
        count, head = snapshot_commitment(state)
        actual_files = verify_snapshot_files(state, artifact_root)
        report["checks"]["snapshot_files"] = actual_files
        if actual_files["missing"]:
            report["status"] = "INCOMPLETE"
            report["checks"]["input_validation"] = "one or more referenced files are unavailable beneath artifact root"
            return report
        report["bundle"] = {"path": str(bundle_path), "bytes": len(raw_bundle), "sha256": bundle_hash}
        report["producer"] = {k: meta[k] for k in ("command", "pins", "host", "operator")}
        report["checks"]["state_commitment"] = {"profile": "file-snapshot-v1", "computed_count": count,
            "claimed_count": commitment.get("count"), "computed_head_digest": head,
            "claimed_head_digest": commitment.get("head_digest"), "match": count == commitment.get("count") and head == commitment.get("head_digest")}
        report["verifiers"] = {"python": run_verifier(python_cmd, bundle_path), "rust": run_verifier(rust_cmd, bundle_path)}
        report["checks"]["verifier_agreement"] = report["verifiers"]["python"]["verdict"] == report["verifiers"]["rust"]["verdict"] and report["verifiers"]["python"]["error_codes"] == report["verifiers"]["rust"]["error_codes"]
        report["checks"]["bundle_unchanged"] = hashlib.sha256(bundle_path.read_bytes()).hexdigest() == bundle_hash[7:]
        p, r = report["verifiers"]["python"], report["verifiers"]["rust"]
        passed = report["checks"]["state_commitment"]["match"] and report["checks"]["verifier_agreement"] and report["checks"]["bundle_unchanged"] and all(v["verdict"] == "TRUSTED" and v["exit_code"] == 0 and v["error"] is None for v in (p, r))
        report["status"] = "PASS" if passed else "FAIL"
        if not passed: report["caveats"].append("A FAIL indicates artifact/profile mismatch, non-TRUSTED verifier result, or verifier disagreement; inspect the recorded details.")
    except FileNotFoundError as exc:
        report["status"] = "INCOMPLETE"
        report["checks"]["input_validation"] = str(exc)
    except RecursionError:
        report["status"] = "FAIL"
        report["checks"]["input_validation"] = "input_nesting_too_deep"
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        report["status"] = "FAIL"
        report["checks"]["input_validation"] = str(exc)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle")
    parser.add_argument("--state")
    parser.add_argument("--metadata")
    parser.add_argument("--artifact-root", help="directory containing the separately captured files listed in the state snapshot")
    parser.add_argument("--python-verifier-command", help="quoted command string, split into argv and executed without a shell")
    parser.add_argument("--rust-verifier-command", help="quoted command string, split into argv and executed without a shell")
    parser.add_argument("--output", default="-")
    args = parser.parse_args(argv)
    try:
        python_cmd = shlex.split(args.python_verifier_command) if args.python_verifier_command else None
        rust_cmd = shlex.split(args.rust_verifier_command) if args.rust_verifier_command else None
    except ValueError as exc:
        report = {"format": "continuity-receipt-other-host-assessment/1", "status": "FAIL",
                  "checks": {"command_parsing": str(exc)}, "caveats": ["Verifier commands are parsed as argv and are never run through a shell."]}
    else:
        report = assess(args.bundle, args.state, args.metadata, args.artifact_root, python_cmd, rust_cmd)
    output = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output == "-": print(output, end="")
    else: Path(args.output).write_text(output, encoding="utf-8")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
