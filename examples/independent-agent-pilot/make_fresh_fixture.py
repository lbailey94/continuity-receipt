#!/usr/bin/env python3
"""Create a synthetic, newly signed 0.4 acceptance fixture for local testing."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("make_vectors", ROOT / "tools" / "make_vectors.py")
vectors = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vectors)


def sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def generate() -> tuple[bytes, bytes]:
    issued_at = vectors.records.utc_now_rfc3339()
    chain = vectors.chain(vectors.SPEC_04)
    session = vectors.pass_body(spend_cap={"minor": 1000, "currency": "USD"})
    session["expires_at"] = "2030-01-01T00:00:00Z"
    chain.add("session.pass.created", "gate", vectors.GATE_DID, vectors.GATE_KEY,
              session, issued_at=issued_at)
    offer_body = vectors.offer_body(valid_until="2030-01-01T00:00:00Z")
    offer = chain.add("agreement.offer", "gate", vectors.GATE_DID, vectors.GATE_KEY,
                      offer_body, issued_at=issued_at)
    accept = chain.add("agreement.accept", "agent", vectors.COUNTERPARTY_DID,
                       vectors.COUNTERPARTY_KEY,
                       vectors.accept_body_04(vectors.receipt_digest(offer)), issued_at=issued_at)
    accept_ref = vectors.receipt_digest(accept)
    chain.add("task.decision", "agent", vectors.COUNTERPARTY_DID,
              vectors.COUNTERPARTY_KEY,
              vectors.bound(vectors.decision_body(), accept_ref), issued_at=issued_at)
    chain.add("task.execution", "agent", vectors.COUNTERPARTY_DID,
              vectors.COUNTERPARTY_KEY,
              vectors.bound(vectors.execution_body(), accept_ref), issued_at=issued_at)
    chain.add("task.termination", "agent", vectors.COUNTERPARTY_DID,
              vectors.COUNTERPARTY_KEY, vectors.termination_body(), issued_at=issued_at)
    bundle = chain.bundle()
    policy = {
        "id": "synthetic-fresh-0.4-independent-agent-v1",
        "accepted_specs": ["continuity-receipt/0.4"],
        "trusted_issuers": sorted([vectors.GATE_DID, vectors.COUNTERPARTY_DID]),
        "required_record_types": ["agreement.offer", "agreement.accept"],
    }
    return (
        (json.dumps(bundle, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        (json.dumps(policy, sort_keys=True, indent=2) + "\n").encode(),
    )


def write_new(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="existing owner-only directory; files will not be overwritten")
    args = parser.parse_args()
    output_dir = args.output_dir.expanduser().absolute()
    if output_dir.is_symlink() or not output_dir.is_dir():
        parser.error("--output-dir must be an existing plain directory")
    if stat.S_IMODE(output_dir.stat().st_mode) & 0o077:
        parser.error("--output-dir permissions must be owner-only (for example chmod 700)")
    bundle, policy = generate()
    bundle_path, policy_path = output_dir / "bundle.json", output_dir / "policy.json"
    if bundle_path.exists() or policy_path.exists() or bundle_path.is_symlink() or policy_path.is_symlink():
        parser.error("bundle.json or policy.json already exists; refusing to overwrite")
    try:
        write_new(bundle_path, bundle)
        write_new(policy_path, policy)
    except OSError as exc:
        print(json.dumps({"status": "GENERATION_FAILED", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps({
        "status": "SYNTHETIC_FIXTURE_CREATED",
        "bundle": str(bundle_path), "bundle_bytes": len(bundle), "bundle_sha256": sha256(bundle),
        "policy": str(policy_path), "policy_bytes": len(policy), "policy_sha256": sha256(policy),
        "scope": "synthetic deterministic test keys; never use as real identity or authority",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
