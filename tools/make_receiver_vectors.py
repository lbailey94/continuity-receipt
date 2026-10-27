#!/usr/bin/env python3
"""Generate only the experimental Python receiver file-snapshot vectors."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from continuity_receipt.memory_snapshot import build_manifest  # noqa: E402

CASES = (
    {
        "id": "canonical-sorted-utf8-paths",
        "files": [{"path": "z.txt", "bytes_hex": "7a0a"},
                  {"path": "é/note.txt", "bytes_hex": "636166c3a90a"},
                  {"path": "a.txt", "bytes_hex": "610a"}],
        "expected_outcome": "ACCEPT",
    },
    {
        "id": "duplicate-nfc-normalized-path",
        "files": [{"path": "é.txt", "bytes_hex": "31"},
                  {"path": "e\u0301.txt", "bytes_hex": "32"}],
        "expected_outcome": "REJECT",
        "expected_reason": "snapshot_duplicate_path",
    },
    {
        "id": "parent-traversal-refused",
        "files": [{"path": "../outside.txt", "bytes_hex": "78"}],
        "expected_outcome": "REJECT",
        "expected_reason": "snapshot_path_invalid",
    },
)


def main() -> None:
    vectors = []
    for case in CASES:
        row = dict(case)
        files = {item["path"]: bytes.fromhex(item["bytes_hex"]) for item in case["files"]}
        if case["expected_outcome"] == "ACCEPT":
            manifest = build_manifest(files)
            row["expected_manifest_utf8"] = manifest.decode("utf-8")
            row["expected_manifest_sha256"] = hashlib.sha256(manifest).hexdigest()
        else:
            try:
                build_manifest(files)
            except ValueError as exc:
                if str(exc) != case["expected_reason"]:
                    raise
            else:
                raise RuntimeError(f"{case['id']} unexpectedly accepted")
        vectors.append(row)
    output = ROOT / "vectors" / "receiver-file-snapshot-v1.json"
    output.write_text(json.dumps({
        "suite": "cpr-python-local-file-snapshot-v1",
        "scope": "experimental local receiver implementation; not a CPR wire specification",
        "vectors": vectors,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {output.relative_to(ROOT)} ({len(vectors)} receiver vectors)")


if __name__ == "__main__":
    main()
