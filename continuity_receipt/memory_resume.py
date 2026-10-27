"""Local operator CLI for the experimental checkpointed memory receiver."""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .memory_snapshot import MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, MAX_DIRECTORY_DEPTH, MAX_TREE_ENTRIES, _path
from .records import utc_now_rfc3339


def _no_follow() -> int:
    return getattr(os, "O_NOFOLLOW", 0)


def _read_regular_at(dir_fd: int, name: str, limit: int) -> bytes:
    fd = os.open(name, os.O_RDONLY | _no_follow() | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=dir_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("input_not_bounded_regular_file")
        chunks = []
        total = 0
        while True:
            part = os.read(fd, min(65536, limit + 1 - total))
            if not part:
                break
            chunks.append(part)
            total += len(part)
            if total > limit:
                raise ValueError("input_file_too_large")
        if len(chunks) == 0:
            return b""
        return b"".join(chunks)
    finally:
        os.close(fd)


def capture_input_tree(root: str | os.PathLike[str]) -> dict[str, bytes]:
    """Read a closed tree of regular files using component-relative no-follow opens."""
    absolute = os.path.abspath(os.path.expanduser(os.fspath(root)))
    root_fd = os.open(os.path.sep, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    result: dict[str, bytes] = {}
    total = 0
    entries_seen = 0
    try:
        for part in Path(absolute).parts[1:]:
            child = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _no_follow() | getattr(os, "O_CLOEXEC", 0), dir_fd=root_fd)
            os.close(root_fd)
            root_fd = child
        if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
            raise ValueError("input_root_not_directory")

        def walk(fd: int, prefix: str = "", depth: int = 0) -> None:
            nonlocal total, entries_seen
            if depth > MAX_DIRECTORY_DEPTH:
                raise ValueError("input_tree_depth_exceeded")
            with os.scandir(fd) as children:
                for child in children:
                    name = child.name
                    entries_seen += 1
                    if entries_seen > MAX_TREE_ENTRIES:
                        raise ValueError("input_tree_entries_exceeded")
                    rel = _path(f"{prefix}/{name}" if prefix else name)
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        child_fd = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _no_follow() | getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
                        try:
                            if not stat.S_ISDIR(os.fstat(child_fd).st_mode):
                                raise ValueError("input_directory_changed")
                            walk(child_fd, rel, depth + 1)
                        finally:
                            os.close(child_fd)
                    elif stat.S_ISREG(info.st_mode):
                        if rel in result or len(result) >= MAX_FILES:
                            raise ValueError("snapshot_file_count_invalid")
                        data = _read_regular_at(fd, name, MAX_FILE_BYTES)
                        total += len(data)
                        if total > MAX_TOTAL_BYTES:
                            raise ValueError("snapshot_total_too_large")
                        result[rel] = data
                    else:
                        raise ValueError("input_special_file_or_symlink")

        walk(root_fd)
    finally:
        os.close(root_fd)
    return result


def _load_public(path: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public_key_must_be_ed25519")
    return key


def _load_private(path: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("private_key_must_be_ed25519")
    return key


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cpr-memory", description="Local experimental checkpointed memory snapshot receiver")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "publish", "recall", "resume", "status"):
        command = sub.add_parser(name)
        command.add_argument("--data-root", required=True)
        command.add_argument("--trust-db", required=True)
        command.add_argument("--context", required=True)
        command.add_argument("--scope", required=True)
        command.add_argument("--public-key", required=True, help="PEM Ed25519 receiver/writer trust anchor")
        command.add_argument("--profile", help="select and pin a versioned adopter receiving-policy JSON")
        command.add_argument("--max-age", type=int, default=3600)
        command.add_argument("--now", default=None, help="trusted operator test-time override; can backdate freshness (default: current UTC)")
        if name == "publish":
            command.add_argument("--key-pem", required=True, help="PEM Ed25519 private signing key")
            command.add_argument("--expected-reference", required=True, help="none for first publish, otherwise current checkpoint digest")
            command.add_argument("--input-root", required=True, help="closed tree of regular files to snapshot")
        if name == "resume":
            command.add_argument("--memory-path", required=True, help="relative file path to emit after full acceptance")
    return parser


def _store(args):
    # Keep snapshot-focused imports independent of SQLite/storage integration.
    from .receiver_store import ReceiverStore
    from . import strict_json
    profile = None
    if args.profile:
        raw = Path(args.profile).read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            raise ValueError("receiver_profile_invalid_json")
        profile = strict_json.loads(raw.decode("utf-8"))
    return ReceiverStore(
        args.data_root, args.trust_db, context=args.context, scope=args.scope,
        trusted_public_key=_load_public(args.public_key), max_age_seconds=args.max_age,
        receiver_profile=profile,
    )


def _json(value) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _outcome_code(value: str) -> int:
    return 0 if value == "ACCEPT" else 1 if value == "NEEDS_EVIDENCE" else 2


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.now is not None and args.profile:
        _json({"outcome": "REJECT", "reason_codes": ["receiver_profile_clock_override_forbidden"]})
        return 2
    now = args.now or utc_now_rfc3339()
    try:
        store = _store(args)
        if args.command == "init":
            result = store.initialize()
            _json(result if isinstance(result, dict) else {"outcome": "ACCEPT", "result": str(result)})
            return _outcome_code(result.get("outcome", "ACCEPT") if isinstance(result, dict) else "ACCEPT")
        if args.command == "status":
            reference = store.current_reference()
            if reference is None:
                _json({"outcome": "NEEDS_EVIDENCE", "reason_codes": ["accepted_reference_missing"], "reference": None})
                return 1
            result = {"outcome": "ACCEPT", "reference": reference}
            if store.receiver_profile is not None:
                result["receiver_profile"] = {"id": store.receiver_profile["id"],
                                        "digest": store.receiver_profile["digest"],
                                        "inventory": list(store.receiver_profile["inventory"])}
            _json(result)
            return 0
        if args.command == "publish":
            files = capture_input_tree(args.input_root)
            expected = None if args.expected_reference == "none" else args.expected_reference
            result = store.publish(files, private_key=_load_private(args.key_pem),
                                   expected_checkpoint_digest=expected, now=now)
            _json(result)
            return _outcome_code(result.get("outcome", "REJECT"))
        if args.command in ("recall", "resume"):
            if args.command == "resume" and store.receiver_profile is not None and args.memory_path not in store.receiver_profile["memory_paths"]:
                raise ValueError("receiver_profile_memory_path_mismatch")
            def resume_sink(files):
                rel = _path(args.memory_path)
                selected = files.get(rel)
                if selected is None:
                    raise ValueError("memory_path_missing")
                try:
                    text = selected.decode("utf-8", errors="strict")
                except UnicodeDecodeError as exc:
                    raise ValueError("memory_text_invalid_utf8") from exc
                # Release while the receiver still holds its publication-excluding read transaction.
                sys.stdout.write(text)
                sys.stdout.flush()

            result = store.recall(now=now, sink=resume_sink if args.command == "resume" else None)
            outcome = result.get("outcome", "REJECT")
            files = result.get("files") if outcome == "ACCEPT" else None
            if args.command == "resume":
                print(json.dumps({k: v for k, v in result.items() if k != "files"}, ensure_ascii=False, sort_keys=True), file=sys.stderr)
            else:
                if outcome == "ACCEPT" and isinstance(files, dict):
                    result = {**result, "files": [{"path": path, "size": len(data), "sha256": "sha256:" + __import__("hashlib").sha256(data).hexdigest()} for path, data in sorted(files.items())]}
                _json(result)
            return _outcome_code(outcome)
    except Exception as exc:
        payload = {"outcome": "REJECT", "reason_codes": [getattr(exc, "reason", None) or str(exc) or type(exc).__name__]}
        if args.command == "resume":
            print(json.dumps(payload, sort_keys=True), file=sys.stderr)
        else:
            _json(payload)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
