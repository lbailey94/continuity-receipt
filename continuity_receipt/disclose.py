"""Selective disclosure tooling for Continuity Receipt bundles (P1).

Redact optional fields with salted commitments, keep the salt+value map
separate, and merge a map back into a bundle for verification. Path grammar
matches the verifier: `receipts[i].body.<field>[.<nested>...]`.

CLI:
  python3 -m continuity_receipt.disclose redact --bundle b.json \
      --path receipts[3].body.spec_ref --out redacted.json --map map.json
  python3 -m continuity_receipt.disclose verify --bundle redacted.json [--map map.json]
  python3 -m continuity_receipt.disclose reveal --bundle redacted.json \
      --map map.json --path receipts[3].body.spec_ref --out package.json
"""
import argparse
import copy
import json
import os
import re
import sys
from pathlib import Path

from . import records
from .bundle import receipt_digest
from .canon import commit_field
from .verify import _required_field_for_path, verify_bundle

_INDEX = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\[(\d+)\]$")


def _tokens(path: str) -> list:
    tokens = path.split(".")
    if not tokens or any(not token for token in tokens):
        raise ValueError(f"malformed path: {path!r}")
    return tokens


def _descend(node, token: str):
    match = _INDEX.match(token)
    if match:
        return node[match.group(1)][int(match.group(2))]
    return node[token]


def _walk(node, path: str):
    for token in _tokens(path):
        node = _descend(node, token)
    return node


def _walk_parent(node, path: str):
    tokens = _tokens(path)
    for token in tokens[:-1]:
        node = _descend(node, token)
    return node, tokens[-1]


def _set(node, path: str, value) -> None:
    parent, key = _walk_parent(node, path)
    match = _INDEX.match(key)
    if match:
        parent[match.group(1)][int(match.group(2))] = value
    else:
        parent[key] = value


def _receipts(bundle: dict) -> list:
    receipts = bundle.get("receipts")
    if not isinstance(receipts, list):
        raise ValueError("bundle has no receipts list")
    return receipts


def _receipt_index(path: str) -> int:
    tokens = _tokens(path)
    match = _INDEX.match(tokens[0])
    if not match or match.group(1) != "receipts":
        raise ValueError(f"path must start with receipts[i]: {path!r}")
    return int(match.group(2))


def _resign_tail(bundle: dict, start: int, signer) -> None:
    """Rebuild `prev` links and signatures from `start` to the end of the chain."""
    receipts = _receipts(bundle)
    key, did = signer
    prev = receipt_digest(receipts[start - 1]) if start > 0 else None
    for index in range(start, len(receipts)):
        receipt = receipts[index]
        issuer = receipt.get("issuer", {}).get("id")
        if issuer != did:
            raise ValueError(f"receipt {index} issuer {issuer!r} != signer {did!r}; cannot re-sign")
        receipt["seq"] = index
        receipt["prev"] = prev
        receipt.pop("sig", None)
        receipts[index] = records.sign_receipt(receipt, key, did)
        prev = receipt_digest(receipts[index])


def redact(bundle: dict, paths: list, salts: dict | None = None, signer=None):
    """Replace each optional field with a commitment; return (redacted, map).

    Redaction is an issuance-time act: the modified receipts (and everything
    after them) are re-signed with `signer=(private_key, did)`, matching the
    test-vector model (vectors 07/08).
    """
    redacted = copy.deepcopy(bundle)
    receipts = _receipts(redacted)
    disclosure = {}
    modified = set()
    for path in paths:
        if _required_field_for_path(path, receipts) is not None:
            raise ValueError(f"required field cannot be redacted: {path}")
        try:
            value = _walk(redacted, path)
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError(f"path not found: {path}") from exc
        salt = (salts or {}).get(path) or os.urandom(16).hex()
        _set(redacted, path, {"redacted": True, "commit": commit_field(salt, value)})
        disclosure[path] = {"salt": salt, "value": value}
        modified.add(_receipt_index(path))
    if modified:
        if signer is None:
            raise ValueError("redaction rewrites signed receipts; pass signer=(private_key, did)")
        _resign_tail(redacted, min(modified), signer)
    return redacted, disclosure


def attach(bundle: dict, disclosure: dict) -> dict:
    attached = copy.deepcopy(bundle)
    merged = dict(attached.get("disclosure_map") or {})
    merged.update(disclosure)
    attached["disclosure_map"] = merged
    return attached


def reveal(redacted: dict, disclosure: dict, paths: list) -> dict:
    """Build a package disclosing only the requested paths from a full map."""
    missing = [path for path in paths if path not in disclosure]
    if missing:
        raise ValueError(f"paths not in disclosure map: {missing}")
    return attach(redacted, {path: disclosure[path] for path in paths})


def _load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _dump(payload, path: str | None) -> None:
    text = json.dumps(payload, indent=2, sort_keys=False)
    if path:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    else:
        print(text)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="continuity-receipt-disclose")
    sub = parser.add_subparsers(dest="cmd", required=True)

    redact_cmd = sub.add_parser("redact")
    redact_cmd.add_argument("--bundle", required=True)
    redact_cmd.add_argument("--path", action="append", required=True)
    redact_cmd.add_argument("--out", required=True)
    redact_cmd.add_argument("--map", required=True)
    redact_cmd.add_argument("--gate-key", required=True, help="issuer private key file to re-sign the redacted tail")

    verify_cmd = sub.add_parser("verify")
    verify_cmd.add_argument("--bundle", required=True)
    verify_cmd.add_argument("--map", default=None, help="attach this disclosure map before verifying")
    verify_cmd.add_argument("--require-anchor", action="store_true")
    verify_cmd.add_argument(
        "--revocations",
        action="append",
        default=None,
        metavar="PATH|URL",
        help="external revocation list (repeatable; REVOCATION_DISTRIBUTION.md)",
    )

    reveal_cmd = sub.add_parser("reveal")
    reveal_cmd.add_argument("--bundle", required=True)
    reveal_cmd.add_argument("--map", required=True)
    reveal_cmd.add_argument("--path", action="append", required=True)
    reveal_cmd.add_argument("--out", required=True)

    check_cmd = sub.add_parser("check")
    check_cmd.add_argument("--salt", required=True)
    check_cmd.add_argument("--value", required=True, help="JSON value")
    check_cmd.add_argument("--commit", required=True)

    args = parser.parse_args(argv)

    if args.cmd == "redact":
        from . import keys

        key = keys.private_from_raw(Path(args.gate_key).read_bytes())
        signer = (key, keys.pubkey_to_did_key(key.public_key()))
        redacted, disclosure = redact(_load(args.bundle), args.path, signer=signer)
        _dump(redacted, args.out)
        _dump(disclosure, args.map)
        return 0
    if args.cmd == "verify":
        from . import revocations

        external = None
        if args.revocations:
            try:
                external = revocations.merge_statements(
                    *[revocations.load_statements(src) for src in args.revocations]
                )
            except revocations.RevocationError as exc:
                _dump(
                    {
                        "verdict": "INSUFFICIENT_EVIDENCE",
                        "errors": [{"code": exc.code, "detail": exc.detail}],
                    },
                    None,
                )
                return 1
        bundle = _load(args.bundle)
        if args.map:
            bundle = attach(bundle, _load(args.map))
        result = verify_bundle(
            bundle,
            require_anchor=args.require_anchor,
            external_revocations=external,
        )
        _dump(result.as_dict(), None)
        return 0 if result.verdict == "TRUSTED" else 1
    if args.cmd == "reveal":
        bundle = _load(args.bundle)
        package = reveal(bundle, _load(args.map), args.path)
        _dump(package, args.out)
        return 0
    if args.cmd == "check":
        value = json.loads(args.value)
        expected = commit_field(args.salt, value)
        ok = expected == args.commit
        _dump({"match": ok, "expected": expected, "commit": args.commit}, None)
        return 0 if ok else 1
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    sys.exit(main())
