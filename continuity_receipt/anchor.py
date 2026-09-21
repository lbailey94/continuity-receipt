"""OpenTimestamps proof verification — 0.3 anchor companion tool.

Scope (ANCHORING.md §5): replay a detached ``.ots`` proof from the file
digest to every attestation, and verify a Bitcoin attestation against an
80-byte block header by exact byte equality with the header's merkle root
(bytes 36..68). Header *chain* validation (proof-of-work, confirmation
depth, reorg handling) is out of scope by design: supply the header from a
source you trust (Bitcoin Core, a header database) and read
``status=verified`` as "this digest is the merkle root of that header",
not "that header is buried under N blocks".

Wire format: python-opentimestamps ``DetachedTimestampFile`` — magic,
uint8 major version, file-hash op tag, digest, then the timestamp tree.
Varints are LEB128 (unsigned little-endian base-128), *not* Bitcoin
CompactSize; the distinction is pinned by tests/test_anchor.py.

Statuses:
  verified   — a Bitcoin attestation's reached digest equals the supplied
               header's merkle root
  unverified — the proof parses and binds to the digest, but reaches only
               pending/unknown attestations, or a Bitcoin attestation
               without a header to check it against
  mismatch   — the proof does not bind to the expected digest, the supplied
               header's merkle root does not match, or the bundle anchor
               entry disagrees
  invalid    — malformed, truncated, or uses an unsupported operation
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from typing import Any

MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
MAJOR_VERSION = 1

MAX_MSG = 4096
MAX_RESULT = 4096
MAX_ATT_PAYLOAD = 8192
MAX_URI = 1000
MAX_NODES = 10000
MAX_DEPTH = 256
MAX_VARUINT_BYTES = 10

HASH_OPS = {
    0x02: ("sha1", 20),
    0x03: ("ripemd160", 20),
    0x08: ("sha256", 32),
}
BINARY_OPS = {0xF0: "append", 0xF1: "prepend"}
UNARY_OPS = {0xF2: "reverse", 0xF3: "hexlify"}
KECCAK_TAG = 0x67

ATT_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
ATT_BITCOIN = bytes.fromhex("0588960d73d71901")
ATT_LITECOIN = bytes.fromhex("06869a0d73d71b45")

HEADER_LEN = 80
MERKLE_OFFSET = 36
TIME_OFFSET = 68


class AnchorError(Exception):
    """Proof-format error; ``code`` is a machine-readable identifier."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise AnchorError("truncated", "proof is truncated")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def read_varuint(self) -> int:
        value = 0
        shift = 0
        for _ in range(MAX_VARUINT_BYTES):
            b = self.read(1)[0]
            value |= (b & 0x7F) << shift
            if not (b & 0x80):
                return value
            shift += 7
        raise AnchorError("invalid_varuint", "varuint exceeds 10 bytes")

    def read_varbytes(self, max_len: int, min_len: int = 0) -> bytes:
        length = self.read_varuint()
        if length > max_len:
            raise AnchorError("invalid_length", f"varbytes length {length} exceeds {max_len}")
        if length < min_len:
            raise AnchorError("invalid_length", f"varbytes length {length} below {min_len}")
        return self.read(length)

    def assert_eof(self) -> None:
        if self.pos != len(self.data):
            raise AnchorError("trailing_data", "unexpected bytes after proof node")


@dataclass(frozen=True)
class Attestation:
    kind: str  # "pending" | "bitcoin" | "litecoin" | "unknown"
    value: Any

    def as_dict(self) -> dict:
        if self.kind == "unknown":
            return {"kind": self.kind, **self.value}
        return {"kind": self.kind, "value": self.value}


@dataclass
class ParsedProof:
    version: int
    file_hash_op: str
    file_digest: bytes
    leaves: list  # list[(reached_digest: bytes, Attestation)]


@dataclass
class AnchorResult:
    status: str
    code: str
    detail: str = ""
    file_digest: str = ""
    attestations: list = field(default_factory=list)
    confirmed: dict | None = None

    @property
    def ok(self) -> bool:
        return self.status == "verified"

    def as_dict(self) -> dict:
        out = {
            "status": self.status,
            "code": self.code,
            "detail": self.detail,
            "file_digest": self.file_digest,
            "attestations": self.attestations,
        }
        if self.confirmed is not None:
            out["confirmed"] = self.confirmed
        return out


def _digest_bytes(value: Any) -> bytes | None:
    """Normalize bytes / hex / ``sha256:<hex>`` into a raw digest."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if ":" in text:
        prefix, _, rest = text.partition(":")
        if prefix != "sha256":
            return None
        text = rest
    if text.startswith("0x"):
        text = text[2:]
    try:
        return bytes.fromhex(text)
    except ValueError:
        return None


def _apply_op(name: str, arg: bytes | None, msg: bytes) -> bytes:
    if len(msg) > MAX_MSG:
        raise AnchorError("message_too_long", f"operation input exceeds {MAX_MSG} bytes")
    if name == "append":
        result = msg + arg
    elif name == "prepend":
        result = arg + msg
    elif name == "reverse":
        result = msg[::-1]
    elif name == "hexlify":
        result = msg.hex().encode()
    else:
        try:
            result = hashlib.new(name, msg).digest()
        except ValueError as exc:  # pragma: no cover - host-dependent
            raise AnchorError("unsupported_op", f"hash {name} unavailable: {exc}") from exc
    if not result or len(result) > MAX_RESULT:
        raise AnchorError("invalid_result", f"{name} produced {len(result)} bytes")
    return result


def _parse_attestation(payload_tag: bytes, payload: bytes) -> Attestation:
    reader = _Reader(payload)
    if payload_tag == ATT_PENDING:
        uri = reader.read_varbytes(MAX_URI)
        reader.assert_eof()
        return Attestation("pending", uri.decode("utf-8", errors="replace"))
    if payload_tag in (ATT_BITCOIN, ATT_LITECOIN):
        height = reader.read_varuint()
        reader.assert_eof()
        return Attestation("bitcoin" if payload_tag == ATT_BITCOIN else "litecoin", height)
    return Attestation("unknown", {"tag": payload_tag.hex(), "payload": payload.hex()})


def _parse_timestamp(
    reader: _Reader, msg: bytes, leaves: list, state: dict, depth: int
) -> None:
    if depth > MAX_DEPTH:
        raise AnchorError("recursion_limit", "timestamp tree exceeds depth limit")
    state["nodes"] += 1
    if state["nodes"] > MAX_NODES:
        raise AnchorError("too_many_nodes", "timestamp tree exceeds node limit")

    def handle(tag: bytes) -> None:
        if tag == b"\x00":
            tag8 = reader.read(8)
            payload = reader.read_varbytes(MAX_ATT_PAYLOAD)
            leaves.append((msg, _parse_attestation(tag8, payload)))
            return
        tag_byte = tag[0]
        if tag_byte == KECCAK_TAG:
            raise AnchorError("unsupported_op", "keccak256 proofs are not supported")
        if tag_byte in HASH_OPS:
            name, _ = HASH_OPS[tag_byte]
            _parse_timestamp(reader, _apply_op(name, None, msg), leaves, state, depth + 1)
            return
        if tag_byte in BINARY_OPS:
            arg = reader.read_varbytes(MAX_RESULT, min_len=1)
            _parse_timestamp(reader, _apply_op(BINARY_OPS[tag_byte], arg, msg), leaves, state, depth + 1)
            return
        if tag_byte in UNARY_OPS:
            _parse_timestamp(reader, _apply_op(UNARY_OPS[tag_byte], None, msg), leaves, state, depth + 1)
            return
        raise AnchorError("unknown_op", f"unknown operation tag 0x{tag_byte:02x}")

    tag = reader.read(1)
    while tag == b"\xff":
        handle(reader.read(1))
        tag = reader.read(1)
    handle(tag)


def parse_detached(data: bytes) -> ParsedProof:
    reader = _Reader(data)
    if reader.read(len(MAGIC)) != MAGIC:
        raise AnchorError("bad_magic", "not an OpenTimestamps detached proof")
    version = reader.read(1)[0]
    if version != MAJOR_VERSION:
        raise AnchorError("unsupported_version", f"major version {version} not supported")
    hash_tag = reader.read(1)[0]
    if hash_tag not in HASH_OPS:
        raise AnchorError("unknown_op", f"unsupported file hash op 0x{hash_tag:02x}")
    file_hash_op, digest_len = HASH_OPS[hash_tag]
    file_digest = reader.read(digest_len)
    leaves: list = []
    _parse_timestamp(reader, file_digest, leaves, {"nodes": 0}, 0)
    reader.assert_eof()
    return ParsedProof(version, file_hash_op, file_digest, leaves)


def verify_proof(
    data: bytes,
    expected_digest: Any,
    block_headers: dict | None = None,
) -> AnchorResult:
    """Verify a detached OTS proof against a digest and optional headers.

    ``block_headers`` maps Bitcoin block height -> 80-byte header. When
    provided, a matching-height Bitcoin attestation is checked by merkle
    root equality; other heights are reported but not verified.
    """
    expected = _digest_bytes(expected_digest)
    if expected is None:
        return AnchorResult("invalid", "bad_digest", "expected digest is not bytes/hex/sha256:<hex>")

    try:
        proof = parse_detached(data)
    except AnchorError as exc:
        return AnchorResult("invalid", exc.code, exc.detail)

    file_digest = f"{proof.file_hash_op}:{proof.file_digest.hex()}"
    if len(expected) != len(proof.file_digest) or expected != proof.file_digest:
        return AnchorResult(
            "mismatch",
            "digest_mismatch",
            "proof was not created for the expected digest",
            file_digest=file_digest,
        )

    headers: dict[int, bytes] = {}
    if block_headers:
        for height, header in block_headers.items():
            if isinstance(header, str):
                header = _digest_bytes(header) or b""
            if not isinstance(header, (bytes, bytearray)) or len(header) != HEADER_LEN:
                return AnchorResult("invalid", "bad_header", f"header for height {height} is not 80 bytes")
            headers[int(height)] = bytes(header)

    attestations = [att.as_dict() for _, att in proof.leaves]
    bitcoins = [(msg, att) for msg, att in proof.leaves if att.kind == "bitcoin"]

    for msg, att in bitcoins:
        header = headers.get(att.value)
        if header is None:
            continue
        if msg == header[MERKLE_OFFSET : MERKLE_OFFSET + 32]:
            confirmed = {
                "block_height": att.value,
                "merkle_root": msg.hex(),
                "header_time": int.from_bytes(header[TIME_OFFSET : TIME_OFFSET + 4], "little"),
            }
            return AnchorResult(
                "verified",
                "anchor_verified",
                f"digest is the merkle root of Bitcoin block {att.value}",
                file_digest=file_digest,
                attestations=attestations,
                confirmed=confirmed,
            )

    if bitcoins and headers:
        heights = ", ".join(str(att.value) for _, att in bitcoins)
        return AnchorResult(
            "mismatch",
            "header_mismatch",
            f"supplied header(s) do not match the proof (attested height(s): {heights})",
            file_digest=file_digest,
            attestations=attestations,
        )

    if bitcoins:
        return AnchorResult(
            "unverified",
            "anchor_unverified",
            "proof reaches a Bitcoin attestation; supply the 80-byte block header to confirm",
            file_digest=file_digest,
            attestations=attestations,
        )

    kinds = {att.kind for _, att in proof.leaves}
    if "pending" in kinds:
        return AnchorResult(
            "unverified",
            "anchor_pending",
            "proof reaches only pending calendar attestations; upgrade it after confirmation",
            file_digest=file_digest,
            attestations=attestations,
        )
    if "litecoin" in kinds:
        return AnchorResult(
            "unverified",
            "anchor_unverified",
            "proof reaches a Litecoin attestation (not checked by this tool)",
            file_digest=file_digest,
            attestations=attestations,
        )
    if proof.leaves:
        return AnchorResult(
            "unverified",
            "anchor_unknown_type",
            "proof reaches only unknown attestation types",
            file_digest=file_digest,
            attestations=attestations,
        )
    return AnchorResult("invalid", "anchor_empty", "proof contains no attestations", file_digest=file_digest)


def _bundle_digest(bundle_path: str, target: str) -> tuple[str, dict | None]:
    with open(bundle_path, "r", encoding="utf-8") as handle:
        bundle = json.load(handle)
    from .bundle import receipt_digest

    for receipt in bundle.get("receipts", []):
        if isinstance(receipt, dict) and receipt.get("receipt_id") == target:
            binding = None
            for anchor in bundle.get("anchors", []) or []:
                if isinstance(anchor, dict) and anchor.get("target") == target:
                    meta = anchor.get("anchor")
                    if isinstance(meta, dict) and meta.get("type") == "opentimestamps":
                        binding = anchor
                        break
            return receipt_digest(receipt), binding
    raise AnchorError("unknown_target", f"no receipt {target!r} in bundle")


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="continuity-receipt-anchor",
        description="Verify an OpenTimestamps (.ots) proof against a receipt digest.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="verify a detached .ots proof")
    verify.add_argument("proof", help="path to the detached .ots proof")
    source = verify.add_mutually_exclusive_group(required=True)
    source.add_argument("--digest", help="expected digest: hex or sha256:<hex>")
    source.add_argument("--bundle", help="bundle JSON; use with --target")
    verify.add_argument("--target", help="receipt_id inside the bundle (with --bundle)")
    verify.add_argument("--header", help="80-byte Bitcoin block header, hex")
    verify.add_argument("--height", type=int, help="block height the header belongs to")
    verify.add_argument("--json", action="store_true", help="print the full result as JSON")

    args = parser.parse_args(argv)

    try:
        expected = args.digest
        binding = None
        if args.bundle:
            if not args.target:
                parser.error("--bundle requires --target")
            expected, binding = _bundle_digest(args.bundle, args.target)
    except AnchorError as exc:
        print(json.dumps({"status": "invalid", "code": exc.code, "detail": exc.detail}))
        return 1
    except OSError as exc:
        print(json.dumps({"status": "invalid", "code": "io_error", "detail": str(exc)}))
        return 1

    headers = None
    if args.header:
        headers = {args.height if args.height is not None else 0: args.header}

    try:
        with open(args.proof, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        print(json.dumps({"status": "invalid", "code": "io_error", "detail": str(exc)}))
        return 1

    result = verify_proof(data, expected, block_headers=headers)

    if binding is not None:
        from .bundle import receipt_digest

        if binding.get("hash") != expected:
            result = AnchorResult(
                "mismatch",
                "anchor_binding_mismatch",
                "bundle anchor hash disagrees with the receipt digest",
                file_digest=result.file_digest,
                attestations=result.attestations,
            )
        else:
            result.detail += "; bundle binding ok"

    if args.json:
        print(json.dumps(result.as_dict(), indent=2))
    else:
        print(f"{result.status}: {result.code} — {result.detail}")
        if result.file_digest:
            print(f"  file digest: {result.file_digest}")
        for att in result.attestations:
            print(f"  attestation: {att}")
        if result.confirmed:
            print(f"  confirmed: {result.confirmed}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
