"""Tests for the OpenTimestamps anchor companion tool."""

import contextlib
import hashlib
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path

from continuity_receipt.anchor import (
    ATT_BITCOIN,
    ATT_PENDING,
    MAGIC,
    AnchorError,
    main,
    parse_detached,
    verify_proof,
)


def varuint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def varbytes(b: bytes) -> bytes:
    return varuint(len(b)) + b


def pending_att(uri: str) -> bytes:
    return ATT_PENDING + varbytes(varbytes(uri.encode()))


def bitcoin_att(height: int) -> bytes:
    return ATT_BITCOIN + varbytes(varuint(height))


def detached(digest: bytes, tree: bytes) -> bytes:
    return MAGIC + bytes([1]) + b"\x08" + digest + tree


def header_for(merkle: bytes, time: int = 1_700_000_000) -> bytes:
    assert len(merkle) == 32
    return (
        b"\x02\x00\x00\x00"
        + b"\x11" * 32
        + merkle
        + struct.pack("<I", time)
        + b"\x00" * 8
    )


class TestAnchor(unittest.TestCase):
    def setUp(self):
        self.digest = hashlib.sha256(b"continuity-receipt test vector").digest()
        self.msg = hashlib.sha256(self.digest).digest()
        self.proof = detached(self.digest, b"\x08" + b"\x00" + bitcoin_att(800000))

    def test_bitcoin_attestation_verified_against_header(self):
        header = header_for(self.msg)
        result = verify_proof(
            self.proof,
            "sha256:" + self.digest.hex(),
            block_headers={800000: header},
        )
        self.assertEqual(result.status, "verified")
        self.assertEqual(result.code, "anchor_verified")
        self.assertTrue(result.ok)
        self.assertEqual(result.confirmed["block_height"], 800000)
        self.assertEqual(result.confirmed["header_time"], 1_700_000_000)
        self.assertEqual(result.confirmed["merkle_root"], self.msg.hex())

    def test_bitcoin_attestation_without_header_is_unverified(self):
        result = verify_proof(self.proof, self.digest)
        self.assertEqual(result.status, "unverified")
        self.assertEqual(result.code, "anchor_unverified")
        self.assertEqual(result.attestations[0]["kind"], "bitcoin")

    def test_header_mismatch(self):
        result = verify_proof(
            self.proof,
            self.digest,
            block_headers={800000: header_for(b"\x00" * 32)},
        )
        self.assertEqual(result.status, "mismatch")
        self.assertEqual(result.code, "header_mismatch")

    def test_digest_mismatch(self):
        result = verify_proof(self.proof, hashlib.sha256(b"other").digest())
        self.assertEqual(result.status, "mismatch")
        self.assertEqual(result.code, "digest_mismatch")

    def test_pending_and_unknown_attestations(self):
        unknown_tag = bytes.fromhex("0011223344556677")
        tree = (
            b"\xff"
            + b"\xf0"
            + varbytes(b"AAAA")
            + b"\x00"
            + pending_att("https://alice.btc.calendar.opentimestamps.org")
            + b"\xf0"
            + varbytes(b"BBBB")
            + b"\x00"
            + unknown_tag
            + varbytes(b"\x01\x02\x03")
        )
        proof = detached(self.digest, tree)
        result = verify_proof(proof, self.digest)
        self.assertEqual(result.status, "unverified")
        self.assertEqual(result.code, "anchor_pending")
        kinds = {att["kind"] for att in result.attestations}
        self.assertEqual(kinds, {"pending", "unknown"})

    def test_leb128_varuints_not_compact_size(self):
        # 130 encodes as b"\x82\x01" in LEB128; CompactSize would read one
        # byte (130) and leave 0x01 to corrupt the URI.
        uri = "a" * 128
        tree = b"\x00" + ATT_PENDING + b"\x82\x01" + b"\x80\x01" + uri.encode()
        proof = detached(self.digest, tree)
        parsed = parse_detached(proof)
        self.assertEqual(parsed.leaves[0][1].kind, "pending")
        self.assertEqual(parsed.leaves[0][1].value, uri)

        # block height 300 = b"\xac\x02" in LEB128; CompactSize would read
        # 172 and fail with trailing data.
        tree300 = b"\x00" + ATT_BITCOIN + varbytes(b"\xac\x02")
        parsed300 = parse_detached(detached(self.digest, tree300))
        self.assertEqual(parsed300.leaves[0][1].value, 300)

    def test_reverse_and_prepend_ops(self):
        prefix = b"X" * 8
        tree = b"\xf1" + varbytes(prefix) + b"\xf2" + b"\x00" + pending_att("https://ots.example")
        proof = detached(self.digest, tree)
        parsed = parse_detached(proof)
        reached, att = parsed.leaves[0]
        self.assertEqual(reached, (prefix + self.digest)[::-1])
        self.assertEqual(att.kind, "pending")

    def test_truncated_and_bad_magic(self):
        self.assertEqual(verify_proof(self.proof[:-3], self.digest).code, "truncated")
        bad = b"\x00" * 16 + self.proof
        self.assertEqual(verify_proof(bad, self.digest).code, "bad_magic")

    def test_keccak_is_unsupported_not_silent(self):
        proof = detached(self.digest, b"\x67" + b"\x00" + pending_att("https://ots.example"))
        result = verify_proof(proof, self.digest)
        self.assertEqual(result.status, "invalid")
        self.assertEqual(result.code, "unsupported_op")

    def test_cli_json_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proof.ots"
            path.write_bytes(self.proof)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["verify", str(path), "--digest", self.digest.hex(), "--json"])
            self.assertEqual(rc, 1)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["code"], "anchor_unverified")

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(
                    [
                        "verify",
                        str(path),
                        "--digest",
                        self.digest.hex(),
                        "--header",
                        header_for(self.msg).hex(),
                        "--height",
                        "800000",
                        "--json",
                    ]
                )
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["status"], "verified")
            self.assertEqual(payload["confirmed"]["block_height"], 800000)


FIXTURES = Path(__file__).resolve().parent.parent / "vectors" / "anchor"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def fixture_headers() -> dict:
    data = json.loads((FIXTURES / "headers.json").read_text(encoding="utf-8"))
    return {int(k): v for k, v in data["headers"].items()}


class TestAnchorRealFixtures(unittest.TestCase):
    """Real .ots proofs from opentimestamps-client/examples (MIT, 2026-09-21)."""

    def test_hello_world_binds_to_the_file_digest(self):
        parsed = parse_detached(fixture("hello-world.txt.ots"))
        self.assertEqual(
            parsed.file_digest,
            hashlib.sha256(fixture("hello-world.txt")).digest(),
        )

    def test_hello_world_verified_against_block_358391(self):
        result = verify_proof(
            fixture("hello-world.txt.ots"),
            hashlib.sha256(fixture("hello-world.txt")).hexdigest(),
            block_headers=fixture_headers(),
        )
        self.assertEqual(result.status, "verified")
        self.assertEqual(result.confirmed["block_height"], 358391)

    def test_sha1_bitcoin_pdf_verified_against_block_465751(self):
        parsed = parse_detached(fixture("bitcoin.pdf.ots"))
        self.assertEqual(parsed.file_hash_op, "sha1")
        result = verify_proof(
            fixture("bitcoin.pdf.ots"), parsed.file_digest, block_headers=fixture_headers()
        )
        self.assertEqual(result.status, "verified")
        self.assertEqual(result.confirmed["block_height"], 465751)

    def test_2025_gdp_proof_verified_against_block_912095(self):
        parsed = parse_detached(fixture("gdp2q25-2nd.pdf.ots"))
        result = verify_proof(
            fixture("gdp2q25-2nd.pdf.ots"), parsed.file_digest, block_headers=fixture_headers()
        )
        self.assertEqual(result.status, "verified")
        self.assertEqual(result.confirmed["block_height"], 912095)

    def test_known_and_unknown_notary_reports_both(self):
        parsed = parse_detached(fixture("known-and-unknown-notary.txt.ots"))
        result = verify_proof(
            fixture("known-and-unknown-notary.txt.ots"), parsed.file_digest
        )
        self.assertEqual(result.status, "unverified")
        self.assertEqual(result.code, "anchor_pending")
        self.assertEqual(
            {att["kind"] for att in result.attestations}, {"pending", "unknown"}
        )

    def test_different_blockchains_fails_loudly_on_keccak(self):
        with self.assertRaises(AnchorError) as raised:
            parse_detached(fixture("different-blockchains.txt.ots"))
        self.assertEqual(raised.exception.code, "unsupported_op")
        result = verify_proof(
            fixture("different-blockchains.txt.ots"), b"\x00" * 32
        )
        self.assertEqual(result.status, "invalid")
        self.assertEqual(result.code, "unsupported_op")


if __name__ == "__main__":
    unittest.main()