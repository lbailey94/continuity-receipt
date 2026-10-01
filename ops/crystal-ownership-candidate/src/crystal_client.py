#!/usr/bin/env python3
"""crystal_client.py — Sovereign Zero-Knowledge Memory Crystal Client.

Provides client-side authenticated encryption (AES-256-GCM / ChaCha20-Poly1305)
for agent memory states. Memory content is sealed locally before leaving the
agent's boundary, ensuring the remote host/gateway sees only opaque ciphertext.

Spec: wm-crystal/1.0
Hard limit: 2 MiB payload per crystal envelope
Content Addressing: sha256:<sha256(ciphertext)>
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
except ImportError:
    AESGCM = None
    ChaCha20Poly1305 = None

SPEC = "wm-crystal/1.0"
SALT = "whitemagic-crystal-salt-v1"
MAX_SIZE = 2 * 1024 * 1024  # 2 MiB hard limit


def compute_tenant_hash(tenant_id: str, salt: str = SALT) -> str:
    """Derive deterministic tenant hash: sha256(salt:tenant_id)."""
    digest = hashlib.sha256(f"{salt}:{tenant_id}".encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def build_aad(cipher: str, tenant_hash: str, parent_crystal_id: str | None, created_at: str) -> bytes:
    """Build authenticated associated data binding ciphertext to its metadata."""
    parent_str = parent_crystal_id if parent_crystal_id is not None else "genesis"
    return f"{cipher}|{tenant_hash}|{parent_str}|{created_at}".encode("utf-8")


def generate_key(cipher: str = "AES-256-GCM") -> bytes:
    """Generate a random 32-byte cryptographic key."""
    if cipher in ("AES-256-GCM", "ChaCha20-Poly1305"):
        return os.urandom(32)
    raise ValueError(f"unsupported cipher: {cipher}")


def seal_crystal(
    content: str | bytes | dict,
    key: bytes,
    tenant_id: str,
    parent_crystal_id: str | None = None,
    metadata_public: dict[str, Any] | None = None,
    cipher: str = "aes-256-gcm",
) -> dict[str, Any]:
    """Client-side Zero-Knowledge seal of memory content into a Memory Crystal envelope."""
    if AESGCM is None:
        raise RuntimeError("cryptography library required for crystal operations (pip install cryptography)")
    if len(key) != 32:
        raise ValueError("encryption key must be exactly 32 bytes (256-bit)")

    cipher_norm = "aes-256-gcm" if cipher.lower() in ("aes-256-gcm", "aes_256_gcm") else (
        "chacha20-poly1305" if cipher.lower() in ("chacha20-poly1305", "chacha20_poly1305") else cipher
    )

    if isinstance(content, dict):
        raw_plaintext = json.dumps(content, sort_keys=True).encode("utf-8")
    elif isinstance(content, str):
        raw_plaintext = content.encode("utf-8")
    else:
        raw_plaintext = content

    if len(raw_plaintext) > MAX_SIZE:
        raise ValueError(f"plaintext size {len(raw_plaintext)} exceeds maximum {MAX_SIZE} bytes")

    tenant_hash = compute_tenant_hash(tenant_id)
    created_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    aad = build_aad(cipher_norm, tenant_hash, parent_crystal_id, created_at)

    nonce = os.urandom(12)
    if cipher_norm == "aes-256-gcm":
        aes = AESGCM(key)
        ciphertext = aes.encrypt(nonce, raw_plaintext, aad)
    elif cipher_norm == "chacha20-poly1305":
        chacha = ChaCha20Poly1305(key)
        ciphertext = chacha.encrypt(nonce, raw_plaintext, aad)
    else:
        raise ValueError(f"unsupported cipher: {cipher}")

    if len(ciphertext) > MAX_SIZE:
        raise ValueError(f"ciphertext size {len(ciphertext)} exceeds maximum {MAX_SIZE} bytes")

    crystal_id = f"sha256:{hashlib.sha256(ciphertext).hexdigest()}"

    return {
        "spec": SPEC,
        "crystal_id": crystal_id,
        "parent_crystal_id": parent_crystal_id,
        "tenant_hash": tenant_hash,
        "cipher": cipher_norm,
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
        "size_bytes": len(ciphertext),
        "created_at": created_at,
        "metadata_public": metadata_public or {},
    }


def unseal_crystal(crystal_envelope: dict[str, Any], key: bytes) -> bytes:
    """Client-side unseal and verification of a Memory Crystal envelope."""
    if AESGCM is None:
        raise RuntimeError("cryptography library required for crystal operations (pip install cryptography)")
    if len(key) != 32:
        raise ValueError("encryption key must be exactly 32 bytes (256-bit)")

    for field in ("crystal_id", "tenant_hash", "cipher", "nonce", "ciphertext", "created_at"):
        if field not in crystal_envelope:
            raise ValueError(f"malformed envelope: missing field {field!r}")

    cipher_raw = crystal_envelope["cipher"]
    cipher_norm = "aes-256-gcm" if cipher_raw.lower() in ("aes-256-gcm", "aes_256_gcm") else (
        "chacha20-poly1305" if cipher_raw.lower() in ("chacha20-poly1305", "chacha20_poly1305") else cipher_raw
    )
    nonce = base64.urlsafe_b64decode(crystal_envelope["nonce"])
    ciphertext = base64.urlsafe_b64decode(crystal_envelope["ciphertext"])

    # Verify content address integrity
    expected_id = f"sha256:{hashlib.sha256(ciphertext).hexdigest()}"
    if crystal_envelope["crystal_id"].lower() != expected_id.lower():
        raise ValueError(f"crystal content-address verification failed: {crystal_envelope['crystal_id']} != {expected_id}")

    aad = build_aad(
        cipher_raw,
        crystal_envelope["tenant_hash"],
        crystal_envelope.get("parent_crystal_id"),
        crystal_envelope["created_at"],
    )

    if cipher_norm == "aes-256-gcm":
        aes = AESGCM(key)
        return aes.decrypt(nonce, ciphertext, aad)
    if cipher_norm == "chacha20-poly1305":
        chacha = ChaCha20Poly1305(key)
        return chacha.decrypt(nonce, ciphertext, aad)
    raise ValueError(f"unsupported cipher: {cipher_raw}")


def push_crystal(
    crystal_envelope: dict[str, Any],
    api_url: str = "https://api.whitemagic.dev",
    auth_token: str = "",
) -> dict[str, Any]:
    """Store sealed Memory Crystal envelope on remote gateway (requires auth/session pass)."""
    target = api_url.rstrip("/") + "/crystals"
    data = json.dumps(crystal_envelope).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(data)),
    }
    if auth_token:
        if auth_token.startswith("wm_pass_"):
            headers["X-Session-Pass"] = auth_token
            headers["Authorization"] = f"Bearer {auth_token}"
        else:
            headers["Authorization"] = f"Bearer {auth_token}"

    req = urllib.request.Request(target, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            return json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {err_msg}") from e


def pull_crystal(
    crystal_id: str,
    tenant_id: str,
    api_url: str = "https://api.whitemagic.dev",
) -> dict[str, Any]:
    """Fetch stored Memory Crystal (keyless read via tenant hash)."""
    tenant_hash = compute_tenant_hash(tenant_id)
    clean_id = crystal_id.replace("sha256:", "").strip()
    target = f"{api_url.rstrip('/')}/crystals/{clean_id}?tenant={urllib.parse.quote(tenant_hash)}"

    req = urllib.request.Request(
        target,
        headers={"User-Agent": "whitemagic-crystal-client/1.0"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            return json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {err_msg}") from e


def pull_lineage(
    tenant_id: str,
    api_url: str = "https://api.whitemagic.dev",
) -> list[dict[str, Any]]:
    """Fetch DAG lineage for tenant crystals (keyless read)."""
    tenant_hash = compute_tenant_hash(tenant_id)
    target = f"{api_url.rstrip('/')}/crystals/lineage?tenant={urllib.parse.quote(tenant_hash)}"

    req = urllib.request.Request(
        target,
        headers={"User-Agent": "whitemagic-crystal-client/1.0"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            doc = json.loads(res.read().decode("utf-8"))
            return doc.get("crystals", [])
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {err_msg}") from e


def main():
    ap = argparse.ArgumentParser(description="Zero-Knowledge Sovereign Memory Crystal Client")
    sub = ap.add_subparsers(dest="command")

    # genkey
    gen_cmd = sub.add_parser("genkey", help="Generate a random 32-byte crystal key")
    gen_cmd.add_argument("--out", default="", help="Save key to binary file")

    # seal
    seal_cmd = sub.add_parser("seal", help="Seal memory content into an encrypted crystal envelope")
    seal_cmd.add_argument("--content", help="Plaintext content string")
    seal_cmd.add_argument("--file", help="Path to plaintext file")
    seal_cmd.add_argument("--key", help="Hex-encoded 32-byte key or key file path", required=True)
    seal_cmd.add_argument("--tenant", help="Tenant ID string", required=True)
    seal_cmd.add_argument("--parent", help="Parent crystal ID (for chain DAG)", default=None)
    seal_cmd.add_argument("--cipher", choices=["AES-256-GCM", "ChaCha20-Poly1305"], default="AES-256-GCM")
    seal_cmd.add_argument("--out", help="Output JSON envelope file")

    # unseal
    unseal_cmd = sub.add_parser("unseal", help="Decrypt and verify a crystal envelope")
    unseal_cmd.add_argument("--envelope", help="Path to crystal envelope JSON", required=True)
    unseal_cmd.add_argument("--key", help="Hex-encoded 32-byte key or key file path", required=True)

    # push
    push_cmd = sub.add_parser("push", help="Push sealed crystal to remote gateway")
    push_cmd.add_argument("--envelope", help="Path to crystal envelope JSON", required=True)
    push_cmd.add_argument("--api", default="https://api.whitemagic.dev", help="Gateway URL")
    push_cmd.add_argument("--token", help="Bearer API key or session pass token", required=True)

    # pull
    pull_cmd = sub.add_parser("pull", help="Keylessly pull crystal envelope from remote gateway")
    pull_cmd.add_argument("--id", help="Crystal ID (sha256:... or hex)", required=True)
    pull_cmd.add_argument("--tenant", help="Tenant ID", required=True)
    pull_cmd.add_argument("--api", default="https://api.whitemagic.dev", help="Gateway URL")
    pull_cmd.add_argument("--out", help="Save pulled envelope to JSON file")

    # lineage
    lineage_cmd = sub.add_parser("lineage", help="Fetch crystal lineage DAG for tenant")
    lineage_cmd.add_argument("--tenant", help="Tenant ID", required=True)
    lineage_cmd.add_argument("--api", default="https://api.whitemagic.dev", help="Gateway URL")

    args = ap.parse_args()

    def resolve_key(key_str: str) -> bytes:
        if os.path.isfile(key_str):
            raw = open(key_str, "rb").read().strip()
            if len(raw) == 32:
                return raw
            if len(raw) == 64:
                return bytes.fromhex(raw.decode("ascii"))
        if len(key_str) == 64:
            return bytes.fromhex(key_str)
        if len(key_str.encode("utf-8")) == 32:
            return key_str.encode("utf-8")
        raise ValueError("key must be 32 bytes or 64 hex characters")

    if args.command == "genkey":
        key = generate_key()
        if args.out:
            with open(args.out, "wb") as f:
                f.write(key)
            print(f"Key written to {args.out}")
        else:
            print(key.hex())

    elif args.command == "seal":
        key = resolve_key(args.key)
        if args.file:
            content = open(args.file, "rb").read()
        elif args.content:
            content = args.content
        else:
            content = sys.stdin.read()
        envelope = seal_crystal(
            content=content,
            key=key,
            tenant_id=args.tenant,
            parent_crystal_id=args.parent,
            cipher=args.cipher,
        )
        out_json = json.dumps(envelope, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(out_json + "\n")
            print(f"Sealed crystal {envelope['crystal_id']} saved to {args.out}")
        else:
            print(out_json)

    elif args.command == "unseal":
        key = resolve_key(args.key)
        envelope = json.loads(open(args.envelope, "r", encoding="utf-8").read())
        plaintext = unseal_crystal(envelope, key)
        sys.stdout.buffer.write(plaintext)
        if not plaintext.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")

    elif args.command == "push":
        envelope = json.loads(open(args.envelope, "r", encoding="utf-8").read())
        res = push_crystal(envelope, api_url=args.api, auth_token=args.token)
        print(json.dumps(res, indent=2))

    elif args.command == "pull":
        doc = pull_crystal(args.id, args.tenant, api_url=args.api)
        out_json = json.dumps(doc, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(out_json + "\n")
            print(f"Pulled crystal saved to {args.out}")
        else:
            print(out_json)

    elif args.command == "lineage":
        items = pull_lineage(args.tenant, api_url=args.api)
        print(json.dumps(items, indent=2))

    else:
        ap.print_help()


if __name__ == "__main__":
    main()
