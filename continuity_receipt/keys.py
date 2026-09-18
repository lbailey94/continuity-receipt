"""Ed25519 keys, signing, and did:key encoding for Continuity Receipts."""
import base64
import hashlib
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_MULTICODEC_ED25519 = b"\xed\x01"


def b58encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = _B58_ALPHABET[remainder] + encoded
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + encoded


def b58decode(text: str) -> bytes:
    number = 0
    for char in text:
        number = number * 58 + _B58_ALPHABET.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    pad = 0
    for char in text:
        if char == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + raw


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def raw_pubkey_bytes(public: Ed25519PublicKey) -> bytes:
    return public.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def private_raw(private: Ed25519PrivateKey) -> bytes:
    return private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def private_from_raw(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


def pubkey_to_did_key(pub) -> str:
    raw = raw_pubkey_bytes(pub) if isinstance(pub, Ed25519PublicKey) else pub
    return "did:key:z" + b58encode(_MULTICODEC_ED25519 + raw)


def did_key_to_pubkey(did: str) -> Ed25519PublicKey:
    if not did.startswith("did:key:z"):
        raise ValueError(f"unsupported did:key form: {did[:24]}")
    raw = b58decode(did[len("did:key:z") :])
    if not raw.startswith(_MULTICODEC_ED25519) or len(raw) != 34:
        raise ValueError("did:key is not an Ed25519 key")
    return Ed25519PublicKey.from_public_bytes(raw[2:])


def generate(seed: bytes | None = None) -> tuple[str, Ed25519PrivateKey]:
    """Returns (did:key, private_key). Deterministic when seed is given."""
    private = (
        Ed25519PrivateKey.from_private_bytes(seed)
        if seed is not None
        else Ed25519PrivateKey.generate()
    )
    return pubkey_to_did_key(private.public_key()), private


def sign(private: Ed25519PrivateKey, message: bytes) -> str:
    return b64u(private.sign(message))


def verify(pubkey_did: str, message: bytes, signature_b64u: str) -> bool:
    try:
        did_key_to_pubkey(pubkey_did).verify(b64u_decode(signature_b64u), message)
        return True
    except (InvalidSignature, ValueError):
        return False


def deterministic_seed(label: str) -> bytes:
    """Deterministic 32-byte seed for tests/vectors (never for production)."""
    return hashlib.sha256(("continuity-receipt/" + label).encode()).digest()


def random_salt_hex() -> str:
    return secrets.token_hex(16)
