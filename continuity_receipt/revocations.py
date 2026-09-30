"""External revocation list distribution — 0.3 tooling.

Decision record: REVOCATION_DISTRIBUTION.md. A revocation list is a JSON
document carrying the same self-signed statements the bundle format accepts
(0.2 §7.5): ``{key, revoked_at, [reason], sig}``. Authenticity is per
statement — the distribution channel is not trusted. A hostile mirror cannot
forge a revocation for a key it does not control; it can only withhold one,
which makes freshness a monitoring concern rather than a cryptographic one.

Document shape::

    {
      "kind": "continuity-receipt-revocations",
      "version": 1,
      "issued_at": "2026-09-21T00:00:00Z",   # optional, informational
      "statements": [ {"key": "did:key:...", "revoked_at": "...", "sig": {...}} ]
    }

Sources may be a filesystem path or an HTTPS URL (``http://`` is accepted
only for loopback hosts, for local testing). Documents are capped at 1 MiB;
failures are loud and map to ``INSUFFICIENT_EVIDENCE`` at the CLI.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request

from . import keys, records
from .strict_json import loads as strict_json_loads
from .canon import canonical_bytes

MAX_DOCUMENT_BYTES = 1 << 20  # 1 MiB
DEFAULT_TIMEOUT = 15
DOCUMENT_KIND = "continuity-receipt-revocations"
DOCUMENT_VERSION = 1
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class RevocationError(Exception):
    """External revocation list failure; ``code`` is machine-readable."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _read_source(source: str, timeout: int) -> bytes:
    parsed = urllib.parse.urlparse(source)
    if parsed.scheme in ("http", "https"):
        if parsed.scheme != "https" and parsed.hostname not in LOOPBACK_HOSTS:
            raise RevocationError(
                "revocations_insecure_url",
                f"refusing plain http for non-loopback host: {source}",
            )
        try:
            with urllib.request.urlopen(source, timeout=timeout) as response:
                data = response.read(MAX_DOCUMENT_BYTES + 1)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise RevocationError(
                "revocations_unreachable", f"cannot fetch {source}: {exc}"
            ) from exc
    else:
        try:
            with open(source, "rb") as handle:
                data = handle.read(MAX_DOCUMENT_BYTES + 1)
        except OSError as exc:
            raise RevocationError(
                "revocations_unreachable", f"cannot read {source}: {exc}"
            ) from exc
    if len(data) > MAX_DOCUMENT_BYTES:
        raise RevocationError(
            "revocations_too_large",
            f"document exceeds {MAX_DOCUMENT_BYTES} bytes",
        )
    return data


def load_statements(source: str, timeout: int = DEFAULT_TIMEOUT) -> list[dict]:
    """Load and shape-check a revocation list document; returns statements."""
    data = _read_source(source, timeout)
    try:
        document = strict_json_loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise RevocationError(
            "bad_revocations_document", f"{source} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(document, dict):
        raise RevocationError(
            "bad_revocations_document", "document is not an object"
        )
    if document.get("kind") != DOCUMENT_KIND:
        raise RevocationError(
            "bad_revocations_document",
            f"kind must be {DOCUMENT_KIND!r}, got {document.get('kind')!r}",
        )
    if document.get("version") != DOCUMENT_VERSION:
        raise RevocationError(
            "bad_revocations_document",
            f"version must be {DOCUMENT_VERSION}, got {document.get('version')!r}",
        )
    statements = document.get("statements")
    if not isinstance(statements, list):
        raise RevocationError(
            "bad_revocations_document", "statements must be a list"
        )
    return statements


def merge_statements(*groups: list[dict] | None) -> list[dict]:
    """Concatenate statement groups, dropping byte-identical duplicates.

    Malformed entries are passed through untouched: rejecting them is the
    verifier's fail-closed job (`bad_revocation`), not the loader's.
    """
    merged: list[dict] = []
    seen: set[bytes | str] = set()
    for group in groups:
        for statement in group or []:
            if not isinstance(statement, dict):
                merged.append(statement)
                continue
            try:
                fingerprint: bytes | str = canonical_bytes(statement)
            except (TypeError, ValueError):
                fingerprint = repr(statement)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            merged.append(statement)
    return merged


def verify_statements(statements: list) -> tuple[list[tuple[str, object]], list[tuple[str, str]]]:
    """Verify self-signed revocation statements (bundle shape, 0.2 §7.5).

    Returns ``(revoked, errors)``: ``revoked`` pairs each verified key with its
    ``revoked_at`` (a datetime), and ``errors`` is ``[(code, detail)]`` for
    statements that do not verify. Callers decide fatality — the bundle
    verifier fails closed with ``bad_revocation`` — and how to apply the times.
    """
    revoked: list[tuple[str, object]] = []
    errors: list[tuple[str, str]] = []
    for statement in statements:
        if not isinstance(statement, dict):
            errors.append(("bad_revocation", "revocation statement is not an object"))
            continue
        key_id = statement.get("key")
        revoked_at = statement.get("revoked_at")
        sig = statement.get("sig")
        if not isinstance(key_id, str) or not records.validate_timestamp(revoked_at):
            errors.append(("bad_revocation", f"malformed revocation statement for {key_id!r}"))
            continue
        if not isinstance(sig, dict) or sig.get("alg") != "ed25519" or not sig.get("value"):
            errors.append(("bad_revocation", f"revocation statement unsigned for {key_id!r}"))
            continue
        message = canonical_bytes({k: v for k, v in statement.items() if k != "sig"})
        if not keys.verify(key_id, message, sig["value"]):
            errors.append(("bad_revocation", f"revocation signature invalid for {key_id!r}"))
            continue
        revoked.append((key_id, records.parse_timestamp(revoked_at)))
    return revoked, errors
