"""Reference emitters for the 0.3 agreement records (offer → accept).

Implementers should not have to hand-roll the binding rules. These helpers
build spec-conformant bodies, keep terms off-receipt (only their hash is
signed), and derive `offer_ref` from the offer receipt exactly the way the
verifier resolves it (the canonical digest used by `prev` links).

Usage::

    chain = TaskChain(spec="continuity-receipt/0.3")
    chain.add("session.pass.created", "gate", gate_did, gate_key, pass_body)
    offer = chain.add(
        "agreement.offer", "gate", gate_did, gate_key,
        offer_body("offer-1", agent_did, terms, "2030-01-01T00:00:00Z", "nonce-1"),
    )
    chain.add("agreement.accept", "agent", agent_did, agent_key, accept_body(offer))
"""
from . import records
from .bundle import receipt_digest
from .canon import canonical_bytes, sha256_prefixed


def terms_hash(terms) -> str:
    """The grounded commitment to off-receipt terms (JCS canonical bytes)."""
    return sha256_prefixed(canonical_bytes(terms))


def offer_body(
    offer_id: str,
    offeree: str,
    terms,
    valid_until: str,
    nonce: str,
    terms_ref=None,
) -> dict:
    """Build an `agreement.offer` body.

    `terms` is any JSON value (kept off-receipt; only its hash is signed).
    `terms_ref` optionally points at where the terms live (URI), or may be a
    redaction object for issuance-time redaction.
    """
    if not records.validate_timestamp(valid_until):
        raise ValueError(f"valid_until must be RFC 3339 UTC: {valid_until!r}")
    body = {
        "offer_id": offer_id,
        "offeree": offeree,
        "terms_hash": terms_hash(terms),
        "valid_until": valid_until,
        "nonce": nonce,
    }
    if terms_ref is not None:
        body["terms_ref"] = terms_ref
    return body


def accept_body(offer_receipt: dict, offer_id: str | None = None) -> dict:
    """Build an `agreement.accept` body bound to a signed offer receipt."""
    body = offer_receipt.get("body") if isinstance(offer_receipt, dict) else None
    if not isinstance(body, dict):
        raise ValueError("offer_receipt must be a receipt object")
    return {
        "offer_ref": receipt_digest(offer_receipt),
        "offer_id": offer_id or body.get("offer_id"),
        "terms_hash": body.get("terms_hash"),
    }
