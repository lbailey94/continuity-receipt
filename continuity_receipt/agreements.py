"""Reference emitters for the agreement records (offer → accept, 0.3 + 0.4).

Implementers should not have to hand-roll the binding rules. These helpers
build spec-conformant bodies, keep terms off-receipt (only their hash is
signed), and derive `offer_ref` / `agreement_ref` from the referenced receipt
exactly the way the verifier resolves them (the canonical digest used by
`prev` links).

Usage (0.4)::

    chain = TaskChain(spec="continuity-receipt/0.4")
    chain.add("session.pass.created", "gate", gate_did, gate_key, pass_body)
    offer = chain.add(
        "agreement.offer", "gate", gate_did, gate_key,
        offer_body("offer-1", agent_did, terms, "2030-01-01T00:00:00Z", "nonce-1"),
    )
    accept = chain.add(
        "agreement.accept", "agent", agent_did, agent_key, accept_body(offer),
    )
    chain.add(
        "task.decision", "agent", agent_did, agent_key,
        bind_body(decision_body, accept),
    )
"""
from . import records
from .bundle import receipt_digest
from .canon import canonical_bytes, sha256_prefixed

# Record types the accept binds in 0.4 (the stages after the agreement).
BOUND_TYPES = ("task.decision", "task.execution", "delivery.attestation", "settlement")


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


def accept_body(
    offer_receipt: dict,
    offer_id: str | None = None,
    offeree: str | None = None,
) -> dict:
    """Build an `agreement.accept` body bound to a signed offer receipt.

    `offeree` defaults to the offer's offeree; 0.4 signs it into the accept
    (required field) and the verifier requires it to equal both the offer's
    `offeree` and the accept's issuer.
    """
    body = offer_receipt.get("body") if isinstance(offer_receipt, dict) else None
    if not isinstance(body, dict):
        raise ValueError("offer_receipt must be a receipt object")
    return {
        "offer_ref": receipt_digest(offer_receipt),
        "offer_id": offer_id or body.get("offer_id"),
        "terms_hash": body.get("terms_hash"),
        "offeree": offeree or body.get("offeree"),
    }


def bind_body(body: dict, accept_receipt: dict) -> dict:
    """Return `body` with `agreement_ref` bound to a signed accept receipt.

    Apply to the bound record types (`BOUND_TYPES`) so a 0.4 bundle carries
    the agreement through the task stages; the verifier checks that the ref
    resolves, follows the accept in time, and matches the offeree.
    """
    if not isinstance(body, dict):
        raise ValueError("body must be an object")
    bound_body = dict(body)
    bound_body["agreement_ref"] = receipt_digest(accept_receipt)
    return bound_body
