#!/usr/bin/env python3
"""Generate the Continuity Receipt test vectors (0.1 conformance + 0.2 additions)."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from continuity_receipt import keys, records  # noqa: E402
from continuity_receipt.bundle import TaskChain, receipt_digest  # noqa: E402
from continuity_receipt.canon import canonical_bytes, commit_field, sha256_prefixed  # noqa: E402

VECTORS = ROOT / "vectors"
POLICY = "2026-09-17.1"
SPEC_01 = "continuity-receipt/0.1"
SPEC_02 = "continuity-receipt/0.2"
SPEC_03 = "continuity-receipt/0.3"

GATE_DID, GATE_KEY = keys.generate(keys.deterministic_seed("gate-1"))
AGENT_DID, AGENT_KEY = keys.generate(keys.deterministic_seed("agent-1"))
COUNTERPARTY_DID, COUNTERPARTY_KEY = keys.generate(keys.deterministic_seed("counterparty-1"))
SUCCESSOR_DID, _SUCCESSOR_KEY = keys.generate(keys.deterministic_seed("gate-2"))


def digest(label: str) -> str:
    return sha256_prefixed(label.encode())


def merkle_digest(label: str) -> str:
    return "merkle-sha256:" + digest(label)[len("sha256:") :]


def pass_body(spend_cap=None) -> dict:
    body = {
        "gate_id": "gate-lite-1",
        "mandala_class": "gate-lite",
        "quotas": {"cpu_ms": 300000, "mem_mb": 1024, "disk_mb": 512, "wall_ms": 300000},
        "expires_at": "2026-09-18T00:00:00Z",
        "policy_version": POLICY,
        "mandate_ref": digest("mandate:dogfood-1"),
        "agent_id": AGENT_DID,
    }
    if spend_cap is not None:
        body["spend_cap"] = spend_cap
    return body


def decision_body(provenance_hash: str | None = None) -> dict:
    return {
        "action": "memory.search",
        "action_args_hash": digest("args:search:1"),
        "model": {"provider": "local", "id": "wm-recall"},
        "input_provenance": {
            "policy_id": "egress.default",
            "allowed_sources": ["gate"],
            "observed_sources_hash": provenance_hash or digest("sources:gate-only"),
        },
        "decision": "allow",
        "policy_version": POLICY,
    }


def execution_body() -> dict:
    return {
        "tool_calls": [
            {
                "name": "memory.search",
                "args_hash": digest("args:search:1"),
                "result_hash": digest("result:search:1"),
            }
        ],
        "egress": [{"destination": "none", "bytes": 0, "allowed": True}],
        "resources": {"cpu_ms": 1200, "mem_peak_mb": 48, "disk_peak_mb": 8},
        "sandbox_class": "bwrap-landlock",
    }


def delivery_body(extra: dict | None = None) -> dict:
    body = {
        "request_hash": digest("request:1"),
        "response_hash": digest("response:1"),
        "counterparty": {"id": COUNTERPARTY_DID},
        "spec_ref": "continuity-receipt/0.2",
    }
    if extra:
        body.update(extra)
    return body


def settlement_body(gated=True, minor=200, currency="USD") -> dict:
    return {
        "rail": "invoice",
        "rail_ref": "inv-0001",
        "amount": {"minor": minor, "currency": currency},
        "gated_on_delivery": gated,
        "settled_at": "2026-09-17T21:10:00Z",
    }


def termination_body() -> dict:
    return {
        "reason": "completed",
        "limits_at_stop": {
            "cpu_ms": 300000,
            "wall_ms": 300000,
            "spend_minor": 1000,
            "currency": "USD",
        },
        "remaining": {
            "cpu_ms": 298800,
            "wall_ms": 299000,
            "spend_minor": 800,
            "currency": "USD",
        },
    }


def succession_body() -> dict:
    return {
        "from_authority": GATE_DID,
        "to_authority": SUCCESSOR_DID,
        "effective_at": "2026-09-18T00:00:00Z",
        "reason": "handoff",
    }


def offer_body(terms_hash: str | None = None, valid_until: str = "2030-01-01T00:00:00Z",
               terms_ref=None) -> dict:
    body = {
        "offer_id": "offer-1",
        "offeree": COUNTERPARTY_DID,
        "terms_hash": terms_hash or digest("terms:recall-pilot-1"),
        "valid_until": valid_until,
        "nonce": "nonce-offer-1",
    }
    if terms_ref is not None:
        body["terms_ref"] = terms_ref
    return body


def accept_body(offer_ref: str, terms_hash: str | None = None) -> dict:
    return {
        "offer_ref": offer_ref,
        "offer_id": "offer-1",
        "terms_hash": terms_hash or digest("terms:recall-pilot-1"),
    }


def add(chain: TaskChain, record_type: str, body: dict) -> dict:
    return chain.add(record_type, "gate", GATE_DID, GATE_KEY, body)


def chain(spec: str = SPEC_02, ms: bool = False) -> TaskChain:
    return TaskChain(spec=spec, ms_timestamps=ms)


def minimal_chain(task_id=None, spec: str = SPEC_02, ms: bool = False) -> TaskChain:
    c = TaskChain(task_id, spec=spec, ms_timestamps=ms)
    add(c, "session.pass.created", pass_body())
    add(c, "task.decision", decision_body())
    add(c, "task.execution", execution_body())
    add(c, "task.termination", termination_body())
    return c


def full_chain(task_id=None, spec: str = SPEC_02) -> TaskChain:
    c = TaskChain(task_id, spec=spec)
    add(c, "session.pass.created", pass_body(spend_cap={"minor": 1000, "currency": "USD"}))
    add(c, "task.decision", decision_body())
    add(c, "task.execution", execution_body())
    add(c, "delivery.attestation", delivery_body())
    add(c, "settlement", settlement_body())
    add(c, "task.termination", termination_body())
    return c


def revocation_statement(key_did: str, private_key, when: str, reason="key-compromise") -> dict:
    statement = {"key": key_did, "revoked_at": when, "reason": reason}
    statement["sig"] = {
        "alg": "ed25519",
        "key": key_did,
        "value": keys.sign(private_key, canonical_bytes(statement)),
    }
    return statement


def write(name: str, bundle: dict) -> str:
    path = VECTORS / name
    path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    return path.name


def main() -> int:
    VECTORS.mkdir(exist_ok=True)
    rows = []

    def record(name, verdict, code="", require_anchor=False, note="", schema_valid=True):
        rows.append(
            {
                "file": name,
                "expected_verdict": verdict,
                "expected_code": code or None,
                "require_anchor": require_anchor,
                "note": note,
                "schema_valid": schema_valid,
            }
        )

    # --- 0.1 conformance set (frozen; regenerated with the 0.1 spec id) -----
    write("01_happy_minimal.json", minimal_chain(spec=SPEC_01).bundle())
    record("01_happy_minimal.json", "TRUSTED")

    write("02_happy_full.json", full_chain(spec=SPEC_01).bundle())
    record("02_happy_full.json", "TRUSTED")

    tampered = minimal_chain(spec=SPEC_01).bundle()
    tampered["receipts"][2]["body"]["resources"]["cpu_ms"] = 999999
    write("03_tampered_body.json", tampered)
    record("03_tampered_body.json", "UNTRUSTED", "bad_signature")

    no_term = chain(SPEC_01)
    add(no_term, "session.pass.created", pass_body())
    add(no_term, "task.decision", decision_body())
    add(no_term, "task.execution", execution_body())
    write("04_missing_termination.json", no_term.bundle())
    record("04_missing_termination.json", "UNTRUSTED", "missing_termination")

    over_cap = chain(SPEC_01)
    add(over_cap, "session.pass.created", pass_body(spend_cap={"minor": 100, "currency": "USD"}))
    add(over_cap, "task.decision", decision_body())
    add(over_cap, "task.execution", execution_body())
    add(over_cap, "delivery.attestation", delivery_body())
    add(over_cap, "settlement", settlement_body(minor=5000))
    add(over_cap, "task.termination", termination_body())
    write("05_cap_exceeded.json", over_cap.bundle())
    record("05_cap_exceeded.json", "UNTRUSTED", "cap_exceeded")

    early_settle = chain(SPEC_01)
    add(early_settle, "session.pass.created", pass_body())
    add(early_settle, "task.decision", decision_body())
    add(early_settle, "task.execution", execution_body())
    add(early_settle, "settlement", settlement_body())
    add(early_settle, "delivery.attestation", delivery_body())
    add(early_settle, "task.termination", termination_body())
    write("06_delivery_before_settlement.json", early_settle.bundle())
    record("06_delivery_before_settlement.json", "UNTRUSTED", "delivery_before_settlement")

    salt = keys.random_salt_hex()
    redacted_value = ["quality-ok"]
    redacted_field = {"redacted": True, "commit": commit_field(salt, redacted_value)}

    redacted_chain = chain(SPEC_01)
    add(redacted_chain, "session.pass.created", pass_body(spend_cap={"minor": 1000, "currency": "USD"}))
    add(redacted_chain, "task.decision", decision_body())
    add(redacted_chain, "task.execution", execution_body())
    add(redacted_chain, "delivery.attestation", delivery_body({"quality_flags": redacted_field}))
    add(redacted_chain, "settlement", settlement_body())
    add(redacted_chain, "task.termination", termination_body())
    write("07_redacted_no_disclosure.json", redacted_chain.bundle())
    record("07_redacted_no_disclosure.json", "PROVISIONAL")

    disclosed = redacted_chain.bundle()
    disclosed["disclosure_map"] = {"receipts[3].body.quality_flags": {"salt": salt, "value": redacted_value}}
    write("08_redacted_disclosed.json", disclosed)
    record("08_redacted_disclosed.json", "TRUSTED")

    erased = chain(SPEC_01)
    erased_body = delivery_body(
        {"quality_flags": {"redacted": True, "commit": redacted_field["commit"], "erased": True}}
    )
    add(erased, "session.pass.created", pass_body(spend_cap={"minor": 1000, "currency": "USD"}))
    add(erased, "task.decision", decision_body())
    add(erased, "task.execution", execution_body())
    add(erased, "delivery.attestation", erased_body)
    add(erased, "settlement", settlement_body())
    add(erased, "task.termination", termination_body())
    write("09_erased_content.json", erased.bundle())
    record("09_erased_content.json", "INSUFFICIENT_EVIDENCE")

    anchored = minimal_chain(spec=SPEC_01).bundle()
    anchored["anchors"] = [
        {"target": anchored["receipts"][0]["receipt_id"], "hash": "sha256:" + "de" * 32}
    ]
    write("10a_anchor_invalid.json", anchored)
    record("10a_anchor_invalid.json", "UNTRUSTED", "anchor_invalid")

    write("10b_anchor_missing.json", minimal_chain(spec=SPEC_01).bundle())
    record("10b_anchor_missing.json", "PROVISIONAL", require_anchor=True, note="--require-anchor")

    # --- 0.2 additions ------------------------------------------------------
    succession = chain()
    add(succession, "session.pass.created", pass_body(spend_cap={"minor": 1000, "currency": "USD"}))
    add(succession, "task.decision", decision_body())
    add(succession, "task.execution", execution_body())
    add(succession, "authority.succession", succession_body())
    add(succession, "delivery.attestation", delivery_body())
    add(succession, "settlement", settlement_body())
    add(succession, "task.termination", termination_body())
    write("11_succession_handoff.json", succession.bundle())
    record("11_succession_handoff.json", "TRUSTED", note="0.2 authority.succession")

    write("12_ms_timestamps.json", minimal_chain(ms=True).bundle())
    record("12_ms_timestamps.json", "TRUSTED", note="0.2 millisecond timestamps")

    attested = chain()
    add(attested, "session.pass.created", pass_body(spend_cap={"minor": 1000, "currency": "USD"}))
    add(attested, "task.decision", decision_body())
    add(attested, "task.execution", execution_body())
    att_body = delivery_body()
    att_body["counterparty"]["attestation"] = records.sign_body_attestation(
        att_body, COUNTERPARTY_KEY, COUNTERPARTY_DID
    )
    add(attested, "delivery.attestation", att_body)
    add(attested, "settlement", settlement_body())
    add(attested, "task.termination", termination_body())
    write("13_attestation_valid.json", attested.bundle())
    record("13_attestation_valid.json", "TRUSTED", note="0.2 counterparty attestation")

    tampered_att = chain()
    add(tampered_att, "session.pass.created", pass_body(spend_cap={"minor": 1000, "currency": "USD"}))
    add(tampered_att, "task.decision", decision_body())
    add(tampered_att, "task.execution", execution_body())
    bad_body = delivery_body()
    attestation = records.sign_body_attestation(bad_body, COUNTERPARTY_KEY, COUNTERPARTY_DID)
    attestation["value"] = "A" + attestation["value"][1:]
    bad_body["counterparty"]["attestation"] = attestation
    add(tampered_att, "delivery.attestation", bad_body)
    add(tampered_att, "settlement", settlement_body())
    add(tampered_att, "task.termination", termination_body())
    write("13b_attestation_tampered.json", tampered_att.bundle())
    record("13b_attestation_tampered.json", "UNTRUSTED", "bad_attestation", note="0.2 attestation tampered")

    revoked = minimal_chain().bundle()
    revoked["revocations"] = [revocation_statement(GATE_DID, GATE_KEY, "2020-01-01T00:00:00Z")]
    write("14a_revoked_key.json", revoked)
    record("14a_revoked_key.json", "UNTRUSTED", "key_revoked", note="revocation before issuance")

    after = minimal_chain().bundle()
    after["revocations"] = [revocation_statement(GATE_DID, GATE_KEY, "2030-01-01T00:00:00Z")]
    write("14b_revocation_after_issue.json", after)
    record("14b_revocation_after_issue.json", "TRUSTED", note="revocation after issuance")

    merkle = chain()
    add(merkle, "session.pass.created", pass_body())
    add(merkle, "task.decision", decision_body(provenance_hash=merkle_digest("sources:gate-only")))
    add(merkle, "task.execution", execution_body())
    add(merkle, "task.termination", termination_body())
    write("15_merkle_provenance.json", merkle.bundle())
    record("15_merkle_provenance.json", "TRUSTED", note="0.2 merkle provenance root")

    bad_prov = chain()
    add(bad_prov, "session.pass.created", pass_body())
    add(bad_prov, "task.decision", decision_body(provenance_hash="blake3:" + "ab" * 32))
    add(bad_prov, "task.execution", execution_body())
    add(bad_prov, "task.termination", termination_body())
    write("15b_provenance_invalid.json", bad_prov.bundle())
    record(
        "15b_provenance_invalid.json",
        "UNTRUSTED",
        "provenance_invalid",
        note="unsupported hash form",
        schema_valid=False,
    )

    anchor_typed = minimal_chain().bundle()
    first = anchor_typed["receipts"][0]
    anchor_typed["anchors"] = [
        {
            "target": first["receipt_id"],
            "hash": receipt_digest(first),
            "anchor": {"type": "quantum-teleport", "value": "n/a"},
        }
    ]
    write("10c_anchor_unknown_type.json", anchor_typed)
    record(
        "10c_anchor_unknown_type.json",
        "UNTRUSTED",
        "anchor_invalid",
        note="0.2 anchor type enum",
        schema_valid=False,
    )

    # --- 0.3 additions ------------------------------------------------------
    agreement = chain(SPEC_03)
    add(agreement, "session.pass.created", pass_body(spend_cap={"minor": 1000, "currency": "USD"}))
    offer_receipt = add(agreement, "agreement.offer", offer_body())
    add(agreement, "agreement.accept", accept_body(receipt_digest(offer_receipt)))
    add(agreement, "task.decision", decision_body())
    add(agreement, "task.execution", execution_body())
    add(agreement, "task.termination", termination_body())
    write("16_offer_accept.json", agreement.bundle())
    record("16_offer_accept.json", "TRUSTED", note="0.3 offer/accept binding")

    mismatch = chain(SPEC_03)
    add(mismatch, "session.pass.created", pass_body(spend_cap={"minor": 1000, "currency": "USD"}))
    offer_receipt = add(mismatch, "agreement.offer", offer_body())
    add(mismatch, "agreement.accept", accept_body(receipt_digest(offer_receipt), terms_hash=digest("terms:other")))
    add(mismatch, "task.decision", decision_body())
    add(mismatch, "task.execution", execution_body())
    add(mismatch, "task.termination", termination_body())
    write("16b_offer_terms_mismatch.json", mismatch.bundle())
    record("16b_offer_terms_mismatch.json", "UNTRUSTED", "offer_mismatch", note="0.3 accept terms mismatch")

    expired = chain(SPEC_03)
    add(expired, "session.pass.created", pass_body(spend_cap={"minor": 1000, "currency": "USD"}))
    offer_receipt = add(expired, "agreement.offer", offer_body(valid_until="2020-01-01T00:00:00Z"))
    add(expired, "agreement.accept", accept_body(receipt_digest(offer_receipt)))
    add(expired, "task.decision", decision_body())
    add(expired, "task.execution", execution_body())
    add(expired, "task.termination", termination_body())
    write("16c_offer_expired.json", expired.bundle())
    record("16c_offer_expired.json", "UNTRUSTED", "offer_expired", note="0.3 accept after valid_until")

    absent = chain(SPEC_03)
    add(absent, "session.pass.created", pass_body(spend_cap={"minor": 1000, "currency": "USD"}))
    add(absent, "agreement.accept", accept_body(digest("offer:absent")))
    add(absent, "task.decision", decision_body())
    add(absent, "task.execution", execution_body())
    add(absent, "task.termination", termination_body())
    write("16d_accept_without_offer.json", absent.bundle())
    record(
        "16d_accept_without_offer.json",
        "INSUFFICIENT_EVIDENCE",
        note="0.3 accept references an offer absent from the bundle",
    )

    terms_salt = keys.random_salt_hex()
    terms_value = "https://example.com/terms/recall-pilot-1"
    terms_ref_redacted = {"redacted": True, "commit": commit_field(terms_salt, terms_value)}

    redacted_terms = chain(SPEC_03)
    add(redacted_terms, "session.pass.created", pass_body(spend_cap={"minor": 1000, "currency": "USD"}))
    offer_receipt = add(redacted_terms, "agreement.offer", offer_body(terms_ref=terms_ref_redacted))
    add(redacted_terms, "agreement.accept", accept_body(receipt_digest(offer_receipt)))
    add(redacted_terms, "task.decision", decision_body())
    add(redacted_terms, "task.execution", execution_body())
    add(redacted_terms, "task.termination", termination_body())
    write("16e_offer_terms_redacted.json", redacted_terms.bundle())
    record(
        "16e_offer_terms_redacted.json",
        "PROVISIONAL",
        note="0.3 redacted terms_ref without disclosure",
    )

    disclosed_terms = redacted_terms.bundle()
    disclosed_terms["disclosure_map"] = {
        "receipts[1].body.terms_ref": {"salt": terms_salt, "value": terms_value}
    }
    write("16f_offer_terms_disclosed.json", disclosed_terms)
    record(
        "16f_offer_terms_disclosed.json",
        "TRUSTED",
        note="0.3 redacted terms_ref disclosed selectively",
    )

    # --- indexes ------------------------------------------------------------
    (VECTORS / "manifest.json").write_text(
        json.dumps({"spec": SPEC_03, "vectors": rows}, indent=2) + "\n", encoding="utf-8"
    )

    index_lines = [
        "# Continuity Receipt — test vector index",
        "",
        "Generated by `tools/make_vectors.py`; machine-readable expectations in `manifest.json`.",
        "Verify with:",
        "`python3 -m continuity_receipt.verify vectors/<file> [--require-anchor]`",
        "",
        "| Vector | Expected verdict | Primary error | Notes |",
        "|---|---|---|---|",
    ]
    for row in rows:
        index_lines.append(
            f"| {row['file']} | {row['expected_verdict']} | {row['expected_code'] or '—'} | {row['note']} |"
        )
    (VECTORS / "INDEX.md").write_text("\n".join(index_lines) + "\n", encoding="utf-8")

    print(f"wrote {len(rows)} vectors to {VECTORS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
