"""Agreement emitters (0.3 + 0.4): builders produce bundles that verify as intended."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from continuity_receipt import keys  # noqa: E402
from continuity_receipt.agreements import (  # noqa: E402
    accept_body,
    bind_body,
    offer_body,
    terms_hash,
)
from continuity_receipt.bundle import TaskChain  # noqa: E402
from continuity_receipt.verify import verify_bundle  # noqa: E402

SPEC = "continuity-receipt/0.3"
SPEC_04 = "continuity-receipt/0.4"
GATE_DID, GATE_KEY = keys.generate(keys.deterministic_seed("agreement-gate"))
AGENT_DID, AGENT_KEY = keys.generate(keys.deterministic_seed("agreement-agent"))
TERMS = {"service": "hosted recall", "calls": 10000, "price_minor": 500, "currency": "USD"}


def pass_body() -> dict:
    return {
        "gate_id": "gate-lite-1", "mandala_class": "gate-lite",
        "quotas": {"cpu_ms": 0, "mem_mb": 0, "disk_mb": 0, "wall_ms": 1000},
        "expires_at": "2030-01-01T00:00:00Z", "policy_version": "p1",
        "mandate_ref": "sha256:" + "0" * 64, "agent_id": AGENT_DID,
    }


def decision_body() -> dict:
    return {
        "action": "agreement.accept", "action_args_hash": "sha256:" + "1" * 64,
        "model": {"provider": "local", "id": "wm"},
        "input_provenance": {"observed_sources_hash": "sha256:" + "2" * 64},
        "decision": "allow", "policy_version": "p1",
    }


def termination_body() -> dict:
    return {"reason": "completed", "limits_at_stop": {}, "remaining": {}}


def base_chain(spec: str = SPEC) -> TaskChain:
    chain = TaskChain(spec=spec)
    chain.add("session.pass.created", "gate", GATE_DID, GATE_KEY, pass_body())
    return chain


def finish(chain: TaskChain) -> dict:
    chain.add("task.decision", "gate", GATE_DID, GATE_KEY, decision_body())
    chain.add("task.termination", "gate", GATE_DID, GATE_KEY, termination_body())
    return chain.bundle()


class TestAgreements(unittest.TestCase):
    def test_offer_accept_round_trip_verifies(self):
        chain = base_chain()
        offer = chain.add("agreement.offer", "gate", GATE_DID, GATE_KEY,
                          offer_body("offer-1", AGENT_DID, TERMS, "2030-01-01T00:00:00Z", "n-1"))
        chain.add("agreement.accept", "agent", AGENT_DID, AGENT_KEY, accept_body(offer))
        result = verify_bundle(finish(chain))
        self.assertEqual(result.verdict, "TRUSTED", result.errors)

    def test_terms_stay_off_receipt(self):
        body = offer_body("offer-1", AGENT_DID, TERMS, "2030-01-01T00:00:00Z", "n-1")
        serialized = json.dumps(body)
        self.assertNotIn("hosted recall", serialized)
        self.assertEqual(body["terms_hash"], terms_hash(TERMS))

    def test_mismatched_terms_fail(self):
        chain = base_chain()
        offer = chain.add("agreement.offer", "gate", GATE_DID, GATE_KEY,
                          offer_body("offer-1", AGENT_DID, TERMS, "2030-01-01T00:00:00Z", "n-1"))
        accept = accept_body(offer)
        accept["terms_hash"] = terms_hash({"service": "something else"})
        chain.add("agreement.accept", "agent", AGENT_DID, AGENT_KEY, accept)
        result = verify_bundle(finish(chain))
        self.assertEqual(result.verdict, "UNTRUSTED")
        self.assertIn("offer_mismatch", result.codes())

    def test_expired_offer_fails(self):
        chain = base_chain()
        offer = chain.add("agreement.offer", "gate", GATE_DID, GATE_KEY,
                          offer_body("offer-1", AGENT_DID, TERMS, "2020-01-01T00:00:00Z", "n-1"))
        chain.add("agreement.accept", "agent", AGENT_DID, AGENT_KEY, accept_body(offer))
        result = verify_bundle(finish(chain))
        self.assertEqual(result.verdict, "UNTRUSTED")
        self.assertIn("offer_expired", result.codes())

    def test_bad_valid_until_rejected_at_emit(self):
        with self.assertRaises(ValueError):
            offer_body("offer-1", AGENT_DID, TERMS, "tomorrow", "n-1")


class TestAgreement04(unittest.TestCase):
    def bound_chain(self):
        chain = base_chain(SPEC_04)
        offer = chain.add("agreement.offer", "gate", GATE_DID, GATE_KEY,
                          offer_body("offer-1", AGENT_DID, TERMS, "2030-01-01T00:00:00Z", "n-1"))
        accept = chain.add("agreement.accept", "agent", AGENT_DID, AGENT_KEY, accept_body(offer))
        return chain, offer, accept

    def test_binding_round_trip_verifies(self):
        chain, _offer, accept = self.bound_chain()
        chain.add("task.decision", "agent", AGENT_DID, AGENT_KEY,
                  bind_body(decision_body(), accept))
        chain.add("task.termination", "agent", AGENT_DID, AGENT_KEY, termination_body())
        result = verify_bundle(chain.bundle())
        self.assertEqual(result.verdict, "TRUSTED", result.errors)

    def test_unbound_offeree_stage_is_provisional(self):
        chain, _offer, _accept = self.bound_chain()
        chain.add("task.decision", "agent", AGENT_DID, AGENT_KEY, decision_body())
        chain.add("task.termination", "agent", AGENT_DID, AGENT_KEY, termination_body())
        result = verify_bundle(chain.bundle())
        self.assertEqual(result.verdict, "PROVISIONAL")
        self.assertTrue(
            any(reason.startswith("missing_agreement_ref:") for reason in result.provisional_reasons)
        )
        self.assertTrue(
            any(reason.startswith("agreement_unreferenced:") for reason in result.provisional_reasons)
        )

    def test_accept_must_be_signed_by_offeree(self):
        chain = base_chain(SPEC_04)
        offer = chain.add("agreement.offer", "gate", GATE_DID, GATE_KEY,
                          offer_body("offer-1", AGENT_DID, TERMS, "2030-01-01T00:00:00Z", "n-1"))
        chain.add("agreement.accept", "gate", GATE_DID, GATE_KEY, accept_body(offer))
        chain.add("task.termination", "agent", AGENT_DID, AGENT_KEY, termination_body())
        result = verify_bundle(chain.bundle())
        self.assertEqual(result.verdict, "UNTRUSTED")
        self.assertIn("offeree_mismatch", result.codes())

    def test_legacy_envelope_ignores_agreement_ref(self):
        chain = base_chain(SPEC)
        offer = chain.add("agreement.offer", "gate", GATE_DID, GATE_KEY,
                          offer_body("offer-1", AGENT_DID, TERMS, "2030-01-01T00:00:00Z", "n-1"))
        chain.add("agreement.accept", "agent", AGENT_DID, AGENT_KEY, accept_body(offer))
        decision = decision_body()
        decision["agreement_ref"] = "sha256:" + "3" * 64
        chain.add("task.decision", "agent", AGENT_DID, AGENT_KEY, decision)
        chain.add("task.termination", "agent", AGENT_DID, AGENT_KEY, termination_body())
        result = verify_bundle(chain.bundle())
        self.assertEqual(result.verdict, "TRUSTED", result.errors)


if __name__ == "__main__":
    unittest.main(verbosity=2)
