# Design note: external evidence references (0.6 candidate)

**Status:** design note, 2026-09-30. Non-normative; candidate material for a
future spec revision (0.6+). No wire format changes are proposed for
`continuity-receipt/0.5`. Companion to `CROSSWALK_AER1_AADP_SCITT.md`.

## 1. Motivation

The IETF landscape now carries receipts at three granularities we do not
re-implement: per-execution (AER-1), per-decision authorization (AADP bound
permits), and recovery registration in transparency logs (SCITT continuity
receipts). Our chain is the lifecycle that binds agreement → authority →
decision → execution → delivery → termination → settlement, verified offline.
The useful move is not to absorb their formats but to **reference them**:
CR records should be able to point at external evidence and prove it stayed
intact, without making external availability a verification dependency.

Precedent: the 0.2 anchor types (`opentimestamps` | `public-chain` | `custom`)
already externalize time proof. This note generalizes the pattern to receipts
and permits.

## 2. Proposal A — per-record external references

A candidate convention (not yet a field definition):

```
external_ref = {
  kind:   "aer1-receipt" | "aadp-permit" | "scitt-receipt" | string,
  id:     string,                 # the external object's identifier
  digest: "sha256:<hex>",         # commitment to the referenced bytes
  url?:   string,                 # optional locator; never required
}
```

- **Where.** `task.execution` and `delivery.attestation` bodies carry
  fine-grained evidence refs; `task.decision` carries the decision/permit
  ref (Proposal B).
- **Semantics (bounded-proof discipline, unchanged).** A ref is evidence,
  not a verdict input: an unresolvable or unreferenced ref lowers the
  verdict to `PROVISIONAL`/`INSUFFICIENT_EVIDENCE` under the same logic as
  missing evidence today; a *checked* digest mismatch is `UNTRUSTED`. The
  presence of an external ref MUST NOT upgrade a verdict on its own.
- **Digest scope.** The digest commits to the external object's own
  serialization (e.g., for AER-1, the verifier record bytes or the canonical
  receipt view — decide per kind in the mapping table). Locators (`url`)
  are advisory; verification must survive their disappearance by relying on
  the digest and, where required, embedded evidence.
- **Privacy.** Locators can leak context; make `url` optional and prefer
  digest-first referencing. Redaction interplay: refs inside redacted
  regions follow existing salted-commitment rules.

## 3. Proposal B — decision/permit portal

For cross-organization flows, the decision record may reference the
authorization envelope that governed the request:

```
authorization_ref = external_ref(kind="aadp-permit", ...)
```

AADP bound permits bind one recipient, presenter key, HTTP request and
action instance, and leave mandates to other specifications — the same
division of labor this spec expects (we record; we do not decide). A permit
digest in `task.decision` lets a verifier tie the executed action to the
exact decision that authorized it without CR re-implementing request
binding. Requires a study pass over AADP §3–§7 (HTTP Message Signatures,
currentness) before any field is proposed.

## 4. Proposal C — state commitments and SCITT registration

`state.commitment` (0.5) commits to chain-head or file-snapshot state. The
SCITT continuity-receipt draft registers *recovery events* of stateful
assets in transparency logs. The two are complementary:

- a CR `state.commitment` digest could be registered as (or referenced by) a
  SCITT recovery statement, giving agent state restoration a
  transparency-log anchor;
- conversely, a SCITT receipt (proof of log position) could travel as an
  `external_ref` on a CR record, sibling to existing anchor types.

Feasibility depends on the SCITT registration API (`draft-ietf-scitt-scrapi`)
and the transparency service's registration policy; assess before proposing.
Naming caution from the companion triage applies: use "agent continuity
receipt" in external copy.

## 5. Open questions

1. Digest scopes per external kind (raw bytes vs canonical view vs verifier
   record) — pin in the mapping table, not in prose.
2. Ref revocation: external objects may be revoked by their issuer; CR has
   its own revocation statements. Decide whether refs inherit revocation
   lookup or stay self-contained.
3. Embedding vs referencing: allow inline embedding of small receipts
   (verifier record) to keep offline verification intact when locators die.
4. Interop probes to land first: AER-1 live probe (done —
   `tools/interop_aer1_probe.py`), AADP feasibility probe (pending), SCITT
   SCRAPI note (pending).
