# Brief: W3C Agent Identity Registry Protocol CG call — 2026-10-06

**Status:** prep note, 2026-09-30. For Lucas (human principal) and any
WhiteMagic seat observing the call. The chair posted the agenda on 2026-09-29;
this is our positioning, artifacts, and questions — no commitments.

## 1. Our position in one paragraph

`continuity-receipt/0.5` records governed agent tasks as signed, hash-chained,
offline-verifiable evidence. It **references** identity (`did:key` issuer
binding, revocation statements, `authority.succession`) but does not
provision identities, authenticate workloads, or decide authorization — that
is the identity layer's job, and we compose with it (WIMSE AIMS mapping is
documented; Entra/Okta are enterprise paths we map to, not rebuild). We
participate in the CG to align identity semantics with what receipts need to
say, not to propose a competing identity mechanism.

## 2. Artifacts we can offer (if asked)

- Crosswalks: `CROSSWALK_SAHU_ACTA_ASQAV.md`, `CROSSWALK_AER1_AADP_SCITT.md`
  and probes: sahu vector reproduction, AER-1 live receipt probe
  (`tools/interop_aer1_probe.py`).
- Representation-session design note (`DESIGN_NOTE_REPRESENTATION_SESSION.md`)
  — relevant if the CG touches delegated human representation.
- A bounded-proof discipline worth naming in specification text: a receipt
  attests what its issuer signed, not that events occurred; missing evidence
  is distinguished from false evidence (`INSUFFICIENT_EVIDENCE` ≠ false).

## 3. Questions to ask / things to listen for

1. **Revocation distribution.** How does the CG expect agent credential
   revocation to propagate to verifiers (CR has its own revocation
   statements; alignment matters).
2. **Attestation composition.** How do RATS-family attestations (PTV and
   hardware-anchored agent identity) bind to the DID/VC identity the CG
   defines? Needed for `runner_profile`/sandbox assertions in receipts.
3. **Delegation chains.** Agent-to-agent mandates with revocation — is the
   CG scoping delegation semantics, or deferring to WIMSE/OAuth?
4. **Post-quantum migration.** Any CG timeline that would force receipt
   signature agility (we are Ed25519-only today, disclosed).
5. **Representation sessions.** Overlap with our representation-session note;
   if the CG productizes the concept, decide compose vs cede early.

## 4. Speaking notes

- Lead with evidence, not ambition: probes and crosswalks exist; no adoption
  or endorsement claims about any draft or author.
- Do not pitch hosting or pricing; this is a standards venue.
- Offer async follow-up with artifacts; ask who owns the revocation and
  attestation-composition topics.
- Log anything said about "continuity", "representation", or "receipts" and
  bring it back to the positioning ledger.

## 5. References

- CG: https://www.w3.org/community/agent-identity/ (agenda 2026-09-29)
- PTV: draft-anandakrishnan-rats-ptv-agent-identity-01
- AER-1: draft-zambo-aer1-04 · SCITT continuity receipts:
  draft-nikolaichuk-scitt-continuity-receipts-01
