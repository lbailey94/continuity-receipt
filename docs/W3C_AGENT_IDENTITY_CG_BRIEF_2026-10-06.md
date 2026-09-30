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

## 3. Agenda map (published 2026-10-06; chair: Adolfo Grego Micha)

The group sets order on-call. Our mapping of the published items:

| agenda item | our angle / contribution |
|---|---|
| §4.2 Landscape document | Crosswalks are ready to offer on request (sahu/AER-1/AADP/SCITT probes); do not dump, offer |
| §4.3 DNS vs alternative roots | We are anchor-agnostic (`did:key` + OTS/chain anchors); nothing to push |
| §4.4 C2PA alignment | Composition path worth supporting: content provenance (C2PA) + action provenance (receipts) are complementary |
| §4.5 Authorization scope across organizations | Maps to AADP bound permits; state the local-seam vs cross-boundary split |
| §4.6 Identifier collisions that fail open | **Closest to our design**: registries bind identifiers; we bind revocation + anchors; our revocation statements are prior art |
| §4.7 ARIA / WAI-ARIA disambiguation | Naming hygiene; mention our "agent continuity receipt" guard briefly |
| AOB | Only if natural: the bounded-proof sentence (receipts attest what issuers signed; missing ≠ false) |

Still to ask (async if no slot): revocation distribution mechanics;
attestation (RATS/PTV) ↔ DID binding; PQ timeline for Ed25519-only formats.

## 4. Speaking notes

- Logistics: Tue 2026-10-06, 15:00 UTC (Google Meet link in the agenda file);
  minutes for 09-22 were promised by the chair — read them if published.
- Highest-value slot: §4.6 (collisions that fail open) — volunteer there.
- Lead with evidence, not ambition: probes and crosswalks exist; no adoption
  or endorsement claims about any draft or author.
- Do not pitch hosting or pricing; this is a standards venue.
- Offer async follow-up with artifacts; ask who owns the revocation and
  attestation-composition topics.
- Log anything said about "continuity", "representation", or "receipts" and
  bring it back to the positioning ledger.

## 5. References

- CG: https://www.w3.org/community/agent-identity/ · 2026-10-06 agenda:
  https://github.com/w3c-cg/agent-identity/blob/main/meetings/2026/2026-10-06-agenda.md
  · minutes: https://github.com/w3c-cg/agent-identity/blob/main/meetings/2026/2026-09-22-minutes.md
- PTV: draft-anandakrishnan-rats-ptv-agent-identity-01
- AER-1: draft-zambo-aer1-04 · SCITT continuity receipts:
  draft-nikolaichuk-scitt-continuity-receipts-01
