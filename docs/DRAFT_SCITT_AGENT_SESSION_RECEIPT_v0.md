# Causal Provenance Receipts for Agent Sessions — A SCITT Profile

**Working title (I-D):** *Causal Provenance Receipts for Agent Sessions: A SCITT Profile*
**Alternative titles:** *Agent Session Receipts: A SCITT Content-Type Profile*
**Avoid:** the bare phrase "Continuity Receipt" — collision with
`draft-nikolaichuk-scitt-continuity-receipts-01` (stateful-asset recovery).

**Status:** skeleton (v0, 2026-10-15) for internal review. **Not submitted.**
No IETF correspondence has been sent; per
`docs/SCITT_PROFILE_PLAN.md`, any submission or list message requires operator
approval. TODO markers below are deliberate, not oversights.

**Author:** TODO (operator decision: name + affiliation to use on an I-D).
**Repository:** <https://github.com/lbailey94/continuity-receipt> (Apache-2.0)
**Reference verifiers:** Python · Rust · JavaScript (`continuity-receipt@0.1.1`
on npm) · hosted referee at `api.whitemagic.dev/conformance`.

## Abstract

This document defines a SCITT payload profile for **agent session provenance**:
signed records that bind an agent session's lifecycle (start, state
transitions, termination, settlement) to offline-verifiable evidence, with an
explicit head commitment that closes local hash-chain truncation. It reuses
the SCITT architecture (RFC 9943) and COSE receipt envelope (RFC 9942):
the CPR receipt bundle is the payload; registration is optional and
disclosed. The profile supplies what per-action sibling work does not cover —
the **session lifecycle and its resumption evidence** — and carries the
bounded semantics of the CPR specification: a verifier checks signed claims
and their bindings; it does not prove that events occurred.

## 1. Introduction

Autonomous agent work happens in **sessions**: bounded stretches of activity
that crash, reset, and resume. Per-action receipts (AER-1, NOA, AAC, Sahu
AADP) attest individual actions; none of them answers "was this the same
session, and is its record complete?" — the question that matters after a
context-window reset, a machine reboot, or an operator hand-off between
agents. CPR (Causal Provenance Receipts; wire identifiers
`continuity-receipt/0.x`) is a published format for exactly that lifecycle,
with reference verifiers and a public conformance corpus.

This profile's contribution to SCITT is narrow and additive: a **payload
content type** and its rules, for Signed Statements over JCS-canonical CPR
receipts. It does not change the SCITT architecture or the COSE receipt
envelope.

## 2. Terminology and disambiguation

- **CPR / Causal Provenance Receipts** — the standard described here (formerly
  published as "Continuity Receipts"; renamed to avoid collision with
  `draft-nikolaichuk-scitt-continuity-receipts`, which registers *stateful
  asset recovery*). Wire identifiers remain `continuity-receipt/0.x`.
- **Session** — a bounded agent activity interval, identified by a
  `subject` and bound to a `store`/state head.
- **Head commitment (`chain_head`)** — final-receipt commitment over the
  chain; closes truncated-chain reconstruction.
- Verdict vocabulary: `TRUSTED / PROVISIONAL / INSUFFICIENT_EVIDENCE /
  UNTRUSTED` — identical strings to CTQ's closed enum (alignment section TODO
  with a normative mapping note).

## 3. Payload type and required members

- Envelope: **COSE_Sign1 Signed Statement over a JCS-canonical payload**
  (RFC 8949 CBOR context + RFC 8785 JCS for the canonical view; see
  `docs/SCITT_MAPPING_AND_COSE_SIGN1_FEASIBILITY.md`).
- Required members: TODO (derive the normative table from `SPEC.md` §receipt
  envelope + `SPEC_0.6_DRAFT.md`; flag 0.6-only members explicitly).
- Media type: TODO (decision item — `application/agent-session-receipt+json`?
  joint registration with sibling drafts? see §10).

## 4. Verdict rules and error classes

- Reuse the CPR spec's four verdicts; this profile does not extend them.
- Error-code classes (digest mismatch, signature invalid, chain broken,
  missing/contradictory evidence distinction) — normative reference to the
  CPR spec; the **missing vs. contradictory** distinction is retained
  explicitly (it is load-bearing for relying parties).

## 5. Registration profile (optional)

- Base profile is **offline-first**: no Transparency Service required.
- A receipt MAY be registered per RFC 9942; when registered, the receipt
  MUST disclose it (`registered` / `anchored` flags) and the SCITT receipt
  handling rules apply unchanged.
- A consumer profile MAY require registration (see §7).

## 6. Head commitment and anchoring

- The `chain_head` member commits to the final receipt of a chain; its
  verification rules are normative in the CPR spec + head-commitment design
  note. Truncation is closed only by head commitment **plus** an anchor or
  registration.
- Anchoring maps to OpenTimestamps (implemented; verifier support in all
  three implementations) and SHOULD be described against
  `draft-fassbender-scitt-time-anchor` (mapping TODO).

## 7. Consumer profiles (informative here; normative in the CPR spec)

- **Head-committed** — requires `chain_head`; typical for session resumption.
- **Authority-required** — requires an `authority.grant` reference;
  assertion-grade only (a signed issuer/operator assertion; it does not prove
  the signer was authorized by the named principal).
- **Regulated-retention** — maps to demand-side evidence surfaces
  (EU AI Act logging, SEC 17a-4-style retention, AIUC-1 E015.x alternates;
  see `docs/CROSSWALK_DEMAND_2026-10.md`).

## 8. Implementation status (RFC 7942 style)

Verified locally on 2026-10-15 (T4800-S) against the merged `main`:

| Surface | Evidence |
|---|---|
| Python reference | 149 conformance tests; 40 bundles + 21 verification receipts walked by CLI (expected verdicts enforced) |
| Rust verifier | 44 tests incl. all-verification-vectors suite |
| JavaScript verifier | `continuity-receipt@0.1.1` (npm); 130/130 tests; corpus parity |
| Cross-implementation | Python ↔ Rust differential 40/40 |
| Conformance corpus | 85 vector files (incl. anchor + disclosure + verification sub-corpora) |
| Anchoring | OpenTimestamps anchor verification (differential-tested) |
| Hosted referee | `api.whitemagic.dev/conformance` (third-party reports solicited) |
| Other surfaces | plugin skills for 6 agent clients; independent 0.5 producer (trust-without-cloud) |

## 9. Security considerations

- **Issuer honesty**: receipts attest what the issuer signed, not that events
  occurred; state explicitly in the draft (not just the repo).
- **Truncation/equivocation**: closed only via head commitment + anchor /
  registration (§6).
- **Replay / revocation distribution**: TODO (port from `THREAT_MODEL.md` and
  `REVOCATION_DISTRIBUTION.md`; consumer-config ownership).
- **Post-quantum migration**: a dual-signature candidate profile exists
  (`SPEC_0.6_PQ_PROFILE_DRAFT.md`; identical canonical bytes, classical +
  ML-DSA/SLH-DSA, policy separation at the relying party). Status:
  candidate; not in this profile's 0.x scope.
- **Identity boundaries**: `did:key` signatures do not establish a
  real-world principal, workload attestation, or permission to act.

## 10. IANA considerations

TODO — decision: request a media type now, or joint registration with the
sibling cluster. Candidate: `application/agent-session-receipt+json`
(payload) + content-format identifier for the COSE profile. The sibling
drafts have pending media-type requests; a joint registration may be cleaner.

## 11. Open questions (operator decisions)

1. Author identity + affiliation for the I-D.
2. File before or after the 0.6 freeze (plan leans **before** — the moment is
   the SCITT payload-conventions decision ahead of IETF 127, not our freeze).
3. Media-type timing (§10).
4. Co-author appetite (WG adoption will want ≥ 2 organizations; a single-author
   I-D is normal first step).
5. List introduction wording on `scitt@ietf.org` (bounded, like the W3C
   packet: no adoption claims, corrections welcome).

## References (initial set)

- RFC 9943 (SCITT architecture), RFC 9942 (COSE receipts)
- RFC 8785 (JCS), RFC 8949 (CBOR)
- `draft-nikolaichuk-scitt-continuity-receipts` (disambiguation)
- Sibling cluster: AER-1, NOA, AAC, Sahu AADP (per-action grain; informative)
- `draft-fassbender-scitt-time-anchor` (anchoring mapping target)
- W3C AI Agent Memory CG (liaison surface for audit anchors/erasure)
- In-repo: `SPEC.md`, `SPEC_0.6_DRAFT.md`, `docs/SCITT_PROFILE_PLAN.md`,
  `docs/SCITT_MAPPING_AND_COSE_SIGN1_FEASIBILITY.md`,
  `docs/DESIGN_NOTE_HEAD_COMMITMENT.md`, `CONFORMANCE.md`, `THREAT_MODEL.md`

_This skeleton is for internal review; it makes no commitments and has not
been submitted anywhere._
