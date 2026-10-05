# SCITT profile plan: an IETF home for agent session continuity receipts

**Status:** plan (2026-10-05). No draft submitted. Requires operator approval
for any IETF submission or list message. This note is the internal plan; it is
not an adoption claim.

## Why SCITT, and why now

- **RFC 9943** (SCITT architecture) and **RFC 9942** (COSE receipts) were
  published June 2026. Registered media types exist only for SCITT
  statements/receipts — **no agent-action content types**.
- At IETF 126 (July 2026) a straw poll (~11/6/5, verify against the session
  materials before quoting) supported SCITT taking on **application-level
  payload interoperability**; chairs/ADs were to decide structure (recharter
  vs conventions/registries) **ahead of IETF 127**. That decision window is
  the single best standards opportunity in this cycle.
- The competing cluster (AER-1, Sahu, NOA, AAC, agentreceipts, DRP) is
  individual-draft-only; AER-1 is the strongest (7 languages, 45 vectors,
  anchored, 10 revisions in 10 days). The bar is now **conformance vectors +
  independent implementations + external anchoring** — which CR already has.
- **Name collision:** `draft-nikolaichuk-scitt-continuity-receipts` (-01,
  2026-09-29) registers *stateful-asset recovery* and calls the result a
  "Continuity Receipt." Our external name is **"agent continuity receipt"**;
  any IETF title must avoid the bare phrase.

## Proposed draft

**Title:** *Agent Session Continuity Receipt: A SCITT Profile*
(working filename `draft-<author>-scitt-agent-session-receipt`).

**Shape:** reuse, don't reinvent.
- Envelope: COSE_Sign1 Signed Statement over a **JCS-canonical payload**
  (RFC 8949 + RFC 8785), registered at a Transparency Service to obtain
  RFC 9942 receipts. The CR bundle remains the payload; the profile defines
  the payload type, required members, and verdict-relevant rules.
- Registration is **optional** in the base profile (offline-first), with an
  `anchored`/`registered` disclosure; a consumer profile may require it.
- Reuse the existing four-value verdict enum
  (`TRUSTED / PROVISIONAL / INSUFFICIENT_EVIDENCE / UNTRUSTED`), stating
  explicitly that it aligns with CTQ's closed enum (identical strings) and
  mapping to CTQ `chain_ref` via the head commitment
  (`DESIGN_NOTE_HEAD_COMMITMENT.md`).

**Explicit boundaries (state these in the draft, not just the repo):**
- Attests what the issuer signed, not that events occurred.
- Does not prove runtime confinement, identity, or principal authorization
  (0.6 `authority.grant` is assertion-grade; principal-authorized delegation
  is a separate consumer profile).
- Truncation: closed only by the head commitment + anchor/registration.

**Cross-references:** RFC 9943/9942; `draft-nikolaichuk` (disambiguation);
NOA, AAC, AER-1, Sahu (sibling work, cross-referenced by grain: they are
per-action, we are session-lifecycle); W3C AI Agent Memory CG (audit
anchors/erasure liaison); CTQ.

## Venue sequencing

1. **Now:** post an individual I-D (citable name; 6-month expiry — iterate
   fast). Discuss on `scitt@ietf.org`. IETF hygiene: BCP 78/79 IPR rules;
   consider an explicit IPR statement; Apache-2.0/royalty-free posture is an
   adoption asset. Include an implementation-status section (RFC 7942) citing
   the Python, Rust, and JS verifiers + the hosted referee.
2. **If SCITT recharters for payload conventions:** seek WG adoption with
   co-authors from ≥ 2 organizations; the conformance corpus + 3
   implementations are the argument.
3. **Parallel (low cost):** a W3C AI Agent Memory CG use-case/profile
   touchpoint (liaison, not normative home).
4. **Later:** AAIF/LF for reference-implementation governance once external
   use exists; x402 Foundation only for the settlement profile; FIDO as
   liaison for identity/delegation alignment.

## Draft outline (suggested)

1. Introduction — agent sessions, continuity, why per-action receipts do not
   cover it.
2. Terminology + disambiguation from asset-recovery "continuity receipts."
3. Payload type + required members (map to CR spec sections).
4. Verdict rules + error-code classes (normative references to the CR spec).
5. Registration profile (optional; RFC 9942 receipt handling).
6. Head commitment + anchoring (normative reference to the design note once
   landed).
7. Consumer profiles (head-committed; authority-required; regulated-retention).
8. Implementation status (Python/Rust/JS + vectors + hosted referee).
9. Security considerations (issuer honesty, truncation, replay, key
   revocation distribution — reuse THREAT_MODEL.md).
10. IANA considerations (media type request `application/agent-continuity-receipt+json`?).

## Open questions / decisions for the operator

- Author identity and affiliation to use on the I-D.
- Whether to file before or after the 0.6 freeze (leaning: before — the
  window is the SCITT recharter decision, not our freeze).
- Whether to request a media type now (the sibling drafts have pending
  requests; a joint registration could be cleaner).
- Appetite for co-authors: an I-D with one author is normal; WG adoption
  will want more.
