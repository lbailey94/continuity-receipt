# DRAFT — W3C CG intro message for operator review (2026-10-15)

**Status:** draft only. Nothing has been sent or posted; no W3C action has been
taken on the project's behalf. Publication/sending is the operator's decision
(CG participation is individual). Edit freely — the voice is yours. Companion
documents: `docs/CROSSWALK_W3C_AGENT_IDENTITY_CG_v0.md` (refreshed 2026-10-15),
`docs/W3C_AGENT_IDENTITY_CG_BRIEF_2026-10-06.md`, `SPEC_0.6_PQ_PROFILE_DRAFT.md`.

## Why now

- The CG's **2026-10-20** meeting agenda is published; additional topics go
  under **AOB (§6)**. The following meeting is **2026-11-17** (IIW 43, Nov 3–6,
  intervenes).
- The W3C-facing materials were refreshed to CPR nomenclature on 2026-10-15
  (commit `1be7a1f`); the repository is public (Apache-2.0) so links are safe
  to paste.

## Two light-touch paths (choose one or neither)

**A. List intro (async).** Join the CG at
<https://www.w3.org/community/agent-identity/> and post the draft below to
`public-agent-identity@w3.org` (per the agenda, the list is the publication
surface; subscription mechanics are on the group page). Timing: any time
before 2026-10-20 maximizes relevance.

**B. Call + AOB (sync).** Join the 2026-10-20 call (15:00 UTC) and raise a
≤1-minute note under AOB: introduce CPR, point at the crosswalk, offer
correctness feedback. Listening-first; no presentation unless invited by the
chair.

## Draft message (bounded; reuses the crosswalk §1 wording)

> **Subject:** Intro — Causal Provenance Receipts (CPR) and the group's themes
> (informational)
>
> Hello — a short introduction and one informational pointer; corrections-only,
> please.
>
> I maintain CPR (Causal Provenance Receipts; earlier "continuity receipts" —
> renamed to avoid collision with draft-nikolaichuk-scitt-continuity-receipts,
> which registers SCITT recovery statements). It is a published format for
> signed agent-task records with offline-verifiable integrity, chain links,
> agreement references, and optional revocation/anchor evidence, with
> Python/Rust/JavaScript verifiers and a public vector corpus:
> <https://github.com/lbailey94/continuity-receipt> (Apache-2.0).
>
> What the verifier checks are the signed claims and their configured
> bindings. It does not prove that issuer claims correspond to real-world
> events, and its `did:key` identifiers do not establish a real-world
> principal, authorization, or permission to act. Missing and contradictory
> evidence remain distinct verdict states.
>
> For the group's registry themes — identifier binding, collisions vs.
> resolution failure, revocation/currentness, delegation boundaries,
> provenance vs. content — I wrote a bounded crosswalk:
> <https://github.com/lbailey94/continuity-receipt/blob/main/docs/CROSSWALK_W3C_AGENT_IDENTITY_CG_v0.md>.
> It is an informational local comparison — not endorsed by W3C or any draft
> author, and no prior-art claim.
>
> If the landscape document would benefit from a factual per-project entry
> when entries open (published vectors + independent verifiers as a
> conformance-evidence surface), I can provide one. Otherwise, please ignore
> this note — and I'm happy to answer any corrections.
>
> Best regards,
> Lucas

## Cautions (from the bounded-language rules)

- No adoption, endorsement, or prior-art claims; nothing on behalf of anyone
  but the sender.
- Use "CPR"; mention the former name once, to explain the transition (wire
  identifiers remain `continuity-receipt/0.x`).
- If PQ comes up: format-level dual-signature profile only
  (`SPEC_0.6_PQ_PROFILE_DRAFT.md`); not an identity claim.
- The crosswalk's §4 question list is for live discussion only (one question
  max if asked).

## Open items for the operator

1. Join status: whether the sender is already a CG participant (posting
   mechanics may differ).
2. Whether to take path A, B, both, or defer to November.
3. Confirm the landscape-entry offer (it is the only forward-leaning sentence).
