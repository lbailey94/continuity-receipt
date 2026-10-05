# Design note: final chain-head commitment (truncation / equivocation closure)

**Status:** design note (2026-10-05). Candidate for a 0.7 additive member (or
a 0.6 consumer-profile requirement if the review prefers it there). Not yet a
spec change; no vectors yet.

## The problem

Every local hash chain shares one honest limit: a chain that has been
**truncated and rebuilt** still verifies. A holder of the signing key can
present a shorter history that is internally consistent, and a verifier
cannot tell it from the real one. AER-1 documents the same limit in its
latest revision (`draft-zambo-aer1-10`): a rebuilt truncated chain verifies
unless an **external commitment binds the final entry digest**. SCITT solves
this by design (registration receipts), but requires a transparency service.

For a receipt chain, truncation is exactly the evidence a hostile party would
want: drop the `task.termination` record, drop the failed execution, drop the
revocation. The chain still verifies; the story changes.

## Prior art to align with (verified 2026-10-04/05)

- `draft-zambo-aer1-10` (2026-10-03): explicit truncation-commitment
  guidance; workflow Merkle roots over steps.
- SCITT RFC 9943 / RFC 9942 receipts (transparency registration is the
  general answer; optional for us).
- `draft-fassbender-scitt-time-anchor-07` (Sep 2026): OpenTimestamps as an
  optional temporal proof with explicit `anchor_status` semantics — the
  profile to map our OTS anchors against.
- `draft-hopley-x402-composite-trust-query-01`: `chain_ref` =
  content-addressed audit-chain root; the composite verifier consumes chain
  roots. A head commitment is what makes a CR chain usable as a `chain_ref`.

## Proposal

Add an optional bundle-level member (name TBD) — `chain_head`:

```json
"chain_head": {
  "seq": 7,
  "receipt_id": "urn:uuid:…",
  "digest": "sha256:<JCS-canonical bytes of the final receipt, minus sig>",
  "anchored": {
    "type": "opentimestamps",
    "proof_ref": "https://api.whitemagic.dev/anchors/sha256:…"
  }
}
```

Rules (shape/signature/reference only, matching the spec's discipline):

1. If present, `seq` and `receipt_id` must match the final record, and
   `digest` must equal the computed digest of that record's canonical view.
   A mismatch is `UNTRUSTED` (`head_mismatch`).
2. If `anchored` is present and an anchor is required
   (`--require-anchor`/`?require_anchor=1`), the anchor must resolve per
   `ANCHORING.md`; a missing/invalid proof is `PROVISIONAL`
   (`head_anchor_missing`) / `UNTRUSTED` (`head_anchor_invalid`).
3. Absence of `chain_head` is **not** an error — it is a disclosure: the
   bundle makes no truncation commitment. A consumer profile
   (`head-committed`) may require it; the base verifier must not upgrade a
   verdict merely because it is present.
4. Anchoring the head is the recommended default for published bundles
   (roadmap: "anchored example bundle"). OTS first; a SCITT registration
   receipt can be carried as external evidence later.

## Why this shape

- It commits to the **whole chain** (the final receipt's `prev` link covers
  every earlier record) without changing record semantics or adding a new
  chain.
- It reuses the existing anchor vocabulary and the hosted `/anchors` lane.
- It gives CTQ-style composite verifiers a stable root (`chain_ref`) and
  gives AIUC-1 E015.4's sequence-integrity requirement a direct answer.
- It is additive: old verifiers ignore unknown members; new verifiers check
  when present.

## Work items if adopted

1. Schema addition (0.7 candidate or 0.6 profile) + SPEC section + conformance
   table rows.
2. Vectors: valid head; head mismatch; head with valid anchor; head with
   missing/invalid anchor under `--require-anchor`; legacy bundle without head
   (verdict unchanged).
3. Both implementations + the new JS verifier.
4. Anchor the `examples/01_wm_governed_session` bundle as the first
   head-committed published example, with the five-minute verification path.
5. Cross-reference AER-1's truncation guidance and the fassbender time-anchor
   profile in the spec text.

## Open questions

- Should the head digest commit to the final receipt only, or to a Merkle
  root over all receipts (AER-1 workflow style)? Final-receipt-only is
  smaller and composes with `prev`; Merkle roots allow partial disclosure of
  the chain. Decide with a vector pair.
- Should anchoring be required for `TRUSTED` in the `head-committed`
  consumer profile, or only recommended? (Leaning: required in the profile,
  optional in the base spec.)
- Where does the anchor proof live: inline (`proof`), by reference
  (`proof_ref`), or both? Existing `anchor` records use a type enum +
  reference; follow that.
