# Independent review brief — verification receipts and the verifier surface

**Status:** open invitation, 2026-09-23. One page of scope, questions, and
logistics.
**Materials frozen at:** the 0.4.0 release-candidate commit (tag `v0.4.0`
to be created at freeze; publication pending at review time) — spec
`continuity-receipt/0.4` (release candidate); Python tooling **0.4.0**
(release candidate); Rust crate **0.4.0** (release candidate); hosted
service verifier 0.4.0 pending deployment.
**Repository:** <https://github.com/lbailey94/continuity-receipt> ·
**Contact:** lbailey94@protonmail.com (subject: "verification review").

## Why

Continuity Receipt is an open format for verifiable records of governed
agent tasks, with two independent implementations and a hosted verification
service. Verification receipts extend it: a verifier signs the full result of
a verification run — verdict, errors, reasons, summary — so any third party
can audit *what was checked and how the result was reached*, offline. We are
approaching standards bodies (W3C AI Agent Memory CG) and enterprise pilots;
before making external claims we want an adversarial technical review by
someone with no stake in the outcome.

**We are asking you to find what is wrong, not to validate.** A report that
finds nothing of consequence is less useful than one that names three real
weaknesses.

## In scope

1. **Verification receipt format v1** — `VERIFICATION_RECEIPTS.md`, schema
   `schema/verification-receipt-1.schema.json`, vectors
   `vectors/verification/` (21 cases): wire format, the JCS-canonical
   `bundle_digest` rule, the offline consistency rules (`error_codes_mismatch`,
   `verdict_mismatch`), revocation semantics (including the positive case), the
   anchoring recipe.
2. **Core bundle verification** — `SPEC.md` (0.4), `continuity_receipt/verify.py`,
   `vectors/` (40 cases): chain, signature, attestation, redaction/erasure
   semantics, the 0.4 agreement-binding rules, hostile-input handling.
3. **Two implementations** — Python reference (`continuity_receipt/`) and Rust
   (`rust/src/`, crate 0.4.0), plus the differential claims
   (`tools/differential_vectors.py` 40/40,
   `tools/differential_verification_receipts.py` 21/21) and the hostile-input
   parity claim (`tools/hostile_input_probe.py --require-parity`).
4. **Cryptographic core** — Ed25519 + `did:key` handling, the pinned JCS
   subset (`canon.py` / `canon.rs`; floats rejected), salted commitments
   (`commit_field`), the canonical-view signing rule.
5. **Anchor tooling** — `ANCHORING.md`, `continuity_receipt/anchor.py` and
   `rust/src/anchor.rs`: OpenTimestamps detached-proof replay (LEB128 varints,
   merkle replay), Bitcoin header handling, failure modes.
6. **Hosted service as one issuer** — the service contract
   (<https://api.whitemagic.dev/docs>, `GET /info`, OpenAPI) and, for the
   reviewer, the service source on request: signing-key handling, rotation and
   revocation procedure, cache semantics, contract-vs-spec consistency.
7. **Claims discipline** — do `CONFORMANCE.md`, `CONFORMANCE_TABLE.md`,
   `THREAT_MODEL.md`, and `VERIFICATION_RECEIPTS.md` claim more than the
   implementation supports? Are any table cells softened to avoid work?

## Out of scope

- Issuer honesty (receipts attest what was recorded, not that it is true).
- Proof-of-work / Bitcoin chain validation (headers are caller-supplied).
- Payment rails, OS/infrastructure hardening, marketing claims.
- Spec 0.1/0.2 beyond "still verifies".

## Questions we would like answered

1. Can a receipt be forged, replayed, or made ambiguous across
   serializations — given the digest and consistency rules?
2. Can the consistency checks be bypassed so a receipt reports a clean verdict
   while carrying failures?
3. Is the JCS-subset pinning sound for the schema's ASCII-key domain? Where
   could Python and Rust diverge on the same bytes?
4. Revocation: can a revoked issuer key still produce receipts that pass? What
   does the known pre-revocation-compromise gap mean in practice?
5. Does anchoring the canonical view actually bound `verified_at`, or is there
   a gap between what is stamped and what is verified?
6. Does the hosted service's contract (cache, rate limits, error shapes)
   contradict or weaken the spec?
7. Redaction/erasure: can a commitment be substituted, or a required field
   hidden, without detection?
8. Anything in the threat model that is asserted but not tested.
9. Can the 0.4 binding be evaded — wrong offeree/signer, chronology, ref
   substitution, mixed-version downgrade — given the new rules and vectors?
10. Does hostile-input handling stay structured and parity-consistent beyond
   the sampled corpus (leaf/deletion mutations, boundaries)?

## Deliverable

A written report (publication encouraged; we will publish it alongside our
response) containing:

- findings classified **critical / major / minor / nit**, each with
  reproduction steps (a failing vector or a script is ideal);
- an explicit list of what you did **not** cover;
- a short statement of the residual risk you would attach to the format.

We will fix or explicitly document every finding. We will not ask for an NDA,
nor to review the report before publication. Please disclose conflicts of
interest; we will decline reviewers with a stake in competing formats.

## Logistics

- **Effort:** scoped as ~3–5 working days; two rounds (initial report, response
  review) preferred.
- **Compensation:** fixed fee, budgeted; terms agreed before work starts.
- **Access:** public repo and packages; live service keyless endpoints, and a
  review key with a raised cap on request.
- **Reproduce:**

  ```bash
  python3 -m unittest discover -s tests -v
  python3 tools/differential_vectors.py
  python3 tools/differential_verification_receipts.py
  python3 tools/hostile_input_probe.py --require-parity
  cargo test --manifest-path rust/Cargo.toml
  ```

## Known weaknesses (so you can aim past them)

- Pre-revocation key compromise is not detectable (`THREAT_MODEL.md`).
- Revocation-list freshness: a mirror can withhold a statement.
- `verified_at` is issuer-asserted unless the receipt is anchored.
- Verification receipts are v1 and young; the format was revised once before
  external issuance (see `CHANGELOG.md`, 0.3.3), and 0.4 was shaped by an
  independent review whose findings and responses are in the changelog.
- The Rust receipt CLI accepts local revocation documents only (no URLs).
