# CPR and SCITT: envelope feasibility and open work

Status: design note, reviewed 26 October 2026 against implementation baseline
`146c4d2439e4f11cc50776e754e98081bb41869e`. This document does not establish
SCITT interoperability, group adoption, a registered CPR statement, or a
post-quantum signing implementation.

## Distinct records and trust decisions

CPR's published JSON format binds disclosed task records using canonical
bytes, digests, and signatures. It checks recorded claims; it does not prove
that the claimed execution, authorization, delivery, or settlement happened.

[SCITT's architecture, RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html),
describes registration of Signed Statements with a Transparency Service and
verification of resulting Transparent Statements. Registration and its
verification do not establish the truth of the issuer's payload.
[COSE Receipts, RFC 9942](https://www.rfc-editor.org/rfc/rfc9942.html), convey
signed proofs about verifiable data structures. A second signature on a CPR
result does not by itself constitute such a receipt.

A possible composition is to register a precisely defined CPR payload and
retain the returned receipt. The caller would still need to evaluate CPR
semantics, expected issuer, authority, freshness, and the Transparency
Service's trust policy separately. The related
[CROSSWALK_AER1_AADP_SCITT.md](CROSSWALK_AER1_AADP_SCITT.md) is an informational
comparison, not proof of compatibility.

## What the current implementation establishes

- `SPEC.md` defines published `continuity-receipt/0.5` records. Individual
  records use `spec`, `type`, `receipt_id`, `seq`, `prev`, `task_id`,
  `issued_at`, `issuer`, `body`, and `sig`, as shown in the vector corpus.
- Core anchor checks validate the implemented anchor shape and digest
  relationships. The companion OpenTimestamps tooling has its own proof and
  caller-supplied-header boundary. Anchor shape alone is not proof validation.
- `SPEC_0.6_DRAFT.md` describes experimental `authority.grant` records. Their
  signed labels do not resolve principal authority or enforce a payment
  budget, tool allowlist, or recipient authorization policy.
- No CPR-to-SCITT registration/retrieval/COSE-receipt verification journey is
  evidenced by this baseline. No CBOR representation replaces the published
  JSON format, and the current verifiers do not gain SCITT support by accepting
  an opaque custom anchor.

## Work needed for an interoperable profile

1. Define the exact registered bytes: a canonical full bundle, one receipt,
   or an explicitly domain-separated digest. Specify how signatures and
   optional metadata affect those bytes.
2. Select a COSE envelope, protected-header requirements, algorithm/key
   identifiers, media type, and verification procedure. Do not treat
   illustrative JSON field names as a registered COSE header profile.
3. Specify receipt conveyance and schema/version negotiation. Existing
   strict CPR validators must reject unsupported structures predictably;
   adding a `scitt` object to `anchors` is not an implemented extension.
4. Define trusted Transparency Service keys and acceptable policies,
   checkpoint/freshness requirements, replay handling, and key rotation.
   A signed timestamp is a statement by its issuer, not an independently
   validated clock.
5. Publish fixed byte-level vectors and a registration/retrieval/verification
   transcript against a named service and independent implementation. Include
   altered payload, wrong service key, mismatched proof, absent proof, stale
   checkpoint, and unsupported algorithm cases.

The design decisions above remain open. A future implementation must also
keep the checkpoint or trust reference outside the state an attacker may roll
back. Registering an old genuine statement does not automatically prove that
it is the latest acceptable agent state.

## Measurements and deferred claims

This repository does not substantiate the earlier estimates of 34% smaller
CBOR, 14/18/22 microsecond verification, or 45 KB additional binary size with
a pinned implementation, corpus, toolchain, raw measurement, and reproduction
command. Those estimates are not performance results. Measure any future
encoding on the same payloads and report framing overhead and verification
work separately.

Post-quantum dual signatures, budget enforcement, runtime confinement, and
complete agent-session recovery each need their own implementation and
acceptance evidence. They are not properties obtained merely by mapping a
CPR record into a proposed SCITT envelope.
