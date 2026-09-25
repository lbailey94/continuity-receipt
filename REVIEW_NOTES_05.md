# Spec 0.5 candidate: adversarial review notes

**Status:** maintainer-side review of an unpublished candidate. This is not an independent cryptographic audit or a release qualification. The existing REVIEW_BRIEF.md still identifies signed v0.4.0 as the frozen external-review surface.

## Scope checked

At the reviewed working-tree state on 2026-09-24: 84 Python tests and the
Rust suite passed; Python/Rust differential results were 40/40 published
bundles, 7/7 candidate bundles, and 21/21 verification receipts. The pinned
hostile probe returned 308 cases / 616 runs with zero failures and zero parity
mismatches; the candidate probe returned 108 cases / 216 runs with the same
outcome. These are sampled and generated checks, not exhaustive proof.

- The 40 published bundle vectors and 21 verification-receipt vectors remained in their original manifests. Candidate vectors 22–22g lived in a separate 0.5 manifest at this review point.
- Python and Rust implement the same 0.5 enum and state-commitment shape checks. A pre-0.5 receipt carrying state.commitment fails as unknown_type; 0.5 agreement binding remains active.
- The file-snapshot example hashes bytes it actually reads, discloses no OS confinement, and signs a local pass. A consumer must recompute the supplied file and mandate digests; the verifier does not do that external observation.

## Follow-up on 2026-09-25

- The previously identified need for a dedicated 0.5 carried-agreement wire vector is closed by vectors 23 and 23b. Vector 23 is TRUSTED with the accepted agreement reference carried through decision and execution; vector 23b omits the execution reference and is PROVISIONAL.
- The focused follow-up ran 21 Python tests across `tests.test_agreements`, `tests.test_vectors`, and `tests.test_schema`; all passed. Python/Rust differential verification matched 9/9 cases from `vectors/manifest-0.5.json`.
- Independent follow-up reran all 85 Python tests, the Rust test suite, and the published bundle and verification-receipt differentials (40/40 and 21/21); all passed after the Rust fuzz corpus test was updated to derive its vector total from the manifests.
- These checks do not change the historical 2026-09-24 scope/check counts above and do not constitute full candidate release qualification or independent adopter evidence.

## Findings and disposition

1. **Pinned referee corpus would have drifted (resolved).** Appending candidate cases to vectors/manifest.json changed the hosted conformance submission from 40 to 47. Candidate cases now have manifest-0.5.json. The original manifest and index are unchanged, and a conformance submission still contains 40 bundles and 21 verification receipts.
2. **Historical test fixture depended on the default spec (resolved).** The external-revocation test uses a legacy class label. Changing the library default to 0.5 made an unrelated positive revocation case fail. The fixture is now explicitly pinned to 0.4, preserving the old behavior while the new 0.5 enum is checked.
3. **Cross-language integer boundary (resolved).** Rust's JSON integer representation and Python's unbounded integers would disagree for state counts above unsigned 64-bit range. Both verifiers and schema 0.5 now limit count to 0 through 2^64−1; vector 22g covers overflow.
4. **Producer output aliases (resolved).** The example producer refuses an output path equal to its snapshot, mandate, or private key path, avoiding an accidental overwrite after hashing.

## Open before a 0.5 release

- Obtain an actual producer-emitted chain-head or snapshot case from a second project or runtime; vector 22 is modeled and the file-snapshot script is a small reference producer, not independent adoption.
- Decide whether the historical mandala_class name and generic scope/state_kind labels are acceptable long-term. The local value avoids a false gate claim, but the field name remains product-specific.
- Have a reviewer independent of this implementation challenge state-commitment semantics, mixed-version handling, integer/canonicalization parity, issuer-key lifecycle, and whether any proof claim exceeds what the verifier observes.
- Freeze a candidate commit, run the exact full battery and package checks, then separately decide tag, PyPI/crates.io publication, hosted rollout, and downstream-site wording. None of these follows automatically from this development branch.
