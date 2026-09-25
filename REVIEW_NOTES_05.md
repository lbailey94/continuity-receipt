# Spec 0.5 candidate: adversarial review notes

**Status:** maintainer-side review of an unpublished candidate. This is not an independent cryptographic audit or a release qualification. The existing REVIEW_BRIEF.md still identifies signed v0.4.0 as the frozen external-review surface.

## Scope checked

At the reviewed working-tree state on 2026-09-24: 84 Python tests and the
Rust suite passed; Python/Rust differential results were 40/40 published
bundles, 7/7 candidate bundles, and 21/21 verification receipts. The pinned
hostile probe returned 308 cases / 616 runs with zero failures and zero parity
mismatches; the candidate probe returned 108 cases / 216 runs with the same
outcome. These are sampled and generated checks, not exhaustive proof.

- The 40 published bundle vectors and 21 verification-receipt vectors remain in their original manifests. Candidate vectors 22–22g live in a separate 0.5 manifest.
- Python and Rust implement the same 0.5 enum and state-commitment shape checks. A pre-0.5 receipt carrying state.commitment fails as unknown_type; 0.5 agreement binding remains active.
- The file-snapshot example hashes bytes it actually reads, discloses no OS confinement, and signs a local pass. A consumer must recompute the supplied file and mandate digests; the verifier does not do that external observation.

## Findings and disposition

1. **Pinned referee corpus would have drifted (resolved).** Appending candidate cases to vectors/manifest.json changed the hosted conformance submission from 40 to 47. Candidate cases now have manifest-0.5.json. The original manifest and index are unchanged, and a conformance submission still contains 40 bundles and 21 verification receipts.
2. **Historical test fixture depended on the default spec (resolved).** The external-revocation test uses a legacy class label. Changing the library default to 0.5 made an unrelated positive revocation case fail. The fixture is now explicitly pinned to 0.4, preserving the old behavior while the new 0.5 enum is checked.
3. **Cross-language integer boundary (resolved).** Rust's JSON integer representation and Python's unbounded integers would disagree for state counts above unsigned 64-bit range. Both verifiers and schema 0.5 now limit count to 0 through 2^64−1; vector 22g covers overflow.
4. **Producer output aliases (resolved).** The example producer refuses an output path equal to its snapshot, mandate, or private key path, avoiding an accidental overwrite after hashing.

## Open before a 0.5 release

- Obtain an actual producer-emitted chain-head or snapshot case from a second project or runtime; vector 22 is modeled and the file-snapshot script is a small reference producer, not independent adoption.
- Decide whether the historical mandala_class name and generic scope/state_kind labels are acceptable long-term. The local value avoids a false gate claim, but the field name remains product-specific.
- Add a dedicated 0.5 wire vector for carried agreement binding. A Python unit regression exists; published 0.4 vectors exercise the old version only.
- Have a reviewer independent of this implementation challenge state-commitment semantics, mixed-version handling, integer/canonicalization parity, issuer-key lifecycle, and whether any proof claim exceeds what the verifier observes.
- Freeze a candidate commit, run the exact full battery and package checks, then separately decide tag, PyPI/crates.io publication, hosted rollout, and downstream-site wording. None of these follows automatically from this development branch.
