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

## Wire-boundary follow-up on 2026-09-25

- Changed 0.5 `state.commitment.count` from unsigned 64-bit to the exact interoperable JSON integer range 0..2^53−1. Python, Rust, schema 0.5, candidate generator/manifest, and conformance rows now share that boundary; vectors 22m and 22n cover the first out-of-range and maximum accepted values. The older 2^64 overflow vector remains as a second invalid boundary.
- Python and Rust bundle and verification-receipt CLIs reject duplicate object member names recursively before constructing maps. This parser-level rule applies to 0.1–0.5 bundles, verification receipt v1, and CLI-loaded revocation documents. Library APIs receiving parsed dictionaries/values cannot identify duplicates already discarded by their callers.
- Duplicate names are ambiguous signed-input syntax and were previously accepted according to each parser's overwrite behavior. Rejecting them is a deliberate raw-input compatibility tightening for all supported specs; published vector bytes, manifests, and verification semantics for unambiguous JSON remain unchanged.
- The candidate hostile-input run exposed a Rust CLI error-code mismatch on deeply nested raw JSON (`malformed` versus Python's `nesting_too_deep`). The Rust CLI mapping was corrected, then the candidate probe passed 108 cases / 216 runs and the published-corpus probe passed 308 cases / 616 runs, both with zero failures and parity mismatches against the rebuilt binary.
- After combining the runner-class branch, all 86 Python tests and the Rust suite passed; bundle differentials matched 40/40 published and 16/16 candidate vectors, verification receipts 21/21. The 108-case candidate hostile-input probe and local file-snapshot integration probe passed on the combined tree. Disclosure checks and seven anchor cases passed before the branch combination and remain CI gates. An isolated wheel and sdist build succeeded before the combination; the wheel contained `strict_json.py`, and the sdist contained that module and `INTEGRATION_READINESS.md`. These are local checks on development trees, not release qualification.

## Design resolves (2026-09-28)

- **D1 — `mandala_class` name: retained.** The historical field name stays on
  the wire for compatibility; the `local` value claims a local issuer only and
  never gate enforcement. No code change; the wording in `SPEC_0.5_DRAFT.md`
  §Local authority is the decision text (vector 22 covers the `local` value).
- **D2 — `scope` is label-only: resolved.** The verifier requires nonempty
  text and applies no scope-enforcement rule; consumers agree on semantics
  out-of-band (same posture as `runner_profile.profile_id`). Wording added to
  `SPEC_0.5_DRAFT.md` §state.commitment; new negative vector
  `22r_empty_scope.json` (empty scope → UNTRUSTED `malformed`).
- **D3 — chain-head vs snapshot profiles: same shape, `state_kind`
  discriminates.** No split required; every kind carries the same required
  fields. New modeled fixture `22s_file_snapshot_state_kind.json` (second
  kind, TRUSTED) joins vector 22.
- **D4 — duplicate object member names: implemented in both CLIs for every
  supported spec.** Python: `tests/test_vectors.py::test_raw_json_rejects_duplicate_members_and_cli_inputs`
  (bundle + verification-receipt CLIs) and `tests/test_revocations.py`
  (CLI-loaded revocation documents). Rust:
  `rust/tests/vectors.rs::verifier_clis_reject_duplicate_json_members` plus the
  `rust/src/strict_json.rs` unit test. No code change in this resolve.

## Findings and disposition

1. **Pinned referee corpus would have drifted (resolved).** Appending candidate cases to vectors/manifest.json changed the hosted conformance submission from 40 to 47. Candidate cases now have manifest-0.5.json. The original manifest and index are unchanged, and a conformance submission still contains 40 bundles and 21 verification receipts.
2. **Historical test fixture depended on the default spec (resolved).** The external-revocation test uses a legacy class label. Changing the library default to 0.5 made an unrelated positive revocation case fail. The fixture is now explicitly pinned to 0.4, preserving the old behavior while the new 0.5 enum is checked.
3. **Cross-language integer boundary (historical fix superseded by stricter wire limit).** The earlier candidate limited counts to unsigned 64-bit and vector 22g caught overflow. This follow-up further narrows the wire limit to 0..2^53−1 so implementations using IEEE-754 JSON numbers can preserve the signed count exactly; vectors 22m and 22n exercise the new boundary.
4. **Producer output aliases (resolved).** The example producer refuses an output path equal to its snapshot, mandate, or private key path, avoiding an accidental overwrite after hashing.

## Open before a 0.5 release

- Obtain an actual producer-emitted chain-head or snapshot case from a second project or runtime; vector 22 is modeled and the file-snapshot script is a small reference producer, not independent adoption. **Partially closed 2026-09-28:** MandalaOS gate-lite emits `runner_profile` + `state.commitment` (`codex/gate-lite-05-profile` `cb0f721`; example `examples/02_gate_lite_state_commitment`, CR `cab4a24`) — a second codebase and runtime, captured same-host on the unpublished candidate; independent adoption by an unrelated operator remains open.
- Decide whether the historical mandala_class name and generic scope/state_kind labels are acceptable long-term. The local value avoids a false gate claim, but the field name remains product-specific. **Resolved 2026-09-28 (D1–D3): retained.** The name stays for wire compatibility; `scope` is a label only and `state_kind` discriminates profiles on the same required shape (see §Design resolves).
- Have a reviewer independent of this implementation challenge state-commitment semantics, mixed-version handling, integer/canonicalization parity, issuer-key lifecycle, and whether any proof claim exceeds what the verifier observes.
- Freeze a candidate commit, run the exact full battery and package checks, then separately decide tag, PyPI/crates.io publication, hosted rollout, and downstream-site wording. None of these follows automatically from this development branch.
