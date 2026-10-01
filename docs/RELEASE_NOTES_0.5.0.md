# Continuity Receipt 0.5.0 — GitHub release entry (draft for review)

Draft by opencode, 2026-09-30, for Lucas's review before publishing the
missing GitHub release for signed tag `v0.5.0`. Do not rebuild or replace
immutable package artifacts; PyPI and crates.io remain the distribution.
A pre-publication checklist is at the bottom as an HTML comment and will not
render in the published body.

---

## Release body

Signed release tag `v0.5.0` freezes
`ff008888af6f225077b0661aa5b2d88da843839c`. The tag carries a valid ED25519
signature (key fingerprint
`SHA256:cbHGzhbKM5Y73C9fOTzg0BlsjLwu4gi04K6+V1PnPrk`). It contains spec
`continuity-receipt/0.5`, Python and Rust tooling 0.5.0, the published
0.5 corpus (21 bundle vectors; the published 0.1–0.4 fixtures are unchanged),
the experimental 0.6 authority implementation and its 10-vector corpus, the
Python-only consumer policy assessment (policy specs 0.1–0.4), and the
adopter qualification harness. The tag is the frozen technical review
surface; later changes on `main` are not part of it.

**Highlights**

- **Local authority and execution vocabulary.** `session.pass.created` gains
  `mandala_class: local`; `task.execution` accepts `sandbox_class` values
  `bwrap`, `landlock`, `bwrap-landlock`, `microvm-ch`, `microvm-fc`, `none`.
- **Runner profile binding.** `bwrap` execution may carry `runner_profile`
  (`profile_id`, `executable_digest`, `invocation_digest`).
- **`state.commitment`.** A signed record type for chain-head and
  file-snapshot state commitments, bounded by exact IEEE-754 integer counts
  in `0..2^53-1`.
- **Hardened parsers.** Boundary parsers reject duplicate object member names
  at any depth for all spec versions.
- **Consumer profile and qualification tooling.** Python-only
  `continuity-consumer` policy assessment plus the 0.5 adopter qualification
  harness. The harness does not itself establish independent adoption.
- **Experimental 0.6 behavior included.** Both package verifiers accept the
  0.6 authority draft. The 0.6 specification remains a development draft;
  there is no standalone 0.6 specification release.

**Install**

```sh
pip install continuity-receipt==0.5.0
cargo install continuity-receipt --version 0.5.0
```

- PyPI: https://pypi.org/project/continuity-receipt/0.5.0/
- crates.io: https://crates.io/crates/continuity-receipt/0.5.0

**Verified artifacts** (checked against registry metadata on 2026-09-30)

| Artifact | SHA-256 |
| --- | --- |
| `continuity_receipt-0.5.0-py3-none-any.whl` | `9b0be02327759b3f95519967f4257ce37a3ee44468359a88f84480d28c5935ee` |
| `continuity_receipt-0.5.0.tar.gz` | `afb373c222a39638b21b6aae05a704d0c890828a0c2db589e8a2f2b54067c2bd` |

**Hosted verifier.** The hosted endpoint
(https://api.whitemagic.dev/info) has served package 0.5.0 since 2026-09-30
and reports its own deployed version and supported specs; it is a separate
release surface from these packages.

**Limits at publication.** Independent adversarial review and independent-host
adopter qualification remained open at publication and remain separate gates.
The consumer profile is Python-only and accepts policy specs 0.1–0.4. 0.6 is
an experimental implementation inside these packages, not a normative
release.

`TRUSTED` means the submitted record passed format and supplied-policy
checks. A signature establishes what a key signed; it does not independently
establish that the narrated work occurred.

**Review entrypoints in the repository at the tag:** `SPEC_0.5_DRAFT.md`,
`CONFORMANCE_TABLE.md`, `THREAT_MODEL.md`, `REVIEW_BRIEF_05.md`,
`REVIEW_NOTES_05.md`, and `REVIEW_RESPONSE.md`.

<!--
PRE-PUBLICATION CHECKLIST (hidden from the rendered release)
[x] Signed tag verified locally: git tag -v v0.5.0 -> good ED25519 signature,
    fingerprint SHA256:cbHGzhbKM5Y73C9fOTzg0BlsjLwu4gi04K6+V1PnPrk
[x] Tag target ff008888af6f225077b0661aa5b2d88da843839c; tag/commit versions all 0.5.0
[x] PyPI 0.5.0 wheel hash matches staging evidence (9b0be023...); sdist hash
    afb373c2... matches PyPI JSON exactly
[x] crates.io 0.5.0 exists (created 2026-09-30T03:03:02Z)
[x] sdist contains CONFORMANCE_TABLE.md and SPEC_0.5_DRAFT.md (no repeat of the
    0.4.0 sdist omission)
[x] No GitHub release exists for v0.5.0 (only "Continuity Receipt 0.4.0")
[ ] Lucas reviews and approves this body
[ ] Create with: gh release create v0.5.0 --verify-tag \
      --title "Continuity Receipt 0.5.0" --notes-file docs/RELEASE_NOTES_0.5.0.md
    (do NOT upload assets; registries are the distribution)
[ ] Decide whether v0.5.0 becomes "Latest" (v0.4.0 is currently Latest)
[ ] Post-publication double-check: rendered body, links resolve, tag row shows
    the verified signature note, install commands work from a clean dir
-->
