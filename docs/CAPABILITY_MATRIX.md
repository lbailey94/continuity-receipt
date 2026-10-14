# Release and capability matrix

State checked on **2026-09-30**. This matrix separates released package
behavior, normative specification status, local policy support, checked-in
corpora, and hosted observations. A package accepting a draft version does
not publish that draft as a normative specification.

## Source and package state

| Surface | Version and support | Evidence checked | Qualification boundary |
|---|---|---|---|
| Normative specification | `continuity-receipt/0.5` is published. `0.6` remains a development draft. | `SPEC.md`; signed tag `v0.5.0` resolves to `ff008888af6f225077b0661aa5b2d88da843839c`; `git verify-tag` reported a good Ed25519 signature in this checkout. | There is no standalone 0.6 spec release. The 0.6 draft file describes experimental behavior included in the 0.5.0 implementations. |
| Python package | PyPI `continuity-receipt==0.5.0`, uploaded 2026-09-30. Core verifier source in the release accepts specs 0.1–0.6. | PyPI JSON API for version 0.5.0; tagged `continuity_receipt/records.py`. | The `continuity-consumer` policy assessment is Python-only and accepts receipt specs 0.1–0.4. Assessment format version is 1. It does not qualify execution or authorize actions. |
| Rust package | crates.io `continuity-receipt==0.5.0`, published 2026-09-30. Core verifier source in the release accepts specs 0.1–0.6. | crates.io version API for 0.5.0; tagged `rust/src/verify.rs`. | There is no Rust consumer policy assessment CLI. The 0.6 verifier behavior is experimental while the 0.6 specification remains draft. |
| GitHub release page | No GitHub Release entry for `v0.5.0` was found on 2026-09-30. | `gh release view v0.5.0 -R lbailey94/continuity-receipt` returned “release not found.” | The signed Git tag and package registry releases exist independently of a GitHub Release entry. |

The 0.5.0 packages therefore expose 0.6 implementation behavior under the
0.5.0 package version. Consumers that rely on `authority.grant` or another
0.6-only behavior must treat it as experimental and pin their implementation;
the package number does not make 0.6 normative. A future 0.6 release needs an
explicit compatibility decision and Python/Rust parity evidence.

## Specification and vector corpora

| Corpus | Checked-in count | State |
|---|---:|---|
| Published 0.4 bundle vectors (`vectors/manifest.json`) | 40 | Frozen published corpus; also the hosted conformance bundle baseline. |
| Verification-receipt vectors (`vectors/verification/manifest.json`) | 21 | Companion format corpus. |
| 0.5 bundle vectors (`vectors/manifest-0.5.json`) | 21 | Included in the signed `v0.5.0` source tag and the published 0.5 release corpus. |
| 0.6 authority vectors (`vectors/manifest-0.6.json`) | 10 | Included in the signed `v0.5.0` source tag alongside experimental 0.6 verifier implementation; this is not a standalone normative 0.6 release. |

The 0.5 spec and its 21-vector manifest shipped together in the 0.5.0 release.
The 0.6 manifest is a development corpus for the draft authority behavior and
is included in the 0.5.0 source tag. Passing those local vectors establishes
implementation behavior against those fixtures, not standalone specification
publication, independent review, or adopter acceptance.

## Hosted service observation

The approved API/package/ERC delta was deployed on **2026-09-30**. Public
`GET https://api.whitemagic.dev/info` now reports package **0.5.0**, supporting
specs 0.1–0.6 (0.6 experimental). All 14 installed Python source modules match
the PyPI-hash-verified wheel. The deployed API source matches the composed
reviewed patch and canonical hosted kit. This source comparison excludes
native/dependency binaries and does not qualify tenant authorization.

The primary independently checked 82 live loopback HTTP cases (71 versioned
vectors plus 11 input boundaries),13 authenticated public `/verify` cases,
and 4 loopback ERC result cases with valid Ed25519 attestations. A transient
hardened staging unit had previously passed 83 cases including no-state writes;
the production matrix explicitly omitted the empty-state check. Temporary
evaluation keys were removed. Gateway usage/audit records remain.

The conformance surface retains its pinned 40 bundle/21 verification-receipt/
208 hostile-input corpus; the additional 71-vector deployment matrix is a
separate test set. No real payment, external registry query, EVM relay or
independent adopter operation was exercised. Authenticated public ERC POST,
explicit issuer policy and Crystal authenticated ownership/migration remain
open. See `../ops/HOSTED_STAGING_2026-09-30.md` for backup/rollback and scope.

## Producer and adopter state

The public Mandala gate-lite line remains the published 0.4 lane (merged
public PR #3, 2026-09-24). The private candidate at
`8ea8c7eb17d576efdbfa0d311b007dd7b95f8389` pins the published
`continuity-receipt==0.5.0` package and emits spec 0.5. Its checked-in
2026-09-28 capture is same-host maintainer evidence. It is not an independent
host qualification; that gate remains open. A published verifier package,
local vectors, a loopback smoke check, and a same-host producer capture are
distinct from external review and independent adoption.

## Reproduction commands

From the repository root:

```sh
python3 -m continuity_receipt.consumer vectors/17_agreement_bound.json \
  --policy examples/consumer-policy-0.4.json
```

Expected local result: `ACCEPT`, core verdict `TRUSTED`. This is a deterministic
fixture-policy demonstration only; it is not independent relying-agent or
production evidence.
