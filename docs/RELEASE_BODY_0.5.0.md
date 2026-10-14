# Continuity Receipt 0.5.0

Signed tag [`v0.5.0`](https://github.com/lbailey94/continuity-receipt/tree/v0.5.0)
freezes commit `ff008888af6f225077b0661aa5b2d88da843839c`. The tag has a valid
ED25519 signature by the maintainer key
`SHA256:cbHGzhbKM5Y73C9fOTzg0BlsjLwu4gi04K6+V1PnPrk`.

This release publishes the `continuity-receipt/0.5` specification, Python and
Rust verifiers, the 21-vector 0.5 bundle corpus, and the unchanged published
0.1–0.4 vector corpus. The tag also includes experimental verifier support
for the 0.6 authority draft and its 10-vector corpus; spec 0.6 is not a
standalone normative release.

## Highlights

- **Local execution claims:** `session.pass.created` may declare
  `mandala_class: local`; `task.execution` recognizes the documented sandbox
  classes `bwrap`, `landlock`, `bwrap-landlock`, `microvm-ch`, `microvm-fc`,
  and `none`.
- **Runner profile binding:** `bwrap` execution can carry `runner_profile`
  fields for profile ID, executable digest, and invocation digest.
- **State commitments:** signed `state.commitment` records can describe
  chain-head or file-snapshot commitments. Counts are bounded to the exact
  integer range `0..2^53-1`.
- **Strict raw JSON inputs:** Python and Rust command-line parsers reject
  duplicate object member names at any depth.
- **Python consumer assessment:** `continuity-consumer` applies an explicit
  relying-party policy to specs 0.1–0.4. It reports a local assessment; it
  does not grant authority or authorize an action.
- **Adopter capture tooling:** the qualification harness checks submitted
  files and verifier results. It does not by itself establish independent
  administration or adoption.

## Install

```sh
pip install continuity-receipt==0.5.0
cargo install continuity-receipt --version 0.5.0
```

- [PyPI 0.5.0](https://pypi.org/project/continuity-receipt/0.5.0/)
- [crates.io 0.5.0](https://crates.io/crates/continuity-receipt/0.5.0)

## Published artifact checksums

These values were checked against live registry metadata on 2026-10-01.

| Registry artifact | SHA-256 |
| --- | --- |
| `continuity_receipt-0.5.0-py3-none-any.whl` | `9b0be02327759b3f95519967f4257ce37a3ee44468359a88f84480d28c5935ee` |
| `continuity_receipt-0.5.0.tar.gz` | `afb373c222a39638b21b6aae05a704d0c890828a0c2db589e8a2f2b54067c2bd` |
| crates.io `continuity-receipt-0.5.0.crate` | `43cbfdf503051ec95057abe5ff33cf8ca37d279ea8f2da65b039c30af64bdfff` |

The separately deployed [hosted verifier metadata](https://api.whitemagic.dev/info)
reported verifier version 0.5.0 and support for specs 0.1–0.6 when checked on
2026-10-01. Hosted service state is separate from this tag and these package
artifacts.

`TRUSTED` means the bundle passed format checks and the supplied verification
policy. A signature establishes what a key signed; it does not independently
establish that the described events occurred. Independent adversarial review
and independent-host adopter qualification are separate evidence gates.

Review entrypoints at the signed tag: `SPEC.md`, `CONFORMANCE_TABLE.md`,
`THREAT_MODEL.md`, `REVIEW_BRIEF_05.md`, `REVIEW_NOTES_05.md`, and
`REVIEW_RESPONSE.md`.
