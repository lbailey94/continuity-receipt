# Continuity Receipt 0.5.1

Continuity Receipt 0.5.1 is a patch release for the published 0.5 line. It does not change the receipt specification, schemas, or vector corpus.

## Changes

- Keep the relying-party consumer profile's accepted record-type vocabulary fixed to published specs 0.1–0.4, and handle excessive nesting during canonicalization as a structured refusal. The accepted policy vocabulary is unchanged from 0.5.0.
- Return a structured qualification failure when an adopter capture exceeds the nesting bound.
- Align the Python distribution and Rust crate package metadata on version 0.5.1. Rust verifier source is unchanged from 0.5.0; this crate version bump synchronizes package releases and does not claim a Rust code change.

Spec 0.6 remains experimental verifier support and a draft specification, not a standalone normative release. The hosted verifier is deployed separately and must be checked independently.

## Install

```sh
pip install continuity-receipt==0.5.1
cargo install continuity-receipt --version 0.5.1
```

Candidate artifact hashes from the local rehearsal build at source commit `d942b1c1fff6e8d153e04c31e3327b4ca7c8ee56` plus the four-file metadata patch:

| Candidate artifact | SHA-256 |
| --- | --- |
| `continuity_receipt-0.5.1-py3-none-any.whl` | `95445d151308186161c82851039199f434e1dbe47a411e477450e3f2a9d3908b` |
| `continuity_receipt-0.5.1.tar.gz` | `0752c0e3232884443560613166041c028b018a382e133e77b88ffa08f576b27b` |

These hashes identify the local candidate files; they are not registry publication evidence.

`TRUSTED` means a bundle passed format checks and supplied policy. It does not independently establish that described events occurred.
