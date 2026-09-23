# Continuity Receipt

**An open specification, test vectors, and reference verifier for verifiable records of governed AI-agent tasks.**

**Spec version:** `continuity-receipt/0.3` — published 2026-09-23 (`0.1` and `0.2` remain supported; open items listed in `SPEC.md` §11).
**License:** Apache-2.0 (specification text, code, and vectors).

**Version matrix** — the spec and the two implementations version
independently:

| Artifact | Current | Installs with |
|---|---|---|
| Spec / wire format | `continuity-receipt/0.3` (additive) | — |
| Python reference + CLIs | **0.3.3** (PyPI) | `pip install continuity-receipt` |
| Rust verifier + CLIs | **0.3.3** (crates.io) | `cargo install continuity-receipt` |

Both implementations support spec 0.3 (offer/accept binding) with identical
verdicts and codes over the full vector set. Verify the version you have with
`continuity-receipt-verify --help` (Python or Rust).

A Continuity Receipt is a signed, hash-chained record of one governed task:
**decision → authority → execution → delivery → termination → settlement**. It is designed to be verified offline by any third party — insurers, arbiters, procurement, courts, other agents — **without requiring trust in the issuer**.

The spec is intentionally small: JSON (RFC 8785 canonicalization), SHA-256, Ed25519, `did:key` identities. No new cryptography. Redaction uses salted commitments so fields can be revealed selectively without breaking integrity; erasure makes commitments opaque while the chain still verifies.

## Why this exists

Agents are accumulating persistent memory and doing delegated work at scale, but accountability is still self-reported. This document is the opposite: claims arrive with evidence, missing evidence is distinguished from false evidence, and "proof it stopped" (`task.termination`) is required for a task to verify as complete.

Verification verdicts (IETF CTQ-aligned):
`TRUSTED` · `PROVISIONAL` · `INSUFFICIENT_EVIDENCE` · `UNTRUSTED`.
`INSUFFICIENT_EVIDENCE` is explicitly not the same as false.

## Layout

```
SPEC.md                    the v0.3 specification (normative; 0.1 + 0.2 supported)
VERIFICATION_RECEIPTS.md   companion: signed statements about a verification run
VERIFY_IN_5_MIN.md         the integration kit page (copy-paste, no SDK)
REVIEW_BRIEF.md            independent review scope (open invitation)
schema/                    JSON Schema (2020-12): bundles + verification receipts
THREAT_MODEL.md            what receipts prove, and what they do not
ANCHORING.md               anchoring policy: OpenTimestamps default, chain optional
OPEN_DATA_ANSWER_RECEIPT.md  worked example: an AI answer over an open-data portal
CONTRIBUTING.md            DCO, test rules, scope
ROADMAP.md                 what lands in 0.3 and beyond, and the selection rule
continuity_receipt/        reference implementation (Python, cryptography>=42)
rust/                      second implementation (verifier crate; cargo test)
vectors/                   26 bundle vectors + 20 verification-receipt vectors
tools/make_vectors.py      regenerates the vectors deterministically
tests/                     conformance suite (vectors, schema, primitives)
```

## Quickstart

```bash
# from PyPI (0.3.3) — clone the repo for the vectors
python3 -m venv .venv && . .venv/bin/activate
pip install continuity-receipt
continuity-receipt-verify vectors/02_happy_full.json   # TRUSTED
continuity-receipt-verify vectors/10b_anchor_missing.json --require-anchor
continuity-receipt-verify-receipt vectors/verification/01_valid.json \
  --bundle vectors/verification/bundle.json
continuity-receipt-disclose --help

# or run from a checkout
pip install 'cryptography>=42'
python3 -m continuity_receipt.verify vectors/02_happy_full.json

# run the conformance suite (vectors + schema + primitives)
python3 -m unittest discover -s tests -v
```

## Test vectors

26 bundle vectors with machine-readable expectations in `vectors/manifest.json`
(human index: `vectors/INDEX.md`): 0.1 conformance (`01`–`10c`), 0.2
additions — succession records, millisecond timestamps, counterparty
attestations, revocation semantics, Merkle provenance, anchor typing — and
0.3 additions: offer → accept binding (`16`–`16d`, including the
missing-offer, terms-mismatch, and expiry cases) and selective disclosure of
redacted offer terms (`16e`/`16f`).
Every schema-valid vector is also checked against
`schema/continuity-receipt-0.3.schema.json` in CI.

20 verification-receipt vectors in `vectors/verification/` (manifest +
`INDEX.md`): valid TRUSTED/PROVISIONAL/INSUFFICIENT_EVIDENCE records (the full
result — errors, reasons, summary), signature/verdict tampering, wrong bundle,
bad kind/version/verdict/timestamp/digest/error-codes/errors/reasons/summary,
consistency violations, missing signature, issuer swap, revoked issuer,
unknown member. Schema: `schema/verification-receipt-1.schema.json`.

## Status and provenance

- **Origin:** developed in the MandalaOS gate-lite work, where it passed acceptance G1–G8 and the wider project suite (49 tests, dogfood evidence). This repository is the format's public home; it versions independently of any product release train.
- **Releases:** `0.1` (2026-09-18) — spec, reference verifier, 11 vectors. `0.2` (2026-09-18) — `authority.succession`, bundle-level revocation statements, counterparty attestation rules, millisecond timestamps, `merkle-sha256:` provenance, anchor typing, JSON Schema, CI, machine-readable vector manifest. `0.3` (2026-09-23) — `agreement.offer` / `agreement.accept` with digest binding, terms/id equality, and expiry semantics; vectors 16–16f; schema 0.3. Tooling `0.3.3` (2026-09-23) — verification receipts (companion v1: schema, 20 vectors, reference verifier + CLI; records the full result — errors, reasons, summary — with offline consistency checks and an anchoring recipe), agreement emitters, integration kit.
- **Second implementation:** `rust/` — an independent Rust verifier
  (crate `continuity-receipt`) with the same verdict/error semantics; `cargo test`
  checks all 26 bundle vectors and CI diffs it against the Python reference
  (26/26) and the verification-receipt vectors (20/20, crate 0.3.3), with
  digest parity pinned by `tools/differential_verification_receipts.py`.
- **Origin implementation:** [WhiteMagic](https://github.com/lbailey94/whitemagic) — an MIT, local-first memory substrate for agents (this spec repo is Apache-2.0; the two are separate works).
- **Standards context:** the format is intended as a contribution to the emerging neutral layer (W3C AI Agent Memory Interoperability CG; IETF agentproto work). It is not endorsed by those bodies, and no claim of adoption is made.

## Development disclosure

This project is developed with AI agents as drafting, implementation, and review collaborators, under the direction and accountability of the human maintainer. Every artifact published here — spec text, code, vectors — is reviewed and signed off by the human maintainer, who is responsible for its claims. We disclose this proactively because verifiability is the project's subject as well as its method.

## The stack

> Local memory → governed execution → verifiable continuity

- [`whitemagic`](https://github.com/lbailey94/whitemagic) — local-first memory and session continuity for AI agents
- [`continuity-receipt`](https://github.com/lbailey94/continuity-receipt) — portable, offline-verifiable evidence for governed tasks (Apache-2.0, this repo)
- [`mandalaos-gate-lite`](https://github.com/lbailey94/mandalaos-gate-lite) — bounded agent execution that emits receipts (review snapshot)
- [`whitemagic-plugins`](https://github.com/lbailey94/whitemagic-plugins) — client integrations and adapters

Each repository stands on its own: WhiteMagic does not require MandalaOS, and
Continuity Receipt does not require WhiteMagic. Three entrances — **use it** →
`whitemagic`; **review a protocol** → `continuity-receipt`; **attack the
security architecture** → `mandalaos-gate-lite`.

## Contributing

Open an issue for spec questions, mapping suggestions, or implementation feedback. Interoperability discussion belongs in the open standards venues; this repository tracks concrete text and vectors.

## License

Apache License 2.0 — see `LICENSE`. The specification is published for royalty-free implementation. Test keys in the vectors are deterministic and public; **never use them for real receipts**.
