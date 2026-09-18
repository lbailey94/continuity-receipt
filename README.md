# Continuity Receipt

**An open specification, test vectors, and reference verifier for verifiable records of governed AI-agent tasks.**

**Spec version:** `continuity-receipt/0.1` — published 2026-09-18 (draft; open items listed in `SPEC.md` §11).
**License:** Apache-2.0 (specification text, code, and vectors).

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
SPEC.md                    the v0.1 specification (normative)
ROADMAP.md                 what lands in 0.1.x / 0.2, and the selection rule
continuity_receipt/        reference implementation (Python, cryptography>=42)
vectors/                   11 test vectors + INDEX.md (expected verdicts)
tools/make_vectors.py      regenerates the vectors deterministically
tests/test_vectors.py      conformance run over all 11 vectors
```

## Quickstart

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install 'cryptography>=42'

# verify a vector (TRUSTED / PROVISIONAL / INSUFFICIENT_EVIDENCE / UNTRUSTED)
python3 -m continuity_receipt.verify vectors/02_happy_full.json

# vectors that require an anchor policy
python3 -m continuity_receipt.verify vectors/10b_anchor_missing.json --require-anchor

# run the conformance suite (11/11 expected)
python3 -m unittest discover -s tests -v
```

## Test vectors (spec §9)

| # | Vector | Expected | Primary error |
|---|---|---|---|
| 1 | `01_happy_minimal.json` | TRUSTED | — |
| 2 | `02_happy_full.json` | TRUSTED | — |
| 3 | `03_tampered_body.json` | UNTRUSTED | `bad_signature` |
| 4 | `04_missing_termination.json` | UNTRUSTED | `missing_termination` |
| 5 | `05_cap_exceeded.json` | UNTRUSTED | `cap_exceeded` |
| 6 | `06_delivery_before_settlement.json` | UNTRUSTED | `delivery_before_settlement` |
| 7 | `07_redacted_no_disclosure.json` | PROVISIONAL | — |
| 8 | `08_redacted_disclosed.json` | TRUSTED | — |
| 9 | `09_erased_content.json` | INSUFFICIENT_EVIDENCE | — |
| 10a | `10a_anchor_invalid.json` | UNTRUSTED | `anchor_invalid` |
| 10b | `10b_anchor_missing.json` | PROVISIONAL | `anchor_missing` (`--require-anchor`) |

## Status and provenance

- **Origin:** developed in the MandalaOS gate-lite work, where it passed acceptance G1–G8 and the wider project suite (49 tests, dogfood evidence). This repository is the format's public home; it versions independently of any product release train.
- **Origin implementation:** [WhiteMagic](https://github.com/lbailey94/whitemagic) — an MIT, local-first memory substrate for agents (this spec repo is Apache-2.0; the two are separate works).
- **Standards context:** the format is intended as a contribution to the emerging neutral layer (W3C AI Agent Memory Interoperability CG; IETF agentproto work). It is not endorsed by those bodies, and no claim of adoption is made.

## Development disclosure

This project is developed with AI agents as drafting, implementation, and review collaborators, under the direction and accountability of the human maintainer. Every artifact published here — spec text, code, vectors — is reviewed and signed off by the human maintainer, who is responsible for its claims. We disclose this proactively because verifiability is the project's subject as well as its method.

## Contributing

Open an issue for spec questions, mapping suggestions, or implementation feedback. Interoperability discussion belongs in the open standards venues; this repository tracks concrete text and vectors.

## License

Apache License 2.0 — see `LICENSE`. The specification is published for royalty-free implementation. Test keys in the vectors are deterministic and public; **never use them for real receipts**.
