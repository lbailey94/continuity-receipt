# Continuity Receipt

**An open specification, test vectors, and reference verifier for verifiable records of governed AI-agent tasks.**

**Spec version:** `continuity-receipt/0.5` — published 2026-09-30. `0.1`–`0.4`
remain supported (open items listed in `SPEC.md` §11).
**License:** Apache-2.0 (specification text, code, and vectors).

**Checkout development:** [SPEC_0.6_DRAFT.md](SPEC_0.6_DRAFT.md) stacks an unpublished authority
candidate (`authority.grant`) on top of 0.5.

**Version matrix** — the spec and the two implementations version
independently:

| Artifact | Current | Published install |
|---|---|---|
| Spec / wire format | `continuity-receipt/0.5` (published 2026-09-30) | — |
| Python reference + CLIs | **0.5.0** | `pip install continuity-receipt==0.5.0` |
| Rust verifier + CLIs | **0.5.0** | `cargo install continuity-receipt --version 0.5.0` |

The pinned install commands resolve to the published release (0.5.0).

Both implementations support spec 0.5 (local authority, execution sandbox vocabulary, runner profiles, state commitments, duplicate member rejection, and consumer profile assessment) with identical verdicts and codes over the full vector set.
Verify the version you have with `continuity-verify --help` or `continuity-receipt-verify --help` (Python or
Rust).

A Continuity Receipt is a signed, hash-chained record of one governed task:
**decision → authority → execution → delivery → termination → settlement**. It is designed to be verified offline by any third party — insurers, arbiters, procurement, courts, other agents — without trusting the channel that delivered it or accepting someone else's verification. What it proves is bounded: a receipt attests what its issuer signed, not that the described events occurred — issuer honesty is out of scope by design (`THREAT_MODEL.md` #2–#3, `CONFORMANCE_TABLE.md` §E).

The spec is intentionally small: JSON (RFC 8785 canonicalization), SHA-256, Ed25519, `did:key` identities. No new cryptography. Redaction uses salted commitments so fields can be revealed selectively without breaking integrity; erasure makes commitments opaque while the chain still verifies.

**Naming.** "Continuity Receipt" currently names two different objects in the standards landscape: this specification's agent-session lifecycle record (`continuity-receipt/0.5`), and an IETF SCITT draft that registers the *recovery of stateful assets* in a transparency log (`draft-nikolaichuk-scitt-continuity-receipts`). They are adjacent concepts, not the same object. In external copy, prefer **"agent continuity receipt"** for this specification; see `docs/CROSSWALK_AER1_AADP_SCITT.md`.

## Why this exists

Agents are accumulating persistent memory and doing delegated work at scale, but accountability is still self-reported. This format makes the difference checkable: claims arrive with signed evidence, missing evidence is distinguished from false evidence, and a termination claim (`task.termination`) is required for a task to verify as complete — it proves the issuer signed that the task stopped, not that it did.

Verification verdicts (IETF CTQ-aligned):
`TRUSTED` · `PROVISIONAL` · `INSUFFICIENT_EVIDENCE` · `UNTRUSTED`.
`INSUFFICIENT_EVIDENCE` is explicitly not the same as false.

## Layout

```
SPEC.md                    the v0.4 specification (normative; 0.1-0.3 supported)
VERIFICATION_RECEIPTS.md   companion: signed statements about a verification run
CONFORMANCE_TABLE.md       rule-by-rule conformance matrix (audit surface)
VERIFY_IN_5_MIN.md         the integration kit page (copy-paste, no SDK)
ADOPTER_GUIDE.md            verify, emit, capture; provenance labels and 0.5 candidate example
REVIEW_BRIEF.md            frozen v0.4 independent-review scope
REVIEW_BRIEF_05.md         prepared v0.5 candidate review brief (external report pending)
REVIEW_NOTES_05.md         candidate self-review, findings and open release gates
INTEGRATION_READINESS.md    exact-candidate gate for producer and verifier integration
REVIEW_RESPONSE.md         response to the first independent review (findings → fixes)
schema/                    JSON Schema (2020-12): bundles + verification receipts
THREAT_MODEL.md            what receipts prove, and what they do not
ANCHORING.md               anchoring policy: OpenTimestamps default, chain optional
OPEN_DATA_ANSWER_RECEIPT.md  worked example: an AI answer over an open-data portal
CONTRIBUTING.md            DCO, test rules, scope
ROADMAP.md                 what lands in 0.4 and beyond, and the selection rule
continuity_receipt/        reference implementation (Python, cryptography>=42)
rust/                      second implementation (verifier crate; cargo test)
vectors/                   40 bundle vectors + 21 verification-receipt vectors
vectors/manifest-0.5.json  separate, unpublished candidate corpus
vectors/manifest-0.6.json  authority candidate corpus (additive over 0.5)
tools/make_vectors.py      regenerates the vectors (fresh ids/timestamps; published fixtures stay frozen)
tools/hostile_input_probe.py  malformed-input corpus, structured outcomes + parity
tests/                     conformance suite (vectors, schema, primitives)
```

## Quickstart

```bash
# from PyPI (0.4.1) — clone the repo for the vectors
python3 -m venv .venv && . .venv/bin/activate
pip install continuity-receipt==0.4.1
continuity-verify vectors/02_happy_full.json            # TRUSTED
continuity-consumer vectors/02_happy_full.json --profile conservative # ACCEPT
continuity-receipt-verify vectors/02_happy_full.json    # compat alias
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

## ERC-8004 Validation (On-Chain Agent Trust on Base)

Any governed task bundle can be validated against ERC-8004 validation standards via the live WhiteMagic trust oracle at `api.whitemagic.dev`:

```bash
# Validate bundle and receive an EIP-712 typed oracle attestation for Base smart contracts
curl -s -X POST https://api.whitemagic.dev/erc8004/validate \
  -H "Content-Type: application/json" \
  -H "X-Payment-Tx: <tx_hash_or_cdp_envelope>" \
  -d '{
    "task_id": "task_2026_0929_alpha",
    "task_type": "governed_task_bundle",
    "task_hash": "sha256:...",
    "bundle": { ... }
  }'
```

- **Verdict → Decision:** Bundles with `TRUSTED` verdict emit `{"decision": "ACCEPT", "attestation": { "domain": { "chainId": 8453, ... }, "types": { ... }, "message": { ... }, "signature": "0x..." }}`.
- **Oracle Signer:** Signed by WhiteMagic trusted validator (`did:key:z6MkmKSa...` / `0x915Ff24dE2882f0EaA728bFE1e80953a99e3a6a1`).
- **x402 Micropayments:** Gated via HTTP 402 challenge ($0.01 USDC on Base to `0x213b6bB4B32c5f9F7e8d7950E6A02187f59d5757`).

## Test vectors

40 bundle vectors with machine-readable expectations in `vectors/manifest.json`
(human index: `vectors/INDEX.md`): 0.1 conformance (`01`–`10c`), 0.2
additions — succession records, millisecond timestamps, counterparty
attestations, revocation semantics, Merkle provenance, anchor typing — 0.3
additions: offer → accept binding (`16`–`16d`, including the missing-offer,
terms-mismatch, and expiry cases) and selective disclosure of redacted offer
terms (`16e`/`16f`) — and 0.4 additions: the binding carried through the chain
(`17`–`17j`, including wrong offeree/signer, chronology, issuer, missing-ref,
and unreferenced-accept cases), the mixed-version compatibility case (`18`),
and dedicated negatives for `policy_mismatch`, `redacted_required`, and
`commit_mismatch` (`19`–`21`).
Every schema-valid vector is checked against the schema for its spec version
in CI.

21 verification-receipt vectors in `vectors/verification/` (manifest +
`INDEX.md`): valid TRUSTED/PROVISIONAL/INSUFFICIENT_EVIDENCE records (the full
result — errors, reasons, summary), signature/verdict tampering, wrong bundle,
bad kind/version/verdict/timestamp/digest/error-codes/errors/reasons/summary,
consistency violations, missing signature, issuer swap, revoked issuer (and
the positive case: a revocation statement dated after `verified_at` leaves the
receipt valid), unknown member. Schema:
`schema/verification-receipt-1.schema.json`.

## Status and provenance

- **Origin:** developed in the MandalaOS gate-lite work, where it passed acceptance G1–G8 and the wider project suite (49 tests, dogfood evidence). This repository is the format's public home; it versions independently of any product release train.
- **Releases:** `0.1` (2026-09-18) — spec, reference verifier, 11 vectors. `0.2` (2026-09-18) — `authority.succession`, bundle-level revocation statements, counterparty attestation rules, millisecond timestamps, `merkle-sha256:` provenance, anchor typing, JSON Schema, CI, machine-readable vector manifest. `0.3` (2026-09-23) — `agreement.offer` / `agreement.accept` with digest binding, terms/id equality, and expiry semantics; vectors 16–16f; schema 0.3. Tooling `0.3.3` (2026-09-23) — verification receipts (companion v1: schema, 20 vectors, reference verifier + CLI; records the full result — errors, reasons, summary — with offline consistency checks and an anchoring recipe), agreement emitters, integration kit. `0.4` (2026-09-24, published) — the offer → accept binding carried through the chain (`offeree` required and signer-checked; `agreement_ref` on the bound stages), hostile-input hardening (whole-shape validation, input boundaries, structured outcomes in both implementations), the rule-by-rule conformance table, and the compatibility vector. Tooling `0.4.0` (published) — schema 0.4, 40 bundle + 21 receipt vectors, `tools/hostile_input_probe.py` in CI.
- **Second implementation:** `rust/` — an independent Rust verifier
  (crate `continuity-receipt`) with the same verdict/error semantics; `cargo test`
  checks all 40 bundle vectors and CI diffs it against the Python reference
  (40/40) and the verification-receipt vectors (21/21, crate 0.4.0), with
  digest parity pinned by `tools/differential_verification_receipts.py` and
  hostile-input parity asserted by `tools/hostile_input_probe.py`.
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
