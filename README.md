# Causal Provenance Receipts (CPR)

**An open specification, test vectors, and reference verifiers for signed agent-task records and offline integrity checks.**

> **Project naming:** Formerly called *Continuity Receipts*, this project uses
> **CPR (Causal Provenance Receipts)** to distinguish agent-task records from
> SCITT asset-recovery proposals. Wire identifiers remain `continuity-receipt/*`.
> Signed hash links bind the disclosed records and their references; they do
> not prove that recorded events happened. Checkpointed session recovery is
> an experimental consumer use case requiring retained state and receiver
> policy; the receipt format alone does not restore an agent session.

**Spec version:** `continuity-receipt/0.5` (CPR core) — published 2026-09-30. `0.1`–`0.4`
remain supported; `0.6` is an experimental development candidate
([SPEC_0.6_DRAFT.md](SPEC_0.6_DRAFT.md) & [SPEC_0.6_PQ_PROFILE_DRAFT.md](SPEC_0.6_PQ_PROFILE_DRAFT.md)). Open items are listed in `SPEC.md` §11.
**License:** Apache-2.0 (specification text, code, and vectors).

**SCITT design work:** [The mapping note](docs/SCITT_MAPPING_AND_COSE_SIGN1_FEASIBILITY.md)
lists the unresolved envelope, registration, trust-policy, and interoperability
work. A CPR signature is not a SCITT registration receipt. No COSE size or speed
improvement is established by this checkout.

**Version matrix** — the spec and the reference implementations version independently:

| Artifact | Current | Published install |
|---|---|---|
| Spec / wire format | `continuity-receipt/0.5` (published 2026-09-30) | — |
| Python reference + CLIs | **0.5.2** | `pip install continuity-receipt==0.5.2` |
| Rust verifier + CLIs | **0.5.1** | `cargo install continuity-receipt --version 0.5.1` |
| JavaScript / TypeScript verifier | **0.1.1** | `npm install continuity-receipt@0.1.1` |

The Python package is 0.5.2; Rust remains 0.5.1 and JavaScript remains 0.1.1.
These are independent registry package pins, separate from a source commit.
Python 0.5.2 includes the experimental local memory receiver; Rust and
JavaScript do not implement that receiver.

The three language verifiers support spec 0.5 record checks: local-authority
and sandbox-class vocabulary, runner-profile binding, state commitments, and
duplicate-member rejection. Consumer policy assessment is Python-only and
accepts receipt specs 0.1–0.4. Differential fixture agreement does not prove
that a producer actually enforced the sandbox or held external authority.
These implementations are maintained by the same project. See the
[review brief](REVIEW_BRIEF.md) for exact scope, reproducible checks, and limits.
Current source and the published Python wheel differ on experimental
0.6 head-binding checks; the review brief records a counterexample. Do not
infer that a registry package enforces the current source's expected-head
rules from their matching version strings.
Record the installed package metadata and artifact hash when reporting results.
For Python, `python -c 'from importlib.metadata import version; print(version("continuity-receipt"))'`
reports the installed package version; a version string alone does not identify
the source tree or binary bytes.

A **Causal Provenance Receipt (CPR)** is a signed, hash-chained record of one governed task:
**decision → authority → execution → delivery → termination → settlement**. It is designed to be verified offline by any third party — insurers, arbiters, procurement, courts, other agents — without trusting the channel that delivered it or accepting someone else's verification. What it proves is bounded: a receipt attests what its issuer signed, not that the described events occurred — issuer honesty is out of scope by design (`THREAT_MODEL.md` #2–#3, `CONFORMANCE_TABLE.md` §E).

The spec is intentionally small: JSON (RFC 8785 canonicalization), SHA-256, Ed25519, `did:key` identities. No new cryptography. Redaction uses salted commitments so fields can be revealed selectively without breaking integrity; erasure makes commitments opaque while the chain still verifies.

**Standards Composition:** For detailed mapping to adjacent emerging standards, see:
- [docs/SCITT_MAPPING_AND_COSE_SIGN1_FEASIBILITY.md](docs/SCITT_MAPPING_AND_COSE_SIGN1_FEASIBILITY.md) (IETF SCITT & COSE_Sign1)
- [docs/CROSSWALK_AER1_AADP_SCITT.md](docs/CROSSWALK_AER1_AADP_SCITT.md) (AER-1 tool receipts, AADP bound permits, SCITT)
- [docs/CROSSWALK_W3C_AGENT_IDENTITY_CG_v0.md](docs/CROSSWALK_W3C_AGENT_IDENTITY_CG_v0.md) (W3C Agent Identity & Memory Interoperability CG)

## Why this exists

Agents are accumulating persistent memory and doing delegated work at scale, but accountability is still self-reported. This format makes the difference checkable: claims arrive with signed evidence, missing evidence is distinguished from false evidence, and a termination claim (`task.termination`) is required for a task to verify as complete — it proves the issuer signed that the task stopped, not that it did.

Verification verdicts (IETF CTQ-aligned):
`TRUSTED` · `PROVISIONAL` · `INSUFFICIENT_EVIDENCE` · `UNTRUSTED`.
`INSUFFICIENT_EVIDENCE` is explicitly not the same as false.

## Layout

```
SPEC.md                    the v0.5 specification (normative; 0.1-0.5 supported)
VERIFICATION_RECEIPTS.md   companion: signed statements about a verification run
CONFORMANCE_TABLE.md       rule-by-rule conformance matrix (audit surface)
VERIFY_IN_5_MIN.md         the integration kit page (copy-paste, no SDK)
ADOPTER_GUIDE.md            verify, emit, capture; provenance labels and 0.5 example
REVIEW_BRIEF.md            current pinned review scope, commands, and trust limits
schema/                    JSON Schema (2020-12): bundles + verification receipts
THREAT_MODEL.md            what receipts prove, and what they do not
ANCHORING.md               anchoring policy: OpenTimestamps default, chain optional
OPEN_DATA_ANSWER_RECEIPT.md  worked example: an AI answer over an open-data portal
examples/03_public_text_claim_review/  bounded text-grading, provenance, artifact hashes, and receipt verification fixture
CONTRIBUTING.md            DCO, test rules, scope
ROADMAP.md                 shipped versions, open qualification gates, and selection rule
docs/                      crosswalks (sahu; ACTA/asqav; AER-1/AADP/SCITT) + design notes + consumer profile
continuity_receipt/        reference implementation (Python, cryptography>=42)
rust/                      second implementation (verifier crate; cargo test)
vectors/                   40 bundle vectors + 21 verification-receipt vectors
vectors/manifest-0.5.json  separate 0.5 corpus (21 vectors; outside the pinned referee set)
vectors/manifest-0.6.json  authority candidate corpus (additive over 0.5)
tools/make_vectors.py      regenerates the vectors (fresh ids/timestamps; published fixtures stay frozen)
tools/hostile_input_probe.py  malformed-input corpus, structured outcomes + parity
tools/interop_sahu_vectors.py  reproduce draft-sahu agent-action-receipts vectors
tools/interop_acta_probe.py    ACTA/asqav minimal-construction probe (pinned revisions)
tools/interop_aer1_probe.py    live AER-1 receipt verification probe (draft-zambo-aer1-20)
tests/                     conformance suite (vectors, schema, primitives)
```

## Quickstart

```bash
# Run from a checkout for the vectors; use the published Python verifier.
python3 -m venv .venv-wheel
.venv-wheel/bin/python -m pip install continuity-receipt==0.5.2
.venv-wheel/bin/continuity-verify vectors/02_happy_full.json            # TRUSTED
.venv-wheel/bin/continuity-consumer vectors/17_agreement_bound.json \
  --policy examples/consumer-policy-0.4.json          # ACCEPT
.venv-wheel/bin/continuity-receipt-verify vectors/02_happy_full.json    # compat alias
.venv-wheel/bin/continuity-receipt-verify vectors/10b_anchor_missing.json --require-anchor
.venv-wheel/bin/continuity-receipt-verify-receipt vectors/verification/01_valid.json \
  --bundle vectors/verification/bundle.json
.venv-wheel/bin/continuity-receipt-disclose --help

# Or install the selected source, including its source-only CLIs.
# Record git rev-parse HEAD before installing; source and PyPI differ.
python3 -m venv .venv-source
.venv-source/bin/python -m pip install -e . jsonschema
.venv-source/bin/python -m continuity_receipt.verify vectors/02_happy_full.json

# Run the conformance suite (vectors + schema + primitives) in the source env.
.venv-source/bin/python -m unittest discover -s tests -v
```

Python 0.5.2 includes an experimental local `cpr-memory` receiver for
signed file snapshots, a separately retained checkpoint reference, and an
explicitly named resume path. It remains an experimental consumer feature;
see [the receiver guide](docs/EXPERIMENTAL_MEMORY_RESUME.md) and
[the local profile contract](docs/LOCAL_RECEIVER_PROFILE.md) for its limits.

The PACMI evaluator (`cpr-check-pacmi` / `continuity-receipt-check-pacmi`)
and the added PACMI/T10 fixtures on current main are **source-only**. The
published 0.5.2 wheel does not contain that module or those console commands.
Use the editable source install above in its separate environment, record its
commit, and run `.venv-source/bin/cpr-check-pacmi --help`. Matching package
version strings do not establish source/wheel parity. The historical,
version-pinned [five-minute verifier exercise](VERIFY_IN_5_MIN.md) retains its
original pins.

## ERC-8004 Validation (Base)

The reviewed hosted API/package/ERC update was deployed on 2026-09-30 after
explicit maintainer approval. Public `GET https://api.whitemagic.dev/info`
reports verifier package 0.5.1, supporting specs 0.1–0.6 (0.6 experimental).
The primary checked installed Python module hashes against the published
wheel,82 live loopback vector/input cases, 13 authenticated public `/verify`
cases, and 4 live loopback ERC cases with independently verified Ed25519
attestations. Temporary evaluation credentials were removed. These checks
made no payment and performed no EVM relay; authenticated public ERC POST
remains untested.
The request below illustrates the adapter shape; consult the live documentation
for credentials and payment gating.

```bash
curl -s -X POST https://api.whitemagic.dev/erc8004/validate \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "task_2026_0929_alpha",
    "task_hash": "sha256:…",
    "bundle": { … }
  }'
```

- **Outcome:** `1: ACCEPT` (TRUSTED), `0: REJECT` (UNTRUSTED), `2: NEEDS_EVIDENCE` (PROVISIONAL / INSUFFICIENT); `422` when `task_hash` does not bind to the bundle.
- **Attestation format:** the advertised `ValidationResponse` has EIP-712-style typed fields, but its signer is an Ed25519 `did:key`, not an EVM EIP-712 wallet signature. It must not be presented as an EVM-verifiable EIP-712 signature. On-chain relay is not enabled (`onchain.relayed: false`). The attestation itself was not retrieved or validated in this audit.
- **Gating:** keyed or x402 — $0.01 USDC (5-minute task lease) or $0.50 USDC (24-hour day pass) on Base to `0x213b6bB4fB073E86167c58DA6Cb6E9477557DaA8`. Live details: https://api.whitemagic.dev/info · docs: https://api.whitemagic.dev/docs

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
in CI. The published 0.5 package tag contains its separate 21-vector manifest
(`vectors/manifest-0.5.json`) and the 10-vector 0.6 draft-authority corpus
(`vectors/manifest-0.6.json`). The latter accompanies experimental 0.6
implementation behavior; it does not make the 0.6 specification a release.

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
- **Releases:** `0.1` (2026-09-18) — spec, reference verifier, 11 vectors. `0.2` (2026-09-18) — `authority.succession`, bundle-level revocation statements, counterparty attestation rules, millisecond timestamps, `merkle-sha256:` provenance, anchor typing, JSON Schema, CI, machine-readable vector manifest. `0.3` (2026-09-23) — `agreement.offer` / `agreement.accept` with digest binding, terms/id equality, and expiry semantics; vectors 16–16f; schema 0.3. Tooling `0.3.3` (2026-09-23) — verification receipts (companion v1: schema, 20 vectors, reference verifier + CLI; records the full result — errors, reasons, summary — with offline consistency checks and an anchoring recipe), agreement emitters, integration kit. `0.4` (2026-09-24, published) — the offer → accept binding carried through the chain (`offeree` required and signer-checked; `agreement_ref` on the bound stages), hostile-input hardening (whole-shape validation, input boundaries, structured outcomes in both implementations), the rule-by-rule conformance table, and the compatibility vector. Tooling `0.4.0` (published) — schema 0.4, 40 bundle + 21 receipt vectors, `tools/hostile_input_probe.py` in CI. `0.5` (2026-09-30, published) — local authority (`mandala_class: local`), execution sandbox vocabulary with `runner_profile` binding, `state.commitment` (chain-head and file snapshots), duplicate-member rejection in all parsers, and the consumer profile assessment; schema 0.5, candidate vectors 22–23b, crosswalk documentation. Tooling `0.5.0` (published) — PyPI + crates.io. Tooling `0.5.1` (2026-10-01, published) — packaging alignment (version metadata); includes the reviewed consumer hardening. Python-only `0.5.2` (2026-10-27) — adds the experimental checkpointed local memory receiver; CPR 0.5 wire behavior, Rust 0.5.1, and JavaScript 0.1.1 stay unchanged.
- **Second implementation:** `rust/` — a separate Rust verifier maintained in this project
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

> Local memory → governed execution → verifiable causal provenance (CPR)

- [`whitemagic`](https://github.com/lbailey94/whitemagic) — local-first memory and session continuity for AI agents
- [`continuity-receipt`](https://github.com/lbailey94/continuity-receipt) — Causal Provenance Receipts (CPR): portable, offline-verifiable task evidence & session resuscitation (Apache-2.0, this repo)
- [`mandalaos-gate-lite`](https://github.com/lbailey94/mandalaos-gate-lite) — bounded agent execution that emits receipts (review snapshot)
- [`whitemagic-plugins`](https://github.com/lbailey94/whitemagic-plugins) — client integrations and adapters

Each repository stands on its own: WhiteMagic does not require MandalaOS, and
CPR / Continuity Receipt does not require WhiteMagic. Three entrances — **use it** →
`whitemagic`; **review a protocol** → `continuity-receipt`; **attack the
security architecture** → `mandalaos-gate-lite`.

## Contributing

Open an issue for spec questions, mapping suggestions, or implementation feedback. Interoperability discussion belongs in the open standards venues; this repository tracks concrete text and vectors.

## License

Apache License 2.0 — see `LICENSE`. The specification is published for royalty-free implementation. Test keys in the vectors are deterministic and public; **never use them for real receipts**.
