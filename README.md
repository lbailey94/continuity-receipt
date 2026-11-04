# Causal Provenance Receipts (CPR)

**An open specification, test vectors, and reference verifiers for signed agent-task records and offline integrity checks.**

> **Project naming:** Formerly called *Continuity Receipts*, this project uses
> **CPR (Causal Provenance Receipts)** to distinguish agent-task records from
> SCITT asset-recovery proposals. Wire identifiers remain `continuity-receipt/*`.
> Signed hash links bind the disclosed records and their references; they do
> not prove that recorded events happened. Checkpointed session recovery is
> an experimental consumer use case requiring retained state and receiver
> policy; the receipt format alone does not restore an agent session.

**Spec version:** `continuity-receipt/0.5` (CPR core) — published 2026-09-30. Versions `0.1`–`0.5`
are fully supported. Open development items are listed in [`SPEC.md`](SPEC.md) §11.  
**License:** Apache-2.0 (specification text, code, and vectors).  
**Standards context:** The linked individual SCITT-related draft and receipt examples are design references; this repository does not establish IETF/W3C adoption, independent conformance or SCITT registration.

**Version matrix** — the spec and reference implementations version independently:

| Artifact | Published observed version | Published install |
|---|---|---|
| Spec / wire format | `continuity-receipt/0.5` (published 2026-09-30) | — |
| Python reference + CLIs | **0.5.2** | `pip install continuity-receipt==0.5.2` |
| Rust verifier + CLIs | **0.5.1** | `cargo install continuity-receipt --version 0.5.1` |
| JavaScript / TypeScript verifier | **0.1.1** | `npm install continuity-receipt@0.1.1` |

The published installation pins above remain separate from source candidates.
This source prepares Python 0.5.4, Rust 0.5.2 and JavaScript 0.1.2 for artifact
review; those candidate versions are not a registry publication claim.
These are independent registry package pins, separate from a source commit.
Python includes the experimental local memory receiver; Rust and
JavaScript do not implement that receiver.

The three language verifiers support spec 0.5 record checks: local-authority
and sandbox-class vocabulary, runner-profile binding, state commitments, and
duplicate-member rejection. Consumer policy assessment is Python-only and
accepts receipt specs 0.1–0.4. Differential fixture agreement does not prove
that a producer actually enforced the sandbox or held external authority.
Record the installed package metadata and artifact hash when reporting results.
For Python, `python -c 'from importlib.metadata import version; print(version("continuity-receipt"))'`
reports the installed package version; a version string alone does not identify
the source tree or binary bytes.

A **Causal Provenance Receipt (CPR)** is a signed, hash-chained record of one governed task:
**decision → authority → execution → delivery → termination → settlement**. It is designed to be verified offline by any third party — insurers, arbiters, procurement, courts, other agents — without trusting the channel that delivered it or accepting someone else's verification. What it proves is bounded: a receipt attests what its issuer signed, not that the described events occurred — issuer honesty is out of scope by design ([`THREAT_MODEL.md`](THREAT_MODEL.md) #2–#3, [`CONFORMANCE_TABLE.md`](CONFORMANCE_TABLE.md) §E).

The spec is intentionally small: JSON (RFC 8785 canonicalization), SHA-256, Ed25519, `did:key` identities. No new cryptography. Redaction uses salted commitments so fields can be revealed selectively without breaking integrity; erasure makes commitments opaque while the chain still verifies.

## Why this exists

Agents are accumulating persistent memory and doing delegated work at scale, but accountability is still self-reported. This format makes the difference checkable: claims arrive with signed evidence, missing evidence is distinguished from false evidence, and a termination claim (`task.termination`) is required for a task to verify as complete — it proves the issuer signed that the task stopped, not that it did.

Verification verdicts (IETF CTQ-aligned):
`TRUSTED` · `PROVISIONAL` · `INSUFFICIENT_EVIDENCE` · `UNTRUSTED`.
`INSUFFICIENT_EVIDENCE` is explicitly not the same as false.

## Layout

```
SPEC.md                    the v0.5 specification (normative; 0.1-0.5 supported)
VERIFICATION_RECEIPTS.md   companion: signed statements about a verification run
CONFORMANCE.md             conformance criteria, verification profiles, and disclosures
CONFORMANCE_TABLE.md       rule-by-rule conformance matrix (audit surface)
THREAT_MODEL.md            what receipts prove, and what they do not
ANCHORING.md               anchoring policy: OpenTimestamps default, chain optional
SIGNING.md                 tag signing policy and public verification keys
SECURITY.md                vulnerability reporting and security boundaries
CHANGELOG.md               version release history and breaking changes
CONTRIBUTING.md            DCO, test rules, scope
schema/                    JSON Schema (2020-12): bundles + verification receipts
continuity_receipt/        reference implementation (Python, cryptography>=42)
rust/                      second implementation (verifier crate; cargo test)
js/                        third implementation (JavaScript / TypeScript verifier)
vectors/                   40 bundle vectors + 21 verification-receipt vectors
examples/                  worked examples and integration fixtures
tests/                     conformance test suite
```

## Quickstart

```bash
# Run from a checkout for the vectors; use the published Python verifier.
python3 -m venv .venv
.venv/bin/python -m pip install continuity-receipt
.venv/bin/continuity-verify vectors/02_happy_full.json            # TRUSTED
.venv/bin/continuity-consumer vectors/17_agreement_bound.json \
  --policy examples/consumer-policy-0.4.json                     # ACCEPT
.venv/bin/continuity-receipt-verify vectors/02_happy_full.json   # compat alias
.venv/bin/continuity-receipt-verify vectors/10b_anchor_missing.json --require-anchor
.venv/bin/continuity-receipt-verify-receipt vectors/verification/01_valid.json \
  --bundle vectors/verification/bundle.json
.venv/bin/continuity-receipt-disclose --help

# Or install editable from source:
.venv/bin/python -m pip install -e . jsonschema
.venv/bin/python -m continuity_receipt.verify vectors/02_happy_full.json

# Run the conformance suite (vectors + schema + primitives)
.venv/bin/python -m unittest discover -s tests -v
```

Python includes the local `cpr-memory` receiver for signed file snapshots, a separately retained checkpoint reference, and an explicitly named resume path.

The PACMI evaluator (`cpr-check-pacmi` / `continuity-receipt-check-pacmi`) and PACMI/T10 threat conformance evaluator are available directly in the reference Python implementation.

## ERC-8004 Validation (Base)

The reviewed hosted API/package/ERC validation interface is deployed at `https://api.whitemagic.dev`. Public `GET https://api.whitemagic.dev/info` reports verifier version, supported specs 0.1–0.5, and endpoint status.

The request below illustrates the adapter shape; consult the live documentation for credentials and payment gating:

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
- **Attestation format:** The advertised `ValidationResponse` carries typed attestation fields signed with an Ed25519 `did:key`.
- **Gating:** Keyed or x402 micro-lease on Base to `0x213b6bB4fB073E86167c58DA6Cb6E9477557DaA8`. Live details: `https://api.whitemagic.dev/info` · docs: `https://api.whitemagic.dev/docs`.

## Test vectors

- **40 bundle vectors** with machine-readable expectations in `vectors/manifest.json` (human index: `vectors/INDEX.md`): 0.1 conformance (`01`–`10c`), 0.2 additions (succession records, millisecond timestamps, counterparty attestations, revocation semantics, Merkle provenance, anchor typing), 0.3 additions (offer → accept binding `16`–`16d`, selective disclosure `16e`/`16f`), 0.4 additions (bound stages `17`–`17j`, mixed-version `18`, negative controls `19`–`21`), and 0.5 additions (sandbox vocabulary, runner profile, state commitment).
- **21 verification-receipt vectors** in `vectors/verification/` (manifest + `INDEX.md`): valid TRUSTED/PROVISIONAL/INSUFFICIENT_EVIDENCE records (errors, reasons, summary), signature/verdict tampering, wrong bundle, bad kind/version/verdict/timestamp/digest/error-codes, consistency violations, and issuer revocation controls.

Every schema-valid vector is verified against the schema for its spec version in CI.

## Status and provenance

- **Origin:** Developed in the MandalaOS gate-lite work, where it passed acceptance G1–G8 and the wider project suite. This repository is the format's public home; it versions independently of any product release train.
- **Releases:** `0.1` (spec, reference verifier, 11 vectors) → `0.2` (succession, revocation, Merkle provenance, anchor typing, schema) → `0.3` (agreements, digest binding, verification receipts v1) → `0.4` (bound chains, hostile-input hardening, conformance table) → `0.5` (local authority, sandbox profiles, state commitments, duplicate-member rejection) → `0.5.4` (strict RFC 3339 calendar bounds and wire spelling).
- **Implementations:**
  - Python: `continuity_receipt/` — primary reference implementation with full CLI tooling and PACMI evaluator.
  - Rust: `rust/` — high-performance verifier crate with identical verdict/error semantics.
  - JavaScript: `js/` — TypeScript / JS npm package (`continuity-receipt`).
- **Standards context:** The format is developed as a contribution to the emerging neutral layer for verifiable agentic computing (IETF SCITT and W3C Agent Identity & Memory Interoperability CG).

## The stack

> Local memory → governed execution → verifiable causal provenance (CPR)

- [`whitemagic`](https://github.com/lbailey94/whitemagic) — local-first memory and session continuity for AI agents
- [`continuity-receipt`](https://github.com/lbailey94/continuity-receipt) — Causal Provenance Receipts (CPR): portable, offline-verifiable task evidence & session resuscitation (Apache-2.0, this repo)
- [`mandala`](https://github.com/lbailey94/mandala) — bounded agent execution and Landlock LSM governance kernel
- [`whitemagic-plugins`](https://github.com/lbailey94/whitemagic-plugins) — client integrations and adapters

Each repository stands on its own: WhiteMagic does not require Mandala, and CPR does not require WhiteMagic. Three entrances — **use it** → `whitemagic`; **review a protocol** → `continuity-receipt`; **attack the security architecture** → `mandala`.

## Contributing

Contributions and issue reports are welcome. Interoperability discussion belongs in open standards venues; this repository tracks concrete specifications, schemas, test vectors, and verifier implementations.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). The specification is published for royalty-free implementation. Test keys in the vectors are deterministic and public; **never use them for real receipts**.
