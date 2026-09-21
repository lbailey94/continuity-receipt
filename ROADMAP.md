# Roadmap

**Current release:** `continuity-receipt/0.2.0` (2026-09-18); `0.1` remains supported.
**Versioning policy:** additive fields within 0.x; breaking changes require a new minor plus a new vector set; the verifier refuses unknown spec versions.
**Selection rule:** a change lands only if it is testable — every change ships with a vector, an acceptance test, or a documented negative case. Failures and rejected designs are published, not hidden.

## Shipped

### 0.1.0 (2026-09-18)
Spec, reference verifier, 11 vectors. JSON + RFC 8785 subset, SHA-256, Ed25519, `did:key`; salted-commitment redaction; CTQ-aligned verdicts.

### 0.1.x housekeeping (2026-09-18)
- [x] JSON Schema (`schema/continuity-receipt-0.2.schema.json`) + CI validation of every schema-valid vector — closes the last open goal from SPEC §1.1.
- [x] Vector-count wording aligned (10 vectors / 11 files in 0.1).
- [x] GitHub Actions CI (Python 3.11 + 3.12; conformance suite + CLI-surface verification).
- [x] `THREAT_MODEL.md` — 13 threat classes, incl. the open pre-revocation-compromise gap and the commitment-substitution analysis.
- [x] `CONTRIBUTING.md` + DCO (no CLA).
- [x] Machine-readable vector manifest (`vectors/manifest.json`).
- [x] Anchor policy decided (`ANCHORING.md`): OpenTimestamps recommended default, `public-chain` supported for counterparties that require it, `custom` opaque; type enum frozen; proof verification delegated to provider tooling until 0.3.
- [x] PyPI packaging prepared: `continuity-receipt` name available (2026-09-18);
  sdist + wheel + console scripts (`continuity-receipt-verify`,
  `continuity-receipt-disclose`); CI job builds the wheel, installs it, and
  runs vectors through the installed CLI.
- [x] PyPI upload — `continuity-receipt` 0.2.0 published 2026-09-18
  (pypi.org/project/continuity-receipt), verified from a clean venv.

### 0.2.0 (2026-09-18)
- [x] `authority.succession` record type.
- [x] Millisecond timestamps + clock-skew policy note.
- [x] Counterparty attestation rule + per-signature reporting (`bad_attestation`).
- [x] Bundle-level self-signed revocation statements with time semantics (`key_revoked`); receipts before revocation remain valid.
- [x] `merkle-sha256:` provenance roots (`provenance_invalid` for unsupported forms).
- [x] Anchor metadata type enum (`anchor_invalid` for unknown types).
- [x] Test set 11 → 20 vectors; suite: vectors + schema + primitives, 10 tests.

## 0.3 candidates (in suggested order)

**Priority pin (2026-09-20):** 1) anchor proof verification, 2) revocation
distribution design, 3) remaining Rust completion + crates.io publication.

1. **Rust second implementation** — **started 2026-09-18:** `rust/` crate
   `continuity-receipt` 0.3.0-alpha.1 covers JCS canonicalization (pinned
   subset), Ed25519 + `did:key`, full verdict/error-code semantics,
   revocation/attestation/anchor/merkle handling, CLI, and the
   `vectors/manifest.json` runner. CI runs `cargo test` (20/20) plus a
   Python-vs-Rust differential over every vector. `disclose` ported
   2026-09-21 (`rust/src/disclose.rs` + `continuity-receipt-disclose` +
   `tools/differential_disclose.py` in CI: identical maps, byte-identical
   re-signed tails, cross-verified verdicts). Generated fuzz corpus landed
   2026-09-21 (`rust/tests/fuzz_corpus.rs`: deterministic structural
   mutations + malformed shapes + byte truncations; every case must produce
   a structured verdict and never panic; `CR_FUZZ_CORPUS_DIR` writes the
   corpus for inspection). **Published 2026-09-21:** `continuity-receipt`
   `0.3.0` on crates.io (`0.3.0-alpha.1` first to validate the pipeline, then
   `0.3.0`); runbook in `rust/PUBLISH.md`. Purpose: the
   CG's ≥2-independent-implementations bar, native embedding for WhiteMagic
   (Rust), single-binary deployment for gate-hard images. The Python
   implementation remains the reference.
2. **Anchor proof verification** — **companion tool landed 2026-09-21:**
   `continuity_receipt.anchor` + `continuity-receipt-anchor` verify
   OpenTimestamps detached proofs (wire-format parser with LEB128 varints,
   tree replay, Bitcoin attestation checked against a supplied 80-byte header
   by merkle-root equality; `verified` / `unverified` / `mismatch` /
   `invalid`). Remaining: optional Rust parity, and a trusted-header helper —
   header supply stays caller-owned by design (no PoW/chain validation).
   **Real fixtures landed** under `vectors/anchor/` (5 example proofs from
   `opentimestamps-client`, MIT, plus headers from the Blockstream Esplora
   API; keccak256 path is a published `unsupported_op` negative case).
   Renewal guidance: `ANCHORING.md` §Failure and renewal.
3. **Conformance packaging** — machine-readable verifier capability
   disclosure + vector manifest prepared for the CG conformance surface;
   SAIHM field-mapping crosswalk and memorywire five-op interop profile.
4. **Revocation distribution design** — **tooling landed 2026-09-21:**
   static revocation lists (`continuity-receipt-revocations` document) +
   `--revocations` on the verify/disclose CLIs, merged with bundle statements;
   per-statement signatures make withholding the only channel attack;
   fail-closed on unusable lists. Policy: `REVOCATION_DISTRIBUTION.md`.
   Remaining: transparency-log omission evidence (demand-gated), global/root
   lists (needs an issuer registry).
5. **Succession hardening** — multi-party signatures on succession records
   (both authorities attest).
6. **Commitment hardening** — HMAC commitments and domain separation; adopt
   only with a demonstrated attack or implementer request (`THREAT_MODEL.md` §9).
7. **CBOR profile** (RFC 8949 §4.2) with byte-equivalence vectors — only
   when an implementer needs it; the signed domain remains JSON canonical
   bytes until then. The Rust implementation may be that implementer.
8. **Required-field minimalism review** with an underwriter (after ~3 months
   of real receipts).

## 0.4+ / open questions

- Selective disclosure beyond per-field salts (evaluate; do not adopt by default — simplicity is a feature).
- Formal specification of canonicalization + verification (small enough to verify mechanically).
- Interop profiles with SAIHM and memorywire once their normative text stabilizes; adapter implementations.

## Non-goals (unchanged)

No custody of funds; no payment protocol; no arbitration; no reputation scoring; no storage protocol. Receipts ground those layers; they do not replace them.

## How to contribute

Open an issue for spec questions, mapping suggestions, or vectors. Interoperability discussion belongs in the open standards venues (W3C AI Agent Memory Interoperability CG; IETF agentproto); this repository tracks concrete text, code, and vectors.
