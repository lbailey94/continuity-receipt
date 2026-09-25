# Roadmap

## 0.5 development candidate (unpublished)

- [x] Local pass class and execution sandbox vocabulary (`bwrap`, `landlock`,
  legacy/combined `bwrap-landlock`, and honest unconfined `none`) implemented
  in both verifiers, schema 0.5, and separate signed candidate vectors. Values
  validate issuer claims only and do not prove runtime confinement.
- [x] State commitment shape implemented with explicit validation and
  non-verification limits (see `SPEC_0.5_DRAFT.md`). The WhiteMagic karma-head
  bundle supplies the initial captured use case; vector 22 is modeled.
- [x] Adopter guide and file-snapshot producer example distinguish verification,
  local issuance, runtime capture, and independent corroboration.
- [ ] Capture a second independent producer use case, resolve the candidate
  design questions, obtain adversarial review, then freeze/publish a 0.5
  release. The hosted referee and published 0.4.0 packages are unchanged.


**Current release:** spec `continuity-receipt/0.4` (2026-09-24; Python tooling
0.4.0 on PyPI, Rust crate 0.4.0 on crates.io). Spec `0.1`–`0.3` remain
supported.
**Versioning policy:** additive fields within 0.x; breaking changes require a new minor plus a new vector set; the verifier refuses unknown spec versions.
**Selection rule:** a change lands only if it is testable — every change ships with a vector, an acceptance test, or a documented negative case. Failures and rejected designs are published, not hidden.

## Shipped

### Spec 0.4 (2026-09-24) — the binding is carried
- [x] `agreement.accept.offeree` required and signer-checked; accept must follow its offer.
- [x] `agreement_ref` on `task.decision` / `task.execution` / `delivery.attestation` / `settlement`, checked for resolution, chronology, and issuer; unreferenced accepts and missing refs are PROVISIONAL.
- [x] Vectors 17–17j (adversarial), 18 (mixed-version compatibility), 19–21 (`policy_mismatch`, `redacted_required`, `commit_mismatch`); schema 0.4; SPEC §10 mixed-version rule.
- [x] Verifier robustness: whole-shape validation pass, input boundaries, structured hostile-input outcomes with Python↔Rust parity (`tools/hostile_input_probe.py`).
- [x] Conformance table (`CONFORMANCE_TABLE.md`) — rule → checks → vectors → non-enforcement.
- [x] Documentation pass: proof-boundary wording, opaque-label identifiers, quota convention, counts and compatibility notes.
- [x] Publication: PyPI + crates.io 0.4.0, hosted verifier redeploy (2026-09-24); signed tags including retro-tags for the 0.3 line.

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

### Spec 0.3 (2026-09-23) — offer → accept binding
- [x] `agreement.offer` / `agreement.accept` record types with digest binding
  (`offer_ref`), terms/id equality, and `valid_until` expiry (§4.8–4.9, §7).
- [x] Verdict semantics: missing offer → `INSUFFICIENT_EVIDENCE`
  (`missing_offer`); mismatch → `UNTRUSTED` (`offer_mismatch`); expired →
  `UNTRUSTED` (`offer_expired`).
- [x] Vectors 16/16b/16c/16d; schema 0.3; capabilities disclosure.
- [x] Rust parity for the 0.3 types — crate 0.3.2, differential 26/26.
- [x] Reference emitters (`continuity_receipt.agreements`) + vectors 16e/16f
  (redacted/disclosed offer terms).

### Companion: verification receipts (2026-09-23) — tooling 0.3.3
- [x] Wire format + semantics frozen (`VERIFICATION_RECEIPTS.md`): signed
  statement binding the JCS-canonical bundle digest to verdict, error codes,
  implementation/version, and time; `did:key` attribution.
- [x] Schema (`schema/verification-receipt-1.schema.json`), 20 vectors
  (`vectors/verification/`, manifest + INDEX), reference verifier
  (`continuity_receipt.verification`) + CLI `continuity-receipt-verify-receipt`.
- [x] Receipts record the **full result** — errors, provisional/insufficient
  reasons, summary — with offline consistency checks (`verdict_mismatch`,
  `error_codes_mismatch`) and an anchoring recipe (`--canonical` + OTS).
- [x] Opt-in issuer-revocation check (`key_revoked`) reusing the bundle
  revocation statement shape.
- [x] Integration kit page (`VERIFY_IN_5_MIN.md`).
- [x] Rust parity — `rust/src/verification.rs` + CLI + 20-vector runner,
  differential 20/20 (crate 0.3.3).

### 0.2.0 (2026-09-18)
- [x] `authority.succession` record type.
- [x] Millisecond timestamps + clock-skew policy note.
- [x] Counterparty attestation rule + per-signature reporting (`bad_attestation`).
- [x] Bundle-level self-signed revocation statements with time semantics (`key_revoked`); receipts before revocation remain valid.
- [x] `merkle-sha256:` provenance roots (`provenance_invalid` for unsupported forms).
- [x] Anchor metadata type enum (`anchor_invalid` for unknown types).
- [x] Test set 11 → 20 vectors; suite: vectors + schema + primitives, 10 tests.

## 0.3 cycle — landed (retained for provenance)

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
   `invalid`). **Rust parity landed 2026-09-21** (`rust/src/anchor.rs` +
   `continuity-receipt-anchor` + `tools/differential_anchor.py` in CI, 7/7
   over the real fixtures) and published as crate `0.3.1`. Remaining: a
   trusted-header helper — header supply stays caller-owned by design (no
   PoW/chain validation).
   **Real fixtures landed** under `vectors/anchor/` (5 example proofs from
   `opentimestamps-client`, MIT, plus headers from the Blockstream Esplora
   API; keccak256 path is a published `unsupported_op` negative case).
   Renewal guidance: `ANCHORING.md` §Failure and renewal.
3. **Conformance packaging** — **landed 2026-09-24:** machine-readable
   capability disclosure + vector manifest + `CONFORMANCE_TABLE.md` (rule →
   checks → vectors) + the hosted conformance referee (`POST /conformance`,
   signed reports). Remaining: SAIHM field-mapping crosswalk and memorywire
   five-op interop profile.
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
