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
- [x] Anchor shape decided: OpenTimestamps as recommended v0 practice; type enum frozen; external proof verification delegated to provider tooling.
- [ ] PyPI packaging (`continuity-receipt`) — name availability check pending.

### 0.2.0 (2026-09-18)
- [x] `authority.succession` record type.
- [x] Millisecond timestamps + clock-skew policy note.
- [x] Counterparty attestation rule + per-signature reporting (`bad_attestation`).
- [x] Bundle-level self-signed revocation statements with time semantics (`key_revoked`); receipts before revocation remain valid.
- [x] `merkle-sha256:` provenance roots (`provenance_invalid` for unsupported forms).
- [x] Anchor metadata type enum (`anchor_invalid` for unknown types).
- [x] Test set 11 → 20 vectors; suite: vectors + schema + primitives, 10 tests.

## 0.3 candidates (in suggested order)

1. **PyPI packaging** and `pip install` path (finish 0.1.x item).
2. **Revocation distribution design** — how statements travel beyond the bundle (static files, transparency log, or monitoring); closes part of the pre-revocation-compromise gap.
3. **Anchor proof verification** — OpenTimestamps proof checking in the verifier (or a companion tool), plus proof-renewal guidance.
4. **Succession hardening** — multi-party signatures on succession records (both authorities attest).
5. **Commitment hardening** — HMAC commitments and domain separation; adopt only with a demonstrated attack or implementer request (analysis on record in `THREAT_MODEL.md`).
6. **CBOR profile** (RFC 8949 §4.2) with byte-equivalence vectors — only when an implementer needs it; the signed domain remains JSON canonical bytes until then.
7. **Conformance packaging** — vector manifest prepared for the W3C CG's conformance surface; verifier capability disclosure.
8. **Required-field minimalism review** with an underwriter (after ~3 months of real receipts).

## 0.4+ / open questions

- Selective disclosure beyond per-field salts (evaluate; do not adopt by default — simplicity is a feature).
- Formal specification of canonicalization + verification (small enough to verify mechanically).
- Interop profiles with SAIHM and memorywire once their normative text stabilizes; adapter implementations.

## Non-goals (unchanged)

No custody of funds; no payment protocol; no arbitration; no reputation scoring; no storage protocol. Receipts ground those layers; they do not replace them.

## How to contribute

Open an issue for spec questions, mapping suggestions, or vectors. Interoperability discussion belongs in the open standards venues (W3C AI Agent Memory Interoperability CG; IETF agentproto); this repository tracks concrete text, code, and vectors.
