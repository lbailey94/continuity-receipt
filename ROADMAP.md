# Roadmap

**Current release:** `continuity-receipt/0.1.0` (2026-09-18).
**Versioning policy:** additive fields within 0.x; breaking changes require a new minor (`0.2`) plus a new vector set; the verifier refuses unknown major versions and warns on unknown minor fields.
**Selection rule:** a change lands only if it is testable — every change ships with a vector, an acceptance test, or a documented negative case. Failures and rejected designs are published, not hidden.

## 0.1.x — housekeeping (short work, high credibility value)

1. **JSON Schema file** — `schema/continuity-receipt-0.1.schema.json` (2020-12): envelope, the six record types, redaction object, bundle + disclosure map. Add a CI check that validates all 11 vectors against it. Closes the one incomplete goal from SPEC §1.1 (schema + vectors + verifier).
2. **Wording fix** — SPEC §1.1 says "10 test vectors"; the release ships 10 vectors as 11 files (anchor sub-cases 10a/10b). Make the count consistent everywhere.
3. **CI** — GitHub Actions: run `python3 -m unittest discover -s tests -v`, verify each vector's expected verdict, and (once it exists) schema validation. Badge in README.
4. **THREAT_MODEL.md** — what receipts do *not* cover: issuer lying before signing, collusion between issuer and counterparty, clock skew, replay of redacted variants, key compromise before revocation exists, metadata correlation. Explicit non-goals restated.
5. **CONTRIBUTING.md + issue templates** — and a contribution policy decision (DCO or lightweight CLA) before accepting outside code.
6. **Verifier ergonomics** — confirm/implement a `--json` output mode for automation; document exit codes.
7. **Packaging** — publish to PyPI (`continuity-receipt`) if the name is available; `pip install` path in README.
8. **Anchor shape** — decide OpenTimestamps vs public-chain anchoring (the W3C CG is ledger-agnostic), define the `anchor` object for the bundle, and document the verification rule for each choice.

## 0.2 — interoperability and robustness (next)

- **CBOR profile** (RFC 8949 §4.2) with byte-equivalence vectors against the JSON model.
- **Commitment hardening** — domain separation and an HMAC option for salted commitments; vectors for cross-field substitution attempts.
- **Provenance sets** — Merkle roots for `observed_sources_hash` (replace the flat hash), with inclusion-proof vectors.
- **Key lifecycle** — rotation records, revocation statements, validity windows; vectors for verification before/after revocation and after rotation.
- **Succession receipts** — authority hand-off as a first-class type (shared envelope), motivated by fleet/multi-tenant operation.
- **Multi-party attestations** — richer counterparty signature vectors; the verifier reports per-signature results rather than a single aggregate.
- **`did:web` vectors** and a documented policy for which DID methods v0 accepts.
- **Time** — millisecond granularity option and a declared maximum clock-skew tolerance; vectors for out-of-order timestamps at second precision.
- **Conformance packaging** — machine-readable vector manifest (name → expected verdict → expected codes) prepared for the W3C CG's conformance surface.

## 0.3+ / open questions

- Selective disclosure beyond per-field salts (e.g., signature schemes with native selective disclosure) — evaluate, do not adopt by default; simplicity is a feature.
- Anchor cadence and public anchor registries; proof renewal.
- Formal specification of canonicalization + verification (small enough to verify mechanically).
- Interop profiles with SAIHM and memorywire once their normative text stabilizes; adapter implementations.

## Non-goals (unchanged)

No custody of funds; no payment protocol; no arbitration; no reputation scoring; no storage protocol. Receipts ground those layers; they do not replace them.

## How to contribute

Open an issue for spec questions, mapping suggestions, or vectors. Interoperability discussion belongs in the open standards venues (W3C AI Agent Memory Interoperability CG; IETF agentproto); this repository tracks concrete text, code, and vectors.
