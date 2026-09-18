# Changelog

## 0.1.0 — 2026-09-18

Initial public release.

- `continuity-receipt/0.1` specification, including pinned 0.1 decisions:
  - JSON-only canonicalization (pinned RFC 8785-compatible subset; floats rejected);
  - commitment scheme `sha256(salt_bytes || 0x7c || JCS(value))`, 16-byte per-field salt;
  - redaction as an issuance-time act (chain tail re-signed);
  - flat `observed_sources_hash` (Merkle roots deferred to 0.2).
- Reference verifier (`continuity_receipt/`) with verdict semantics
  `TRUSTED | PROVISIONAL | INSUFFICIENT_EVIDENCE | UNTRUSTED` and 13 error codes.
- 11 test vectors (10 plus anchor sub-cases 10a/10b) with expected verdicts.
- Vector generator (`tools/make_vectors.py`) for deterministic reproduction.
- Conformance suite: `python3 -m unittest discover -s tests -v`.

Source lineage: extracted from the MandalaOS gate-lite work, where the module passed
gate acceptance G1–G8 and the wider project suite; this repository versions independently.

Open items for 0.2 are listed in `SPEC.md` §11 (CBOR profile, Merkle source roots,
HMAC/domain separation, required-field minimalism review with an underwriter,
succession receipts).
