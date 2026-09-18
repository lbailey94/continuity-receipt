# Changelog

## Unreleased

- **Rust second implementation (0.3.0-alpha.1)** in `rust/`: full verifier port
  (JCS canonicalization, Ed25519 + `did:key`, chain/verdict semantics,
  revocation statements, counterparty attestations, anchors, Merkle
  provenance) with a CLI matching the Python interface. `cargo test` passes
  all 20 vectors; CI gains a Rust job and a differential check comparing
  Python and Rust outputs over every vector (20/20). Python remains the
  reference implementation.
- Packaging: `pyproject.toml` at 0.2.0 with console scripts
  (`continuity-receipt-verify`, `continuity-receipt-disclose`), a full sdist
  via `MANIFEST.in`, and a CI job that builds the wheel, installs it, and
  exercises both console scripts. **0.2.0 published to PyPI 2026-09-18**
  (`pip install continuity-receipt`).
- `ANCHORING.md` — anchoring policy and decision record: OpenTimestamps as the
  recommended default issuance path, `public-chain` supported for
  counterparties that require it, `custom` as an opaque escape hatch;
  verifier scope stays shape + digest binding only, proof verification
  targeted for 0.3.

## 0.2.0 — 2026-09-18

Interoperability and robustness release; `0.1` remains supported.

- **New record type** `authority.succession` (authority hand-off).
- **Millisecond timestamps** (optional 1–3 fractional digits); second precision
  still valid. Ordering within a chain remains by `seq`.
- **Counterparty attestations** — signing rule defined (body with
  `counterparty.attestation` removed) and verified per-signature; invalid
  attestation → `bad_attestation`. Absence is reported, not penalized.
- **Revocation statements** — bundle-level, self-signed by the revoked key;
  receipts issued at or after `revoked_at` fail with `key_revoked`; earlier
  receipts remain valid. Invalid statements fail closed (`bad_revocation`).
- **Provenance roots** — `observed_sources_hash` accepts `merkle-sha256:`;
  unsupported forms fail with `provenance_invalid`.
- **Anchor typing** — anchor metadata `type` ∈ {`opentimestamps`,
  `public-chain`, `custom`}; unknown types → `anchor_invalid`.
- **JSON Schema** (`schema/continuity-receipt-0.2.schema.json`) validated
  against every schema-valid vector in CI.
- **CI** (GitHub Actions) + **machine-readable vector manifest**
  (`vectors/manifest.json`) + CLI-surface verification of all vectors.
- **THREAT_MODEL.md** (13 threat classes, including the open
  pre-revocation-compromise gap) and **CONTRIBUTING.md** (DCO, no CLA).
- Test set grows from 11 to 20 vectors; suite is 10 tests (vectors, schema,
  primitives).

Deferred to 0.3 with reasons in `SPEC.md` §11: CBOR equivalence, commitment
HMAC/domain separation, revocation distribution, anchor proof verification,
succession multi-signatures.

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
