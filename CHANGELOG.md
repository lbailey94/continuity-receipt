# Changelog

## Unreleased

- **Revocation distribution (0.3 candidate 4).** `continuity_receipt/revocations.py`
  + `--revocations <path|https-url>` on `continuity-receipt-verify` and
  `continuity-receipt-disclose verify`: static revocation lists carrying the
  same self-signed statements as bundles, merged and deduplicated with
  bundle-level statements. Authenticity is per statement (a mirror can
  withhold, never forge); HTTPS required (loopback http for local tests);
  1 MiB cap; supplied-but-unusable lists fail closed as
  `INSUFFICIENT_EVIDENCE`. Policy and monitoring guidance:
  `REVOCATION_DISTRIBUTION.md`; THREAT_MODEL #7 and SPEC §7/§11 updated.
  8 tests in `tests/test_revocations.py`.
- **Anchor proof verification (companion tool, 0.3 candidate 2).**
  `continuity_receipt/anchor.py` + `continuity-receipt-anchor` CLI replay an
  OpenTimestamps detached proof from the file digest to every attestation and
  check a Bitcoin attestation against an 80-byte block header by exact
  merkle-root equality. Statuses `verified` / `unverified` / `mismatch` /
  `invalid` with machine codes; digest sources are `--digest` or
  `--bundle ... --target ...` (with an anchor-binding cross-check when the
  bundle carries an `opentimestamps` anchor). Parses the wire format
  directly (LEB128 varints — pinned by a test that fails under Bitcoin
  CompactSize); no proof-of-work or chain validation by design, the header is
  caller-supplied. 16 tests in `tests/test_anchor.py`, including 5 real example
  proofs from `opentimestamps-client/examples` (MIT) with block headers
  fetched from the Blockstream Esplora API (`vectors/anchor/README.md`);
  the keccak256 example is kept as a published negative case
  (`unsupported_op`, never a silent skip). Usage notes in `ANCHORING.md`.
- `continuity_receipt.__init__.SPEC_ID` corrected to `continuity-receipt/0.2`
  (was stale at 0.1; records already defaulted to 0.2).
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
