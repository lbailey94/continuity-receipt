# Changelog

## Unreleased — 0.4.0 release candidate (2026-09-24)

Spec 0.4 and tooling 0.4.0: the offer → accept binding is carried through the
chain, plus verifier robustness hardening, the conformance table, and the
documentation pass. **Release candidate — publication pending.**

- **Spec 0.4 — binding carried.** `agreement.accept` requires `offeree` and
  must be signed by it; accepts must follow their offer; bound stages
  (`task.decision`, `task.execution`, `delivery.attestation`, `settlement`)
  carry `agreement_ref` — the digest of the accept — checked for resolution
  (`missing_agreement` → `INSUFFICIENT_EVIDENCE`), chronology
  (`agreement_before_accept`), and issuer (`agreement_issuer_mismatch`).
  Offeree stages that skip the ref (`missing_agreement_ref`) and accepts that
  nothing references (`agreement_unreferenced`) are PROVISIONAL. Mixed-version
  bundles are legal: each receipt is verified under its own spec, and members
  a version does not define are ignored (compatibility vector `18`).
- **Verifier robustness.** A whole-shape validation pass runs before the
  semantic checks in both implementations; malformed input returns structured
  verdicts (the four crash reproductions from the independent review are
  permanent corpus cases). Input boundaries: 10,000 receipts, nesting depth
  64, 8 MiB bundle cap (CLI). `tools/hostile_input_probe.py` asserts
  structured outcomes and Python↔Rust parity of verdicts and error-code sets
  in CI; an exhaustive in-process sweep of 26,280 leaf mutations across the
  vector set raises nothing.
- **Vectors 26 → 40, receipt vectors 20 → 21.** New: `17`–`17j` (binding
  carried, adversarial), `18` (mixed-version compatibility), `19`–`21`
  (`policy_mismatch`, `redacted_required`, `commit_mismatch`), and the
  positive receipt-level revocation case. The published 0.1–0.3 fixtures are
  byte-for-byte unchanged.
- **Schema 0.4** (`schema/continuity-receipt-0.4.schema.json`): `offeree`
  required on 0.4 accepts, `agreement_ref` documented on bound bodies; every
  schema-valid vector is validated against the schema for its spec version.
- **Conformance table** (`CONFORMANCE_TABLE.md`): every normative rule mapped
  to Python and Rust checks, positive and negative vectors, and deliberate
  non-enforcement; coverage gaps closed with `19`–`21` and `verification/21`.
- **Docs aligned with the proof boundary**: README/SPEC openings state that a
  receipt attests what its issuer signed, not that the described events
  occurred; `agent_id`-style identifiers are documented as opaque labels;
  zero-valued quotas mean "not enforced".
- **Independent review brief** (`REVIEW_BRIEF.md`): one-page scope for an
  adversarial technical review of the verification-receipt format, both
  implementations, the cryptographic core, the anchor tooling, and the hosted
  issuer — including the specific questions we want answered and the
  weaknesses we already know about.

## Rust crate 0.4.0 — release candidate (2026-09-24)

`continuity-receipt` 0.4.0: parity for spec 0.4 (the binding carried through
the chain), the whole-shape validation pass, input boundaries, and the
hostile-input parity assertions — differential 40/40 bundle and 21/21
verification-receipt vectors.

## Rust crate 0.3.3 — 2026-09-23

`continuity-receipt` 0.3.3: Rust parity for **verification receipts**
(companion v1), completing the two-independent-implementations bar for the
full surface. The crate now verifies both bundle formats (0.1–0.3) and
verification receipts with identical validity, error codes, and digests to
the Python reference over the 20 receipt vectors (differential 20/20).

- **`verification.rs`** — port of `continuity_receipt/verification.py`:
  shape checks, the two offline consistency rules (`error_codes_mismatch`,
  `verdict_mismatch`), signature verification over the canonical view minus
  `sig`, optional bundle-digest match, and opt-in issuer-revocation checking
  via the shared `verify_revocation_statements` helper (extracted from the
  bundle verifier; behavior unchanged, differential 26/26).
- **CLI** `continuity-receipt-verify-receipt`: receipt path, `--bundle`,
  `--revocations <document.json>`, `--digest`, `--canonical <path>`
  (writes the canonical view for anchoring). Local files only — no HTTP
  client in the crate.
- **Tests** `tests/verification.rs`: the 20-vector manifest runner, receipt
  digest pinning, malformed fail-closed cases, unsigned-revocation refusal.
- **Differential** `tools/differential_verification_receipts.py` (validity,
  error sets, exit codes, and digests) added to CI.
- One pinned divergence: a non-enum verdict is `bad_verdict` only (Python
  skips the consistency check for it); the Rust port mirrors that rule.

## 0.3.3 — 2026-09-23

Python tooling release: verification receipts now record the **full
verification result** — not just the verdict. Published to PyPI as
`continuity-receipt` 0.3.3 (revised within hours of 0.3.2, before any external
issuance; 0.3.2 receipts are superseded).

- **Full-result receipts.** `errors` (code/detail/receipt_id),
  `provisional_reasons`, `insufficient_reasons`, and `summary` are now signed
  into the receipt alongside `verdict`/`error_codes`, so a holder can audit
  how and why the result was reached — and check its internal consistency
  offline, without the bundle. `issue_verification_receipt` now takes the
  `VerifyResult` (or its `as_dict()`) and refuses to sign an inconsistent
  result; `verify_verification_receipt` adds shape checks (`bad_errors`,
  `bad_provisional_reasons`, `bad_insufficient_reasons`, `bad_summary`) and
  two consistency rules: `error_codes` must equal the codes in `errors`
  (`error_codes_mismatch`), and the verdict must be the class implied by the
  lists (`verdict_mismatch`).
- **Anchoring recipe.** `verification.receipt_digest` and
  `continuity-receipt-verify-receipt --canonical PATH` produce the canonical
  bytes and digest to timestamp with OpenTimestamps
  (`VERIFICATION_RECEIPTS.md` §Anchoring), bounding `verified_at` externally.
- **Vectors 14 → 20**: real PROVISIONAL (`anchor_missing`) and
  INSUFFICIENT_EVIDENCE (erased content) records, plus
  `verdict_mismatch`/`error_codes_mismatch`/`bad_errors`/`bad_summary` cases.
  Schema and capability disclosure updated; suite is 64 tests.

## 0.3.2 — 2026-09-23

Python tooling release: **verification receipts** (companion, version 1)
formalized, plus the agreement emitters and vectors previously staged as
unreleased. Published to PyPI as `continuity-receipt` 0.3.2.

- **Verification receipts — formalized** (`continuity_receipt/verification.py`,
  `VERIFICATION_RECEIPTS.md`): a signed statement that a verifier ran the
  bundle verification algorithm over a bundle and recorded a verdict. The
  wire format (kind `continuity-receipt-verification`, version 1) binds the
  **JCS-canonical bundle digest** to the verdict, error codes, implementation
  and version, and time; the signature follows the bundle canonical-view rule
  (object minus `sig`). `issue_verification_receipt` /
  `verify_verification_receipt`; CLI `continuity-receipt-verify-receipt`;
  schema `schema/verification-receipt-1.schema.json`; 14 vectors under
  `vectors/verification/` (manifest + INDEX) covering signature/verdict
  tampering, wrong bundle, shape violations, issuer swap, revocation, and
  unknown members. Issuer-revocation checking is opt-in input (`key_revoked`),
  sharing the bundle statement shape via the new
  `revocations.verify_statements` helper (bundle behavior unchanged;
  differential 26/26).
- **Integration kit** — `VERIFY_IN_5_MIN.md`: install → verify offline →
  hosted verdict → signed receipt → offline receipt check, copy-paste only.
- **Reference emitters for agreements** (`continuity_receipt.agreements`):
  `offer_body` (hashes off-receipt terms, validates `valid_until`),
  `accept_body` (binds `offer_ref` to a signed offer receipt exactly the way
  the verifier resolves it), and `terms_hash`. Tests cover the round trip,
  terms staying off-receipt, mismatch, and expiry.
- **Vectors 16e/16f** (26 total): selective disclosure of redacted offer terms
  — `16e` redacted without disclosure (PROVISIONAL), `16f` disclosed
  (TRUSTED). Rust parity holds; differential 26/26.
- Capability disclosure (`verifier-capabilities.json`) gains the
  `verification_receipts` section; CONFORMANCE/README/ROADMAP updated; CI
  verifies the verification-receipt vectors through the CLI surface.

## Rust crate 0.3.2 — 2026-09-23

`continuity-receipt` 0.3.2: Rust parity for the spec 0.3 record types
(`agreement.offer` / `agreement.accept`), completing the
two-independent-implementations bar for 0.3. The crate now verifies specs
0.1–0.3 with identical verdicts and codes to the Python reference over the
full 24-vector set (differential 24/24).

## 0.3.1 — 2026-09-23

Python tooling release supporting **spec 0.3** (additive): the offer → accept
binding. Published to PyPI as `continuity-receipt` 0.3.1.

- **Spec 0.3 — `agreement.offer` / `agreement.accept`** (SPEC §4.8–4.9, §7).
  `agreement.accept.offer_ref` is the digest of the referenced offer receipt;
  the verifier resolves it against offers present in the bundle and checks
  `offer_id`/`terms_hash` equality and `valid_until` expiry. Missing offer →
  `INSUFFICIENT_EVIDENCE` (`missing_offer`); mismatch → `UNTRUSTED`
  (`offer_mismatch`); expired → `UNTRUSTED` (`offer_expired`). Terms stay
  off-receipt (only their hash is signed).
- **Vectors 16/16b/16c/16d** (24 total). `schema/continuity-receipt-0.3.schema.json`
  validates every schema-valid vector; the capabilities disclosure lists the
  0.3 spec, the `agreement_binding` check, and the new codes.
- **Rust parity for the 0.3 types is pending** — the Rust crate remains at
  0.3.1 and rejects `continuity-receipt/0.3` envelopes until ported
  (fail-closed by design; tracked in the roadmap).

## Rust crate 0.3.0 — 2026-09-21

`continuity-receipt` 0.3.0 published to crates.io (2026-09-21) — the
independent Rust verifier and selective-disclosure CLI. A tooling release on
spec 0.2 with no wire changes; `cargo install continuity-receipt` installs both
binaries. Runbook: `rust/PUBLISH.md`.

- **crates.io publication.** Package metadata (`homepage`, `keywords`,
  `categories`), license text inside the crate (`rust/LICENSE`), install
  instructions in `rust/README.md`, and `rust/PUBLISH.md`. `cargo publish
  --dry-run` passed (18 files, compiles); `0.3.0-alpha.1` published first to
  validate the pipeline, then `0.3.0`.
- **Rust fuzz corpus.** `rust/tests/fuzz_corpus.rs` generates deterministic
  structural mutations of all 20 vectors plus synthetic malformed shapes and
  byte truncations (fixed seed, reproducible); every case must produce one of
  the four verdicts with coded errors and must never panic.
  `CR_FUZZ_CORPUS_DIR` writes the generated corpus to disk for inspection or
  seeding a future `cargo fuzz` run. Runs in CI with the Rust suite.
- **Rust selective disclosure.** `rust/src/disclose.rs` +
  `continuity-receipt-disclose` port `continuity_receipt/disclose.py`:
  `redact` (salted commitments, tail re-signing), `attach`, `reveal`, and
  `check`, with the same path grammar, refusal behavior, and exit codes. New
  `rust/tests/disclose.rs` (10 tests) plus `tools/differential_disclose.py`
  in CI: both implementations produce identical disclosure maps and
  byte-identical re-signed tails, and each implementation's output verifies
  `TRUSTED` under the other's verifier. Rust CLI extensions documented in
  `rust/README.md` (`--salt <path>=<hex>` for reproducible redaction;
  `verify` has no `--revocations` until the Rust revocation-list loader
  lands).
- **Rust second implementation.** Full verifier port (JCS canonicalization,
  Ed25519 + `did:key`, chain/verdict semantics, revocation statements,
  counterparty attestations, anchors, Merkle provenance) with a CLI matching
  the Python interface. `cargo test` passes all 20 vectors; CI runs the Rust
  job plus differential checks comparing Python and Rust outputs over every
  vector (20/20) and over selective disclosure. Python remains the reference
  implementation.

## Rust crate 0.3.1 — 2026-09-21

`continuity-receipt` 0.3.1 published to crates.io (2026-09-21): adds the
OpenTimestamps anchor companion to the Rust crate (all three binaries now
install via `cargo install continuity-receipt`).

- **Rust anchor parity.** `rust/src/anchor.rs` + `continuity-receipt-anchor`
  port the OpenTimestamps companion: detached-proof replay (LEB128 varints,
  node/depth limits), Bitcoin attestation checked against a supplied 80-byte
  header by merkle-root equality, and the same statuses/codes as Python.
  16 tests (`rust/tests/anchor.rs`) over synthetic proofs and the five real
  fixtures; `tools/differential_anchor.py` in CI compares both CLIs (7/7).
  Header chain validation remains out of scope by design (`ANCHORING.md`).

## 0.3.0 — 2026-09-22

Python tooling release on **spec 0.2** (no wire changes), published to PyPI
as `continuity-receipt` 0.3.0. The Rust crate versions independently
(`rust/` is at 0.3.1); see the version matrix in `README.md`.

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
- Packaging: console scripts `continuity-receipt-verify`,
  `continuity-receipt-disclose`, and (new in 0.3.0)
  `continuity-receipt-anchor`; full sdist via `MANIFEST.in`; CI builds the
  wheel, installs it, and exercises the console scripts. **0.2.0 published to
  PyPI 2026-09-18; 0.3.0 published 2026-09-22** (`pip install continuity-receipt`).
- `ANCHORING.md` — anchoring policy and decision record: OpenTimestamps as the
  recommended default issuance path, `public-chain` supported for
  counterparties that require it, `custom` as an opaque escape hatch;
  verifier scope stays shape + digest binding, with proof verification
  shipped in 0.3 as the `continuity-receipt-anchor` companion.

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
