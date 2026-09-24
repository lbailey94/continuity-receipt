# Conformance table — normative rule → implementation → vectors

**Status:** release candidate for `continuity-receipt/0.4` (2026-09-24);
publication pending. This table is the audit surface: every normative rule maps
to a check in both implementations and to vectors that exercise it. Where a
rule is deliberately not enforced, the row says so and why.
**Companion documents:** `SPEC.md` (normative), `CONFORMANCE.md`
(prose disclosure), `verifier-capabilities.json` (machine-readable),
`THREAT_MODEL.md` (what receipts do and do not prove).

Columns: **Rule** (spec section) · **Specs** · **Python** check
(`continuity_receipt/`) · **Rust** check (`rust/src/`) · **+ vector** ·
**− vector** · **Notes**.

Unit-test names refer to `tests/` (Python); `tools/hostile_input_probe.py`
generates the malformed-input corpus in both implementations.

## A. Envelope, chain, and signatures

| Rule | Specs | Python | Rust | + vector | − vector | Notes |
|---|---|---|---|---|---|---|
| Supported spec versions; unknown refused (`version_unsupported`) | 0.1–0.4 | `verify_bundle` | `verify_bundle` | 01 | unit `test_unsupported_spec_refused` | no published negative vector |
| Whole-shape pass: non-empty receipts; receipt/body/issuer objects; anchors/revocations/disclosure-map shapes | 0.1–0.4 | `_check_shape` | `check_shape` | 01 | probe `repro.*`, boundary cases | runs before semantic checks |
| Canonical bytes reconstructable; floats rejected | 0.1–0.4 | `_try_digest`, `canon` | `receipt_digest`, `canon` | 01 | unit `test_float_rejected`, `test_non_canonical_float_is_structured` | |
| `issued_at` RFC 3339 UTC; 1–3 ms digits from 0.2 | 0.1–0.4 | `records.validate_timestamp` | `validate_timestamp` | 01, 12 | probe mutations | no dedicated negative vector |
| Chain: `seq` contiguous from 0; `prev` = previous receipt digest | 0.1–0.4 | `verify_bundle` (chain block) | `verify_bundle` | 01 | 03, unit `test_chain_link_tamper_detected` | 03 reports `bad_signature` + `chain_break` |
| Ed25519 over canonical view minus `sig`; `did:key` resolution | 0.1–0.4 | `verify_bundle` (sig block) | `verify_bundle` | 01 | 03 | |
| Input boundaries: ≤10,000 receipts; nesting ≤64; ≤8 MiB (CLI) | 0.1–0.4 | `verify_bundle`, `main` | `verify_bundle`, CLI | 01 | probe `boundary.*`; unit `test_oversized_file_is_structured` | limits are refusal guards, not verdicts about the task |
| Mixed-version bundles: bundle `spec` names the envelope; each receipt verified under its own spec; members a version does not define are ignored | 0.1–0.4 | `verify_bundle` (per-receipt gates) | `verify_bundle` | 18 | — | deliberate: published 0.1–0.3 bundles keep their old judgement |

## B. Cross-record and evidence rules

| Rule | Specs | Python | Rust | + vector | − vector | Notes |
|---|---|---|---|---|---|---|
| `session.pass.created` present; decision policy version equals pass policy | 0.1–0.4 | `_check_cross_record` | `check_cross_record` | 01 | 19 | |
| Settlement ≤ spend cap when the pass sets one | 0.1–0.4 | `_check_cross_record` | `check_cross_record` | 02 | 05 | |
| Gated settlement follows a delivery attestation | 0.1–0.4 | `_check_cross_record` | `check_cross_record` | 02 | 06 | |
| `task.termination` present | 0.1–0.4 | `_check_cross_record` | `check_cross_record` | 01 | 04 | |
| Provenance form `sha256:` / `merkle-sha256:` | 0.2–0.4 | `_check_provenance` | `check_provenance` | 15 | 15b | |
| Counterparty attestation signing rule; absence reported, not penalized | 0.2–0.4 | `_check_attestations` | `check_attestations` | 13 | 13b | |
| Revocation statements self-signed; `revoked_at <= issued_at` → `key_revoked`; invalid statements fail closed | 0.2–0.4 | `_check_revocations` | `check_revocations` | 14b | 14a, unit `test_forged_statement_fails_closed` | external lists are 0.3 tooling (`REVOCATION_DISTRIBUTION.md`) |
| Anchor digest binding; type enum when metadata present | 0.1–0.4 (enum 0.2+) | `_check_anchors` | `check_anchors` | 10b (`--require-anchor`), 01 | 10a, 10c | proof verification is the companion tool, not the verifier |
| Redaction/erasure semantics; required fields may not be redacted; commitment match | 0.1–0.4 | `_check_redactions` | `check_redactions` | 08 | 07 (PROVISIONAL), 09 (INSUFFICIENT), 20 (`redacted_required`), 21 (`commit_mismatch`) | |

## C. Agreements (offer → accept)

| Rule | Specs | Python | Rust | + vector | − vector | Notes |
|---|---|---|---|---|---|---|
| `offer_ref` resolves to a present offer (digest) | 0.3–0.4 | `_check_accept` | `check_accept` | 16 | 16d (`missing_offer` → INSUFFICIENT) | |
| `offer_id` and `terms_hash` equal the offer's | 0.3–0.4 | `_check_accept` | `check_accept` | 16 | 16b | |
| Accept `issued_at` ≤ offer `valid_until` | 0.3–0.4 | `_check_accept` | `check_accept` | 16 | 16c | |
| Redacted offer terms: undisclosed → PROVISIONAL; disclosed → TRUSTED | 0.3–0.4 | `_check_redactions`, `_check_accept` | `check_redactions`, `check_accept` | 16f | 16e | |
| 0.4 accept `offeree` present, equals its issuer and the offer's `offeree` | 0.4 | `_check_accept` | `check_accept` | 17 | 17b, 17c | `offeree` is a required field in 0.4 envelopes |
| 0.4 accept follows the offer | 0.4 | `_check_accept` | `check_accept` | 17 | 17d | |
| 0.4 bound `agreement_ref` resolves to a present accept | 0.4 | `_check_agreements` | `check_agreements` | 17 | 17g (`missing_agreement` → INSUFFICIENT) | gated on the bound record's own spec |
| 0.4 bound record follows the accept | 0.4 | `_check_agreements` | `check_agreements` | 17 | 17e | |
| 0.4 bound record issued by the offeree | 0.4 | `_check_agreements` | `check_agreements` | 17 | 17f | |
| 0.4 offeree stages after the accept carry the ref (`missing_agreement_ref` → PROVISIONAL) | 0.4 | `_check_agreement_completeness` | `check_agreement_completeness` | 17 | 17i | |
| 0.4 unreferenced accept (`agreement_unreferenced` → PROVISIONAL) | 0.4 | `_check_agreement_completeness` | `check_agreement_completeness` | 17 | 17h | |
| Duplicate `offer_id`s disambiguated by digest | 0.3–0.4 | `_check_accept` | `check_accept` | 17j | — | |

## D. Verification receipts (companion, version 1)

| Rule | Version | Python | Rust | + vector | − vector | Notes |
|---|---|---|---|---|---|---|
| Document shape: kind, version, verdict enum, `verified_at`, digest shape, errors/reasons/summary shapes | v1 | `verify_verification_receipt` | `verify_verification_receipt` | verification/01 | verification/05–11, verification/14, verification/19, verification/20 | |
| Offline consistency: `error_codes` equals `errors`; verdict equals the class implied by the lists | v1 | `verify_verification_receipt` | `verify_verification_receipt` | verification/01, 15, 16 | verification/17, 18 | checkable without the bundle |
| Signature: `sig.key` equals `issuer`; Ed25519 over canonical view minus `sig` | v1 | `verify_verification_receipt` | `verify_verification_receipt` | verification/01 | verification/02, 09, 10 | |
| Bundle digest match when a bundle is supplied | v1 | `verify_verification_receipt` | `verify_verification_receipt` | verification/01 | verification/04 | |
| Issuer-revocation check is opt-in input | v1 | `verify_verification_receipt` | `verify_verification_receipt` | verification/21 (statement after `verified_at`), unit `test_revocation_check_is_opt_in` | verification/12 (`key_revoked`) | bundle-level positive: 14b; receipt-level positive: verification/21 |
| Unknown members are inside the signed bytes and ignored | v1 | `verify_verification_receipt` | `verify_verification_receipt` | verification/13 | — | |

## E. Deliberate non-enforcement — do not infer

| Not checked | Where documented | Why |
|---|---|---|
| **Issuer honesty / that the recorded event happened.** A valid signature proves a key signed the recorded claims — not that the work occurred, the sandbox enforced its limits, or termination happened outside the issuer's report. `TRUSTED` means "passes this format's checks under the supplied trust and revocation policy". | `THREAT_MODEL.md` #2–#3, README | No format can ground its own issuer; grounding comes from counterparty attestations, anchors, and external evidence |
| Nested field validation beyond required keys — the verifier checks required-field presence and the rules in this table; the JSON Schemas (published per version) are validated over the vector corpus in CI | `CONFORMANCE.md`, schema files | Verifier scope is the format's rules, not full schema validation of every nested value |
| Identifier form for opaque labels (`agent_id`, `counterparty.id`, succession authorities, `offer_id`) | `SPEC.md` §3, issue #5 | Labels in practice hold free-form subjects; enforcing a URN/DID form would invalidate real records |
| Quota enforcement | `SPEC.md` §4.1 (zero = not enforced) | Quotas are policy inputs recorded in the pass, not verifier-enforced limits |
| Proof-of-work / header-chain validation for anchors | `ANCHORING.md` | Headers are caller-supplied inputs; the companion tool checks proof structure and merkle-root equality only |
| Revocation-list freshness (a mirror can withhold a statement) | `REVOCATION_DISTRIBUTION.md` | Cryptography cannot detect withholding; polling cadence and multiple mirrors bound it |
| CBOR profile, HMAC commitments/domain separation, succession multi-signatures, global revocation roots | `SPEC.md` §11 | Deferred with published reasons; adopt with a demonstrated need |
| Verification-receipt result correctness — a receipt records a verifier's result; it does not recompute it | `VERIFICATION_RECEIPTS.md` | Re-run the bundle verifier to check a recorded result; the receipt is evidence about the verification run |

## Reproduce

```bash
python3 -m unittest discover -s tests -v            # unit + vector + schema suites
python3 tools/differential_vectors.py               # Python vs Rust, all bundle vectors
python3 tools/differential_verification_receipts.py # Python vs Rust, all receipt vectors
python3 tools/hostile_input_probe.py --require-parity  # structured outcomes + parity
cargo test --manifest-path rust/Cargo.toml          # second implementation
```
