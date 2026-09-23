# Verifier conformance and capability disclosure

Machine-readable companion:
[`verifier-capabilities.json`](verifier-capabilities.json). This page
explains what the reference implementation checks, what its verdicts mean,
and what it deliberately does not do. It is an implementation disclosure, not
a spec: `SPEC.md` is normative.

## Supported spec versions

`continuity-receipt/0.1`, `continuity-receipt/0.2`, and
`continuity-receipt/0.3`. Unknown versions are refused
(`version_unsupported`) rather than guessed at.

## Checks, in order (first failure wins)

1. **Envelope and schema** — required fields per record type; `issued_at`
   RFC 3339 UTC (0.2 allows milliseconds); canonical bytes reconstructable.
2. **Chain** — `seq` contiguous from 0; `prev` equals the previous receipt's
   digest (canonical bytes excluding `sig`).
3. **Signatures** — Ed25519 over the unsigned view, `did:key` resolution.
   Counterparty attestations verify under the body-minus-attestation rule and
   are reported individually.
4. **Cross-record consistency** — mandate present at creation; policy
   versions agree; settlement ≤ run cap; delivery before settlement when
   gated; termination present; provenance hash form (`sha256:` or
   `merkle-sha256:`).
5. **Revocations** — bundle statements plus external lists (0.3 tooling;
   `--revocations`), merged and deduplicated; a receipt issued at or after
   `revoked_at` fails `key_revoked`.
6. **Anchors** — digest binding and declared type only. Proof verification is
   the companion tool's job (`continuity-receipt-anchor`, OpenTimestamps
   proofs against a caller-supplied header); header chain validation is out
   of scope.
7. **Redactions and erasure** — required fields may not be redacted; redacted
   values without disclosure are provisional; erased payloads are
   insufficient evidence, not failures.

## Verification receipts (companion, version 1)

`continuity_receipt.verification` verifies the signed records the hosted
service (and any other verifier) issues about a verification run — see
`VERIFICATION_RECEIPTS.md` for the wire format and semantics. A receipt
records the **full result** (verdict, errors, provisional/insufficient
reasons, summary), not just the verdict. Checks: document shape,
`kind`/`version`, verdict enum, RFC 3339 `verified_at`, `sha256:` digest
shape, `error_codes`/`errors`/reason-list/summary shapes, `error_codes`
consistency with `errors`, verdict consistency with the reason lists
(`verdict_mismatch`), `sig.key == issuer` + Ed25519 signature over the
canonical view minus `sig`; optional bundle digest match
(`bundle_digest_mismatch`); optional issuer-revocation check (`key_revoked`,
statements in the bundle shape). CLI: `continuity-receipt-verify-receipt`
(`--digest` prints the receipt digest for anchoring); vectors:
`vectors/verification/` (20 cases).

## Verdicts

| Verdict | Meaning |
|---|---|
| `TRUSTED` | every check passed |
| `PROVISIONAL` | structure intact; optional evidence missing (`anchor_missing`, `redacted_without_disclosure:<path>`) |
| `INSUFFICIENT_EVIDENCE` | cannot verify (e.g. `erased_content:<path>`); not the same as false |
| `UNTRUSTED` | a checked claim failed (bad signature, chain break, cap exceeded, revocation, missing termination) |

## Error codes

**Bundle verification:** `malformed`, `unknown_type`, `bad_signature`,
`chain_break`, `task_mismatch`, `policy_mismatch`, `cap_exceeded`,
`delivery_before_settlement`, `missing_termination`, `anchor_invalid`,
`redacted_required`, `commit_mismatch`, `version_unsupported`,
`bad_attestation`, `bad_revocation`, `key_revoked`, `provenance_invalid`.

**Revocation lists (CLI):** `bad_revocations_document`,
`revocations_unreachable`, `revocations_insecure_url`,
`revocations_too_large`.

**Anchor tool:** statuses `verified` / `unverified` / `mismatch` / `invalid`
with codes including `anchor_verified`, `anchor_unverified`,
`anchor_pending`, `header_mismatch`, `digest_mismatch`,
`anchor_binding_mismatch`, `unsupported_op`; the full list is in the
`continuity_receipt/anchor.py` docstring.

**Verification receipts:** `not_an_object`, `bad_kind`, `bad_version`,
`bad_verdict`, `bad_verified_at`, `bad_bundle_digest`, `bad_error_codes`,
`bad_errors`, `bad_provisional_reasons`, `bad_insufficient_reasons`,
`bad_summary`, `error_codes_mismatch`, `verdict_mismatch`,
`bad_signature_shape`, `bad_signature`, `bundle_digest_mismatch`,
`key_revoked`.

## Reproduce

```bash
python3 -m unittest discover -s tests -v          # unit + real-fixture tests
python3 tools/differential_vectors.py             # Python vs Rust over all vectors
cargo test --manifest-path rust/Cargo.toml        # Rust second implementation
```

CI runs all three; `vectors/manifest.json` pins the conformance verdicts,
`vectors/verification/manifest.json` pins the verification-receipt cases, and
`vectors/anchor/` pins the anchor tool against real OpenTimestamps proofs.

## Out of scope — do not infer

- **Issuer honesty.** Receipts attest what was recorded, not that the record
  is true.
- **Proof-of-work / header-chain validation** for anchors (headers are
  supplied inputs).
- **Revocation-list freshness.** A mirror can withhold a statement; polling
  cadence and multiple mirrors bound that, cryptography does not
  (`REVOCATION_DISTRIBUTION.md`).
- CBOR encoding, HMAC commitments, succession multi-signatures, global
  revocation roots — see `ROADMAP.md`.
