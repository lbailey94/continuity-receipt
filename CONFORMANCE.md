# Verifier conformance and capability disclosure

Machine-readable companion:
[`verifier-capabilities.json`](verifier-capabilities.json). This page
explains what the reference implementation checks, what its verdicts mean,
and what it deliberately does not do. It is an implementation disclosure, not
a spec: `SPEC.md` is normative. For the rule-by-rule audit surface — every
normative requirement mapped to a check in both implementations and to its
vectors — see [`CONFORMANCE_TABLE.md`](CONFORMANCE_TABLE.md).

## Supported spec versions

`continuity-receipt/0.1`, `continuity-receipt/0.2`, `continuity-receipt/0.3`,
and `continuity-receipt/0.4`. Unknown versions are refused
(`version_unsupported`) rather than guessed at. Each receipt carries its own
`spec` and is verified under that version's rules; mixed-version bundles are
legal (SPEC §10).

## Checks, in order of exposition (all failures are collected)

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
5. **Agreement binding** — 0.3: `offer_ref` resolves to a present offer, with
   `offer_id`/`terms_hash` equality and `valid_until` expiry. 0.4: the accept
   names and is signed by its `offeree`; accepts follow their offer; bound
   stages carry `agreement_ref`, checked for resolution, chronology, and
   issuer; offeree stages that skip the ref and accepts nothing references are
   PROVISIONAL.
6. **Revocations** — bundle statements plus external lists (0.3 tooling;
   `--revocations`), merged and deduplicated; a receipt issued at or after
   `revoked_at` fails `key_revoked`.
7. **Anchors** — digest binding and declared type only. Proof verification is
   the companion tool's job (`continuity-receipt-anchor`, OpenTimestamps
   proofs against a caller-supplied header); header chain validation is out
   of scope.
8. **Redactions and erasure** — required fields may not be redacted; redacted
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
`vectors/verification/` (21 cases).
A valid receipt proves that a signer made an internally consistent, signed
statement about a bundle digest at a time — it does **not** recompute the
verification result. To check a recorded result, re-run the bundle verifier
over the bundle and compare (`VERIFICATION_RECEIPTS.md` §What it proves).

## Conformance referee (hosted service)

`POST /conformance` on the hosted API grades a verifier's outputs over the
pinned corpus and returns a signed **conformance report**
(`kind: continuity-receipt-conformance`, version 1). Submissions carry
implementation metadata plus per-vector outputs — bundles
(`{verdict, codes}`) and verification receipts (`{valid, errors}`) — and are
built with `tools/conformance_submit.py`; the referee never executes
submitted code. The report binds the submission and the corpus manifests by
digest, records per-corpus matches/mismatches, and carries a verdict
(`CONFORMANT` / `PARTIAL` / `NONCONFORMANT`) signed by the service's
`did:key` (canonical view minus `sig`, the same rule as verification
receipts). Verify a report with
`python3 tools/conformance_submit.py --verify-report report.json`; endpoint
contract in the service docs (`api.whitemagic.dev/docs`).

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
`bad_attestation`, `bad_revocation`, `key_revoked`, `provenance_invalid`,
`offer_mismatch`, `offer_expired`, `offeree_mismatch`, `accept_before_offer`,
`agreement_before_accept`, `agreement_issuer_mismatch`, `too_many_receipts`,
`nesting_too_deep`, `bundle_too_large`.

**PROVISIONAL reasons (bundle):** `anchor_missing`,
`redacted_without_disclosure:<path>`, `agreement_unreferenced:<path>`,
`missing_agreement_ref:<path>`.
**INSUFFICIENT_EVIDENCE reasons (bundle):** `erased_content:<path>`,
`missing_offer:<receipt_id>`, `missing_agreement:<receipt_id>`.

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
python3 tools/differential_vectors.py             # Python vs Rust over all bundle vectors
python3 tools/differential_verification_receipts.py  # Python vs Rust over all receipt vectors
python3 tools/hostile_input_probe.py --require-parity  # structured outcomes + parity
cargo test --manifest-path rust/Cargo.toml        # Rust second implementation
```

CI runs these (plus the disclosure and anchor differentials);
`vectors/manifest.json` pins the conformance verdicts,
`vectors/verification/manifest.json` pins the verification-receipt cases,
`vectors/anchor/` pins the anchor tool against real OpenTimestamps proofs, and
`CONFORMANCE_TABLE.md` maps every rule to its checks and vectors.

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
