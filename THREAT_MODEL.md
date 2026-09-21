# Threat model

**Scope:** what Continuity Receipts prove, what they do not, and how each attack class is handled in `continuity-receipt/0.1` / `0.2`.

A receipt is evidence about what a governed system recorded and signed — not a claim about ground truth. The verifier's job is to distinguish **missing** evidence (`PROVISIONAL`, `INSUFFICIENT_EVIDENCE`) from **false** evidence (`UNTRUSTED`), and to make the difference legible to a third party who trusts nobody in the chain.

## Adversaries and failure classes

| # | Threat | Status | Mitigation / rule |
|---|---|---|---|
| 1 | **Bundle tampering** (edit a field, drop a receipt, reorder) | Handled | Hash chain (`prev`), Ed25519 signatures over canonical bytes, contiguous `seq`; verdict `UNTRUSTED`. |
| 2 | **Dishonest issuer at issuance** (signs a false record) | Out of scope by design | Receipts attest *what was recorded*, not that the record is true. Grounding comes from hashes, counterparty attestations, sandbox/resource evidence, and external anchors. Consumers must treat issuer-attested fields as issuer claims. |
| 3 | **Colluding issuer + counterparty** | Out of scope | Two signatures are still only two parties. Anchoring and independent logs are the outer-layer remedies; the format makes their inputs verifiable rather than preventing collusion. |
| 4 | **Counterparty attestation forged or tampered** | Handled (0.2) | When present, the attestation is verified over the body with `counterparty.attestation` removed; invalid → `bad_attestation` (`UNTRUSTED`). Absence is reported in the verifier summary but does not downgrade the verdict; consumers that require attestations must check for them. |
| 5 | **Redaction tampering** (strip fields, forge disclosure) | Handled | Redaction is an issuance-time act; the tail is re-signed. Commitments are `sha256(salt ‖ 0x7c ‖ JCS(value))`; mismatch → `commit_mismatch`; undisclosed redaction → `PROVISIONAL`; required fields may not be redacted. |
| 6 | **Erasure abuse** (claim erasure to hide evidence) | Disclosed | Erased content yields `INSUFFICIENT_EVIDENCE` — never `TRUSTED`, never silently ignored. Consumers must treat it as missing, not as clean. |
| 7 | **Key compromise** | Partially handled (0.2 + 0.3 tooling) | Bundle-level self-signed revocation statements; receipts issued **at or after** `revoked_at` fail (`key_revoked`). Receipts issued **before** revocation remain valid. External revocation lists (0.3 tooling, `--revocations`, `REVOCATION_DISTRIBUTION.md`) let verifiers learn revocations without a re-issued bundle; authenticity is per statement, so a mirror can withhold but not forge. **Open gap:** compromise *before* a statement is published is indistinguishable — monitoring cadence and multiple mirrors bound it; no transparency log exists. |
| 8 | **Clock manipulation / skew** | Disclosed (0.2) | Chain order is `seq`, not time; timestamps are not trust anchors. Verification does not fail on skew. Millisecond precision reduces ordering ambiguity but is not authoritative. |
| 9 | **Commitment substitution across fields** | Disclosed | Per-field random salts are issued at redaction time; substitution requires a salt collision. Domain separation and HMAC commitments are deferred to 0.3 with this analysis on record. |
| 10 | **Provenance-set misrepresentation** | Partially handled | `observed_sources_hash` must be `sha256:` or `merkle-sha256:` (`provenance_invalid` otherwise). Merkle inclusion proofs are *not* shipped in 0.2; the root alone does not prove membership. |
| 11 | **Anchor games** (fake/stale anchors) | Partially handled | Anchor entries must bind an existing receipt by digest and use a declared type (`opentimestamps`, `public-chain`, `custom`). **The verifier does not validate external proofs** — that is done with the anchor provider's tooling. Anchoring is optional in v0. |
| 12 | **Verifier implementation bugs** | Acknowledged | The reference verifier is small (no new cryptography) and schema-checked, but is not audited. Independent implementations are explicitly invited; conformance is defined by the vectors. |
| 13 | **Metadata correlation** (receipts leak who worked with whom) | Disclosed | Identifiers are DIDs; required fields avoid names/emails, but issuer/counterparty/timing correlation is possible. Selective disclosure and privacy profiles are future work. |

## Non-goals (restated)

No custody of funds, no payment protocol, no arbitration, no reputation scoring, no storage protocol. Receipts ground those layers; they do not replace them.

## Reporting

Security-relevant issues in the spec or the reference verifier: open an issue or email the maintainer (`lbailey94@protonmail.com`); do not file public issues containing exploit details for the verifier before a fix is prepared.
