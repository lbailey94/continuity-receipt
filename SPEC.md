# Continuity Receipt — v0.3 Specification

**Status:** `continuity-receipt/0.3` — published 2026-09-23; `0.1` and `0.2`
remain supported by the verifier. Open items in §11.
**Date:** 0.1 draft 2026-09-17; 0.2 released 2026-09-18; 0.3 released 2026-09-23.
**Home:** this repository — versioned independently of any product release
train.

## 0.3 changes at a glance

- New record types `agreement.offer` and `agreement.accept` — the
  offer → accept binding that precedes a receipt (§4.8, §4.9).
- Verification: `agreement.accept.offer_ref` must resolve to a present offer
  receipt; absent offer → `INSUFFICIENT_EVIDENCE` (`missing_offer`); terms/id
  mismatch → `UNTRUSTED` (`offer_mismatch`); accept after `valid_until` →
  `UNTRUSTED` (`offer_expired`) (§7).
- JSON Schema `continuity-receipt-0.3.schema.json`; vectors 16/16b/16c/16d.

## 0.2 changes at a glance

- New record type `authority.succession` — authority hand-off (§4.7).
- Millisecond timestamps allowed (optional 1–3 fractional digits; §3).
- Counterparty attestation signing rule + per-signature verification
  reporting (§4.4, §7).
- Bundle-level self-signed revocation statements with time semantics
  (`key_revoked`; §7).
- Provenance sets may use `merkle-sha256:` roots (§4.2, §7).
- Anchor metadata shape frozen with a type enum
  (`opentimestamps` | `public-chain` | `custom`; §7).
- JSON Schema (`schema/continuity-receipt-0.2.schema.json`), CI, and a
  machine-readable vector manifest (`vectors/manifest.json`).
- CBOR and commitment hardening deferred to 0.3 with rationale (§11).

---

## 1. Purpose

A Continuity Receipt is a portable, independently verifiable, privacy-preserving
record of one governed task: **decision → authority → execution → delivery →
termination → settlement**. It is designed to be consumed by insurers,
arbiters, procurement, reputation systems, and courts — without requiring trust
in the issuer.

### 1.1 Goals (v0)
1. One canonical record per task, hash-chained; integrity verifiable offline.
2. Grounded: fields bind to verifiable events (hashes, signatures,
   counterparty attestations), never self-reported claims alone.
3. Privacy-preserving: redaction with salted commitments; content erasure
   possible without breaking integrity verification.
4. Rail-agnostic: settlement references are opaque strings (x402 tx, invoice
   line, offchain://).
5. Small enough to implement: JSON Schema + 10 test vectors + reference
   verifier; no new cryptography beyond Ed25519 + SHA-256.

### 1.2 Non-goals (v0)
- Not a payment protocol; no custody; settlement stays on external rails.
- Not an arbitration system; issuers do not judge their own cases.
- Not a reputation ledger; it *grounds* reputation rather than scoring it.
- Not a storage protocol; bundles may live anywhere (the verifier takes bytes).

## 2. Terminology

| Term | Meaning |
|---|---|
| Receipt | One signed record (one line of the chain). |
| Task | One unit of governed work (an agent run, a pass, a service call). |
| Chain | Ordered receipts for a task; `prev` links by hash. |
| Bundle | One or more chains + optional anchors, in a single file. |
| Issuer | Party that signs a receipt (gate, agent, counterparty). |
| Verifier | Any third party running the verification algorithm (§7). |
| Anchor | External timestamp/hash commitment (P1; optional in v0). |

## 3. Envelope and chain model

Every receipt is a JSON object (CBOR for transport; identical data model):

```json
{
  "spec": "continuity-receipt/0.1",
  "receipt_id": "urn:uuid:...",
  "task_id": "urn:uuid:...",
  "issued_at": "2026-09-17T21:04:03Z",
  "issuer": { "kind": "gate|agent|counterparty", "id": "did:key:z6Mk..." },
  "type": "task.decision",
  "seq": 3,
  "prev": "sha256:...",
  "body": { ... type-specific ... },
  "sig": { "alg": "ed25519", "key": "did:key:z6Mk...", "value": "base64url..." }
}
```

Rules:
- `seq` starts at 0 per task; `prev` is the SHA-256 of the canonical bytes of
  the previous receipt. **Canonical rule (frozen by the reference
  implementation):** the canonical view of any receipt is the object
  **excluding the `sig` member**, and `prev`/signatures are both computed over
  that same view — one rule for both.
- `sig` covers JCS-canonical bytes of the object excluding the `sig` member.
- Timestamps are RFC 3339 UTC: second precision in 0.1; optional millisecond
  precision (1–3 fractional digits) in 0.2. Ordering within a chain is by
  `seq`, never by timestamp; verifiers must not fail on clock skew alone.
- Money is integer minor units + ISO-4217-like currency code, never floats.
- Identifiers are UUIDv7 URNs or DID URIs; no emails, names, or free-text PII
  in required fields.

**Reference implementation:** `continuity_receipt/` in this repository
(Python, Ed25519 via `cryptography`), status 2026-09-18 — 11 test vectors
green; verifier CLI `python3 -m continuity_receipt.verify <bundle.json>`;
disclosure CLI `python3 -m continuity_receipt.disclose`. Origin lineage:
the MandalaOS gate-lite work, where the module passed acceptance G1–G8 and
the wider project suite.

## 4. Record types and required fields

`body` variants (v0). Required = must be present for the type; optional marked
`?`. Fields marked **grounded** must be hashes/signatures, not prose.

### 4.1 `session.pass.created`
`gate_id`, `mandala_class` (`gate-lite|gate-hard`), `quotas`
{`cpu_ms`,`mem_mb`,`disk_mb`,`wall_ms`}, `expires_at`, `policy_version`,
`mandate_ref` (hash), `agent_id`, `principal_id`, `pass_token_id`.
### 4.2 `task.decision`
`action` (tool/verb), `action_args_hash` (grounded), `model` {`provider`,
`id`, `version`?}, `input_provenance` {`policy_id`, `allowed_sources[]`,
`observed_sources_hash`} (grounded), `decision` (`allow|deny|require_approval`),
`policy_version`, `rationale_hash`? (hash of an off-receipt explanation).
### 4.3 `task.execution`
`tool_calls[]` {`name`, `args_hash`, `result_hash`, `denied`?}, `egress[]`
{`destination`, `bytes`, `allowed`}, `resources` {`cpu_ms`, `mem_peak_mb`,
`disk_peak_mb`}, `sandbox_class` (`bwrap-landlock|microvm-ch|microvm-fc`),
`denials[]`?
### 4.4 `delivery.attestation`
`request_hash`, `response_hash`, `counterparty` {`id`, `attestation`? (sig)},
`spec_ref`? (what "done" means), `quality_flags[]`?.
**Attestation rule (0.2):** when `counterparty.attestation` is present it is an
Ed25519 signature over the canonical bytes of the receipt body with
`counterparty.attestation` removed. Presence is optional; absence is reported
in the verifier summary but does not change the verdict. Consumers that
require counterparty attestations must check for them explicitly.
### 4.5 `task.termination`
`reason` (`completed|budget_exhausted|time_expired|killed|error`),
`limits_at_stop` {`cpu_ms`, `wall_ms`, `spend_minor`, `currency`},
`remaining` {…}, `kill_signal`? (`dharma|operator|quota|aup`).
**Presence of a termination receipt is required for a task to verify as
complete.** (The "proof it stopped" link.)
### 4.6 `settlement`
`rail` (`x402|invoice|stripe|offchain|none`), `rail_ref`, `amount`
{`minor`, `currency`}, `gated_on_delivery` (bool), `settled_at`,
`dispute_window_s`?.

### 4.7 `authority.succession` (0.2)
`from_authority`, `to_authority` (identifiers), `effective_at`, `reason`
(`handoff|expiry|operator_change`). Records an authority hand-off; the
successor's subsequent receipts carry the new issuer key. Outside of
succession, key rotation is a new `issuer.key` plus re-signing (0.2 adds
bundle-level revocation statements, §7).

### 4.8 `agreement.offer` (0.3)
`offer_id` (issuer-local), `offeree` (identifier), `terms_hash` (grounded —
hash of the off-receipt terms), `valid_until` (RFC 3339 UTC), `nonce`;
optional `terms_ref` (URI or redaction). The offeror is the receipt issuer.
Terms stay off-receipt by construction: only their hash is signed, so the
terms can be disclosed selectively or kept private without invalidating the
binding. `nonce` makes otherwise-identical offers distinct.

### 4.9 `agreement.accept` (0.3)
`offer_ref` (grounded — the SHA-256 digest of the referenced offer receipt,
the same canonical view used by `prev` links), `offer_id`, `terms_hash`.
An accept binds the offeree's subsequent receipts (decision → execution →
delivery → settlement) to a specific offer: verifiers resolve `offer_ref`
against the offers present in the bundle and check the id and terms match
(§7, step 4). An accept whose offer is not in the bundle is
`INSUFFICIENT_EVIDENCE`, never silently trusted.

## 5. Canonicalization and signing

- JSON canonicalization: **RFC 8785 (JCS)**. `continuity-receipt/0.1` is
  **JSON-only**: the reference implementation uses a pinned JCS subset (sorted
  keys, UTF-8, integers/strings/bools/null; floats rejected) and key order is
  by Unicode code point — identical to JCS for the ASCII keys this schema
  requires. CBOR (RFC 8949 §4.2) is an interop target for 0.2, not required
  for 0.1 verification. The spec pins exact bytes so signatures are
  reproducible across languages.
- Hash: SHA-256, lowercase hex with `sha256:` prefix.
- Signatures: Ed25519 over canonical bytes; `did:key` (v0) with `did:web`
  (hosted gates) accepted. Key rotation is a new `issuer.key` + re-sign; no
  revocation list in v0 (documented gap).
- Multi-party receipts: delivery attestations and settlement may carry
  additional signatures under `body.counterparty.attestation`; the verifier
  reports which signatures it could check.

## 6. Privacy: redaction, selective disclosure, erasure

- Any optional field may be replaced by an object
  `{"redacted": true, "commit": "sha256:<salt||value>"}`; the salt is random
  per field and disclosed selectively (e.g., to an insurer under NDA).
- **Commitment scheme (frozen by the reference implementation for 0.1):**
  `commit = "sha256:" + SHA256(salt_bytes || 0x7c || JCS(value))`, where
  `salt_bytes` is the decoded 16-byte random salt (hex in the map) and `0x7c`
  is `|`. Disclosure entries carry `{"salt": "<hex>", "value": <json>}`.
  Redaction is an **issuance-time act**: the redacted receipt and every
  receipt after it in the chain are re-signed by the issuer (a redaction that
  invalidates a signature is not a disclosure, it is tampering). See vectors
  07/08 and `continuity_receipt.disclose`.
- A `disclosure_map` (outside the signed envelope, in the bundle) lists
  `path → {salt, value?}` for whichever fields the holder chooses to reveal.
  Paths use receipt indexing, e.g. `receipts[3].body.quality_flags`.
- Required fields (identity refs, hashes, caps, termination) may **not** be
  redacted in v0 — a receipt that hides them is not a receipt.
- **Erasure (Q39 semantics):** erasing an encrypted payload's content key makes
  its commitments opaque. Structure and integrity still verify; content-level
  claims become `insufficient_evidence`. Receipts never contain raw payloads,
  only hashes, so erasure acts on referenced stores, not on the chain.

## 7. Verification algorithm and semantics

Ordered checks (first failure wins):
1. Parse + schema per record type; canonical bytes reconstructable; envelope
   `issued_at` is RFC 3339 UTC (0.2: milliseconds allowed).
2. Chain: `seq` contiguous, `prev` hashes match.
3. Signatures valid for each issuer. Counterparty attestations (when present)
   verify under the §4.4 rule; each result is reported individually.
4. Cross-record consistency: `mandate_ref` present at creation; decision policy
   version equals authority policy version; settlement amount ≤ run cap;
   `delivery` precedes `settlement` when `gated_on_delivery`; **termination
   present**; provenance hash form is `sha256:` or `merkle-sha256:`.
   **Agreement binding (0.3):** each `agreement.accept.offer_ref` must resolve
   to an `agreement.offer` receipt present in the bundle (by receipt digest);
   the accept's `offer_id` and `terms_hash` must equal the offer's; and the
   accept's `issued_at` must be ≤ the offer's `valid_until`. A missing offer is
   `INSUFFICIENT_EVIDENCE` (`missing_offer`) — unverifiable, not false; a
   mismatch is `UNTRUSTED` (`offer_mismatch`); an expired accept is
   `UNTRUSTED` (`offer_expired`).
5. Revocations (0.2, bundle-level): each statement is self-signed by the key it
   revokes; a receipt whose issuer key was revoked at or before its
   `issued_at` fails (`key_revoked`). Receipts issued before revocation remain
   valid. Statements may also be distributed in external revocation lists
   (0.3 tooling; identical statement shape, same per-statement signatures,
   `--revocations` in the reference CLI — see `REVOCATION_DISTRIBUTION.md`).
6. Anchors (optional): if present, the committed digest must match the
   receipt; anchor metadata, when present, must declare one of the known types
   (`opentimestamps`, `public-chain`, `custom`); if anchors are absent and the
   caller required one, note `anchor_missing` (not fatal by default). External
   proof verification is performed with the anchor provider's tooling, not by
   this verifier.

Output semantics (IETF CTQ-aligned):
`TRUSTED` (all checks pass), `PROVISIONAL` (structure intact; some optional
evidence missing/redacted), `INSUFFICIENT_EVIDENCE` (cannot verify — not the
same as false), `UNTRUSTED` (a checked claim failed: bad signature, chain
break, cap exceeded, missing termination for a "completed" claim).

Error codes: `malformed`, `unknown_type`, `bad_signature`, `chain_break`,
`task_mismatch`, `policy_mismatch`, `cap_exceeded`,
`delivery_before_settlement`, `missing_termination`, `anchor_invalid`,
`redacted_required`, `commit_mismatch`, `version_unsupported`;
0.2 adds `bad_attestation`, `bad_revocation`, `key_revoked`,
`provenance_invalid`; 0.3 adds `offer_mismatch`, `offer_expired`
(`missing_offer` is an insufficient-evidence reason, not an error).

## 8. Interop mapping (informative)

| External artifact | Mapping |
|---|---|
| Insurance evidence pack (AIUC-1-shaped) | bundle export: decision/execution/route-settle + termination |
| IETF Composite Trust Query | verdict enum shared; receipts supply the evidence chain |
| t402 dispute extension | `receipt_hash` binds a SignedDispute to the settlement record |
| ERC-8004 Validation Registry | request/response hashes anchored when it ships |
| x402 | `settlement.rail_ref` = tx hash; gating enforced at the server |

## 9. Test vectors

The full set ships with the verifier:
**machine-readable expectations** in `vectors/manifest.json` (file → expected
verdict → expected error code → anchor requirement), and a human index in
`vectors/INDEX.md`. The JSON Schema is
`schema/continuity-receipt-0.3.schema.json`; every schema-valid vector is
validated against it in CI.

Companion (not bundle) vectors: `vectors/verification/` pins the
verification-receipt format (`VERIFICATION_RECEIPTS.md`,
`schema/verification-receipt-1.schema.json`).

0.1 conformance set (frozen): `01`–`10c` — happy paths, tampering, missing
termination, cap/delivery ordering, redaction/erasure, anchors.

0.2 additions:

| Vector | Expected | Exercises |
|---|---|---|
| `11_succession_handoff.json` | TRUSTED | `authority.succession` record |
| `12_ms_timestamps.json` | TRUSTED | millisecond `issued_at` |
| `13_attestation_valid.json` | TRUSTED | counterparty attestation verifies |
| `13b_attestation_tampered.json` | UNTRUSTED (`bad_attestation`) | attestation tampering |
| `14a_revoked_key.json` | UNTRUSTED (`key_revoked`) | revocation before issuance |
| `14b_revocation_after_issue.json` | TRUSTED | revocation after issuance |
| `15_merkle_provenance.json` | TRUSTED | `merkle-sha256:` provenance root |
| `15b_provenance_invalid.json` | UNTRUSTED (`provenance_invalid`) | unsupported hash form |
| `10c_anchor_unknown_type.json` | UNTRUSTED (`anchor_invalid`) | anchor type enum |

0.3 additions:

| Vector | Expected | Exercises |
|---|---|---|
| `16_offer_accept.json` | TRUSTED | offer → accept binding resolves |
| `16b_offer_terms_mismatch.json` | UNTRUSTED (`offer_mismatch`) | accept terms differ from the offer |
| `16c_offer_expired.json` | UNTRUSTED (`offer_expired`) | accept issued after `valid_until` |
| `16d_accept_without_offer.json` | INSUFFICIENT_EVIDENCE (`missing_offer`) | referenced offer absent from the bundle |

## 10. Versioning

`spec: continuity-receipt/0.3` in new envelopes; `0.1` and `0.2` remain supported
(bundle-level and per-receipt). Additive fields within 0.x; breaking changes
require a new minor version plus a new vector set. The verifier refuses
unknown spec versions (`version_unsupported`); unknown *additional* members
are preserved and ignored (they are inside the signed bytes, so they cannot be
injected after signing).

## 11. Open items

**Resolved for 0.1** (pinned 2026-09-18): JSON-only canonicalization; salt
scheme `sha256(salt_bytes || 0x7c || JCS(value))`; flat `observed_sources_hash`;
redaction as issuance-time re-signing.

**Resolved for 0.2** (2026-09-18): millisecond timestamps; counterparty
attestation rule; bundle-level revocation statements (receipts before
revocation remain valid); `authority.succession`; `merkle-sha256:` provenance
roots; anchor metadata type enum; JSON Schema + CI; machine-readable vector
manifest.

**Resolved for 0.3** (2026-09-23): `agreement.offer` / `agreement.accept`
with digest binding (`offer_ref`), terms/id equality checks, expiry semantics,
and the missing-offer-is-insufficient rule; vectors 16–16d; schema 0.3.
Rust parity landed 2026-09-23 (crate 0.3.2; differential 26/26).

**Deferred to 0.3, with reasons:**
1. **CBOR equivalence** — no implementer need demonstrated yet, and the signed
   domain is JSON canonical bytes; adding a second encoding requires an
   equivalence proof and vectors, not a paragraph.
2. **Commitment hardening (HMAC / domain separation)** — current per-field
   random salts make substitution require a salt collision; the analysis is on
   record in `THREAT_MODEL.md` §9. Revisit with a concrete attack or an
   implementer request.
3. **Revocation distribution** — **tooling landed 2026-09-21:** static-list
   convention + `--revocations` merge with per-statement signatures
   (`REVOCATION_DISTRIBUTION.md`); monitoring guidance recorded. Remaining:
   transparency-log omission evidence, only with a consumer that needs it.
4. **Anchor proof verification** — **landed 2026-09-21** as the companion
   tool `continuity-receipt-anchor` (OpenTimestamps proofs checked against a
   caller-supplied header; `ANCHORING.md`). The bundle verifier itself still
   checks anchor shape and digest binding only, by design.
5. **Succession hardening** — multi-party signatures on succession records.

**Still open:** required-field minimalism vs insurance needs (review with one
underwriter, after ~3 months of real receipts).
