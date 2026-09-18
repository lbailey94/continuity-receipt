# Continuity Receipt — v0.1 Specification

**Status:** `continuity-receipt/0.1` — published 2026-09-18 as a draft for public
review (open items in §11). Pins were frozen with the reference implementation.
**Date:** 2026-09-17 (draft); published 2026-09-18.
**Home:** this repository — versioned independently of any product release
train. Consumes karma-ledger primitives; not coupled to any 9.x release.

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
- Timestamps are RFC 3339 UTC, second precision (v0).
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
1. Parse + schema per record type; canonical bytes reconstructable.
2. Chain: `seq` contiguous, `prev` hashes match.
3. Signatures valid for each issuer.
4. Cross-record consistency: `mandate_ref` present at creation; decision policy
   version equals authority policy version; settlement amount ≤ run cap;
   `delivery` precedes `settlement` when `gated_on_delivery`; **termination
   present**.
5. Anchors (v0 optional): if present, verify commitment; if absent, note
   `anchor_missing` (not fatal in v0).

Output semantics (IETF CTQ-aligned):
`TRUSTED` (all checks pass), `PROVISIONAL` (structure intact; some optional
evidence missing/redacted), `INSUFFICIENT_EVIDENCE` (cannot verify — not the
same as false), `UNTRUSTED` (a checked claim failed: bad signature, chain
break, cap exceeded, missing termination for a "completed" claim).

Error codes: `malformed`, `unknown_type`, `bad_signature`, `chain_break`,
`task_mismatch`, `policy_mismatch`, `cap_exceeded`,
`delivery_before_settlement`, `missing_termination`, `anchor_invalid`,
`redacted_required`, `commit_mismatch`, `version_unsupported`.

## 8. Interop mapping (informative)

| External artifact | Mapping |
|---|---|
| Insurance evidence pack (AIUC-1-shaped) | bundle export: decision/execution/route-settle + termination |
| IETF Composite Trust Query | verdict enum shared; receipts supply the evidence chain |
| t402 dispute extension | `receipt_hash` binds a SignedDispute to the settlement record |
| ERC-8004 Validation Registry | request/response hashes anchored when it ships |
| x402 | `settlement.rail_ref` = tx hash; gating enforced at the server |

## 9. Test vectors (v0 set — full JSON shipped with the verifier)

| # | Vector | Expected |
|---|---|---|
| 1 | Minimal happy path (pass → 1 tool call → termination → no settlement) | TRUSTED |
| 2 | Full path with x402 settlement, gated_on_delivery = true | TRUSTED |
| 3 | Tampered body byte | UNTRUSTED (`bad_signature`) |
| 4 | Removed termination record ("completed" claim) | UNTRUSTED (`missing_termination`) |
| 5 | Cap exceeded: settlement > run cap | UNTRUSTED (`cap_exceeded`) |
| 6 | Settlement before delivery attestation | UNTRUSTED (`delivery_before_settlement`) |
| 7 | Redacted optional field with commitment, salt withheld | PROVISIONAL |
| 8 | Redacted optional field, salt later revealed in disclosure_map | TRUSTED |
| 9 | Genuinely erased content (key gone) | INSUFFICIENT_EVIDENCE |
| 10 | Anchor mismatched / absent (two sub-cases) | UNTRUSTED (`anchor_invalid`) / PROVISIONAL (`anchor_missing`) |

## 10. Versioning

`spec: continuity-receipt/0.1` in every envelope. Additive fields within 0.x;
breaking changes require 0.2 + new test vector set. The verifier refuses
unknown major versions (`version_unsupported`) and warns on unknown minor
fields (does not fail).

## 11. Open items

Resolved for `continuity-receipt/0.1` (pinned 2026-09-18):
1. **CBOR equivalence:** deferred — 0.1 is JSON-only (see §5); CBOR profiles
   are a 0.2 interop target.
2. **Salt/commit scheme:** `sha256(salt_bytes || 0x7c || JCS(value))`, 16-byte
   random salt per field, hex in the disclosure map (see §6). HMAC and
   domain-separation tags deferred to 0.2.
3. **`observed_sources_hash`:** flat SHA-256 in 0.1; Merkle roots deferred to
   0.2.
4. **Redaction mechanics:** issuance-time re-signing of the tail, as
   implemented by `continuity_receipt.disclose` (see §6).

Still open (not blocking 0.1 freeze):
5. Required-field minimalism vs insurance needs (review with one underwriter
   at P2, after ~3 months of receipts).
6. Succession receipts (authority hand-off) — same envelope; type definition
   deferred to Layer 7 work.
