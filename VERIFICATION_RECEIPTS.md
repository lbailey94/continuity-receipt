# Verification receipts (companion, version 1)

**Status:** companion document to the Continuity Receipt specification; wire
format frozen 2026-09-23 (`kind: continuity-receipt-verification`, version 1;
revised the same day to record the full result before any external issuance).
Verification receipts are **not** part of the `continuity-receipt/0.x` bundle
format: they are standalone records of a verification run, never chain
members.
**Reference implementation:** `continuity_receipt.verification` (Python),
CLI `continuity-receipt-verify-receipt`; second implementation:
`rust/src/verification.rs` + the same CLI in the Rust crate (differential
20/20 over the vectors); schema `schema/verification-receipt-1.schema.json`;
vectors `vectors/verification/` (21 cases).

## Why

A verdict on its own is a claim. When a verifier answers `TRUSTED`, the party
that needs to rely on that answer — a buyer, an insurer, an arbiter, a
downstream agent — currently has to trust the channel or re-run verification
itself. A verification receipt closes the loop: the verifier signs *what it
checked and how the result was reached* — the bundle digest, the verdict,
**every error, the provisional/insufficient reasons, and the summary** — and
anyone can verify that record offline, with the bundle in hand.

Three properties do the work:

1. **Binding.** `bundle_digest` is the SHA-256 of the JCS-canonical bytes of
   the bundle object, so the record is tied to exact content, independent of
   how the bundle was serialized or transported.
2. **Attribution.** The record is signed by the verifier's `did:key`; the
   issuer is discoverable, and its key is revocable like any other key.
3. **Fidelity.** The record is a signed copy of the calculation's result, not
   a summary judgment: errors carry codes (and details), reasons explain
   `PROVISIONAL`/`INSUFFICIENT_EVIDENCE`, and the summary carries the stats
   (receipt count, types, issuers, terminated/settled, and any
   attestation/anchor/revocation checks that ran). Its internal consistency
   is checkable offline — a holder does not need the bundle to see that the
   verdict matches its reasons.

## Wire format

```json
{
  "kind": "continuity-receipt-verification",
  "version": 1,
  "bundle_digest": "sha256:9f2c…",
  "verdict": "UNTRUSTED",
  "error_codes": ["cap_exceeded"],
  "errors": [
    {
      "code": "cap_exceeded",
      "detail": "settlement {'minor': 5000, 'currency': 'USD'} exceeds cap {'minor': 100, 'currency': 'USD'}",
      "receipt_id": "urn:uuid:01997c4e-…"
    }
  ],
  "provisional_reasons": [],
  "insufficient_reasons": [],
  "summary": {
    "receipts": 6,
    "types": ["session.pass.created", "task.decision", "task.execution", "delivery.attestation", "settlement", "task.termination"],
    "issuers": ["did:key:z6Mk…"],
    "terminated": true,
    "settled": true
  },
  "verified_at": "2026-09-23T21:00:00Z",
  "verifier": {"implementation": "python-reference", "version": "0.4.0"},
  "issuer": "did:key:z6Mk…",
  "sig": {"alg": "ed25519", "key": "did:key:z6Mk…", "value": "…"}
}
```

| Field | Meaning |
|---|---|
| `kind`, `version` | Document identity. Unknown versions are refused (`bad_version`), never guessed at. |
| `bundle_digest` | `sha256:` + SHA-256 of the JCS-canonical bytes of the verified bundle object (see §Digest rule). |
| `verdict` | One of `TRUSTED` · `PROVISIONAL` · `INSUFFICIENT_EVIDENCE` · `UNTRUSTED` — the verdict the verifier recorded. |
| `error_codes` | The codes of `errors`, in order; must equal them exactly (`error_codes_mismatch`). Empty on non-`UNTRUSTED` verdicts. |
| `errors` | Every error the verifier reported: `{code, detail?, receipt_id?}`. Details may quote bundle values (amounts, ids) — they are evidence, share accordingly. |
| `provisional_reasons` | Why the verdict is `PROVISIONAL` (e.g. `anchor_missing`, `redacted_without_disclosure:<path>`). |
| `insufficient_reasons` | Why the verdict is `INSUFFICIENT_EVIDENCE` (e.g. `erased_content:<path>`, `missing_offer:<receipt_id>`). |
| `summary` | The verification summary: `receipts`, `types`, `issuers`, `terminated`, `settled`, plus optional checks (`attestations`, `anchors`, `revocations_checked`, …). |
| `verified_at` | When the verification ran. RFC 3339 UTC; 1–3 fractional digits allowed. Issuer-asserted unless the receipt is anchored (§Anchoring). |
| `verifier` | Implementation name and version — "which verifier, which version" is part of the record. |
| `issuer` | The DID of the signing key. |
| `sig` | Ed25519 over the JCS-canonical bytes of the object minus `sig` (the same canonical-view rule as bundle receipts). `sig.key` MUST equal `issuer`. |

Additional members are allowed; they are inside the signed bytes, and
verifiers MUST ignore members they do not know (vector `13_unknown_member`).

### Consistency rules (checkable without the bundle)

- `error_codes` equals the codes in `errors`, in order.
- The verdict is the class implied by the lists:
  errors non-empty → `UNTRUSTED`; else `insufficient_reasons` non-empty →
  `INSUFFICIENT_EVIDENCE`; else `provisional_reasons` non-empty →
  `PROVISIONAL`; else `TRUSTED` (`verdict_mismatch`).

These mirror the core verifier's verdict rule exactly, so a receipt cannot
quietly claim `TRUSTED` while carrying errors.

## Digest rule

`bundle_digest` = `"sha256:" + SHA-256(JCS(bundle_object))`, where JCS is the
pinned canonicalization of SPEC §5 (RFC 8785 for the ASCII-key JSON subset
this schema requires; floats are rejected). The digest is over **content, not
serialization**: pretty-printed and compact encodings of the same bundle
object produce the same digest, and any holder of the bundle (object or JSON
bytes) can recompute it. `digest_match` in the reference result is exactly
that equality; without a supplied bundle it is `null`.

Bundles that cannot be canonically encoded (e.g. containing floats) cannot be
digested; the reference issuer refuses to issue a receipt for them.

## Verification algorithm

Ordered checks; the reference verifier collects **all** failures and the
result is `valid` only when the list is empty:

1. Document is an object — `not_an_object`.
2. `kind` equals `continuity-receipt-verification` (`bad_kind`); `version`
   equals `1` (`bad_version`).
3. `verdict` is one of the four enum values (`bad_verdict`).
4. `verified_at` is RFC 3339 UTC (`bad_verified_at`).
5. `bundle_digest` is `sha256:` + 64 lowercase hex (`bad_bundle_digest`).
6. Result shapes: `errors` is a list of `{code}` objects (`bad_errors`);
   `provisional_reasons` / `insufficient_reasons` are string lists
   (`bad_provisional_reasons` / `bad_insufficient_reasons`); `summary` is an
   object (`bad_summary`); `error_codes` is a string list (`bad_error_codes`).
7. Consistency: `error_codes` matches `errors` (`error_codes_mismatch`);
   verdict matches the reason lists (`verdict_mismatch`).
8. `sig` has shape `{alg: "ed25519", key, value}` (`bad_signature_shape`);
   `sig.key` equals `issuer`, and the Ed25519 signature verifies over the
   JCS-canonical bytes of the document minus `sig` (`bad_signature`).
9. If the caller supplies the bundle: digest equality
   (`bundle_digest_mismatch`; `digest_match` reports the comparison).
10. If the caller supplies revocation statements covering the issuer: a
    statement with `revoked_at <= verified_at` makes the receipt invalid
    (`key_revoked`). Without revocation input the check is not performed.

Reference result shape:

```json
{
  "valid": true,
  "errors": [],
  "issuer": "did:key:z6Mk…",
  "verdict": "TRUSTED",
  "verified_at": "2026-09-23T21:00:00Z",
  "bundle_digest": "sha256:9f2c…",
  "digest_match": true
}
```

## What a verification receipt proves — and does not

**Proves:** this issuer ran a named, versioned verification implementation
over content with this digest at this time, and the recorded result —
verdict, errors, reasons, summary — is internally consistent and signed. With
the bundle in hand, a holder can re-run the verification and compare every
recorded field — the receipt is evidence about the *verification run*; the
bundle is the evidence about the task.

**Does not prove:** that the bundle's claims are true (issuer honesty is out
of scope, as in `THREAT_MODEL.md`), that the recorded result is *correct*
(re-run verification; a disagreeing receipt is simply a different record), or
that the issuer is trustworthy (check the issuer's key and revocation
status). A valid receipt whose verdict is `UNTRUSTED` is still a valid
receipt — and a useful one.

## Anchoring

`verified_at` is issuer-asserted. To bound it externally, anchor the receipt
digest — `sha256` of the receipt's canonical bytes minus `sig`
(`continuity_receipt.verification.receipt_digest`):

```bash
# 1. Write the canonical view and print the digest (the view is what gets stamped)
continuity-receipt-verify-receipt receipt.json --canonical receipt.canonical

# 2. Timestamp it with the OpenTimestamps client (external)
ots stamp receipt.canonical

# 3. Verify the proof against the digest (companion tool; add --header/--height
#    once the Bitcoin attestation confirms — see ANCHORING.md)
continuity-receipt-anchor receipt.canonical.ots \
  --digest "$(sha256sum receipt.canonical | cut -d' ' -f1)" --json

# 4. Optional: host the proof (keyed)
#    POST /anchors {"digest": "sha256:…", "proof": "<base64 of the .ots>"}
```

The proof covers the canonical bytes, so anyone can reproduce both the digest
and the stamped file from the receipt itself.

## Revocation

The issuer key carries the same revocation semantics as bundle receipts:
statements are self-signed by the key they revoke
(`REVOCATION_DISTRIBUTION.md`), and a receipt is invalid when
`revoked_at <= verified_at`; a statement dated after `verified_at` leaves the
receipt valid (vector `21_valid_statement_after_verified_at`). The check is **opt-in input** — a verifier
without revocation information cannot perform it. Consumers who need the
check can fetch the issuer's published document (the hosted service serves
`GET /revocations/<issuer>`) and pass its statements.

## Vectors and schema

- Schema: `schema/verification-receipt-1.schema.json` (JSON Schema 2020-12).
- Vectors: `vectors/verification/` — 21 cases: valid TRUSTED, PROVISIONAL
  (`anchor_missing`), INSUFFICIENT_EVIDENCE (erased content),
  signature/verdict tampering, wrong bundle, bad
  kind/version/verdict/timestamp/digest/error-codes/errors/reasons/summary,
  consistency violations (`verdict_mismatch`, `error_codes_mismatch`),
  missing signature, issuer swap, revoked issuer (`key_revoked`) and the
  positive revocation case (a statement dated after `verified_at` leaves the
  receipt valid), unknown member.
  Machine-readable expectations in `vectors/verification/manifest.json`;
  human index in `vectors/verification/INDEX.md`.
- Verify with:
  `continuity-receipt-verify-receipt <receipt.json> [--bundle <bundle.json>] [--revocations <file|url>]`
  or from Python with `continuity_receipt.verification`.

## Open items

- **Countersignatures / multi-verifier receipts** — two verifiers, one
  statement set; no consumer yet.
- **Freshness vs idempotency** — the hosted service can return the original
  `verified_at` for a repeated verification within its cache TTL; callers who
  need a fresh attestation re-run without the cache. Service policy, not wire
  format.
- Hosted-service policy (rate limits, opt-in digest cache) is not wire
  format; see the service contract (`RECEIPT_API.md`).
