# Verification receipts (companion, version 1)

**Status:** companion document to the Continuity Receipt specification; wire
format frozen 2026-09-23 (`kind: continuity-receipt-verification`, version 1).
Verification receipts are **not** part of the `continuity-receipt/0.x` bundle
format: they are standalone statements about a verification run, never chain
members.
**Reference implementation:** `continuity_receipt.verification` (Python),
CLI `continuity-receipt-verify-receipt`; schema
`schema/verification-receipt-1.schema.json`; vectors `vectors/verification/`
(14 cases).

## Why

A verdict on its own is a claim. When a verifier answers `TRUSTED`, the party
that needs to rely on that answer — a buyer, an insurer, an arbiter, a
downstream agent — currently has to trust the channel or re-run verification
itself. A verification receipt closes the loop: the verifier signs *what it
checked* — the bundle digest, the verdict, the error codes, the
implementation and version, the time — and anyone can verify that statement
offline, with the bundle in hand.

Two properties do the work:

1. **Binding.** `bundle_digest` is the SHA-256 of the JCS-canonical bytes of
   the bundle object, so the statement is tied to exact content, independent
   of how the bundle was serialized or transported.
2. **Attribution.** The statement is signed by the verifier's `did:key`; the
   issuer is discoverable, and its key is revocable like any other key.

## Wire format

```json
{
  "kind": "continuity-receipt-verification",
  "version": 1,
  "bundle_digest": "sha256:9f2c…",
  "verdict": "TRUSTED",
  "error_codes": [],
  "verified_at": "2026-09-23T21:00:00Z",
  "verifier": {"implementation": "python-reference", "version": "0.3.2"},
  "issuer": "did:key:z6Mk…",
  "sig": {"alg": "ed25519", "key": "did:key:z6Mk…", "value": "…"}
}
```

| Field | Meaning |
|---|---|
| `kind`, `version` | Document identity. Unknown versions are refused (`bad_version`), never guessed at. |
| `bundle_digest` | `sha256:` + SHA-256 of the JCS-canonical bytes of the verified bundle object (see §Digest rule). |
| `verdict` | One of `TRUSTED` · `PROVISIONAL` · `INSUFFICIENT_EVIDENCE` · `UNTRUSTED` — the verdict the issuer recorded, not a judgment about truth. |
| `error_codes` | The `errors[].code` list from the verification result, order preserved; may be empty. Provisional/insufficient *reasons* stay in the verification payload; the verdict carries their class. |
| `verified_at` | When the verification ran. RFC 3339 UTC; 1–3 fractional digits allowed. |
| `verifier` | Implementation name and version — "which verifier, which version" is part of the record. |
| `issuer` | The DID of the signing key. |
| `sig` | Ed25519 over the JCS-canonical bytes of the object minus `sig` (the same canonical-view rule as bundle receipts). `sig.key` MUST equal `issuer`. |

Additional members are allowed; they are inside the signed bytes, and
verifiers MUST ignore members they do not know (vector `13_unknown_member`).

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
6. `error_codes` is an array of strings (`bad_error_codes`).
7. `sig` has shape `{alg: "ed25519", key, value}` (`bad_signature_shape`);
   `sig.key` equals `issuer`, and the Ed25519 signature verifies over the
   JCS-canonical bytes of the document minus `sig` (`bad_signature`).
8. If the caller supplies the bundle: digest equality
   (`bundle_digest_mismatch`; `digest_match` reports the comparison).
9. If the caller supplies revocation statements covering the issuer: a
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
over content with this digest at this time and recorded this verdict and
these error codes. With the bundle in hand, a holder can re-run the
verification and confirm the verdict — the receipt is evidence about the
*verification run*; the bundle is the evidence about the task.

**Does not prove:** that the bundle's claims are true (issuer honesty is out
of scope, as in `THREAT_MODEL.md`), that the verdict is correct (re-run
verification; a disagreeing receipt is simply a different statement), or that
the issuer is trustworthy (check the issuer's key and revocation status). A
valid receipt whose verdict is `UNTRUSTED` is still a valid receipt.

## Revocation

The issuer key carries the same revocation semantics as bundle receipts:
statements are self-signed by the key they revoke
(`REVOCATION_DISTRIBUTION.md`), and a receipt is invalid when
`revoked_at <= verified_at`. The check is **opt-in input** — a verifier
without revocation information cannot perform it. Consumers who need the
check can fetch the issuer's published document (the hosted service serves
`GET /revocations/<issuer>`) and pass its statements.

## Vectors and schema

- Schema: `schema/verification-receipt-1.schema.json` (JSON Schema 2020-12).
- Vectors: `vectors/verification/` — valid receipt, signature/verdict
  tampering, wrong bundle, bad kind/version/verdict/timestamp/digest/error
  codes, missing signature, issuer swap, revoked issuer, unknown member.
  Machine-readable expectations in `vectors/verification/manifest.json`;
  human index in `vectors/verification/INDEX.md`.
- Verify with:
  `continuity-receipt-verify-receipt <receipt.json> [--bundle <bundle.json>] [--revocations <file|url>]`
  or from Python with `continuity_receipt.verification`.

## Open items

- **Rust parity** — the second implementation does not verify verification
  receipts yet; tracked in `ROADMAP.md`.
- **Countersignatures / multi-verifier receipts** — two verifiers, one
  statement set; no consumer yet.
- **Anchoring verification receipts** — timestamping the receipt digest
  itself would bound `verified_at` externally; the OpenTimestamps tooling
  (`ANCHORING.md`) already exists.
- Hosted-service policy (rate limits, opt-in digest cache) is not wire
  format; see the service contract (`RECEIPT_API.md`).
