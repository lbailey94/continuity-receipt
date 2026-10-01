# Memory Crystal ownership — Phase 4C decision and review brief

**Status: production cutover completed on 2026-10-01; owner mapping remains
deliberately empty.** This brief records the deployed Crystal access boundary
and the selected disposition for the owner-unknown legacy envelope. Companion
evidence: `CRYSTAL_OWNERSHIP_EVIDENCE_2026-09-30.md`. The registry has three
credential rows and zero owner IDs; existing credentials remain denied
Crystal access pending explicit operator assignment.

## Recorded decision: legacy envelope

The owner is **unknown**. Preserve the envelope and quarantine it from public
reads and lineage until an operator establishes an owner through an explicit,
reviewed mapping process. Do not delete it, expose it, or infer ownership
from its locator, its ciphertext ID, or the first authenticated reader.

The candidate CLI defaults to writing a hash-bearing dry-run plan. Applying a
plan requires an explicit `--apply`, rechecks every planned byte hash before
moving any file, and stores the exact bytes under a separate quarantine root
that the Crystal API does not search. For a store with assigned owners, each
verified ID must be supplied with a repeated `--registered-owner-id` option;
only those exact `sha256:<owner_id>` locators are excluded. Synthetic tests
exercise the helper's all-or-nothing preflight. In production, one envelope
was preserved in a root-only quarantine namespace and a consistent protected
backup; plaintext was not inspected and the service account cannot read the
quarantine. See
`ops/review-evidence/crystal-protected-backup-summary-2026-10-01.json`.

## Deployed contract choices

### Authenticated principal and owner mapping

The deployed gateway looks up a 64-character lowercase `owner_id` on the
authenticated gateway key record. It does not derive an owner from a token,
key label, payer, IP address, request body, ciphertext, or tenant locator.
Unmapped principals fail closed. Session passes and OAuth records still need
explicit registry mappings before Crystal access can be enabled for them.
Payment authorizes billing only and never claims ownership.

### Internal assertion and key rotation

The deployed HMAC assertion binds `kid`, owner ID, method, exact path and
query, body digest, lifetime, and nonce. The API uses a persistent SQLite
nonce ledger so replay rejection survives workers and restarts. Keyring
rotation uses a bounded overlap: install a new active key while retaining the
old verifier key for at least the maximum assertion lifetime plus skew, switch
the issuer, then remove the old key. Disposable backup/restore and key overlap
rehearsals passed before cutover. Production owner mappings were left unchanged;
any later owner assignment requires separate operator review.

### Locator and envelope versioning

The deployed owner locator is `sha256:<owner_id>`. An authenticated
`GET /crystals/owner-locator` bootstrap returns only the locator assigned by
the explicit gateway registry. The client offers
`owner-locator --token ...`, `seal --owner-locator ...`, and authenticated
token-based pulls and lineage.

The deployed enforcement retains the `wm-crystal/1.0` envelope shape
and existing AAD rules. New clients can use the registry-assigned locator in
the existing locator field. This is an access-control transition with a
client behavior change, not a claim that a new `wm-crystal/2.0` wire format
has been defined. Legacy public-salt locators are not translated or assigned
to an owner automatically. A future 2.0 format should have its own reviewed
specification and migration plan.

## Verification and production status

- [x] Synthetic two-owner upload/read/lineage and foreign-write refusal.
- [x] Unmapped principal, forged internal headers, selector mismatch, and
  direct-to-API assertion checks.
- [x] Lifetime ordering/type validation, exact expiry-skew handling,
  method/target/body binding, and one-time nonce tests.
- [x] Replay persistence across module reload, concurrent reservation, and
  key overlap/revocation behavior.
- [x] Authenticated locator bootstrap and client envelope sealing.
- [x] Synthetic legacy dry-run/apply quarantine, byte-hash preservation,
  owner-read/lineage isolation, whole-manifest, duplicate-entry, and
  destination-permission preflight.
- [x] Current local 25-case harness includes private/no-store and credential
  variation checks for Crystal success, denial, uniform miss, and 304 paths.
- [x] Prior 22-case transient VPS staging used disposable state; it predates
  the final quarantine/cache-header fixes. The primary then passed the final
  25-case matrix through disposable Caddy TLS on the VPS; see
  `ops/review-evidence/crystal-caddy-vps-staging-2026-10-01.txt`.
- [x] Read-only parity checks confirmed Caddy and both API units matched the
  hosted-kit source before the approved cutover.
- [x] Canonical source/config patches apply cleanly to temporary copies;
  source outputs match candidate byte-for-byte.
- [x] Disposable backup/restore and assertion key-overlap/retirement
  rehearsal restored state hashes and replay marker.
- [x] Disposable target-host Caddy TLS matrix, 25 cases.
- [x] Approved production source/config cutover and production-domain TLS
  checks; results are in
  `ops/review-evidence/crystal-live-cutover-2026-10-01.json`.
- [x] One owner-unknown envelope preserved in root-only quarantine and
  protected consistent backup; encrypted-byte hash and backup hash are in
  `ops/review-evidence/crystal-protected-backup-summary-2026-10-01.json`.
- [x] Public `/info` and hosted static API/server-card docs updated to describe
  owner-bound `wm-crystal/1.0`, private/no-store behavior, and hosted verifier
  runtime 0.5.0 semantics.
- [ ] Assign owner IDs only after separate operator verification and review.
  Until then, all three existing credentials remain unmapped and Crystal
  requests fail closed for them.

## Deployed boundary and remaining action

Production now requires an explicit owner mapping for each principal that
should use Crystal. The current three key records remain unmapped by design.
Any future mapping must be verified and recorded by an operator; x402 payment,
a session pass, a tenant locator, possession of a ciphertext ID, and first
read are not ownership proofs. The ownerless envelope remains unavailable in
root-only quarantine unless and until a separate verified migration decision
is made.

The source/config cutover, quarantine, and post-cutover checks are recorded in
the cutover and protected-backup evidence artifacts; they are not represented
as package publication or a new Crystal envelope version.

## Final primary review continuation

Final source/config pins are in `ops/review-evidence/crystal-final-pins-2026-10-01.json`.
The canonical source patch preserves unrelated MCP batch title/annotations.
The production registry has three credential rows and zero owner mappings;
all existing Crystal credentials will be denied until explicit mappings are
established. Production cutover and quarantine are complete as recorded in the
linked live evidence; only operator owner assignment remains.
