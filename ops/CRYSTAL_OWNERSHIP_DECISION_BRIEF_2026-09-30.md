# Memory Crystal ownership — Phase 4C decision and review brief

**Status: isolated candidate updated; production decisions and rollout remain
open.** This brief records the selected disposition for the known ownerless
legacy envelope and the concrete candidate boundary. Companion evidence:
`CRYSTAL_OWNERSHIP_EVIDENCE_2026-09-30.md`. No canonical or live service
change has been made.

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
only those exact `sha256:<owner_id>` locators are excluded. This has been
tested with temporary synthetic data only. A production manifest has not
been generated and no live data has been accessed.

## Candidate contract choices

### Authenticated principal and owner mapping

The candidate looks up a 64-character lowercase `owner_id` on the
authenticated gateway key record. It does not derive an owner from a token,
key label, payer, IP address, request body, ciphertext, or tenant locator.
Unmapped principals fail closed. Session passes and OAuth records still need
explicit registry mappings before Crystal access can be enabled for them.
Payment authorizes billing only and never claims ownership.

### Internal assertion and key rotation

The candidate HMAC assertion binds `kid`, owner ID, method, exact path and
query, body digest, lifetime, and nonce. The API uses a persistent SQLite
nonce ledger so replay rejection survives workers and restarts. Keyring
rotation uses a bounded overlap: install a new active key while retaining the
old verifier key for at least the maximum assertion lifetime plus skew, switch
the issuer, then remove the old key. Actual file permissions, secret
provisioning, backup, and rotation must be rehearsed on the target host.

### Locator and envelope versioning

The candidate owner locator is `sha256:<owner_id>`. An authenticated
`GET /crystals/owner-locator` bootstrap returns only the locator assigned by
the explicit gateway registry. The candidate client offers
`owner-locator --token ...`, `seal --owner-locator ...`, and authenticated
token-based pulls and lineage.

For this enforcement candidate, retain the `wm-crystal/1.0` envelope shape
and existing AAD rules. New clients can use the registry-assigned locator in
the existing locator field. This is an access-control transition with a
client behavior change, not a claim that a new `wm-crystal/2.0` wire format
has been defined. Legacy public-salt locators are not translated or assigned
to an owner automatically. A future 2.0 format should have its own reviewed
specification and migration plan.

## Candidate evidence status

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
- [x] Read-only parity checks confirmed current Caddy and both API units
  match the hosted-kit source; no live route was changed.
- [x] Canonical source/config patches apply cleanly to temporary copies;
  source outputs match candidate byte-for-byte.
- [x] Disposable backup/restore and assertion key-overlap/retirement
  rehearsal restored state hashes and replay marker.
- [x] Disposable target-host Caddy TLS matrix, 25 cases.
- [ ] Actual production-domain post-cutover TLS checks after approval.
- [ ] Review root's protected one-item production dry-run manifest, then
  preserve/quarantine the ownerless envelope. Manifest:
  `/root/continuity-rollouts/crystal-review-qjI5Ho5P/legacy-dry-run.json`,
  SHA-256 `de5f53492f552672db0c3225c305ff67c8fcd4e610a681c12ca6c72e9ab5081c`;
  source-byte SHA-256
  `f638468a80c55d2c68054b0576a497c2d90b9ad9d216c0e313aabd3752a822ae`.
  No apply has occurred.
- [ ] Canonical kit, public `/info`, docs, client, discovery copy, and gateway
  keyless route changes in a separate reviewed PR.
- [ ] Production keyring/owner mapping, host rollback rehearsal, deployment,
  and post-deployment verification.

## Recommended next sequence

1. Review the candidate source, client, harness, and quarantine helper as one
   change; independently rerun the 25-case harness, including malformed
   gateway keyring refusal and restoration, and the actual
   cross-process replay race and process-restart probe.
2. Check the target gateway's principal types, Caddy route normalization, and
   API loopback boundary. Decide which account records receive explicit owner
   IDs; leave unmapped credentials denied.
3. Complete the public TLS/Caddy matrix and review root's protected
   production quarantine dry-run manifest without printing crystal contents.
   Apply only after each source hash and protected destination are reviewed.
4. Update canonical clients and public copy, remove the gateway's keyless
   Crystal paths, run production rollback checks, then request explicit
   release/deployment approval.

The candidate does not authorize a merge, release, deployment, or actual
production quarantine. It is ready for independent source review, not
production rollout.

## Final primary review continuation

Final source/config pins are in `ops/review-evidence/crystal-final-pins-2026-10-01.json`.
The canonical source patch preserves unrelated MCP batch title/annotations.
The production registry has three credential rows and zero owner mappings;
all existing Crystal credentials will be denied until explicit mappings are
established. Production cutover/quarantine are not performed by staging.
