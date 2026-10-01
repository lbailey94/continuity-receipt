# Memory Crystal owner-bound access — Phase 4C evidence

**Status: deployed on 2026-10-01; production owner mappings remain empty.**
Canonical gateway/API/client sources and route configuration were synchronized
to the reviewed candidate. The owner-unknown legacy envelope was preserved as
encrypted bytes in root-only quarantine and in a protected consistent backup;
no plaintext or decryption key was inspected. The registry remains unchanged
with three credential records and zero owner IDs, so existing credentials are
denied Crystal access until explicit mappings are assigned. Production
cutover evidence is recorded in the linked JSON artifacts below.

## Deployed behavior

The reviewed implementation lives under `ops/crystal-ownership-candidate/`
and its source hashes are pinned in
`ops/review-evidence/crystal-final-pins-2026-10-01.json`. `authd.py` requires an explicit
64-hex `owner_id` on the authenticated key registry entry for Crystal routes.
An unmapped principal fails closed; payments, public-salt tenant hashes,
ciphertext IDs, and first reads never claim an owner. The gateway strips
client-supplied internal identity headers and signs a short-lived assertion
binding `kid`, owner, method, exact path/query, body digest, issue/expiry, and
nonce.

`receipt-api.py` derives storage scope from the verified assertion. Item
reads, lineage, writes, and the locator bootstrap require the assertion.
Cross-owner item lookups and foreign locator selectors return uniform 404s;
foreign-owner writes fail 403. `GET /crystals/owner-locator` returns
`sha256:<owner_id>` only after the authenticated gateway registry has resolved
the principal. The candidate client can fetch that value with
`owner-locator --token ...`, pass it to `seal --owner-locator ...`, and use
authenticated token-based `pull`/`lineage`. It has no automatic owner claim.

The wire envelope remains **`wm-crystal/1.0`** with its existing field shape
and AAD construction. New candidate writes can use the registry locator in
`tenant_hash`; old public-salt locators are not automatically translated.
Legacy envelopes without an independently established owner remain
unavailable through owner-scoped reads and lineage.

Assertion replay is stored in a stdlib SQLite ledger with an atomic unique
nonce insert. The ledger is shared across worker processes and persists across
API restarts; nonce retention lasts through `exp + 5s` to match the acceptance
skew. Malformed lifetimes, booleans used as integers, `iat >= exp`, wrong
bindings, expired/future assertions, and replay all fail closed. Assertion
keys use `crystal_assertion.keys.json`: authd issues with `active_kid`, while
the API accepts keys retained in the `keys` map. Rotation is overlap-based:
install a new active key while retaining the old key for at least the 120s
maximum lifetime plus skew, switch issuer, then remove the old key. The old
single secret file is accepted only as the legacy `kid` format when no keyring
exists.

## Ownerless legacy quarantine

The decision for the one existing production envelope is **owner unknown;
preserve and quarantine**. Cutover preserved the encrypted bytes in root-only
quarantine and a consistent protected backup; the service account cannot read
the quarantine. No plaintext was inspected. The candidate includes
`quarantine_legacy.py`: dry-run is the default and
writes a JSON plan with exact source paths, tenant locators, and source-byte
SHA-256 values. `--apply` is required to apply a saved plan. Before planning
against a store with already-mapped owners, pass each explicitly verified ID
with a repeated `--registered-owner-id <64-hex>`; the helper excludes only
those exact `sha256:<owner_id>` locators. It never derives mappings. Before any move,
the helper checks non-overlapping roots, regular non-symlink entries, all
source hashes, path containment, and destination absence across the complete
manifest. It creates destinations without overwriting, verifies bytes, fsyncs
directories, then removes the source name. The quarantine root is separate
from the API's readable crystal root, so ordinary reads and lineage do not
enumerate quarantined files. The plan makes no owner assignment. Any eventual
mapping requires a separately approved, recorded operator mapping.

The harness exercises only synthetic envelopes in fresh temporary directories.
It checks the dry-run leaves bytes in place, applying moves the exact bytes to
the quarantine namespace, and the API cannot return that crystal by owner
read or lineage. A changed source in a later manifest row fails whole-plan
preflight before any file moves. The live one-envelope disposition is
independently summarized at
`ops/review-evidence/crystal-protected-backup-summary-2026-10-01.json`; the
cutover matrix is at
`ops/review-evidence/crystal-live-cutover-2026-10-01.json`.

## Verification

Run the isolated harness explicitly:

```bash
python3 ops/test_crystal_ownership_candidate.py \
    --authd ops/crystal-ownership-candidate/src/authd.py \
    --api ops/crystal-ownership-candidate/src/receipt-api.py
```

Current candidate evidence: **25 tests passed**. Coverage includes two-owner
round-trip and lineage, unmapped principal refusal, forged-header stripping,
foreign selector and write refusal, direct API assertion checks, method/path/
body binding, expiry/future/overlong and malformed lifetimes, replay through
the expiry-skew boundary, actual subprocess race and restart persistence,
threaded single-use reservation, old/new key overlap and key revocation,
malformed non-object/duplicate-key gateway keyring refusal with valid-keyring
restoration, owner-locator bootstrap and client sealing, legacy quarantine
byte preservation/read isolation, whole-manifest, duplicate-entry, and
destination-permission preflight, and private/no-store plus credential-vary
headers across owned, denied, uniform-miss, and conditional 304 responses.
`py_compile` passed for candidate source, harness, and quarantine CLI.

The primary's prior transient VPS staging run exercised the then-current
22-case candidate with disposable service state; the transcript is
`ops/review-evidence/crystal-vps-staging-2026-10-01.txt`. This did not change
the public Caddy route or production state. It predates the later quarantine
preflight and private-cache-header fixes. Primary subsequently passed all
25 cases through disposable Caddy TLS under the hardened VPS service account
with the final source; the CA, synthetic state, files and processes were removed.
See `ops/review-evidence/crystal-caddy-vps-staging-2026-10-01.txt` and
`ops/review-evidence/crystal-final-pins-2026-10-01.json`. The regenerated rollout source patch and
gateway-config patch each passed `patch --dry-run` and apply on temporary
copies, and resulting source files matched the candidate byte-for-byte. The
disposable `rollout/rehearse_state.py` rehearsal restored the exact saved
state hashes and preserved the replay marker; old and new keys validated
during overlap, and the old key failed after retirement.

Read-only pre-cutover `deploy-check.sh --detail` parity checks for the Caddyfile
and both API service units matched the local hosted-kit copies. The later
approved cutover synchronized the pinned source/config to production. The
separate production-domain TLS matrix is recorded in the live cutover JSON.

Completed gates:

- [x] Local 25-case harness and `py_compile` rerun on the current candidate.
- [x] Prior transient VPS staging with disposable state, 22/22 passing on its
  then-current source pin; final 25-case Caddy TLS VPS staging also passed.
- [x] Source/config patch dry-run and exact candidate match on temporary
  copies.
- [x] Disposable state backup/restore and key-overlap/retirement rehearsal.
- [x] Read-only pre-cutover Caddy and API-unit parity checks.

## Production cutover results and remaining condition

- [x] Approved source/config cutover completed; service state is
  `cutover-services-active`.
- [x] Protected consistent backup recorded with SHA-256
  `d9d183ad21529005374b26fa5fa4234a6beed927275b07864eab7b56584a0a22`.
- [x] One encrypted envelope preserved in quarantine with byte SHA-256
  `f638468a80c55d2c68054b0576a497c2d90b9ad9d216c0e313aabd3752a822ae`;
  plaintext not inspected and service-account quarantine reads denied.
- [x] Production registry unchanged: three credential rows, zero owner
  mappings. No customer locator was requested.
- [x] Public TLS checks: unauthenticated Crystal requests received 402,
  authenticated but unmapped requests received 403, and authenticated
  `/verify` returned 200. Crystal responses were `private, no-store`.
- [x] `/info` publishes the owner-bound `wm-crystal/1.0` access contract.
- [ ] Assign any customer owner IDs only through a separate, explicit,
  reviewed operator mapping. Until then existing credentials remain denied.

## Final primary review and cutover record

Final source/config pins are in `ops/review-evidence/crystal-final-pins-2026-10-01.json`.
The canonical source patch preserves unrelated MCP batch title/annotations.
The production registry has three credential rows and zero owner mappings;
all existing Crystal credentials remain denied until explicit mappings are
established. The source deployment and quarantine are production actions
recorded in the live cutover and protected-backup summaries, not inferred from
staging results.
