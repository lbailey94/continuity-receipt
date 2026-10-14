# Memory Crystal authenticated ownership contract — Phase 4C

**Status: deployed on 2026-10-01; owner-mapped customer access remains disabled.** The Crystal ownership boundary is active in production. The deployed envelope remains `wm-crystal/1.0`; this is an authenticated access-control change, not a new wire-format release. The production registry has three credential records and zero owner mappings, so those credentials fail closed for Crystal until an operator explicitly assigns owners. Payment alone does not establish ownership.

The owner-unknown legacy envelope was preserved in a consistent root-only
backup and moved as encrypted bytes into a root-only quarantine namespace. No
plaintext or decryption key was inspected, and the service account cannot read
the quarantine. The production registry was unchanged. Live TLS checks passed
for health/info, owner-mapped-denial behavior, and authenticated `/verify`; see
[`crystal-live-cutover-2026-10-01.json`](review-evidence/crystal-live-cutover-2026-10-01.json)
and [`crystal-protected-backup-summary-2026-10-01.json`](review-evidence/crystal-protected-backup-summary-2026-10-01.json).
The backup summary records backup SHA-256
`d9d183ad21529005374b26fa5fa4234a6beed927275b07864eab7b56584a0a22` and
encrypted-envelope SHA-256
`f638468a80c55d2c68054b0576a497c2d90b9ad9d216c0e313aabd3752a822ae`.

## Current deployed contract

- The gateway requires normal route authorization/billing and an explicit
  registry-mapped `owner_id` for every Crystal operation. It strips
  client-supplied identity/assertion headers and signs an internal assertion
  bound to the owner, method, exact path/query, body digest, lifetime, key ID,
  and single-use nonce. The API derives storage scope only from that assertion.
- `GET /crystals/owner-locator` returns only the authenticated registry
  assignment. Item reads, writes, and lineage are owner-scoped; a foreign or
  absent item produces the same 404. No first-reader ownership, locator-based
  migration, or payment-based owner selection occurs.
- x402 payment or a session pass may authorize billing/access to a metered
  route; neither creates or selects a Crystal owner. With zero current owner
  mappings, paid or keyed principals remain denied until an explicit mapping
  is recorded.
- Crystal responses, including denials and conditional responses, use
  `Cache-Control: private, no-store` and vary by authentication headers. An
  ETag/304 response is returned only after owner assertion validation and does
  not authorize shared caching.
- The envelope and AAD remain `wm-crystal/1.0`. The locator is assigned by the
  registry and used by the client; no automatic mapping from legacy public-salt
  locators is performed. The ownerless envelope remains quarantined and
  excluded from reads and lineage.
- The existing hosted Crystal client implements the authenticated locator
  bootstrap and owner-bound access. Older clients that rely on keyless reads
  or client-selected tenant locators must update before use.

Live `/info` reports verifier runtime 0.5.0 and accepts receipt specs 0.1–0.6;
that hosted runtime version does not assert publication of matching PyPI or
crates.io releases. The ERC-8004 adapter returns an Ed25519-signed canonical
JSON statement and does not produce an EVM EIP-712 signature or relay a
transaction. Caller-claim notarization binds submitted claims to a signer; it
does not observe or prove the underlying context or execution. The refreshed
hosted-kit descriptions are in `planning/private/hosted-kit/RECEIPT_API.md`
and `server-card-api.json`.

## Historical boundary inspected before cutover (2026-09-30)

Inspected the canonical hosted kit's `receipt-api.py`, `authd.py`, `Caddyfile`, `whitemagic-api-gateway.service`, `RECEIPT_API.md`, `crystal_client.py`, and existing Crystal test, plus `WMv9/scripts/crystal_client.py`. The two client files are not identical; both independently documented/implemented client-chosen tenant hashes and keyless pulls before cutover. Source hashes at inspection time: hosted API `f3daa358f055ae1ac4667629c2a73ecd6df694684ad778c0a2a8410ccd72c134`; authd `e84330ff169ec28324b332901a431ec95d10818500c982c25ae959e9801fcaf6`; Caddyfile `7becd6f62019976c3cd7995e2c0a14976084c34b0883ccdffe02ba4ae94ce32a`; API service unit `b3498f5fcf0d9be5bbfc479add2b66fc764111681582c5972768a5a8cac5d67d`; hosted client `81cf497be3683fd07fbb2f79d9101b75d71d3e93660f9aaff5fd533a0533be55`; WMv9 client `4db935cc8c72166219624a592db5b9c55adab104c61766ad41e28026681b3ac5`; API docs `1071f4e8425884df1931b797259e12eda0193ddece4c09e09500baebb864b679`. The pre-cutover behavior was:

- The gateway routes `/crystals` to authd. Its service configuration lists `/crystals/*` as keyless; authd's keyless-path check applies only to GET/HEAD. Thus Crystal reads, including `/crystals/<id>` and `/crystals/lineage`, can pass the gateway without an authenticated account principal. Crystal writes are outside that keyless wildcard and require a key/session or x402 at the gateway.
- The API's `GET /crystals/<id>` takes the storage tenant locator from a caller-provided `X-Tenant-Hash`, `?tenant=`, or `/crystals/<tenant>/<id>` path. Lineage likewise accepts caller-provided tenant query/header. No API ownership authorization binds that locator to the authenticated caller.
- authd authenticates/meter-caps requests, but its normal upstream forwarding removes authorization headers and does not derive or attach a Crystal owner principal. The API therefore cannot associate the caller's gateway identity with an envelope's tenant locator. The forwarding path preserves other request headers, including tenant-selection input.
- `crystal_client.py` computes `tenant_hash = sha256("whitemagic-crystal-salt-v1:" + tenant_id)`. The salt is public and static. This stable locator is supplied by the caller; it is not an authorization credential. Low-entropy tenant IDs may be guessable, and any learned locator can select the corresponding storage directory.
- The API stores by `tenant_hash`, verifies content-address integrity, and returns ciphertext envelopes. The client AEAD AAD binds cipher, tenant hash, parent ID, and creation time. This binds envelope data for decryption integrity; it does not authenticate a caller to the service or prove storage ownership.
- `metadata_public`, content address, parent ID, size, and timestamp are returned in read/lineage responses. Ciphertext retrieval is disclosure of opaque encrypted bytes and metadata. It does not by itself give an outsider plaintext access; successful decryption still requires the client's encryption key.

## Offline baseline characterization

The opt-in harness [`test_crystal_access_boundary.py`](/home/lucas/Desktop/continuity-receipt/ops/test_crystal_access_boundary.py) starts the canonical API handler on a dynamic loopback port, sets a fresh temporary `WM_RECEIPT_API_STATE`, stores one locally generated synthetic AEAD envelope, and performs read requests without an identity header or token. It reads no real crystal, fixture credential, persistent state, or key. All generated keys and ciphertext exist only for the test and are deleted with the temporary directory.

Run explicitly with:

```bash
RUN_CRYSTAL_ACCESS_CHARACTERIZATION=1 python3 -m unittest ops.test_crystal_access_boundary -v
```

Observed result: **1 characterization test passed, reproducing the baseline gap**. An unauthenticated request with the envelope's known synthetic tenant locator received HTTP 200 and the exact ciphertext plus public lineage metadata. The owner's synthetic key decrypted the returned envelope; an independent synthetic outsider key failed AEAD decryption. The console explicitly prints `BASELINE GAP REPRODUCED (not a security pass)`.

This is a characterization of the API handler. The authd/Caddy routing conclusion above is source/config inspection, not a live gateway test. No public Crystal ID/tenant probe was made. With no opt-in variable, unittest skipped the class; pytest collection also returned one skip, so the baseline assertion does not run as part of general test discovery.

## Original design proposal (not selected): `wm-crystal/2.0` ownership-bound access

### Principal and trusted gateway-to-API assertion

1. Resolve every Crystal operation to a stable `crystal_owner_id` from an authenticated account/ownership registry. The registry maps verified API-key, OAuth, or session-pass subjects to an owner; raw key labels, bearer strings, payer labels, IP addresses, user agents, body fields, and caller-selected tenant IDs are not principals. A temporary session pass must resolve to the same owner account as its issuer. Anonymous requests have no owner and fail closed.
2. A valid x402 payment authorizes billing for an operation only. It does not create, claim, or select a Crystal owner. Crystal write access requires both a known owner principal and the route's normal billing/authentication authorization. A payer can own data only through a separate authenticated account mapping.
3. At the public boundary, authd removes every client-supplied internal identity/assertion header (including duplicate/case variants) and never trusts `X-WM-Principal`, `X-WM-Crystal-Owner`, or `X-Tenant-Hash` as proof of identity. It replaces them only from its verified owner mapping. Caller-supplied tenant selectors are rejected on v2 routes (or ignored only during an explicitly versioned compatibility route); they cannot override the authenticated owner.
4. Authenticate authd-to-API independently of user auth. Preferred deployment is a private Unix socket or loopback-only API plus mutually authenticated proxy identity. If a signed internal assertion is used, it must bind version/key ID, principal ID, HTTP method, normalized path, body digest, issued/expiry times, and a single-use nonce under a domain-separated MAC/signature. API verifies authenticity, audience, short lifetime, nonce replay, method/path/body binding, and owner mapping before storage lookup. Keep assertion keys separate from client AEAD keys; never forward the user's bearer token to receipt-api.
5. API operations derive owner storage scope from the verified principal. GET item and lineage, POST, update/delete if later added, and conditional ETag paths all authorize against this same scope. A supplied `tenant_hash` must match the server-assigned owner locator for new envelopes; it remains an AAD/content field, never an access credential. Return the same not-found response for absent and other-owner IDs to avoid an existence oracle.

### Versioned envelope and routes

- Introduce `wm-crystal/2.0`; do not silently reinterpret v1 fields. The authenticated client obtains its owner locator over an authenticated API operation before sealing. A new v2 envelope binds its opaque locator into AEAD AAD, with the authenticated principal independently checked by the API.
- Preserve familiar route shapes where possible: authenticated `POST /crystals`, authenticated `GET /crystals/<content-id>`, and authenticated `GET /crystals/lineage`. GET derives owner scope from the authenticated assertion; a `tenant` query, `X-Tenant-Hash`, or tenant path segment is rejected on v2. The old keyless tenant-selector read contract must be retired or isolated behind a deliberately temporary legacy boundary; it must not be described as tenant isolation.
- V2 returns encrypted bytes only to the owning authenticated principal. The access check does not make the service capable of decrypting data. Keep public metadata classification explicit: `metadata_public` is visible to an authorized owner and remains unauthenticated as AEAD data unless a future version includes it in AAD.
- Missing/invalid identity, mismatched envelope owner locator, bad internal assertion, replay, and cross-owner access fail closed. Use 401/403 for authentication/authorization at the gateway, and a uniform 404 for item IDs outside the caller's owner scope. No fallback to caller-selected legacy locator is allowed after v2 auth fails.

### Existing data: explicit migration, no first-reader ownership

Existing v1 rows contain a public-salt tenant hash but no authenticated owner mapping. Do not assign them to the first principal that supplies the locator or ciphertext ID. During migration:

1. Stop legacy keyless reads at the gateway and inventory storage internally without publishing IDs or owner locators.
2. Assign an existing locator only when an administrator can tie it to an independently verified preexisting owner record, or a pre-agreed migration procedure establishes control using evidence stronger than merely knowing the public-salt hash. Document the accepted proof and retain an audit record.
3. Where ownership cannot be established, quarantine the row from all API reads and lineage results. Leave it unclaimed; offer recovery only through a separately verified owner/support process. Do not use possession of a ciphertext ID or the first successful GET as a claim.
4. Store migration mapping and disposition transactionally; verify counts/hashes before and after cutover. Keep a rollback snapshot inaccessible to the public API. Do not silently migrate a row whose locator conflicts with an existing authenticated owner.

### Key rotation and recovery

- Client AEAD keys and gateway/API assertion keys have separate lifecycles. The host never receives client AEAD keys.
- Normal client key rotation is client-side: retrieve as the authenticated owner, decrypt locally with the old key, seal under the new key using the same owner locator and new nonce, upload as a version/successor, read back and verify locally, then retire the old ciphertext according to an explicit retention policy. Preserve parent/lineage semantics without permitting a caller to move data between owners.
- Lost AEAD key means the host cannot recover plaintext. Account recovery may restore authorized access to ciphertext but does not reconstruct a lost encryption key; restoration requires the owner's own encrypted backup/recovery material.
- Rotate proxy assertion keys with key IDs and a bounded overlap period: install new verifier material, switch issuer, observe successful traffic, then revoke old key. Keep key access restricted and audited; rotate owner-locator HMAC keys only through a mapping-preserving migration. Do not change locators in place if they are part of existing ciphertext AAD.

## Compatibility consequences and separate gates

This section records the earlier design exploration. The selected deployed implementation retains the `wm-crystal/1.0` envelope/AAD and changes the access boundary; it does not implement a `wm-crystal/2.0` format.

Those choices were resolved for this cutover with explicit registry assignment as the ownership source, a signed internal assertion, and preserve-and-quarantine for unknown-owner data. The baseline characterization below documents the pre-cutover gap, not current deployed behavior.

## Primary independent review

The primary reran the opt-in local characterization on 2026-09-30. The
unauthenticated synthetic ciphertext and lineage read was reproduced; the
owner key decrypted and the outsider key did not. This confirms the access
gap in the inspected handler, not that plaintext encryption failed. The
gateway's keyless read configuration was separately source-reviewed. No
public tenant/crystal retrieval was attempted.

A read-only production filesystem inventory (names/content not returned)
found one tenant directory and one `.crystal` envelope, 558 serialized bytes.
No owner mapping was established or data classification inferred. Any legacy
cutover therefore needs an explicit owner/migration decision for that row;
knowing its locator must not confer ownership.

## Candidate review history — 2026-10-01

The isolated implementation candidate went through primary review before
cutover. The initial 12-case candidate had an expiry-skew
replay bug. Primary review reproduced it, then Luna implemented persistent
SQLite reservations through the complete acceptance window, strict lifetime
ordering, keyring overlap/revocation, authenticated locator bootstrap and
client changes, and dry-run/apply quarantine. A further malformed gateway
keyring issue found in primary review is fixed with a regression.

Primary independently passed the earlier 22-case harness locally and on the
VPS under a disposable hardened unit with synthetic owners/state. Tests
include separate-process nonce races and replay after restart. The staging
files/processes were removed afterward. API candidate hash a492f5f347c560be4d0bdd44b6f5852060b3444eab5f62358891683adee973a9;
authd candidate hash 0b3eaaf9ea309620db23d0ce21af69aaf05be9f0b85297bdf01fa5697aa77b3b.

The selected deployed implementation retains the wm-crystal/1.0 envelope/AAD shape while
changing the authenticated access contract and adding owner-locator
bootstrap. This is a deliberate staged alternative to the original v2
proposal, not an implicit v2 specification. Published core semantics are
unchanged. No automatic locator-to-owner assignment is permitted.

Lucas selected preserve-and-quarantine for the owner-unknown production
envelope. That decision was implemented during the approved cutover described
above; the live row is now quarantined as encrypted bytes and is present in the
protected consistent backup.

The final candidate adds whole-manifest permission/duplicate preflight and
private/no-store cache policy for owner-bound responses. Primary passed its
25-case matrix through disposable Caddy TLS on the VPS. Exact source hashes
are recorded in `ops/review-evidence/crystal-final-pins-2026-10-01.json` and
were synchronized to the canonical kit during cutover. Production still has
zero mapped owner IDs; denial until explicit assignment is the active
fail-closed behavior.

## Production cutover — 2026-10-01

The approved source/config cutover completed and services are active. The
protected backup summary records one quarantined envelope, unchanged registry,
and service-account denial of quarantine reads. No plaintext was inspected.
Post-cutover public TLS checks returned 402 to unauthenticated Crystal
requests and 403 to authenticated but unmapped principals; the public
`/verify` check returned 200. Direct loopback API requests without a valid
assertion returned 401. The exact status/cache-control matrix is in
`ops/review-evidence/crystal-live-cutover-2026-10-01.json`.

Remaining operational condition: an administrator must separately verify and
record each desired principal-to-owner assignment before Crystal access can
be enabled for that principal. The three current credentials remain unmapped.
