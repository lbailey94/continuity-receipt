# Memory Crystal owner-bound access — Phase 4C local candidate evidence

**Status: isolated local candidate, not deployed.** The canonical hosted kit,
the live host, and existing stored data are unchanged. This candidate exists
to exercise the core of `CRYSTAL_OWNERSHIP_CONTRACT_2026-09-30.md` on loopback
with synthetic principals, keys, and crystals. It is not a security control
and does not close the contract's production gates.

## Sources and hashes

| Artifact | SHA-256 |
| --- | --- |
| Canonical `authd.py` base | `e84330ff169ec28324b332901a431ec95d10818500c982c25ae959e9801fcaf6` |
| Candidate `authd.py` | `64bb900b1bd132993bd23fb56237db077d3627d100399f0f7ba0a110e9c89fa1` |
| Canonical `receipt-api.py` base (post Phase 4B) | `10f36afc7afa3571d44bd355ba82af77787a543f6d7cd50294bdbd1afc5d19b0` |
| Candidate `receipt-api.py` | `30e32e84e64177166c070ab4ce70fba5808aff1e75f8074b77b2e298b141863c` |
| `crystal_client.py` (copied, unmodified) | `81cf497be3683fd07fbb2f79d9101b75d71d3e93660f9aaff5fd533a0533be55` |
| Loopback harness `ops/test_crystal_ownership_candidate.py` | `91cb5a5017c7155e77bfa44517b4ed9adcbb9ffb5f4eaa43b31cce46cc46cbd3` |

Candidate tree: `ops/crystal-ownership-candidate/src/`. Diffs against canonical:
`authd.py` +56/−3, `receipt-api.py` +129/−19, `crystal_client.py` unchanged.

## Implemented behavior (candidate only)

Trusted gateway (`authd.py`):

- An authenticated request to `/crystals` or `/crystals/*` resolves the
  caller's `owner_id` from the gateway key registry (`keys.json` entries may
  carry `"owner_id": "<64-hex>"`). A key that authenticates but has no valid
  owner mapping is refused with `403 crystal_owner_not_mapped`; keyless and
  anonymous matches have no owner and fail closed. Write billing (x402) alone
  does not select an owner.
- The gateway strips every client-supplied `X-WM-Crystal-Assertion`,
  `X-WM-Crystal-Owner`, `X-WM-Principal`, and `X-Tenant-Hash` header
  (case-insensitive) on Crystal requests, then attaches its own
  `X-WM-Crystal-Assertion` signed with `crystal_assertion.secret` from the
  gateway state dir. Claims bind version, `owner_id`, method, exact
  path+query target, SHA-256 of the body, `iat`/`exp` (30 s), and a 128-bit
  nonce.

API (`receipt-api.py`):

- `/crystals` reads, lineage, and writes require a valid assertion; missing,
  malformed, wrongly signed, expired, future-issued, over-long, retargeted,
  method/body-mismatched, or replayed requests fail closed with
  `401 crystal access denied`. The replay cache is in-memory and
  per-process (single loopback instance here).
- Owner scope is the server-assigned locator `sha256:<owner_id>`, derived
  only from the verified assertion. Caller-supplied tenant selectors
  (`X-Tenant-Hash`, `?tenant=`, `/crystals/<tenant>/<id>`) that do not match
  the owner scope get the same `404 crystal not found` as an absent item;
  matching or absent selectors add no privilege.
- Writes whose envelope `tenant_hash` is not the caller's own locator are
  refused with `403 crystal owner mismatch` and are not stored.
- Lineage is always scoped to the verified owner; a foreign selector is a
  uniform miss.

Not changed: `crystal_client.py` (no v2 client bootstrap), `/info` and
discovery copy (still describe the v1 keyless locator; candidate-only),
envelope `spec` remains `wm-crystal/1.0` (no `wm-crystal/2.0` versioning).

## Evidence

Run explicitly (skipped by default discovery):

```bash
python3 ops/test_crystal_ownership_candidate.py \
    --authd ops/crystal-ownership-candidate/src/authd.py \
    --api ops/crystal-ownership-candidate/src/receipt-api.py
```

Observed 2026-09-30: **12 tests, all passed** (`Ran 12 tests ... OK`). Cases:

1. owner write → owner read roundtrip via the gateway, envelope decrypted
   with the synthetic AEAD key, tenant bound to `sha256:<owner A>`;
2. keyless `GET /crystals/<id>` fails closed at the gateway (403);
3. authenticated key without an owner mapping is refused (403);
4. owner B reading owner A's crystal gets a uniform 404, no ciphertext;
5. forged client assertion/owner/principal/tenant headers are stripped and
   replaced (owner A read still succeeds under the verified mapping);
6. caller-supplied foreign locators (query and path form) are uniform 404;
7. owner B cannot store an envelope sealed under owner A's locator (403),
   while owner B's own envelope stores (201);
8. lineage is scoped to the verified owner; foreign selector is 404;
9. direct-to-API request without an assertion, or with a wrong-secret
   signature, is 401;
10. a valid assertion is accepted once, then the identical replay is 401;
11. expired, future-issued, and over-long lifetimes are 401;
12. target, body-digest, and method mismatches are 401.

General repo suite at the same checkpoint: `134 passed, 21 skipped,
10 subtests passed` — unchanged from the recorded Phase 4B baseline; the
candidate files are not imported by package tests.

## Explicitly open — not covered by this candidate

- Production principal registry: who assigns `owner_id` (API keys, OAuth
  subjects, session passes), x402 owner binding, and storage locator
  derivation (the candidate equates `owner_id` with the locator).
- `wm-crystal/2.0` envelope versioning, client owner-locator bootstrap, and
  client updates; legacy v1 keyless contract retirement.
- Ownerless/legacy data migration, quarantine, conflict handling, and the
  one existing production envelope's owner decision.
- `/info`, discovery, and docs copy reconciliation; deployed channel
  hardening (mTLS/Unix socket or signed assertion) and key rotation tests;
  clock-skew/replay reasoning for multi-process deployments; Caddy path
  rewrite review against exact target binding.
- Reviewed diff, staging smoke, backup/rollback, and deployment — all
  separate gates per the contract and Phase 4 plan.

No public Crystal ID/tenant probe was made and no real credential, key, or
stored crystal was read at any point.
