# Memory Crystal ownership — production decision brief (Phase 4C)

**Status: decision brief for Lucas. No implementation is implied until the
decisions below are recorded.** Companion documents:
`CRYSTAL_OWNERSHIP_CONTRACT_2026-09-30.md` (the proposed contract) and
`CRYSTAL_OWNERSHIP_EVIDENCE_2026-09-30.md` (the local candidate and its 12
loopback cases). The candidate is isolated; the canonical kit and production
are unchanged.

## Why this is ready to decide

- The gap is real and reproduced: keyless `GET /crystals/<id>` returns
  ciphertext and metadata to anyone who knows the locator
  (`ops/test_crystal_access_boundary.py`).
- A concrete contract and a working local candidate exist; the remaining
  work is decisions (this brief) plus implementation, staging, and rollout.
- Production exposure today is small: a read-only inventory found **one
  tenant directory and one `.crystal` envelope (558 bytes)** with no owner
  mapping. There is no external reader population to break that we know of.

## Decisions requested

### D1 — Authoritative principal and owner mapping

How an authenticated caller resolves to an owner id.

- **Recommended:** the gateway key registry (`keys.json`) gains an
  `"owner_id"` field per key: 64 lowercase hex characters, randomly assigned
  per account, never derived from email, tenant name, key label, or payer id.
  OAuth token records map to an owner through the same registry (fail closed
  if unmapped). Session passes resolve to the issuing account's owner —
  today the pass carries a payer id, so passes stay unmapped and fail closed
  until a payer→owner mapping exists. x402 payment never selects an owner.
- **Consequence:** existing keys keep working for other routes but Crystal
  routes return 403 until the owner assignment is made; assignment is a
  one-line registry edit per account.

### D2 — Internal authd → API channel

- **Recommended:** keep the signed assertion from the candidate (HMAC over
  version, owner, method, exact path+query, body digest, `iat`/`exp`, nonce)
  with the secret in a `0600` file on both sides. Rotation is a file swap;
  no client restart needed. A Unix socket or mTLS remains an option later if
  the topology changes.
- **Consequence:** no systemd/socket changes; the secret file must be
  provisioned on the VPS and included in backups.

### D3 — Owner locator

- **Recommended:** locator = `sha256:<owner_id>`. The existing v1 client-side
  public-salt tenant hash becomes legacy-only; new writes bind the locator
  into AEAD AAD.
- **Consequence:** a locator change requires re-sealing data (AAD binding),
  so treat `owner_id` as stable. Do not reuse the public-salt scheme for new
  owners.

### D4 — Legacy data disposition (the one existing envelope)

- **Recommended:** quarantine: remove it from all API reads/lineage until an
  owner is established through a process stronger than knowing its locator;
  keep a protected backup copy. No first-reader claims.
- **Question for Lucas:** is that envelope known internal test data? If yes,
  the cleanest disposition is export-to-backup then remove; if it might be
  someone's data, quarantine it and decide later.

### D5 — Versioning and client compatibility

- **Recommended staging:** Stage A (same release as enforcement): owner-bound
  access on the existing `wm-crystal/1.0` envelope, keyless `/crystals/*`
  removed from the gateway, `/info` and docs updated, no `wm-crystal/2.0`
  yet. Stage B (separate, later): `wm-crystal/2.0` envelope that binds the
  server-assigned locator in AAD, plus a client owner-locator bootstrap and
  rotation/recovery tests.
- **Alternative:** go straight to 2.0. Slower, more client surface, no
  known reader population that justifies it first.
- **Consequence:** Stage A is a breaking access change for any unauthenticated
  reader; we know of none, but the release note must say so explicitly.

### D6 — Ops, copy, and rollout mechanics

- Update `/info`, `RECEIPT_API.md`, and discovery copy; remove `/crystals/*`
  from the gateway's keyless paths; keep audit events for 403/404 outcomes;
  watch assertion-failure rates after rollout.
- Reuse the reviewed deployment pattern: protected backup, narrow delta,
  restart only receipt-api/authd, live checks, rollback on failure.
- `/info` currently still describes keyless locator reads; it must not after
  rollout.

### D7 — Evidence required before rollout (checklist)

- [x] Local: two-owner upload/read/lineage, forged-header stripping, replay,
  lifetime and binding checks, foreign-envelope write refusal (12/12).
- [ ] Local: owner key rotation/recovery test; migration/quarantine test for
  the ownerless row.
- [ ] Staging on the VPS: the changed routes under the production unit
  hardening, plus a repeat of forged-header/replay through Caddy (exact
  path+query binding must be verified against any rewrite rules).
- [ ] Prod readiness: owner ids assigned to internal keys; assertion secret
  provisioned and backed up; `/info` copy updated; keyless path removed;
  rollback rehearsal.
- [ ] Post-deploy double-check: live 403 keyless, owner read works, second
  owner 404, audit events present; then monitor for a day.

## Proposed sequencing if approved

1. Record D1–D6 decisions here (one line each is enough).
2. Codex (or opencode) implements D1–D3 + D6 in the canonical kit, adds the
D7 missing tests, and re-runs the full suites.
3. Primary review of the diff; staging matrix on the VPS.
4. D4 legacy disposition executed by the primary with a protected backup.
5. Rollout with the reviewed deploy pattern, then the post-deploy checks.
6. Stage B (2.0 + client bootstrap + rotation exercise) as a separate change.

## What we are NOT deciding tonight

- `wm-crystal/2.0` wire details (Stage B), external-evidence references,
  issuer-policy/anchors, and independent adoption keep their own gates.
- No package publication is required for Phase 4C; this is hosted-lane
  source, not a spec change.
