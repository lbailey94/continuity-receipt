# Crystal ownership rollout preparation

**Approved and deployed 2026-10-01. Do not rerun this one-time migration.** The only
owner disposition selected so far is: the known legacy envelope has unknown
ownership, must be preserved, and must be quarantined. No owner IDs are to be
added to production `keys.json` until each assignment is separately
established. The approved cutover preserved the one envelope in a consistent protected backup and root-only quarantine; no plaintext was inspected or decrypted. The preparation history below is retained; the deployment record at the end is current.

## Files in this packet

- `canonical-kit.patch` applies the isolated `authd.py`, `receipt-api.py`,
  and `crystal_client.py` candidate to the exact hosted-kit source baselines
  listed below.
- `gateway-config.patch` removes `/crystals/*` from authd's keyless path list
  and updates the Caddy route comment. The two Caddy `handle` blocks keep
  forwarding `/crystals` and `/crystals/*` directly to loopback authd.
- `rollback-crystal-deny.patch` is an emergency Caddy overlay for rollback to
  pre-ownership API code. It returns 503 on both Crystal paths until an
  owner-safe implementation is restored.
- `whitemagic-hosted-api.tmpfiles.conf` declares private state and
  root-only quarantine directory modes.
- `rehearse_state.py` runs a disposable backup/restore and old/new assertion
  key overlap rehearsal. It emits no key material and accesses only a
  temporary directory.

## Read-only topology check

The current private hosted-kit deployment files identify this path:

```text
client -> Caddy TLS :443
       -> authd 127.0.0.1:18792 (keys/caps/audit)
       -> receipt-api 127.0.0.1:18791
```

Both systemd services run as `whitemagic:whitemagic` and share
`/var/lib/whitemagic-hosted-api`. The API service is restricted by
`ProtectSystem=strict` and `ReadWritePaths=/var/lib/whitemagic-hosted-api`;
authd has the matching write path and reads `/etc/whitemagic-hosted`.
`Caddyfile` uses `handle /crystals` and `handle /crystals/*` with a direct
`reverse_proxy 127.0.0.1:18792`; it does not use `handle_path` or a URI rewrite
for these routes. The systemd command currently includes
`/crystals/*` in `--keyless-paths`; the proposed service patch removes it.

The read-only remote `deploy-check.sh --detail` checks for Caddyfile,
`whitemagic-api-gateway.service`, and `receipt-api.service` all matched their
local kit copies at preparation time. The observed hashes were:

| Source/config | SHA-256 |
| --- | --- |
| authd base | `cba03d0f26abdbf90e1d24df3a469bfc1ec14d9bae56b480f73dba982e2a458d` |
| receipt-api base | `10f36afc7afa3571d44bd355ba82af77787a543f6d7cd50294bdbd1afc5d19b0` |
| crystal client base | `81cf497be3683fd07fbb2f79d9101b75d71d3e93660f9aaff5fd533a0533be55` |
| Caddyfile | `c7a8401a5fdae11722daadd413b35e0e01a4533b921874a5c9b7c889bb20872b` |
| receipt-api unit | `c54cc984cd42f0682a6ab70e8153491b208b368a9dda96b0142dcb5e86f2c735` |
| API gateway unit | `b3498f5fcf0d9be5bbfc479add2b66fc764111681582c5972768a5a8cac5d67d` |

This is a read-only comparison with the `whitemagic` SSH target and proves
file parity at that check time. It does not establish a live Crystal
authorization result or Caddy-to-API adversarial behavior. The separate
transient VPS staging transcript is
`ops/review-evidence/crystal-vps-staging-2026-10-01.txt`.

## Proposed state permissions

Both services need to read the same assertion keyring and the API needs to
create its replay database. Keep the shared state root mode `0700`, owned by
`whitemagic:whitemagic`. Install
`crystal_assertion.keys.json` as `whitemagic:whitemagic`, mode `0600`. The
SQLite replay database is created beneath that private directory; its
directory boundary prevents other users from reading it.

The quarantine directory is separate from `tenant-crystals`, mode `0700`,
owned by `root:root`. `receipt-api` must not be able to traverse it. The
quarantine helper creates it with mode `0700` and refuses an existing
group/world-accessible root. Do not add the quarantine path to API search,
backup serving, or static web roots. Retain a second protected backup outside
the service state tree before any quarantine move.

The tmpfiles file is a proposed config, not installed. Its directory line
must be reviewed against existing state permissions before use; changing the
state root mode can affect other hosted components. The dedicated Crystal
quarantine subdirectory must remain inaccessible to the service account.

## Staging and patch validation

Apply the source patch only to a disposable copy of the hosted kit. The
patch is pinned to the six hashes above; stop if any baseline differs and
rebuild the review delta. Then validate that the patched files byte-match the
candidate, run `py_compile`, the 25-case ownership harness, relevant hosted
API tests, and the transient VPS staging run. Keep the production
`keys.json` owner mappings absent during these checks; all Crystal requests
must fail closed for unmapped principals.

The candidate does not require changing the receipt-api listen address or
systemd sandbox. The two services already share one state directory as the
same Unix user. Caddy routes remain direct proxies, so the exact path and
query arrive at authd without an explicit rewrite in the checked config.
Test the exact public path through the actual TLS/Caddy layer before release;
the loopback assertion harness alone does not prove that boundary.

## Later production rehearsal, only after approval

1. Confirm current file hashes and service status read-only. Prepare a
   root-owned backup directory with mode `0700`. Stop both API services
   before a consistent state snapshot; preserve owner, mode, timestamps, and
   ACLs. Back up the canonical source files, both unit files, Caddyfile,
   complete service state, current client artifact, and key material. Keep
   the backup outside `/var/lib/whitemagic-hosted-api`.
2. Install only the reviewed source/config patch and private directory
   permissions. Keep `keys.json` unchanged: no new `owner_id` values. If no
   assertion key exists, provision a random 32-byte key directly to the
   0600 keyring file using an approved secret-generation method; never print
   it to a terminal, transcript, or manifest. If a legacy assertion secret
   exists, import it under `kid="legacy"` and test it before switching to a
   new active key. The API and gateway read the same keyring path.
3. Before starting the new route behavior, produce a private quarantine
   dry-run manifest from the saved state. Supply only independently verified
   owner IDs using repeated `--registered-owner-id`; the tool excludes those
   exact registry locators and marks every remaining crystal ownerless. Keep
   the manifest root-only and review its file count, source paths, and hashes.
   Do not include crystal contents in the review artifact. The selected
   ownerless envelope must be preserved; never delete it or infer its owner.
   The root agent produced a protected read-only manifest at
   `/root/continuity-rollouts/crystal-review-qjI5Ho5P/legacy-dry-run.json`.
   Manifest SHA-256:
   `de5f53492f552672db0c3225c305ff67c8fcd4e610a681c12ca6c72e9ab5081c`;
   the single source envelope byte SHA-256 is
   `f638468a80c55d2c68054b0576a497c2d90b9ad9d216c0e313aabd3752a822ae`.
   The manifest reports one item and has not been applied.
4. Apply the reviewed plan only as a separate explicit command with
   `--apply`. The helper preflights every source and hash before moving any
   file, creates the root-only namespace without overwrites, verifies each
   hash, and fsyncs directories. Record the resulting manifest and compare
   quarantine file hashes with the pre-move hashes. This step has only been
   exercised on synthetic temporary data.
5. Start API then gateway. Check `/health`, `/info`, and owner-locator
   behavior using synthetic staging credentials. Check keyless `/crystals`
   is denied, an unmapped API key gets 403, the owner can retrieve only its
   mapped scope, and a second owner receives a uniform 404. Verify audit
   events, then exercise the same requests through Caddy/TLS. Do not expose a
   real owner mapping until each owner assignment is reviewed.
6. For key rotation, first install `new` in the verifier keyring while
   retaining the old `kid`, set `active_kid` to `new`, and verify the issuer
   signs with `new` while both IDs validate. Keep the previous key for at
   least 125 seconds (120-second maximum assertion TTL plus five-second
   skew), then remove it and prove a fresh assertion under the retired `kid`
   fails. The disposable rehearsal result is
   `isolated-rehearsal-result.json`; rerun its script for each candidate build.

## Rollback rules

If the candidate fails before any public route change, stop the candidate
services, restore source/config and the exact pre-change keyring from the
protected backup, restore the pre-change state only if no service wrote to it
after the snapshot, then restart and verify the prior `/info` version. Do not
blindly replace the live state directory after requests have resumed: this
can discard payment receipts, audit records, replay entries, or new key
material.

If candidate code must be rolled back after routes have been opened, first
apply `rollback-crystal-deny.patch` and reload Caddy so `/crystals` returns
503. Then restore the old code. Leave the public Crystal routes denied until
an owner-safe candidate is restored; the previous API permits caller-chosen
tenant locators. Do not restore the old keyless route or unquarantine an
ownerless envelope. Restore a quarantined object only to its original store
after verifying its recorded hash and only while public Crystal access is
denied.

The existing `ops/deploy_reviewed_hosted.sh` handles a different receipt-api
and wheel-only deployment. It is not an applicable rollout script for this
cross-service Crystal change.

## Preparation gates at review time (superseded by cutover record)

- [x] Current candidate local harness: 25 cases pass, including quarantine
  destination preflight checks and private/no-store Crystal response
  headers. Primary final 25-case Caddy TLS VPS staging passed after preserving
  unrelated canonical MCP title/annotations in the candidate authd source.
- [x] Read-only comparison of live Caddy and both API systemd unit files to
  the private hosted-kit sources.
- [x] Source and gateway-config patch dry-run/apply on temporary copies.
- [x] Temporary backup/restore plus assertion key overlap/revocation
  rehearsal; state hashes and replay marker restored.
- [x] Primary review and independent temporary patch apply/source-match check.
- [ ] Public TLS/Caddy request matrix against the owner-bound candidate.
- [ ] Production owner registry mappings, key provisioning, backup,
  quarantine manifest, and controlled release/deployment decision.

No production file, key, registry, service, Caddy route, or stored crystal was
modified by this preparation.

## Final primary review continuation

Final source/config pins are in `ops/review-evidence/crystal-final-pins-2026-10-01.json`.
The canonical source patch preserves unrelated MCP batch title/annotations.
The production registry has three credential rows and zero owner mappings;
all existing Crystal credentials will be denied until explicit mappings are
established. Production cutover/quarantine are not performed by staging.

## Approved cutover record — current

The explicit user approval of PR #11 `4a473a5` was executed on October 1.
Canonical and VPS source/config are synchronized. Backup/key provisioning and
root-only quarantine are complete. See
`ops/review-evidence/crystal-protected-backup-summary-2026-10-01.json` and
`ops/review-evidence/crystal-live-cutover-2026-10-01.json` for exact pins,
backup/envelope hashes and public TLS checks. The customer encrypted bytes
are unchanged, registry unchanged, and service-account quarantine access denied.
Owner assignment remains unknown: all three existing credentials remain unmapped
and Crystal requests fail closed. Positive owner cases were run on isolated
synthetic staging. Do not rerun migration, assign an owner, restore the old
keyless route, or blindly replace active state.

## Client-only follow-up after cutover

The approved source/config deployment at `4a473a5` is preserved above.
The local client helper subsequently received independently reviewed HTTPS
origin, redirect, strict-ID and credential-input hardening; binary key bytes
are preserved and generated key files are private/exclusive. Apply
`client-hardening.patch` after the historical `canonical-kit.patch` when
reconstructing the current client. The canonical local helper now matches
the reviewed candidate. No API/gateway source, package, owner registry or
customer data was changed by this follow-up. Tests and source hashes:
`ops/review-evidence/crystal-client-hardening-2026-10-01.json`.
The WMv9 port is reviewed in its isolated worktree and retained as a patch;
it has not been integrated into WMv9 main or released.
