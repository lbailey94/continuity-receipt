# Hosted verifier staging, approved deployment and public qualification — 2026-09-30

**Current status:** reviewed API/package/ERC delta deployed after explicit human
approval; post-deployment qualification passed. The earlier sections preserve
the preparation/staging evidence and its scope. See the deployment record below.

## State and reviewed candidate

Canonical hosted source and the production receipt-api process remain unchanged.
The API source SHA-256 is `f3daa358f055ae1ac4667629c2a73ecd6df694684ad778c0a2a8410ccd72c134`.
The candidate composes `hosted-api-qualification.patch` then
`hosted-erc-evidence.patch`, producing SHA-256
`10f36afc7afa3571d44bd355ba82af77787a543f6d7cd50294bdbd1afc5d19b0`.
Both patches were reconstructed and reviewed by the primary.

`hosted-package-pin.patch` updates provisioning to reconcile existing as well
as new environments to package 0.5.0, corrects the README's old versions, and
corrects the service description to include opt-in storage. It is unapplied.
Reconstruction and `bash -n` on the patched recipe passed. The broader provision
script performs many other operations and is not the proposed production
command; deploy only the reviewed API/unit/package delta.

## Package provenance

Downloaded wheels were independently checked against PyPI JSON artifact hashes:

| Wheel | SHA-256 |
|---|---|
| continuity_receipt-0.4.1-py3-none-any.whl | `2d03a1d79ea0cfd192b8b889eb479fcec8cd50990e5d3df4d51cc7bccd1b5374` |
| continuity_receipt-0.5.0-py3-none-any.whl | `9b0be02327759b3f95519967f4257ce37a3ee44468359a88f84480d28c5935ee` |

All 14 installed production Python modules match wheel 0.4.1 byte for byte.
13 of 14 match wheel 0.5.0; only `_version.py` differs. This compares Python
source modules, not all distribution metadata, bytecode, dependencies or native
libraries. Staging used published 0.5.0 extracted into a separate import target,
with existing runtime Python 3.13 and cryptography 50.0.1. Production venv was
not modified. The locally hardened consumer is absent from these published
wheel bytes; hosted verification staging does not qualify that local consumer.

## Primary staging checks

1. Temporary loopback API process using Phase4A + published wheel 0.5.0:
   **83 HTTP checks passed**: 40 frozen 0.4 vectors, 21 0.5 vectors, 10
   experimental 0.6 vectors, and 12 parser/boundary/no-state checks. Expected
   verdicts and configured error codes were checked, including require-anchor
   cases. Stateless calls wrote no state.
2. A transient `receipt-api-qualification-20260930` systemd unit used the
   production unit's User/Group, NoNewPrivileges, ProtectSystem=strict,
   ProtectHome, PrivateTmp, MemoryMax=512M, CPUQuota=200%, with separate
   WorkingDirectory/ReadWritePaths and port 18891. The Phase4A candidate and
   then composed Phase4B candidate each passed the same **83-check matrix**.
3. Primary executed the Phase4A harness on the VPS: **4 passed**, including
   negative/boundary and persisted notarization signature/digest checks. Its
   state was temporary and separate from the staging service and production.
4. Primary executed the revised ERC harness on the VPS: **4 passed**, including
   signed TRUSTED/PROVISIONAL/structural-UNTRUSTED results, task mismatch,
   malformed receipt containers and deep input. The adapter no longer infers
   individual check success from the absence of an error substring.

The ERC response keeps its outcome mapping and keys, but five check fields
now return null. Boolean-only clients need adjustment. Core verdict and task
binding remain explicit; no issuer allowlist or independent anchor status is
implemented. This compatibility change requires service-owner review before
production rollout.

## Disposable rollback rehearsal

Restored the staging source from its original-source copy and removed the
candidate package import target so the unchanged installed 0.4.1 package was
used. Restarted only the transient staging unit. `/info` reported 0.4.1; 0.4,
0.5 and experimental 0.6 positive bundle smokes each returned TRUSTED. Restored
source SHA matched the canonical baseline above. This rehearses source/package
selection and service restart in disposable staging; it does not restore or
qualify production signing keys, receipt/crystal storage or disaster backups.

The transient service was stopped. Its /opt and /var/lib directories and the
remote upload directory were removed. A socket check confirmed port 18891 had
no listener. Production receipt-api remained active and its source hash was
unchanged.

## Authenticated public path (existing production)

`qualify_public_verify.py` created a random temporary evaluation credential in
existing API gateway keys.json using the same flock/atomic-replace discipline
as keyd. It ran as the state owner, made no payment, requested no receipt/cache
persistence, preserved other keys, and removed/verified removal of its own key
in finally. No credential was printed. Gateway usage/audit records from the
requests remain normal operational effects; no real user identity/email was
submitted.

**13 public TLS checks passed**:

- 0.4/0.5/experimental 0.6 positive bundles: HTTP 200/TRUSTED.
- Duplicate and escaped duplicate keys, BOM, UTF16, invalid UTF8 and parser
  recursion: HTTP 400.
- Core depth limit: HTTP 200 with structured UNTRUSTED.
- Body over1MiB: HTTP 413.
- Missing authentication: HTTP402; invalid authentication: HTTP401.

This qualifies the current public verification/auth boundary. It does not
exercise paid settlement, the candidate through public routing, or independent
adoption. Candidate public checks must be repeated after any approved rollout.

## Remaining deployment gates

- Review the nullable ERC check-field compatibility correction.
- For production: back up the precise source/unit/environment and state with
  protected permissions; preserve signing identity and unrelated gateway
  configuration; apply a narrowly scoped delta; restart only receipt-api;
  verify exact runtime/package/source and public behavior; rollback on failure.
- Crystal ownership contract/enforcement, issuer policy, external registry/
  chain state and independent relying-agent action remain separate gates.
- No production install/restart, website merge or package publication occurred.

## Approved production deployment record

The user explicitly approved the reviewed hosted rollout after being told
that five inferred ERC check booleans become null and that Crystal ownership
enforcement remains a separate change.

Primary executed `deploy_reviewed_hosted.sh` against the reviewed upload.
It checked baseline/candidate source and wheel hashes, created protected
backup `/root/continuity-rollouts/20260930.7oCqdj6v` (root, mode 700), copied
source/unit/venv, stopped only receipt-api, backed up API state, installed the
verified wheel with `--no-index --no-deps`, verified all 14 installed Python
module hashes, installed the source/unit description, and started receipt-api.
An error trap could restore source/unit/venv; default rollback preserves live
state instead of discarding concurrent gateway usage/key changes. The state
copy is a protected backup, not a claim of an atomic cross-service snapshot.
The signing key compared byte-identical before/after.

Deployed package: **0.5.0**. API source SHA256:
`10f36afc7afa3571d44bd355ba82af77787a543f6d7cd50294bdbd1afc5d19b0`.
Canonical hosted kit now contains the same API source and service description;
its provision recipe/README are synchronized. `deploy-check.sh --quiet`
passed after synchronization. Only receipt-api was restarted; gateway, Crystal
data and ownership behavior were unchanged. No new package was published.

Post-deployment checks independently executed by the primary:

- **82 loopback HTTP checks passed** against the deployed process: all 71
  versioned vectors plus 11 raw-input/boundary cases. The empty-state assertion
  was explicitly omitted for the existing production state; the separate
  staging matrix above included it (83 checks).
- **13 authenticated public TLS checks passed again** against production,
  with a new temporary evaluation key removed afterward. No payment, cache
  or verification-receipt persistence was requested. Usage/audit remain.
- **4 live loopback ERC cases passed**: TRUSTED/ACCEPT,
  PROVISIONAL/NEEDS_EVIDENCE, structural UNTRUSTED/REJECT, and requested-task
  mismatch422/REJECT. All five corrected check fields were null and each
  returned Ed25519 attestation verified independently. No relay or registry
  call occurred; these attestations were not stored by the adapter.
- Live `/info` reported 0.5.0 and the reviewed caller-claim/ERC scope limits.
  Service remained active. Upload directory removed; protected backup retained.

The earlier production-install and authenticated-public gates are now closed
for this specific delta. Issuer policy, tenant ownership/migration, external
registry/chain state, website merge and independent relying-agent operation
remain separate open work.
