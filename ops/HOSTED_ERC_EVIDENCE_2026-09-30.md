# Hosted ERC adapter evidence semantics — Phase 4B

Current status: revised candidate reviewed and deployed after explicit human approval. The preparation sections below describe the earlier offline handoff; the deployment update records current state.

## Artifacts and reconstruction

- Offline patch: [`hosted-erc-evidence.patch`](/home/lucas/Desktop/continuity-receipt/ops/hosted-erc-evidence.patch)
- Isolated regression harness: [`test_hosted_erc_candidate.py`](/home/lucas/Desktop/continuity-receipt/ops/test_hosted_erc_candidate.py)
- Patch target is `receipt-api.py` after Phase 4A's `hosted-api-qualification.patch`.
- Phase 4A candidate base SHA-256: `aa238c2fdfaf1419384d0e879a94ecefbbb0bceb1b8d9f6c02693d42c6c391c9`.
- Phase 4B candidate SHA-256: `10f36afc7afa3571d44bd355ba82af77787a543f6d7cd50294bdbd1afc5d19b0`.
- Canonical hosted source SHA-256 was rechecked as `f3daa358f055ae1ac4667629c2a73ecd6df694684ad778c0a2a8410ccd72c134`.
- Reconstructed the Phase 4A candidate from canonical source plus its patch; Phase 4A base hash matched. Applied this patch with `patch --dry-run` and then to a disposable copy; resulting hash matched the Phase 4B candidate hash.

## Change scope and compatibility

The adapter's acceptance/outcome mapping and task binding behavior are unchanged: matching TRUSTED remains ACCEPT (1), PROVISIONAL remains NEEDS_EVIDENCE (2), and UNTRUSTED remains REJECT (0); a task mismatch remains HTTP 422 / REJECT. `checks.chain_integrity`, `checks.signatures_valid`, `checks.policy_compliant`, `checks.resource_caps_respected`, and `checks.anchors_verified` remain present but now return JSON `null`; none is inferred from missing error text. New fields mark issuer policy unevaluated and anchors unnecessary for the adapter outcome. `termination_present` is now limited to a list item whose `type` is exactly `task.termination`; malformed/non-list receipts cannot throw during this check. `evaluation_scope` also says individual per-check outcomes are not reported. Clients that require any of these five fields to be booleans need to tolerate `null`; this is an intentional correction to the evidence meaning, while preserving keys and outcome values.

The descriptions state that no relying-party issuer policy is evaluated; anchors are not required for the adapter outcome and no independent anchor status is reported (the core verifier may inspect supplied anchor evidence); and the returned statement uses an Ed25519 signature over a canonical JSON message. The service does not produce an EVM-compatible signature or relay the statement onchain. This patch does not change ERC wire outcome values, issuer policy, anchor rules, signature format, or storage/authentication behavior.

## Tests executed

Command: `python3 ops/test_hosted_erc_candidate.py --source /tmp/hosted-erc-phase4b.yDH88A/receipt-api.py`

Result: **4 tests passed**. The harness started the candidate handler on an ephemeral `127.0.0.1` port with a fresh temporary `WM_RECEIPT_API_STATE`, and restored the prior environment setting on cleanup. It used published signed vectors as read-only fixtures and checked cryptographic verification of each returned Ed25519 attestation:

- `01_happy_minimal.json`: core TRUSTED; ACCEPT (1).
- `07_redacted_no_disclosure.json`: core PROVISIONAL; NEEDS_EVIDENCE (2).
- `04_missing_termination.json`: core UNTRUSTED without a bad-signature error; REJECT (0).
- A TRUSTED bundle with a mismatched requested task: HTTP 422, task mismatch, REJECT (0).
- For all result cases, per-check chain integrity, signature, resource cap, issuer policy, and anchor status are `null`, not inferred successes. The harness checks the signed response attestation.
- Malformed `receipts` as a string, a list containing a non-object, a shape-invalid receipt, and a nesting-depth failure all returned without HTTP 500 and did not claim per-check success; malformed receipt containers do not produce a false termination-present result.

Collection-safety check: `pytest -q ops/test_hosted_erc_candidate.py` returned **4 skipped** because no candidate source was supplied. Direct invocation without `--source` exited **2** with argparse's required-option error. The tests were not run against production or the canonical hosted source.

## Remaining qualification boundaries

This candidate does not establish that a relying party's issuer policy passes, nor that an external anchor was verified; it explicitly reports per-check anchor status as unknown and anchors as unnecessary for the adapter outcome. It also does not validate external registry/chain state or perform an EVM signature or relay. Separate staging authorization and service-owner review are needed before any live change. Package version pinning/provenance, authenticated tenant isolation for the keyless tenant-hash Crystal locator, and issuer-policy/anchor requirements remain follow-up gates. No credentials, authenticated public actions, deployment, or canonical source mutation were used in this phase.

## Primary review and VPS staging

The primary identified additional inferred success flags after the first
candidate; the revised patch sets all five unevidenced check fields to null
and guards malformed receipt containers. Primary independently reconstructed
the revised candidate and ran all four harness cases on the VPS using the
PyPI-hash-verified 0.5.0 wheel and disposable state. All passed. The composed
API also passed the 83-check HTTP matrix under a transient systemd unit with
the production service hardening settings. See HOSTED_STAGING_2026-09-30.md.
Canonical source and live receipt-api remain unchanged pending rollout review.

## Deployment update

After explicit user approval, this reviewed patch was deployed with Phase4A
and published package 0.5.0. All 4 live loopback ERC cases passed with valid
Ed25519 signatures and null per-check fields. See HOSTED_STAGING_2026-09-30.md
for the approved delta, protected backup and post-deployment evidence. The
preparation-only status above describes the earlier handoff.
