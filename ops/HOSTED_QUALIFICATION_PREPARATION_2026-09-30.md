# Hosted API qualification preparation — 2026-09-30

## Scope and evidence boundary

This is a read-only source audit for Phase 4. The canonical deploy source is
`/home/lucas/Desktop/WHITEMAGIC/planning/private/hosted-kit`; no source-kit files
were changed. The primary agent reports that `bash deploy-check.sh --quiet`
completed successfully and all files in that script's manifest match the
hosted copies. That establishes parity for the listed files at that check; it
does not attest to the live Python environment's installed package, exercise
authenticated public paths, or qualify runtime behavior. I did not run tests,
connect to the host, inspect credential contents, or make live requests.

No applicable `AGENTS.md` files were present in either checkout's ancestor
directories. The hosted-kit directory is not a Git worktree. Existing local
changes in the continuity-receipt checkout were left untouched.

## Findings from inspected source

### 1. Runtime package pin and advertised capability disagree

- `provision.sh` installs `continuity-receipt==0.4.0` at line 127. `README.md`
  also documents a 0.4.0 environment at line 42.
- The Phase 4 plan records that the currently observed live API reports
  verifier 0.4.1 and specs 0.1–0.6, while the 0.5.0 PyPI and crates.io
  packages contain 0.6 implementation behavior. This observed state is newer
  than the checked-in provisioning pin.
- `receipt-api.py:723-729` constructs `/info`'s verifier version and supported
  specs from the imported package at runtime. This is useful dynamic
  reporting, but doesn't pin deployment reproducibility.
- `deploy-check.sh` compares `receipt-api.py`, corpus files, docs, and service
  definitions; it does not compare the installed venv package inventory.

**Patch recommendation:** pin the intended, reviewed verifier build in the
canonical provisioning/deployment recipe and README; record the package
version and immutable distribution hashes in a machine-readable deployment
lock/capability record. Keep package release, supported spec range, consumer
profile range, corpus revisions, and observation time as separate fields.
Add a deployment check that queries package metadata from the service venv
without printing environment secrets. Do not change protocol acceptance in
this metadata repair.

### 2. `/info` and `RECEIPT_API.md` understate persistence and overstate isolation

- `/info` says verification is stateless (accurate for `/verify`'s core
  operation), but its privacy field at `receipt-api.py:822` says persisted
  storage is only revocations, anchors, and signing key. The same handler
  exposes persistent payment receipts, notarizations, and crystal storage;
  those paths are listed in the endpoint table at lines 737–746.
- `RECEIPT_API.md:220-234` repeats the narrower storage description. Earlier
  sections document settlement receipt and crystal persistence, so the same
  page contradicts itself.
- `RECEIPT_API.md:187-197` calls crystals “Zero-Knowledge” and describes “dark
  tenant silos.” `/info` calls isolation “per-tenant filesystem silos” at
  `receipt-api.py:809`. `TenantCrystalStore` partitions files under a
  directory derived from the caller-supplied tenant hash (`:237-258`); reads
  accept a caller-selected tenant hash from the header, query, or URL
  (`:1597-1659`). The shown server code contains no read-side ownership check
  connecting that selector to an authenticated principal. A tenant hash is
  therefore a locator, not proof of tenant authorization. Existing tests
  prove a wrong, empty tenant directory returns 404, which does not test
  another tenant's valid identifier being accessed.
- Client-side encryption code and unit tests establish that the client can
  seal/unseal and detect tampering with a changed ciphertext, AAD tenant, or
  key. They do not establish authorized tenant isolation, server-side
  non-observation across the full request path, durable persistence, backup
  recovery, or encrypted storage at rest.

**Patch recommendation:** make `/info` and docs enumerate each persistent
class and its access/retention model: revocations, anchors, payment receipts,
notarizations, crystals, signing key, and opt-in in-memory verdict cache.
Keep “verification of submitted bundles is stateless” scoped to that endpoint.
For crystals, either add and test an authenticated tenant ownership binding
before claiming isolation, or describe reads as keyless and tenant-hash
addressed, with confidentiality depending on client-held keys and identifier
secrecy. Remove “Zero-Knowledge” and “dark silos” unless separately defined
and demonstrated.

### 3. Notarization attests to supplied claims, and canonicalization errors need handling

- `/notarize` accepts caller-supplied `context_digest` and/or `prompt_hash`
  (`receipt-api.py:1117-1147`), copies optional `action`, `model`, `agent_id`,
  and metadata into the statement (`:1166-1174`), signs it, then stores it by
  digest (`:1176-1195`). It does not receive or observe the underlying prompt,
  context, action, model invocation, or agent execution.
- `metadata` permits float values (`:1170-1174`), then calls
  `canonical_bytes` without catching its `ValueError` (`:1176`). The repository
  canonicalization routine rejects floats. Thus this input can escape the
  route's invalid-JSON handling and fail as an unstructured server error
  before persistence. Python's default JSON parser also accepts non-finite
  numeric constants unless explicitly rejected.
- Digest values are coerced through `str(...)` instead of requiring JSON
  strings (`:1127-1147`); optional descriptive fields are also coerced. The
  current happy-path test proves a caller can receive a signed statement and
  later verify its digest/signature, not that the service observed the
  represented event.
- `GET /notarize/<digest>` is keyless; both `/info` and docs should state the
  resulting public retrieval and persistence behavior.

**Patch recommendation:** describe the result as an Ed25519 service
attestation over caller-supplied digest and claims. Validate types and exact
field constraints before signing. Reject floats/non-finite values at the raw
JSON/canonical boundary with structured 400 responses, and catch any
canonicalization failure before key use or writes. Test that every rejected
input leaves the notarization directory unchanged. Retain strict UTF-8 and
duplicate-member rejection.

### 4. ERC-8004 outcome is core verdict plus task binding, not a relying-party policy decision

- The adapter calls `verify_bundle(..., require_anchor=False)` and derives
  outcome from the core verdict plus `_check_task_binding`
  (`receipt-api.py:1452-1471`). Task matching accepts several bundle fields
  and receipt hashes (`:298-...`); it does not evaluate an explicit caller or
  relying-party issuer allowlist/profile.
- The response's `policy_compliant` is set to `cr_verdict != "UNTRUSTED"`
  (`:1494-1505`), which is an inference from the core verdict, not a separate
  policy evaluation. `anchors_verified` is inferred from absence of any
  `provisional_reasons`, although the core call explicitly does not require
  anchors. A lack of provisional reasons is not direct anchor evidence.
- Other boolean “checks” are also coarse string searches over error text;
  they should not be represented as independent checks without defining and
  testing their semantics.
- The existing `tests/wedge_ab_tests.sh` checks one passing fixture and one
  task mismatch, but does not cover relying-party issuer policy, anchor
  evidence, or the interpretation of these flags.

**Patch recommendation:** define the relying-party acceptance contract before
changing outcomes. Keep core protocol validity, task binding, explicit local
issuer policy, and external authority as distinct results. Replace inferred
success flags with tri-state evidence (`checked`, `not_checked`, `failed`) or
evidence references, especially for anchors and policy. Add positive and
negative issuer-policy and anchor-required cases, and ensure a valid core
signature with a denied issuer cannot produce policy success. Do not imply
that an unsigned local policy decision authorizes execution.

### 5. Existing tests cover fixtures but are unsafe to run in place

- `tests/notarize_tests.sh` binds port 18995, deletes/recreates `tests/not-state`,
  and writes response/log artifacts in `tests/` (`:2-18`). Its crypto check
  validates the generated signature but has no float, NaN, strict duplicate
  input, or no-write-on-rejection case.
- `tests/crystal_tests.py` has three useful isolated client cryptography unit
  cases (`TestCrystalClient`, `:19-83`). Its integration class starts on
  18995, uses a temporary state directory, but performs keyless retrieval by
  tenant locator; it has no cross-tenant access test involving a valid
  stored crystal (`:85-168`).
- `tests/wedge_ab_tests.sh` starts an isolated local server on port 18991 and
  cleans its `wedge_test_state` directory on exit, but removes that path
  before starting (`:9-24`). It tests a fabricated successful bundle and
  task mismatch; crystal wrong-tenant coverage checks a nonexistent tenant
  tree only (`:173-177`).
- `tests/payment_receipts_tests.sh` covers mocked local settlement,
  unsuccessful/ambiguous facilitator outcomes, a large paid response,
  nonce race, and receipt digest/signature (`:1-4`, `:16-64`, `:85-176`). It
  begins with `rm -rf pr-state pr-receipts` (`:9`) and these paths already
  exist in the source kit, so it was not run. The existing payment receipt
  fixture directory also contains a token file; its contents were not read.
- `tests/x402_tests.sh` uses localhost stubs but removes and recreates
  `state-x` and `state-d` (`:6-8`, `:58-72`); not run. Its cases cover failed
  payment parsing/replay telemetry and upstream-down response, not successful
  settlement proof or public verifier correctness.
- No Phase 4 tests were executed in this preparation. Existing test artifacts
  and credential-bearing fixture paths were left unchanged.

**Patch recommendation:** move each destructive test's state/output under a
fresh `mktemp -d` root with cleanup traps and dynamically allocated loopback
ports. Make server unit tests call the handler/service through injected
temporary state where possible. Add raw-body matrices to `/verify` and
`/notarize`: UTF-8, duplicate keys (top-level and nested), BOM, UTF-16,
malformed UTF-8, maximum and over-limit body sizes, excessive nesting, and
spec 0.4/0.5/0.6. Assert structured status/verdict and no unintended disk
writes. For crystals, store tenant A and test all B read/lineage routes with
valid A identifiers under the chosen authorization contract. Preserve
payment receipts' mocked facilitator tests in isolated temp roots; these
remain gateway tests and do not replace verifier endpoint qualification.

## Recommended Phase 4 implementation slice

1. Add a tested package pin/capability record and deployment-vetting check;
   reconcile `provision.sh`, README, `/info`, and API docs with the actual
   selected package, preserving 0.5.0 package / 0.6 experimental-spec
   distinctions.
2. Correct `/info` and `RECEIPT_API.md` persistence/privacy and crystal
   access-control claims. Keep verification correctness and storage claims
   separate.
3. Harden notarization input types and canonicalization failures; revise the
   description to caller-supplied claims and add signature/no-write failure
   tests.
4. Before modifying ERC outcome semantics, document the relying-party policy
   contract; then replace derived flags and add targeted tests.
5. Add handler-level endpoint tests while preserving strict raw JSON parsing.
   Rework scripts to use isolated temporary directories before executing the
   broader local suites.

## Test and external qualification sequence for primary review

### Offline/local, after patch review

- Test `/info` against package import metadata, supported specs, loaded corpus
  manifests/counts/digests, endpoint map, and storage/privacy claims.
- Test version pin installation in a fresh temporary venv with network-free
  wheel/hash verification where artifacts are available; record exact source
  and installed distribution hashes.
- Run notarization negative/positive handler matrix, verify Ed25519 statement
  and recomputed digest, assert failed canonicalization has no persisted file.
- Run ERC adapter matrix for trusted/invalid signatures, mismatched task,
  required/missing anchors, explicit allowed/denied issuer policy, and
  not-checked evidence reporting.
- Run crystal crypto unit suite and temp-service storage/retrieval/lineage,
  valid cross-tenant attempts, substitution/tamper, size, and encryption
  envelope checks. These still cannot establish external tenant isolation
  without a real auth boundary and hostile principal test.
- Run payment receipt and x402 gateway tests only after converting their
  state/output roots to fresh temp directories. Treat mocked facilitator
  settlement as local code-path evidence only.
- Run strict raw JSON/size/depth cases at the HTTP boundary and Python/Rust
  verifier regressions for 0.4/0.5/0.6. Keep verifier correctness distinct
  from gateway/authentication and payment.

### Staging / public prerequisites (not completed here)

- A reviewed deployment diff, backup and rollback rehearsal, and a staging
  slot with the intended pinned package and isolated state directory.
- Staging loopback `/verify` and `/notarize` boundary matrices; verify
  0.4/0.5/0.6 examples and strict duplicate/BOM/UTF-16/depth/size handling.
- Authenticated public `/verify` and related endpoint checks require the
  primary operator's authorized test credential and must separately record
  auth/payment status from verifier outcomes. Do not put credentials in this
  report or shell output.
- A real paid call is not required to establish core verification correctness.
  If payment behavior is separately checked, distinguish facilitator
  settlement, returned `PAYMENT-RESPONSE`, upstream payload delivery, and
  persisted payment receipt. Check nonce replay, concurrent reuse, ambiguous
  settlement, and analytics route coverage from controlled staging evidence.
- Live `/info`, version, authentication, and storage checks require a later
  explicit operation by the primary. A successful deploy check or health
  endpoint alone is not qualification.

## Execution ledger

| Item | State | Evidence |
|---|---|---|
| Repair plan read | Inspected | `docs/REPAIR_AND_QUALIFICATION_PLAN_2026-09-30.md` |
| Canonical hosted source | Inspected | `/home/lucas/Desktop/WHITEMAGIC/planning/private/hosted-kit/receipt-api.py`, provisioning, docs, and named tests |
| Hosted source/live manifest parity | Reported run by primary; PASS | Primary reports `bash deploy-check.sh --quiet` succeeded; manifest is source-file scoped |
| Local test suites in this preparation | Not run | Existing destructive output/state paths; no regression result claimed |
| Public authenticated API or staging | Not run | Requires primary-operated credentials/staging and controlled deployment procedure |
| Hosted-kit source edits/deployment | None | Read-only audit only |

## Phase 4A offline candidate (primary review complete)

The following are a separate reviewable candidate based on the exact canonical
source hash below. They do not modify hosted-kit source or establish deployed
behavior.

- Candidate patch: `ops/hosted-api-qualification.patch`.
- Candidate regression harness: `ops/test_hosted_api_candidate.py`.
- Base `receipt-api.py` SHA-256:
  `f3daa358f055ae1ac4667629c2a73ecd6df694684ad778c0a2a8410ccd72c134`.
- Candidate `receipt-api.py` SHA-256:
  `aa238c2fdfaf1419384d0e879a94ecefbbb0bceb1b8d9f6c02693d42c6c391c9`.
- The unified patch applies with `patch -p1` against a fresh copy of the base;
  `patch --dry-run` completed successfully.

### Candidate changes

- `/notarize` now allows only its documented fields and validates digest,
  optional claim, and metadata types and bounds without coercing or
  truncating. Metadata accepts strings, integers, booleans, and null; it
  rejects floats, non-finite JSON numbers, nested values, non-ASCII or
  overlong keys, integers outside ±(2^53−1), oversized strings, too many
  entries, and unknown fields.
  Original JSON duplicate-key and UTF-8 decoding behavior remains, with
  non-finite constants explicitly rejected.
- Caller-derived notarization data is canonicalized before
  `signing_identity()` can create the service key. Canonicalization failures
  return structured HTTP 400 before key creation or persistence.
- `/info`, `GET /notarize`, `GET /crystals`, and the stored notarization note
  describe caller-supplied claims, keyless tenant-hash crystal addressing,
  and persistence accurately. The verifier compatibility text points to
  runtime `/info` metadata instead of calling 0.4.0 current.
- `/info` labels ERC issuer policy as unevaluated and anchors as not required
  for the adapter outcome. ERC outcomes and response/storage/auth wire
  behavior are unchanged; the response's existing derived `checks` fields
  still need a separately reviewed contract and repair.
- The package provisioning pin is untouched. Reconciling it remains a
  separate follow-up after the primary chooses the tested deployment package.

### Candidate test evidence

The explicit command
`python3 ops/test_hosted_api_candidate.py --source /tmp/hosted-api-phase4a.Bei3Kr/receipt-api.py`
ran against the temporary candidate copy on an ephemeral loopback port with a
fresh temporary `WM_RECEIPT_API_STATE` directory: **4 tests passed**. The
negative test includes **23 input scenarios** covering floats, NaN/Infinity,
duplicate keys, BOM, UTF-16, deep nesting, digest/claim types and bounds,
metadata shape/key/value/count limits and beyond-safe integers, an escaped
lone surrogate, unknown fields, exactly-maximum-size valid JSON returning
structured `missing_required_digest` 400, and a declared over-limit body
returning 413. Rejected requests assert that no key or receipt was written.
The positive path accepts string/int/bool/null metadata, stores and retrieves
a receipt, and verifies its digest and Ed25519 signature using the actual
`continuity_receipt` crypto implementation. The harness restores the caller's
prior `WM_RECEIPT_API_STATE` environment value after cleanup.

Pytest collection check for the standalone test file without `--source`:
**4 skipped** with the explicit standalone-harness message; ordinary pytest
collection therefore has no setup error. Running the script directly without
`--source` exits **2** with argparse's required-option error. These checks
were rerun after the final candidate edit.

At the Phase 4A handoff, the x402/payment scripts had not yet been run; the
candidate adds no gateway or payment changes. No authenticated public request,
staging exercise, deployment, or production write was performed. Primary
independent review and the Phase 4 external qualification gates above remain
open.

## Phase 4 gateway regression follow-up

The primary independently reviewed and reconstructed the Phase 4A candidate:
the 4 harness tests and 23 negative/boundary scenarios passed, the candidate
hash is `aa238c2fdfaf1419384d0e879a94ecefbbb0bceb1b8d9f6c02693d42c6c391c9`,
and the canonical hosted source remained unchanged. The offline candidate
patch remains distinct from the primary's live-environment observation.

### Primary-reported live environment observation

- The live venv distribution and imported module both report `0.4.1`; live
  `/info` reports supported specs `0.1`–`0.6`.
- The primary reports these deployed module files match the current
  continuity-receipt checkout by SHA-256:
  - `records.py`: `58b7eac906ae4bf13818d01373f325f4480007f6ffe9e2ef1f8bab95108e8041`
  - `verify.py`: `15676162a93171add16a1d5d844a0829279482e9876b4aa1da7ce010d6aea771`
  - `canon.py`: `ac8770c2a5134bd74ebcf2bfb086ec80d33b58fa09e67885f1450907c56b8851`
- This is a primary-reported observation, not a fresh check by this phase.
  It covers these three files only and does not prove whole-package
  provenance, a reproducible live venv, or a deployment pin.

### Local gateway/payment suites

Before execution, the selected scripts were inspected: their facilitator,
upstream, and API URLs target loopback stubs only. They were run from a fresh
temporary kit containing allowlisted `authd.py`, `stub_upstream.py`, test
scripts, `crystal_client.py`, and the Phase 4A candidate as `receipt-api.py`.
The scripts' destructive state paths were confined to that temporary copy;
no canonical test state or fixture credentials were copied. The payment test
generated its internal test token there. Child-process cleanup traps were
added only to those temporary script copies.

- `tests/payment_receipts_tests.sh`: **20 passed, 0 failed**. This includes
  local mocked successful/failed/ambiguous settlement, settlement receipt
  storage and offline signature verification, large response delivery,
  nonce race, and missing internal-token rejection. The facilitator and
  upstream were local stubs; this is not real payment settlement evidence.
- `tests/x402_tests.sh`: **12 passed, 1 failed**. The mismatch was
  `two free paths (got '3' want '2')`; challenge shape, audit/fingerprinting
  for invalid/missing/replayed payment data, discovery audit, and dead-upstream
  502 checks passed. Investigation confirmed this was a stale test assertion:
  `authd.py:398-454` emits `trial`, `evaluation_key`, and `faucet` paths when
  the trial option is enabled. No gateway behavior was changed.
- `tests/crystal_tests.py TestCrystalClient`: **3 passed**. This exercises
  local seal/unseal and tamper checks only, not service tenancy or persistence.
- All three suites ran against loopback services in the temp kit. No public
  network endpoints were invoked and no real paid call was made. Temporary
  test processes were stopped after each suite.

### x402 assertion refresh

Prepared [hosted-gateway-test-refresh.patch](hosted-gateway-test-refresh.patch)
against only `tests/x402_tests.sh`; its base SHA-256 is
`4f645d5f08f4964be86589b205cb3663d7d0eae0aa418e1cda5e36c9e4da8fb4` and its
candidate SHA-256 is `e14e635d2ad9cc0c758cb987e4f4f18a07b203b430b7823ecd97d71142a472c5`.
The stale exact count was replaced with required `trial`, `evaluation_key`,
and `faucet` types plus a uniqueness check; the faucet assertion checks
`https://mcp.whitemagic.dev/faucet` and `account_required: false`. A dry run
applied the patch to a fresh temporary kit.

Rerunning the refreshed x402 suite in an isolated temp kit produced **15
passed, 0 failed**. It used loopback upstream/authd only and made no public
network call. The temporary kit and generated state were removed after the
suite; listeners were confirmed stopped. The payment receipt suite was not
rerun because this patch changes only the x402 test assertion and does not
touch shared runtime code; its earlier 20/20 result remains unchanged.

### Remaining Phase 4 gates

- Choose and pin the intended deployment package, then qualify the live venv
  package provenance. The source provisioning recipe still carries its older
  pin; the three matching module hashes do not close that gate.
- Run reviewed staging deployment, backup/rollback rehearsal, raw-input and
  spec 0.4/0.5/0.6 matrices, then authenticated public endpoint checks with
  the primary operator's credential. Separate authentication/payment status
  from verifier correctness; no such credentials or public requests were
  used here.
- Define and enforce crystal tenant ownership before claiming tenant
  isolation; adversarial reads using a different tenant's valid crystal ID
  remain untested.
- Define relying-party issuer policy and anchor evidence semantics for
  ERC-8004. `/info` labels the current gaps, while the adapter's outcome and
  existing derived response `checks` remain unchanged in this candidate.
- Independent relying-agent action on another operator's host, adoption, and
  production behavior remain separate later gates.

## Primary independent regression review — 2026-09-30

The primary reconstructed both patches from their recorded canonical base
hashes in fresh disposable directories and inspected the resulting sources.
The explicit hosted API harness passed all 4 cases (23 negative/boundary
inputs plus no-write and persisted Ed25519 verification checks).

A separate primary run of the refreshed x402 script passed **15/15**. A
separate primary payment-receipt run passed **20/20**, including ambiguous
settlement, withholding failed paid responses, concurrent nonce reuse,
internal-token enforcement and full 86 KB response delivery. These used
loopback facilitator/upstream stubs, generated temporary credentials/state,
and process-group cleanup; no real payment or public paid call occurred.
Canonical API and x402 script hashes were rechecked unchanged afterward.

The 3 crystal client crypto checks above remain delegate-reported. They do
not establish hosted persistence, authorization or tenant isolation. Both
patches remain unapplied to canonical source and the VPS. Staging, package
provenance, authenticated public POST and rollback qualification remain open.
