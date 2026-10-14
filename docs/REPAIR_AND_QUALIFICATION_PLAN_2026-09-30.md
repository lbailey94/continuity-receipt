# Repair and qualification plan — 2026-09-30

Baseline: clean main at 894eadc. Package 0.5.0 is published on PyPI and
crates.io; signed tag v0.5.0 points to ff00888. Both packages include spec
0.6 verification behavior, although the authority specification remains a
development draft. At the initial baseline the live API reported tooling 0.4.1 and accepted
specs 0.1–0.6; it now runs approved package 0.5.0 (deployment record below).
This plan records observed behavior separately from qualification claims.

## Execution and review

Luna implements one bounded phase at a time. The primary agent inspects the
diff and independently reruns meaningful regression checks before starting
the next phase. Preserve unrelated changes; use an isolated current-base
worktree for website edits. Do not rewrite published vectors or released
artifacts. Record local, preview, deployed, and independently qualified
states separately. Lucas authorized a Sangha handoff to mac-stranger for a second-host rehearsal; external adoption requires separate administrator evidence.

## Phase 1 — Consumer and qualification input boundaries

Owner: Luna; review: primary. Status: local implementation reviewed 2026-09-30.
Independent checks: 35 focused tests and 134 full Python tests passed;
documented CLI ACCEPT, absent-policy NEEDS_EVIDENCE, denied-issuer REJECT,
and 1,800-level direct input structured REJECT. Diff whitespace check passed.
Changes are committed locally at e03a268 on codex/receipt-phase-closure; no new package was published.

- Return structured failure for excessive recursion during direct API bundle
  canonicalization and adopter qualification; retain fail-closed outcomes.
- Freeze the existing consumer profile's spec and record vocabulary explicitly
  through 0.4. Do not silently broaden an existing policy contract.
- Provide a runnable policy example with fixture issuer IDs and correct
  `--policy` syntax. Keep assessments unsigned and local.
- Acceptance: focused regression suites, independent direct-API depth check,
  successful documented CLI example, missing-policy and denied-issuer cases.

## Phase 2 — Release and capability reconciliation

Owner: Luna after Phase 1 review; review: primary.
Status: local changes passed primary review on 2026-09-30. Independent focused
suite: 35 passed; all four tag manifests match current corpora (40/21/10/21).
Review corrected an erroneous draft claim that the 0.6 corpus was absent from
the 0.5.0 tag. Schema, corpus and implementation are all present in that tag;
the 0.6 specification remains experimental. No package acceptance changed.

- Reconcile README, roadmap, changelog, adopter guide, draft status, capability
  metadata, and research crosswalk wording against actual package behavior.
- State precisely: 0.5 packages published; 0.6 implementation shipped inside
  them; 0.6 specification is experimental and has no standalone 0.6 release.
  Document this exposure without changing verifier acceptance in this phase.
- Describe consumer assessment as Python-only and supporting 0.1–0.4.
- Prepare the missing GitHub release entry from the existing signed tag and
  registry artifacts; review its claims before publication. Do not rebuild
  or replace immutable package artifacts merely to fill the release-page gap.
- Add a checked-in capability matrix separating package version, spec support,
  consumer policy support, published corpora, and hosted observation date.
- Acceptance: all documented CLI examples exercised; claims match tagged
  sources, manifests, registry metadata, and live API; historical statements
  remain identified as historical. Decide any future 0.6 gating as an explicit
  compatibility change with Python/Rust parity coverage.

## Phase 3 — Browser inspector and settlement binding

Owner: Luna in isolated website worktree; review: primary.
Status: local implementation independently reviewed and rendered in
`/home/lucas/Desktop/WHITEMAGIC/whitemagic-site-receipt-review`, branch
`codex/receipt-explorer-hardening`, base d243935. Primary site checkout remains
untouched. Final 12 browser regressions, typecheck, offline surface and lint
checks passed under primary review; Luna reported the final production build
passed. Rendered EN/zh pages verified the published eight-receipt fixture,
and duplicate-key raw JSON was visibly rejected. The local proxy/browser also
verified a live public signed payment example against its requested tx and
stored digest. Website candidate commit: `30b03ec`; Vercel preview and explicit
production approval remain separate gates.
Draft PR: https://github.com/lbailey94/whitemagic-site-private/pull/28.
Vercel preview is READY and all applicable PR checks passed (the production
smoke job intentionally skips on PRs). Protected preview EN/zh HTML was
retrieved with authenticated `vercel curl` and checked for disclosure/input
controls. Browser rendering was checked locally; the preview browser redirects
to Vercel login, so preview browser interaction remains an explicit gate.
Preview: https://whitemagic-site-rjz9ngwke-lbailey94s-projects.vercel.app/verify.
Its payment API returned server_verified=true for the known public example;
stored/computed digests and signed `tx` matched the request. This verifies the
preview proxy contract, not on-chain finality or service delivery.

- Label signature inspection consistently in EN/zh without a core TRUSTED
  verdict. Show signature validity and chain status independently.
- Require first prev null, subsequent prev present and correctly bound under
  the core protocol's digest definition; check sequence and task consistency
  or clearly disclose any unimplemented checks.
- Validate signature algorithm and key/issuer binding; reject malformed keys.
- Bind queried transaction hash and returned signed transaction, and compare
  stored receipt digest to the recomputed digest. Remove unconditional
  `digestMatches: true` semantics.
- Respect raw JSON duplicate-member/canonicalization boundaries or reject
  unsupported inputs explicitly. Never imply browser parity with the complete
  verifier without the same conformance evidence.
- Use real, reproducible signed fixtures for examples and disclose their
  provenance. A payment signature validates the service's statement; on-chain
  transaction/amount/payee confirmation needs separate chain evidence.
- Acceptance: regressions for missing/wrong prev, wrong task/sequence,
  signature key mismatch, digest/transaction substitution, and valid receipts;
  site typecheck/build and rendered EN/zh preview. Merge/deployment is a
  separate reviewed step following the website's applicable instructions.

## Phase 4 — Hosted API source, semantics, and staging

Owner: Luna prepares source changes and tests; primary reviews and operates.
Preparation and offline candidate review are complete. Canonical source located at
`/home/lucas/Desktop/WHITEMAGIC/planning/private/hosted-kit`.
Primary ran `bash deploy-check.sh --quiet` successfully on 2026-09-30.
Independent live loopback `/verify` checks: published 0.4 agreement vector,
0.5 carried-agreement vector and experimental 0.6 authority vector each
returned HTTP 200/TRUSTED; duplicate object members returned HTTP 400.
No cache or receipt persistence was requested. The primary subsequently
qualified authenticated public POST with 13 bounded checks and removed its
temporary evaluation key; normal gateway usage/audit records remain.
See `../ops/HOSTED_STAGING_2026-09-30.md` for source/package/hardened staging
and rollback evidence and the remaining deployment gates.
Preparation report reviewed. A minimal offline notarization/claim correction
patch and isolated regression harness are delegated as Phase 4A; canonical
source and live host were unchanged at that preparation checkpoint. Runtime package pinning, ERC acceptance
policy, tenant ownership and staging are later explicit gates.
Phase 4A local candidate passed primary diff/hash review and independent
reconstruction/testing: 4 tests passed, including 23 negative/boundary cases,
no-write checks and actual stored/retrieved Ed25519 verification. Base hash
`f3daa358f055ae1ac4667629c2a73ecd6df694684ad778c0a2a8410ccd72c134`;
candidate `aa238c2fdfaf1419384d0e879a94ecefbbb0bceb1b8d9f6c02693d42c6c391c9`.
Regular pytest: 134 passed, 4 standalone candidate cases explicitly skipped,
10 subtests passed. The explicit candidate command executes all 4 cases.
Primary also reconstructed the gateway test-only refresh and independently
ran 15/15 x402 checks plus 20/20 payment-receipt checks in disposable isolated
kits. Facilitator/upstream were loopback stubs and no real payment was made.
Canonical hosted source and live state were unchanged at that offline checkpoint.

- Locate the canonical deploy source and compare it with current live code
  before edits. Preserve strict JSON hardening and unrelated gateway work.
- Pin the tested verifier package; reconcile reported version, supported
  specs, conformance counts, endpoint and persistence/privacy descriptions.
- Qualify `/verify` through both loopback and the authenticated public path,
  including UTF-8, duplicates, BOM/UTF-16, depth/size boundaries, and spec
  0.4/0.5/0.6 inputs. Separate endpoint authentication/payment checks from
  verification correctness.
- Check gateway nonce replay, ambiguous settlement, paid-response binding,
  and canonical analytics-route coverage against actual deployed behavior;
  distinguish payment settlement, returned payload, and receipt storage.
- Notarization: describe signatures over caller-supplied digest/claims;
  validate all signed fields and canonicalization failures (including floats)
  before persistence. No claim of observed context or execution.
- ERC-8004 adapter: document Ed25519 statement and EVM relay limitations;
  separate protocol validity, task binding, local issuer policy, and authority.
  Replace inferred anchor/policy success flags with evidence-backed values.
  Define any relying-party acceptance contract before changing outcomes.
- Crystal lane: inventory storage, retrieval, tenant/auth boundaries and
  encryption claims; use adversarial access/substitution tests before claiming
  isolation. Health checks do not qualify persistence or tenancy.
- Acceptance: offline handler tests, reviewed deployment diff, staging smoke,
  backup/rollback rehearsal, then live version and authenticated behavior
  checks. Record unavailable credentials or staging as open gates, not PASS.

Phase4B evidence-field corrections were independently reviewed and tested.
The composed candidate with published package 0.5.0 passed 83 HTTP checks under
a transient systemd unit on the VPS, plus the four ERC candidate tests. A
disposable source/package rollback rehearsal passed. All staging processes and
remote staging directories were removed before approved production rollout.
Crystal baseline characterization and a versioned ownership contract are
prepared and independently reviewed. The opt-in local test reproduced
unauthenticated ciphertext/lineage disclosure for a known locator, while
outsider decryption failed. Contract enforcement/migration are unimplemented.
The user explicitly approved the API/package/ERC production delta. Primary
deployed it after a protected source/unit/venv/state backup, preserved the
signing key, and restarted only receipt-api. Package0.5.0/module hashes and
source hash matched;82 live loopback cases, 13 public cases and 4 live ERC
cases passed. Canonical kit synchronized; deploy-check clean. Upload/staging
directories removed and protected rollback backup retained. Crystal ownership
enforcement/migration remains a separate unimplemented change.

## Phase 5 — Independent relying-agent qualification

Owner: primary coordinates; Luna prepares harness and instructions.
Prepared `INDEPENDENT_RELYING_AGENT_PACKET.md` and a bounded eight-case local
demo; primary ran it against both checkout and published0.5.0 wheel bytes.
All expected consumer outcomes and refusal classifications matched. This is
preparation only: no external operator was contacted or action executed.

- Add a separately versioned consumer policy profile for 0.5 if the pilot
  requires it, retaining old profile behavior and explicitly limiting claims
  about runner/state evidence. Do not infer authority from record presence.
- Prepare an external-operator capture packet with raw bytes, source/package
  pins, snapshot artifacts, explicit policy and expected action/refusal.
- Exercise ACCEPT, denied issuer/spec, missing evidence, replay/freshness,
  interrupted recovery, and altered state. Include a failed case in the report.
- Evidence must show a relying decision controlling a real next action on an
  independently administered host. Local fixture/same-host PASS and paid
  calls do not close this gate.
- External participation is required to finish; do not fabricate independence.

## Phase 6 — Standards composition and closure

- Read AADP bound-permit sections 6–7 and update the crosswalk against exact
  draft revisions. AER1 probe proves only the checks actually performed.
  Primary read sections 6–7 of revision 00 on 2026-09-30: issuer scope is
  recipient-owned; time-bounded currentness leaves a declared revocation
  window; status-checked mode needs current evidence and explicit treatment
  of unavailable status. Crosswalk and human-review-only W3C brief updated against current AER1-05,
  AADP bound-permit-00 and SCITT Continuity Receipts-01, then source-reviewed
  by the primary. No correspondence sent; no wire/runtime semantics added.
- Resolve external-evidence-reference digest scope and whether unresolved
  evidence affects verdicts before implementing wire changes. Keep compute
  SLA/attestation extensions demand-gated.
- Refresh the W3C brief for the Oct 6 agenda. Prepare correspondence for human
  review; no automatic sending.
- Final acceptance: full Python/Rust suites, frozen and candidate parity,
  verification-receipt and hostile-input checks; clean owned worktrees; source
  and deployment pins; reconciled public claims; a closure ledger listing each
  defect, regression evidence, and remaining external gate.

## Closure rule

Code repair, package publication, deployment, and independent adoption are
different milestones. This plan is complete only when required evidence is
recorded, or a remaining external prerequisite is clearly reported as open.

## Phase 3 production closure — 2026-09-30

Lucas approved PR #28 merge and deployment. Squash merge 740c5b6a6d75c413ecd2b1dfaa2fedc732d26b8e deployed to Vercel production READY at https://www.whitemagic.dev/verify. Primary production browser checks in EN and zh passed the live signed payment example, the eight-receipt bundle (all signatures valid, structure valid, chain intact), and duplicate-member rejection. Screenshots are in ops/review-evidence/explorer-production-2026-09-30.jpg and explorer-production-zh-2026-09-30.jpg. These signature checks do not establish chain settlement or delivery. The protected preview browser login limitation is superseded by these production rendered checks.

Core independent closure checks: 43 Rust tests; Python/Rust core vectors 40/40, 21/21, 10/10; verification-receipt vectors 21/21; hostile input 208 cases and 416 runs with zero failures or parity mismatches.
