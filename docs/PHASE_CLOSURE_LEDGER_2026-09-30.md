# Phase closure ledger — 2026-09-30

**Status:** local closure ledger assembled 2026-09-30 from
`REPAIR_AND_QUALIFICATION_PLAN_2026-09-30.md` and the linked evidence reports.
Per the plan's closure rule, code repair, package publication, deployment, and
independent adoption stay separate milestones: an item is closed only where
evidence is recorded, otherwise the remaining external prerequisite is
explicitly listed as open. This ledger adds no new claims and does not replace
the linked evidence.

Assembly note: this file was completed by opencode after the Codex threads
were cut off by usage limits mid-task. Entries from the Phase 4C candidate and
the Phase 6 document updates (external-evidence design note, this ledger) are
newer than the primary's last review pass and are marked review pending.

## Milestone separation

| Milestone | Current state |
| --- | --- |
| Code repair (local branch `codex/receipt-phase-closure`) | Phases 1–4B local changes reviewed; Phase 4C candidate prepared locally (review pending); Phase 6 documents updated (review pending) |
| Package publication | `0.5.0` on PyPI and crates.io; signed tag `v0.5.0` → `ff00888`. No package publication resulted from Phases 1–6; published wheel bytes predate the Phase 1–4 local changes |
| Deployment | Reviewed Phase 4A+4B hosted delta deployed (package 0.5.0, API source `10f36afc…`), post-deployment checks passed, protected rollback backup retained. Website production merge `740c5b6a` (PR #28) deployed READY |
| Independent adoption | **Open.** No external relying-agent run and no second-host capture has been produced |

## Phase 1 — Consumer and qualification input boundaries

Local implementation reviewed 2026-09-30; committed at `e03a268`.

| Defect / theme | Regression evidence | Remaining gate |
| --- | --- | --- |
| Excessive recursion during direct-API bundle canonicalization/adopter qualification could escape structured handling | 35 focused tests and 134 full Python tests passed; 1,800-level direct input produced a structured REJECT; fail-closed outcome preserved | None local. Not part of any published artifact (see Phase 1–4 publication note) |
| Consumer profile vocabulary could silently broaden | Spec/vocabulary frozen through 0.4; documented CLI ACCEPT, absent-policy NEEDS_EVIDENCE, denied-issuer REJECT | Separate versioned profile only if the Phase 5 pilot demands it |
| Missing runnable policy example | `examples/independent-agent-pilot/policy.json` with fixture issuer IDs and correct `--policy` syntax; assessments unsigned and local | None local |

## Phase 2 — Release and capability reconciliation

Local changes passed primary review 2026-09-30; commit `e03a268`.

| Defect / theme | Regression evidence | Remaining gate |
| --- | --- | --- |
| Documentation/capability wording did not match actual package behavior (including an erroneous claim that the 0.6 corpus was absent from the 0.5.0 tag) | 35 focused tests; all four tag manifests match current corpora (40/21/10/21); claim corrected after review | GitHub release entry for `v0.5.0` (from the existing signed tag and registry artifacts) remains a preparation/review item; no page has been published from this phase, and publishing it is a human decision. Future 0.6 gating, if wanted, must be an explicit compatibility change with Python/Rust parity coverage |
| Capability matrix absent | `docs/CAPABILITY_MATRIX.md` separates package version, spec support, consumer policy support, corpora, hosted observation date | Refresh when any of those inputs changes |

## Phase 3 — Browser inspector and settlement binding

Local implementation reviewed; website candidate commit `30b03ec` on
`codex/receipt-explorer-hardening` (base `d243935`), PR #28. Production
closure recorded in the plan: squash merge `740c5b6a`, Vercel production
READY at https://www.whitemagic.dev/verify.

| Defect / theme | Regression evidence | Remaining gate |
| --- | --- | --- |
| Signature inspection could be read as a core TRUSTED verdict; chain status conflated | 12 browser regressions, typecheck, lint, offline surface checks under primary review; EN/zh rendered fixture checks | None for the deployed site |
| `prev` binding, sequence/task consistency, signature algorithm and key/issuer binding were unchecked or undisclosed | Rendered EN/zh pages verified the published eight-receipt fixture; chain-intact and signature-valid shown separately | None; browser does not claim full-verifier parity |
| Unconditional `digestMatches: true`; queried tx not bound to returned signed tx | Local proxy/browser verified a live public signed payment example against its requested tx and stored digest; duplicate-key raw JSON visibly rejected | On-chain finality/settlement and service delivery remain outside this evidence |
| Protected preview browser redirects to Vercel login | Superseded by production rendered checks (screenshots in `ops/review-evidence/explorer-production[-zh]-2026-09-30.jpg`) | None |

## Phase 4 — Hosted API source, semantics, and staging

| Item | Regression / qualification evidence | Remaining gate |
| --- | --- | --- |
| 4A strict-JSON/notarization hardening candidate (`aa238c2f…`) | 4 harness tests incl. 23 negative/boundary cases, no-write checks, stored/retrieved Ed25519 verification; gateway refresh 15/15 x402 and 20/20 payment-receipt checks in disposable isolated kits (loopback facilitator stubs, no real payment) | Deployed inside the approved delta |
| 4B ERC evidence semantics: five per-check booleans were inferred from absent error text; malformed containers could throw | Revised candidate `10f36afc…` sets `chain_integrity`, `signatures_valid`, `policy_compliant`, `resource_caps_respected`, `anchors_verified` to `null`; 4 tests incl. malformed containers and deep input; 4 live loopback ERC cases after deployment with independently verified Ed25519 attestations | Intentional compatibility change (null-tolerant clients) reviewed and human-approved. No issuer allowlist or independent anchor status implemented — separate relying-party policy gate |
| Staging qualification | 83-check HTTP matrix under a transient hardened systemd unit; disposable source/package rollback rehearsal; all staging processes and directories removed | None; completed before rollout |
| Production rollout | Explicit human approval; `deploy_reviewed_hosted.sh` with hash checks, protected backup `/root/continuity-rollouts/20260930.7oCqdj6v`, signing key byte-identical before/after; post-deployment 82 loopback + 13 authenticated public + 4 live ERC checks passed; live `/info` reports 0.5.0 | Paid settlement has only been exercised against loopback stubs; no real x402 payment has been made |
| Package pin/provisioning (`hosted-package-pin.patch`) | Patch reconstruction and `bash -n` passed; deployment instead installed the PyPI-hash-verified 0.5.0 wheel with `--no-index --no-deps`; canonical provision recipe/README synchronized and `deploy-check.sh --quiet` clean | The standalone patch remains unapplied — keep or retire as explicit review |
| Crystal lane: caller-supplied tenant-hash locator is not an authorization credential; keyless reads disclose ciphertext/metadata and authd forwards no owner principal | Baseline characterization (opt-in) reproduced unauthenticated ciphertext/lineage retrieval for a known locator while outsider AEAD decryption failed; primary reran it; read-only production inventory found one envelope (no owner mapping inferred) | Superseded by the approved October 1 ownership rollout below; explicit customer owner assignment remains open |
| Phase 4C ownership contract and local candidate (prepared 2026-09-30 after the original thread was interrupted) | Contract `ops/CRYSTAL_OWNERSHIP_CONTRACT_2026-09-30.md`; candidate in `ops/crystal-ownership-candidate/src/` (+56/−3 authd, +129/−19 receipt-api) with 12/12 loopback cases: write/read roundtrip, keyless and unmapped-key fail-closed, cross-owner uniform 404, spoofed header stripping, foreign selector miss, foreign-envelope write 403, owner-scoped lineage, direct-API 401s, replay rejection, lifetime bounds, method/target/body binding. See `ops/CRYSTAL_OWNERSHIP_EVIDENCE_2026-09-30.md` | Historical 12-case preparation superseded by 25-case local/Caddy TLS staging, persistent replay, authenticated client bootstrap, key rotation/restore rehearsal and approved October 1 deployment. Envelope remains `wm-crystal/1.0`; no v2 migration. Explicit owner assignment remains open |

## Phase 5 — Independent relying-agent qualification

Historical checkpoint: packet and bounded local dry demo only on September 30.
The October 1 release and verified Mac return are recorded below.

| Item | Evidence | Remaining gate |
| --- | --- | --- |
| Relying-agent packet | `docs/INDEPENDENT_RELYING_AGENT_PACKET.md` with raw bytes, source/package pins, explicit policy and expected action/refusal; fixture from signed tag `v0.5.0` | External operator evaluation; local/same-host PASS and paid calls cannot close this |
| Bounded eight-case demo | Ran against both the checkout and published 0.5.0 wheel bytes; expected consumer outcomes and refusal classifications matched | Post-Phase-1 local consumer hardening is not in the published wheel; external report must pin wheel/sdist and module hashes |
| Second-host (mac) rehearsal | Sangha handoff to mac-stranger authorized; packet prepared; claim #456 covers `uploads/t4800-s/continuity-receipt-mac-pilot` preparation | **Open.** Real clean-host producer capture, negative tamper control, and independent review are required; a passing capture still does not prove sandbox enforcement or VPS readiness |

## Phase 6 — Standards composition and closure

| Item | Evidence | Remaining gate |
| --- | --- | --- |
| Crosswalk revision drift (AER-1, AADP bound permits, SCITT continuity receipts) | `docs/CROSSWALK_AER1_AADP_SCITT.md` checked 2026-09-30 against AER-1 `-05`, AADP bound-permit `-00` (base `-04`), SCITT continuity receipts `-01`; primary read sections 6–7; AER-1 probe claims bounded to checks performed | Informational only; Internet-Drafts can change |
| W3C CG brief for 2026-10-06 | `docs/W3C_AGENT_IDENTITY_CG_BRIEF_2026-10-06.md` mapped to the published agenda (item 4.6 priority) | Human review; no correspondence or agenda submission sent |
| External-evidence reference digest scope unresolved | `docs/DESIGN_NOTE_EXTERNAL_EVIDENCE_REFS.md` rewritten as a concrete recommendation: default to exact artifact bytes, keep canonical-JSON digests separately labeled, six explicit decisions listed before any wire change | Review pending; no schema/code/wire change until decided |
| Compute delivery/SLA attestations | Demand-gated design note | No implementation without demand |
| Final acceptance checks | 43 Rust tests; Python/Rust core vectors 40/40, 21/21, 10/10; verification-receipt vectors 21/21; hostile input 208 cases / 416 runs with zero failures or parity mismatches | Re-run on any future change; clean-worktree requirement still in flight on this branch (see note) |

## Consolidated open external gates

1. External relying-agent run with a real next-action decision on an
   independently administered host (Phase 5). No fabrication of independence.
2. Private L2 W2 host capture: revised packet released at Sangha #497; Mac operator run and primary review remain open. Native Python relying-agent Mac capture is verified; claim #456 is closed.
3. Crystal customer owner assignment: approved ownership enforcement and protected quarantine are deployed. Preserve ciphertext until independently established ownership permits an explicit mapping and reviewed restoration; no automatic claim.
4. External-evidence wire decisions and only then a versioned field
   definition (Phase 6).
5. W3C correspondence and GitHub `v0.5.0` release-entry decisions (human
   review).
6. Any future publication: Phases 1–4 local changes are not in a published
   package; the next package version is an explicit human decision.
7. Paid settlement lane: this repair pass made no real x402 transaction.
   Settlement/replay/paid-response regressions used loopback stubs. The site
   retains its separately sourced public payment fixture; this repair pass
   does not infer delivery or chain finality from that signed fixture.

## Known blemishes and accepted limitations

- ERC per-check fields are intentionally `null` (compatibility change,
  human-approved); boolean-only clients must tolerate nulls.
- The pre-rollout production runtime matched 13/14 Python modules of wheel
  0.5.0. After the approved rollout, all 14/14 match; independently
  rechecked against the SHA-256-verified PyPI wheel on 2026-10-01.
- The published 0.5.0 wheel predates the Phase 1–4 local changes; the local
  hardened consumer is not published.
- Crystal `/info` now advertises authenticated registry-mapped owner scope and retained `wm-crystal/1.0` envelopes. Three existing credentials have no mappings; their Crystal requests are intentionally denied pending explicit assignment.
- The original Phase 4C candidate used an in-memory per-process replay cache.
  The reviewed continuation uses persistent atomic SQLite reservations and
  retains nonces through expiry plus skew; cross-process replay is tested.
- The protected preview browser login limitation for the site is superseded
  by production rendered checks, but preview browser interaction itself was
  never exercised.

## Review continuation — 2026-10-01

Primary revalidated PR #11 head e9d44c8, current service source 10f36afc…
and tooling 0.5.0; canonical deploy-check passed. Phase 4C existing harness
passed 12/12, but independent expiry-boundary review reproduced assertion
replay during the five-second acceptance grace window. This is an open
candidate defect assigned a regression and repair, not a production change.
The missing actual relying-agent action runner and Mac release under claim
#456 are assigned separately. See REPAIR_STRATEGY_2026-10-01.md.

## Independently verified repair progress — 2026-10-01

- Native Mac packet source c255661 is released at Sangha #491, SHA-256
  451eb4269c9c28e6b303bad7abf0f3ee024e869602578d0732a6d813fb27824c.
  Preparation claim #456 released by #492. Clean extraction passed 13 action
  regressions, the preserved eight-case dry demo, real fresh assessment
  recording, duplicate refusal and expired-input refusal. Mac returned board #495: native macOS/arm64 Python 3.14.7 rehearsal PASS.
  Primary verified all 23 evidence hashes and recomputed the stored assessment.
  Shared fleet administration means independently administered adoption stays open.
- Revised Crystal candidate passed 25 local and disposable Caddy TLS VPS
  staging cases. Persistent expiry-skew replay protection, cross-process
  reservation, rotation, owner bootstrap, synthetic quarantine and malformed
  keyring refusal are covered. The reviewed cutover is now applied in the canonical kit and production; see the live checks below.
- Lucas chose preserve and quarantine for the unknown-owner legacy row.
  Protected consistent backup and quarantine are complete; account assignment remains open.
- Website receipt regressions 12/12, route checks and offline discovery
  checks passed again. Public gate-lite runtime-version pin follow-up
  0eeac42 passed 103 tests with 6 explicit runner skips and PR #7 CI.

- Final integrated private L2 candidate ca79981 passed 130 tests with 6
  explicit profile skips, plus the independent real Bubblewrap probe.
  Private main received reviewed POSIX fallback 2a52027; no deployment follows
  from either source update. Public PRs #6 and #7 merged after review and CI; main e14acbb.
- Receipt final suite: 150 passed, 59 skipped, 13 subtests; Python/Rust parity
  40/40 published, 21/21 0.5 candidate, 10/10 0.6 candidate and 21/21
  verification receipts; hostile inputs 208 cases/416 runs, zero failures or
  parity mismatches. Pilot source-import follow-up fixes preloaded-module
  ambiguity without invalidating the immutable fresh-process Mac capture.

## Approved production ownership cutover — 2026-10-01

Lucas explicitly approved the reviewed breaking access change at PR #11
`4a473a5`. API/gateway sources match the final reviewed pins; keyless Crystal
access was removed. The canonical hosted kit matches deployed source/config
(`deploy-check.sh --quiet` passed). API, gateway, key issuance and Caddy are active.

- Gateway, API and the shared-state key writer were stopped for the complete
  consistent backup at `/root/continuity-rollouts/approved-20261001/consistent-backup.tar`
  (root-only). Backup SHA-256 is `d9d183ad21529005374b26fa5fa4234a6beed927275b07864eab7b56584a0a22`.
- Exactly one customer envelope was preserved in root-only quarantine. Its
  original, backup and quarantine encrypted-byte hash is
  `f638468a80c55d2c68054b0576a497c2d90b9ad9d216c0e313aabd3752a822ae`.
  No plaintext or payload was inspected, and no decryption was attempted.
  Hash verification reads encrypted bytes only. No locator is published.
  The API service account cannot read quarantine.
- Registry bytes were unchanged. Three credentials still have zero owner
  mappings. New assertion keys are private; persistent replay reservations
  and authenticated registry scope enforce the reviewed model.
- Actual public TLS checks: health/info 200, anonymous Crystal requests 402,
  an unmapped existing credential 403, direct data API without assertion 401,
  and all Crystal responses `private, no-store`. Direct `/crystals` API is
  non-sensitive discovery metadata (200). Authenticated public `/verify`
  returned TRUSTED for the published synthetic agreement fixture.
- Full positive/cross-owner/key-rotation adversarial checks use isolated
  synthetic staging, not invented production owner mappings. Rollback must
  retain closed Crystal routes and preserved quarantine.

Evidence: `ops/review-evidence/crystal-live-cutover-2026-10-01.json` and
`ops/review-evidence/crystal-protected-backup-summary-2026-10-01.json`.

Final W2 archive released at board #497: `e657bbfe3989b34565e21a6cc0f4c74b5bc5d5940161ad5f0fd876e12be1d8a0`,
private source `ca79981`. Primary clean extraction passed 130 tests/6 skips
and the real Bubblewrap egress probe; operator host results remain open.

## Website and client review closure — 2026-10-01

Site PR #29 (`cae9885`) merged as `629b60b2acad95ea1284c8933aa3711c713ef7dc`
after primary inspection, green CI and a Ready Vercel preview. Both preview
and production passed 12-route CLI content checks. Production deployment
`whitemagic-site-5psnbuerz-lbailey94s-projects.vercel.app` is Ready and
serves `www.whitemagic.dev`. English/Chinese hosted, receipts and trust pages
and coupled discovery surfaces describe current 0.5.0/0.1–0.6 support,
owner-registry Crystal access, caller-claim notarization and ERC outcome limits.
PR #21's DID/profile/anchor corrections are incorporated and #21 is closed.
The earlier failed Vercel build at `16edb1c` was an MCP snapshot version
mismatch corrected by `918a975`; no build-gate weakening was needed.
The preview browser permission was declined; no retry or browser workaround
was used. CLI preview checks had already completed; rendered local checks,
CI, Ready preview and production CLI checks provide the review evidence.

Primary client review: CR 10 tests and isolated WMv9 12 tests passed; final
local Crystal integration 25/25 passed. The current CR suite is 160 passed,
59 explicit skips, 13 subtests. Canonical local client synchronized; WMv9
port remains a reviewed isolated candidate with a retained patch. No client
network requests or customer payload reads were used in these tests.
See `ops/HOSTED_DISCOVERY_DEPLOYMENT_2026-10-01.md` and the source/test
pins in `ops/review-evidence/crystal-client-hardening-2026-10-01.json`.

## Next-phase review and integration — 2026-10-01

User authorized the five-phase continuation with Luna implementation and
primary review. Customer recovery design/harness is accepted as synthetic
control-flow evidence after primary corrections: actual subprocess termination,
stale-stage refusal/reconciliation, preserved v1 AAD locator and opaque byte
identity, simulated mapping-conflict refusal. Three tests and the CLI pass;
no real customer identity/mapping/restoration occurred.

WMv9 client ad8a4dc and source-distribution/CI follow-up ea41f00 are reviewed,
integrated and pushed to main. Primary12clienttests and combined host-script
suite pass. GitHub Host Scripts, Linux/macOS tests, Clippy and boundary E2E
passed on ea41f00; remaining broader jobs were still running at this checkpoint.
This does not constitute a new binary release or VPS deployment.

GitHub's missing historicalv0.5.0 release entry is now published as Latest,
after primary signed-tag, artifact checksum and exact-body checks. Existing
package/tag artifacts were not replaced. A distinct local0.5.1 candidate passed primary metadata and 14 installed checks;
it is not published or deployed.

SitePR30 corrects the blanket read-only claim to apply to recall and offers
EN/zh manual ownership-review contact guidance that prohibits sending plaintext,
encryption keys or bearer credentials. CI and Ready preview passed; primary
12preview/production routes and targeted newcopy checks passed. Production
merge5d14b6f is Ready. Actual browser checks also passed on the prior deployed
explorer's public fixtures: payment signature valid; eight bundle signatures
valid/intact chain; tamperedfirstgate invalid/brokenchain. These are subset
checks rather than protocol verdict or payment-finality proof.

New independent-adoption packet d942b1c was clean-extracted and reviewed by
primary:27/27sourcehashes,16actiontests,freshCLIassessment and replayrefusal.
Handoff instructions were corrected and released on Sangha#500. The real
independent-admin return and the separate W2 Linux capture remain open.

Currentreceiptpytest163passed59skipped16subtests. Revised CI explicitly runs
client, pilot and synthetic recovery tests and verifies installed imports from
outside the checkout. See NEXT_PHASE_EXECUTION_2026-10-01.md and ops evidence.
Federated gateway scope collision is a response-label defect; inner arguments
are preserved. Direct endpoint claims/freeze scopes were verified before WMv9
integration. A bounded response annotation fix 6f1a6f is retained as a reviewed isolated
source candidate, with patch and primary test evidence; no merge or deployment.
