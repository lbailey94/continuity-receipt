# Reviewed repair strategy — 2026-10-01

The primary coordinates three explicitly authorized Luna lanes and reviews
actual diffs and independent evidence before integration. Starting receipt
branch: e9d44c8 (PR #11); private Mandala main a4ef893, L2 PR #2 54eedcc.
No published vectors, deployed source, or frozen W1/W2 archives are modified
by delegation. Scope claim Sangha #486; Mac preparation claim #456 closed at #492 after the release at #491; native
Mac evidence returned at #495 and passed primary hash/assessment review.

## Implementation lanes and gates

| Lane | Scope | Acceptance |
| --- | --- | --- |
| Mac relying agent | pilot example and packet doc | Real bounded assessment-file action gated by consumer ACCEPT, pinned raw inputs and caller freshness; durable replay/prepared recovery; negative/tamper tests; portable source/hash capture; root-tested archive and Sangha release |
| Crystal ownership | isolated candidate, harness, evidence and decision brief | Fix expiry-skew replay; persistent atomic nonce handling; malformed lifetime refusal; two owners; same-owner key rotation; legacy quarantine; compatible authenticated client bootstrap; accurate candidate discovery copy |
| Mandala L2 | isolated PR #2 worktree | Correct host/port receipt accounting; bounded proxy lifecycle; fail-closed missing/malformed evidence; meaningful adversarial tests and local real probe; isolated public POSIX fallback backport |
| Primary integration | strategy, closure records, export/review evidence | Independently inspect diffs, rerun targeted tests and relevant full suites, compare runtime/package pins and public surfaces, record exact artifacts and remaining gates |

## Verification sequence

1. Revalidate current source hashes, live service version and site disclosure.
2. For each lane, inspect changed paths and run the regression that failed
   before the change. Test crash/restart/concurrency boundaries where relevant.
3. Run full Python/Rust and parity gates after the final receipt delta; run
   Mandala's full candidate suite and real sandbox probe on the exact delta.
4. Export the reviewed native-Python Mac packet, whitelist source/tests/docs,
   verify the archive and internal manifest, execute from a clean extraction,
   then post exact instructions and return-evidence requirements on Sangha.
5. Crystal staging uses isolated disposable state and synthetic owners. A
   deployment candidate needs exact source/config pins, owner registry setup,
   protected backup, rollback rehearsal, route/discovery reconciliation and
   successful staging before any live cutover approval is requested.
6. Review stacked public #6 then #7; integrate L2 only after private review.

## External prerequisites that local tests cannot supply

- Actual Mac/operator run, returned capture and administrative-separation facts.
- Legacy owner remains unknown. Lucas selected preservation and quarantine;
  the actual protected migration still requires reviewed rollout preparation.
- Explicit production approval for the new breaking Crystal access change.
- Real paid settlement or external issuer/anchor policy if those claims are
  desired; synthetic stubs and signed service statements do not prove them.
- Package publication and release-page decisions remain separate from fixes.

The objective tonight is to close implementable defects and handoffs, and
prepare tested reviewable integration/deployment candidates. External results
remain open until supplied. A green delegate report is not primary evidence.
