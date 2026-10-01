# Continuity Receipt 0.5.0 release reconciliation

Audit date: 2026-10-01. This file records release-state evidence and review
decisions. The clean text intended for the GitHub release description is
[`RELEASE_BODY_0.5.0.md`](RELEASE_BODY_0.5.0.md); it contains no internal
checklist or planning notes.

## Reconciled release state before publication

- Signed tag `v0.5.0` resolves to commit
  `ff008888af6f225077b0661aa5b2d88da843839c`. `git tag -v v0.5.0` reports a
  good ED25519 signature by the maintainer key fingerprint
  `SHA256:cbHGzhbKM5Y73C9fOTzg0BlsjLwu4gi04K6+V1PnPrk`.
- PyPI reports version 0.5.0, uploaded 2026-09-30, with wheel SHA-256
  `9b0be02327759b3f95519967f4257ce37a3ee44468359a88f84480d28c5935ee` and
  sdist SHA-256
  `afb373c222a39638b21b6aae05a704d0c890828a0c2db589e8a2f2b54067c2bd`.
- crates.io reports version 0.5.0, created 2026-09-30, with crate checksum
  `43cbfdf503051ec95057abe5ff33cf8ca37d279ea8f2da65b039c30af64bdfff`.
- GitHub's release-by-tag endpoint returns 404 for `v0.5.0`. The releases
  listing contains `v0.4.0` only, so the latest GitHub release is still 0.4.0.
- A live request to `https://api.whitemagic.dev/info` on 2026-10-01 returned
  `verifier_version: 0.5.0` and supported specs 0.1–0.6. This hosted service is
  a separate deployment surface from the signed tag and package registries.

## Scope and compatibility review

The release tag contains the published 0.5 specification and 21-vector
corpus, experimental 0.6 verifier support and its 10-vector corpus, the
Python consumer profile, and the adopter-capture harness. The 0.6 specification
remains a draft. The Python consumer profile accepts receipt specs 0.1–0.4;
it is not the core verifier and does not authorize actions.

From `v0.5.0` to candidate `d942b1c`, the normative 0.5/0.6 schemas, vector
manifests, Python/Rust core verifiers, and package version declarations do not
change. The package-relevant Python edits are limited to the consumer profile
and capture qualification tooling: a fixed list of record types for its
published 0.1–0.4 profile, and structured handling of excessive nesting during
canonicalization. The Rust crate has no post-tag source changes. Other
post-tag edits are documentation, hosted-service/client work, and local pilot
material; they do not belong in the 0.5.0 GitHub release description as if
they shipped in the frozen packages.

Recommend `0.5.1` for the package-level hardening once its candidate checks
pass. The new explicit consumer record-type tuple is byte-for-byte equivalent
in membership to the tag's previous dynamic expression
(`records.RECORD_TYPES` minus `state.commitment` and `authority.grant`), so
valid existing 0.1–0.4 profile policies retain the same vocabulary. The new
`RecursionError` handling turns excessive nesting during canonicalization
into the consumer's structured refusal path. There are no normative spec or
schema changes and no Rust implementation changes after the tag. This is a
patch-level package fix; do not advertise it as a new protocol spec. No version
bump or release action is included in this reconciliation.

## Temporary candidate package rehearsal

On 2026-10-01, a fresh wheel and sdist were built from the current candidate
tree with `python3 -m build --outdir
/tmp/continuity-receipt-release-audit-2026-10-01`. These are local rehearsal
artifacts, not the published 0.5.0 artifacts. Their SHA-256 values and clean
virtual-environment smoke results are preserved under
`/tmp/continuity-receipt-release-audit-2026-10-01/`:

- Candidate wheel and sdist checksums are preserved in
  `ops/review-evidence/release-reconciliation-2026-10-01/SHA256SUMS`. The
  release notes are included in the source distribution, so the hashes are
  kept outside the archive to avoid a self-referential checksum.
- `installed-smoke.json` records 16 successful installed-package and
  regression-suite checks from
  `/tmp`, including CLI entrypoints, bounded verifier and consumer examples,
  and all eight independent-agent pilot dry-run cases. A replay of the exact
  expanded GitHub package-job script also succeeded with `GITHUB_WORKSPACE`
  set and is logged in `ci-package-step.log`. The imported consumer resolved
  from the temporary virtual environment's `site-packages`, outside the
  checkout; the CI assertion checks both paths explicitly.
- The candidate sdist includes `CONFORMANCE_TABLE.md` and
  `SPEC_0.5_DRAFT.md`. The wheel contains the 14 Python runtime modules and
  entrypoint metadata; it does not bundle repository fixtures or examples.
  The sdist also omits `examples/independent-agent-pilot/`, which remains a
  repository example rather than a packaged example.

The temporary build identifies itself as version 0.5.0 because package
metadata has not been changed. Do not confuse its hashes with the frozen
PyPI/crates.io artifacts above.

## CI regression coverage

The workflow now explicitly runs the 10 Crystal client boundary regressions,
16 independent-agent pilot regressions, and three synthetic customer-recovery
regressions. Those 29 targeted regressions passed locally on 2026-10-01. The
package job installs the wheel, changes to `/tmp`, checks the installed import
path against both the virtual environment and checkout, exercises the console
entrypoints, and runs the bounded pilot against the installed package. The
exact package-job script was replayed successfully; logs are in
`ci-package-step.log`. Primary independently reran the corrected subprocess-crash rehearsal successfully.

## Publication handling

`RELEASE_BODY_0.5.0.md` is ready as the proposed GitHub release body for the
existing tag. Publish it only after final review, without rebuilding or
uploading package artifacts. Keep the independent adversarial review and
independent-host adopter qualification limits stated in that body.

## Primary publication confirmation

After independent tag signature/target, live registry checksum, body and
installed-package checks, the primary published the historical GitHub release
for `v0.5.0` on 2026-10-01 at 17:18:59 UTC and marked it Latest. The served
body exactly matches `RELEASE_BODY_0.5.0.md`. No release assets were uploaded
and no package/tag artifact was rebuilt or replaced. The missing-release and
0.4.0-Latest observations above are the pre-publication audit snapshot.
Evidence: `ops/review-evidence/release-reconciliation-2026-10-01/github-v0.5.0-published.json`.
