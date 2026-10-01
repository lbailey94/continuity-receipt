# Continuity Receipt 0.5.1 local release candidate

**Status:** local candidate reviewed by primary; 14 installed checks independently rerun. No tag, commit,
registry publication, hosted deployment, or GitHub release was made from this
candidate.

## Source and version map

The candidate was prepared in detached worktree
`/tmp/continuity-receipt-051-candidate-2026-10-01` from exact source commit
`d942b1c1fff6e8d153e04c31e3327b4ca7c8ee56`. No package or version files in
the shared checkout were changed for this candidate.

| Surface | 0.5.0 source | 0.5.1 candidate source | Meaning |
| --- | --- | --- | --- |
| Python distribution | `pyproject.toml` | `0.5.1` | Wheel and sdist metadata |
| Python runtime | `continuity_receipt/_version.py` | `0.5.1` | `__version__` and default version in newly issued verification receipts |
| Rust crate | `rust/Cargo.toml`, `rust/Cargo.lock` | `0.5.1` | Cargo package/install metadata |
| Receipt protocol | `continuity-receipt/0.5` | unchanged | Protocol version is independent of package version |
| Experimental authority draft | `continuity-receipt/0.6` | unchanged | Still draft behavior, not a standalone normative release |

Rust has no verifier CLI `--version` output or package-version string in
runtime results. Cargo's package metadata reports the crate version, so the
candidate increments its manifest and lockfile entry to keep the Python and
Rust package releases aligned without changing Rust verifier source. The
hosted service remains a separate deployment surface and is not changed by
this package candidate.

The minimal version patch changes only:

- `pyproject.toml`
- `continuity_receipt/_version.py`
- `rust/Cargo.toml`
- `rust/Cargo.lock` (the crate's own package entry)

No spec, schema, vector, or Rust source changes are in the candidate patch.
The changes retain the published 0.5 protocol while packaging the already
reviewed Python consumer/capture hardening as a patch release.

## Candidate artifacts

Built from the detached worktree with:

```sh
python3 -m build \
  --outdir /tmp/continuity-receipt-051-evidence-2026-10-01/final-dist
```

| Local rehearsal artifact | SHA-256 |
| --- | --- |
| `continuity_receipt-0.5.1-py3-none-any.whl` | `95445d151308186161c82851039199f434e1dbe47a411e477450e3f2a9d3908b` |
| `continuity_receipt-0.5.1.tar.gz` | `0752c0e3232884443560613166041c028b018a382e133e77b88ffa08f576b27b` |

These are locally built candidate files, not published artifacts. The exact
version patch is saved at
`/tmp/continuity-receipt-051-evidence-2026-10-01/version-metadata.patch`;
the proposed release description is
`/tmp/continuity-receipt-051-evidence-2026-10-01/release-body-0.5.1.md`.
Artifact and evidence checksums are recorded in that directory's
`SHA256SUMS` and `EVIDENCE-SHA256SUMS`.

## Verification

The wheel was installed into a clean virtual environment under `/tmp`; all
runtime checks ran from
`/tmp/continuity-receipt-051-evidence-2026-10-01/outside-run`, outside the
detached candidate worktree. The import path resolved from that virtual
environment's `site-packages`.

The smoke verified:

- Installed distribution metadata, `continuity_receipt.__version__`, and a
  newly issued, successfully reverified verification receipt all report
  `0.5.1`.
- All six Python console entrypoints load and show help; verifier,
  disclosure, consumer, and verification-receipt commands pass bounded
  examples. The 0.5 state-commitment vector remains `TRUSTED`.
- The anchor example returns `anchor_unverified` without a block header; this
  is the expected bounded result.
- The wheel contains 14 Python runtime modules and entrypoint metadata. The
  sdist contains the package sources, spec/conformance documents, schemas,
  vectors, and tooling.
- `cargo metadata --locked --no-deps --format-version 1` and the lockfile both
  report Rust package version `0.5.1`. The Rust implementation sources are
  unchanged from `d942b1c`; no Cargo build or core test suite was run for this
  metadata-only version change.

The full smoke command/result record is
`/tmp/continuity-receipt-051-evidence-2026-10-01/python-smoke.json`; the
version-specific report is
`/tmp/continuity-receipt-051-evidence-2026-10-01/python-version-report.json`.

## Preserved review evidence

The version patch, proposed release body, build/installation reports, checksums
and primary rerun report are retained in
`ops/review-evidence/release-candidate-0.5.1-2026-10-01/`.
`EVIDENCE-SHA256SUMS` covers the original delegate evidence files;
`SHA256SUMS` identifies candidate binaries retained in the temporary build
directory, not committed or published. The primary report is additional evidence.
