# Independent relying-agent pilot specimen

This directory is a local, bounded dry-run specimen for a relying agent. It
contains an unmodified signed 0.4 conformance vector, an explicit caller-owned
policy, and a small refusal harness. It is not an independent operator run,
adoption evidence, or authorization to perform an action.

Run from the repository root:

```sh
python3 examples/independent-agent-pilot/run_pilot.py
python3 -m continuity_receipt.consumer \
  examples/independent-agent-pilot/bundle.json \
  --policy examples/independent-agent-pilot/policy.json
```

The first command checks eight dry-demo cases. The consumer returns `ACCEPT`
for the historical fixture, while its hypothetical action gate still returns
`REFUSE` because external action controls are unproven. It also checks issuer
denial (`REJECT`), unsupported consumer spec (`REJECT`), a missing required
record (`NEEDS_EVIDENCE`), simulated replay, missing freshness, interrupted
recovery, and changed caller-side artifact bytes. The second command emits
only the consumer assessment. Neither command executes a tool or changes
external state.

For a historical dry-demo comparison only, an operator with the pinned wheel
installed in an isolated, non-editable environment can run the harness from
outside the repository (the runner rejects a package import that resolves
back to this checkout):

```sh
cd /tmp
/path/to/venv/bin/python \
  /path/to/continuity-receipt/examples/independent-agent-pilot/run_pilot.py \
  --installed-package
```

## Input provenance and pins

`bundle.json` is a byte-for-byte copy of
[`vectors/17_agreement_bound.json`](../../vectors/17_agreement_bound.json) from
the published Continuity Receipt source tag `v0.5.0` (tag commit
`ff008888af6f225077b0661aa5b2d88da843839c`, signed with the maintainer key
fingerprint `SHA256:cbHGzhbKM5Y73C9fOTzg0BlsjLwu4gi04K6+V1PnPrk`). The tag’s raw
fixture and this copy are each 9,659 bytes with SHA-256
`35f2a99f4c5d13dd868c81070491f949d932190ed9a577d2d9153044936b6976`. The
canonical bundle digest reported by the consumer is
`sha256:6ec87ad89b003b998178f4bbdc72d5c521a6b8de37c2839ed0a743844bcd9767`.
`LICENSE` preserves the source repository’s Apache-2.0 license notice.

The package line used for an external reproduction is pinned to
`continuity-receipt==0.5.0`; the consumer assessment profile still accepts
receipt specs 0.1–0.4 only. Capture the downloaded wheel/sdist SHA-256 and the
hash and path of the actual imported `continuity_receipt.consumer` module on
the operator’s machine. A version string by itself does not bind the imported
source to the package artifact.

The hardened consumer source is committed at `e03a268` but is not present in
the published 0.5.0 wheel. The dry demo prints the working-tree commit,
whether verifier source files are dirty, the imported module path, and SHA-256
values for its verifier source files. For a real pilot, use the reviewed,
committed source snapshot identified by the handoff; do not infer source
identity from the published 0.5.0 package version. Record the exact source
hashes and rerun on the independent relying agent’s host.

The explicit issuer allowlist and raw policy digest are printed by the harness.
The sample policy requires `agreement.offer` and `agreement.accept`; those
record types are presence checks only. Their presence does not establish
principal identity, authority, scope, or permission to act.

`sample-input.txt` and `artifact-manifest.json` are separate local fixtures for
testing the caller-side file hash check. They are neither signed nor
referenced by the 0.4 bundle. The changed-file scenario tests that the harness
refuses a byte mismatch; it does not claim that Continuity Receipt itself
binds the external artifact.

## Opt-in local assessment record

`make_fresh_fixture.py` creates a new, synthetic, signed 0.4 agreement bundle
and explicit policy with current receipt timestamps and future expiry. Its
deterministic test keys are public and must never be treated as real identity
or authority. The script writes only into an existing owner-only directory
and refuses to overwrite either output.

`run_action.py` performs one bounded local action: after the consumer returns
`ACCEPT`, exact expected raw bundle and policy SHA-256 values match, and every
receipt passes caller freshness checks, it writes a fixed `assessment.json`
into an operator-selected existing owner-only directory. The caller supplies
`--now-utc` and `--max-age-seconds`; the report records that timestamp as
operator-supplied and says no trusted time oracle was used. It checks that all
receipt `issued_at` values are at or before that time and within the age bound,
and that the session pass and agreement offer have not expired. The receipt's
claimed action is never executed.

Example from the repository root on macOS or Linux with Python 3.11+:

```sh
mkdir -m 700 -p /tmp/cr-pilot-input /tmp/cr-pilot-output
python3 examples/independent-agent-pilot/make_fresh_fixture.py \
  --output-dir /tmp/cr-pilot-input
date -u '+%Y-%m-%dT%H:%M:%SZ'
shasum -a 256 /tmp/cr-pilot-input/bundle.json /tmp/cr-pilot-input/policy.json
python3 examples/independent-agent-pilot/run_action.py \
  --record-assessment \
  --bundle /tmp/cr-pilot-input/bundle.json \
  --policy /tmp/cr-pilot-input/policy.json \
  --bundle-sha256 sha256:<copy-bundle-hash-here> \
  --policy-sha256 sha256:<copy-policy-hash-here> \
  --now-utc <copy-current-UTC-time-here> \
  --max-age-seconds 86400 \
  --output-dir /tmp/cr-pilot-output
```

Replace the three marked values with the exact output from the preceding
commands. The output directory must already exist with mode `700`; its final
path must not be a symlink, and the operator must trust its parent path and
local filesystem. Result, temporary, and SQLite state files use mode `600`.
SQLite serializes concurrent
callers. The journal records `PREPARED` before file creation, then marks the
operation complete after durable output. A repeated run is refused, a
`PREPARED` operation is never resumed, and a changed/missing output is
refused. This is a local single-directory replay control, not a distributed
ledger.

The checked-in historical fixture remains unchanged. Running the action with
it should refuse because its signed receipts are stale and its session pass is
expired; the positive action case uses the generated fresh synthetic fixture.

## What an operator must add

An independent operator must record their operator/agent identity, host and
administrative separation from the producer, operating system and Python
version, exact command, installed package artifact and imported source hashes,
raw bundle and policy copies, stdout/stderr, machine-readable output, and the
result of independently repeating the positive and negative controls. Have a
separate reviewer retrieve the retained artifacts and reproduce the hashes.
Until that happens, this directory remains a fixture and local harness only.
