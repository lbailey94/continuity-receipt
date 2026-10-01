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

The first command checks eight cases. The consumer should return `ACCEPT` for
the fixture and the harness should still return `REFUSE` because external
action controls are unproven. It also checks issuer denial (`REJECT`), an
unsupported consumer spec (`REJECT`), a caller-required record not present
(`NEEDS_EVIDENCE`), simulated replay, missing freshness, interrupted recovery,
and changed caller-side artifact bytes. No case executes a tool or changes
external state. The second command emits the assessment JSON; `ACCEPT` is only
the local verifier plus policy result.

An operator with the pinned wheel installed in an isolated, non-editable
environment can run the harness against that installation from outside the
repository (the runner rejects a package import that resolves back to this
checkout):

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

The repository currently has local changes in the consumer module. The demo
prints the working-tree commit, whether verifier source files are dirty, the
imported module path, and SHA-256 values for its verifier source files. Its
current execution is therefore a local candidate check; it is not evidence
that the published 0.5.0 package has byte-identical code. For a real pilot,
use a reviewed, committed source snapshot or the pinned package in an isolated
environment, record the exact artifact hashes, and rerun on the independent
relying agent’s host.

The explicit issuer allowlist and raw policy digest are printed by the harness.
The sample policy requires `agreement.offer` and `agreement.accept`; those
record types are presence checks only. Their presence does not establish
principal identity, authority, scope, or permission to act.

`sample-input.txt` and `artifact-manifest.json` are separate local fixtures for
testing the caller-side file hash check. They are neither signed nor
referenced by the 0.4 bundle. The changed-file scenario tests that the harness
refuses a byte mismatch; it does not claim that Continuity Receipt itself
binds the external artifact.

## What an operator must add

An independent operator must record their operator/agent identity, host and
administrative separation from the producer, operating system and Python
version, exact command, installed package artifact and imported source hashes,
raw bundle and policy copies, stdout/stderr, machine-readable output, and the
result of independently repeating the positive and negative controls. Have a
separate reviewer retrieve the retained artifacts and reproduce the hashes.
Until that happens, this directory remains a fixture and local harness only.
