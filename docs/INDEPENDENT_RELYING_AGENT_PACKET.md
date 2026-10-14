# Independent relying-agent pilot packet

**Status: prepared local packet; external run and adoption are not yet
demonstrated.** This packet asks an external agent/operator to evaluate a
disclosed Continuity Receipt bundle as a relying party using its own explicit
policy and refusal controls. It does not ask the operator to execute the
bundle’s claimed action. Sangha preparation notices #456 and #486 were posted to the Mac/fleet; the primary releases the tested archive separately. No returned Mac run is yet evidenced.

The profile in scope accepts receipt specifications 0.1–0.4. The pilot uses a
real signed 0.4 conformance vector and the offline Python consumer. The
consumer’s `ACCEPT` means that the core verifier returned `TRUSTED`, the
canonical bundle digest was available, and the explicit local policy passed.
It is not proof of a real principal, authority, real-world execution, complete
history, freshness, revocation status, replay safety, safe recovery, or
independent key custody. A record type appearing in the bundle is not a grant
of authority.

## Exact input and policy pins

The packet’s raw fixture is
[`examples/independent-agent-pilot/bundle.json`](../examples/independent-agent-pilot/bundle.json),
copied byte-for-byte from `vectors/17_agreement_bound.json` in signed source
tag `v0.5.0`:

- Source tag commit: `ff008888af6f225077b0661aa5b2d88da843839c`.
- Tag verification observed locally: valid maintainer signature, key
  fingerprint `SHA256:cbHGzhbKM5Y73C9fOTzg0BlsjLwu4gi04K6+V1PnPrk`.
- Bundle raw size and SHA-256: `9659` bytes,
  `sha256:35f2a99f4c5d13dd868c81070491f949d932190ed9a577d2d9153044936b6976`.
- Canonical bundle digest: `sha256:6ec87ad89b003b998178f4bbdc72d5c521a6b8de37c2839ed0a743844bcd9767`.
- Pinned distribution line: `continuity-receipt==0.5.0`. The 0.5.0 package
  includes experimental 0.6 verifier support, while this Python consumer
  profile accepts receipt specs 0.1–0.4. The package version is not a consumer
  profile version.

The local consumer CLI imports its module from the checkout. The current
checkout has uncommitted Phase-1 consumer hardening, so the successful local
demo is not proof that published 0.5.0 wheel bytes match that source. The
runner prints the actual imported path, runtime-source SHA-256 values, package
metadata version, repository HEAD, and dirty-source flag. An external report
must capture the actual downloaded wheel/sdist hash and hash the imported
module; do not infer those values from `pip show` or the version string. Run
from outside a source checkout when testing the installed package, or record
and pin the exact committed source snapshot used.

The policy is
[`examples/independent-agent-pilot/policy.json`](../examples/independent-agent-pilot/policy.json):

- Raw size: `336` bytes.
- Raw SHA-256: `sha256:3025268fbcadd8eda6e77708451597c0b087ec5a7e037f8620e14b6f13e0f343`.
- Canonical policy digest: `sha256:4cc427db5aee6c057f725975bc8c5e236add0c497e28da822a31459655949c8c`.
- Accepted bundle/receipt spec: `continuity-receipt/0.4`.
- Exact receipt envelope issuer allowlist:
  - `did:key:z6MkiqMhLhuq26ofXDsP6WeDPTm74a27qdqjKSmNvEmnJjSb`
  - `did:key:z6MkwSG2hFkD41K85fvQFtNGCZXYFUwEZDqrzahZvWHt5hm1`
- Required record types: `agreement.offer`, `agreement.accept`.

These DID strings are policy inputs tied to public keys in this test fixture.
The policy does not establish legal or real-world identities for them. The
required record types only test presence. The fixture’s claimed gate expiry is
`2026-09-18T00:00:00Z`, already past the packet date (`2026-09-30`); the
consumer does not enforce freshness. Its local `ACCEPT` result is deliberately
not an action clearance.

## Reproduce the bounded local demo

From the repository root:

```sh
python3 examples/independent-agent-pilot/run_pilot.py
python3 -m continuity_receipt.consumer \
  examples/independent-agent-pilot/bundle.json \
  --policy examples/independent-agent-pilot/policy.json
```

The dry-demo harness reads local files only (maximum 1 MiB each), uses no
network, and has no action/actuator code. It emits a JSON summary and checks
these expected assessment outcomes:

| Scenario | Consumer result | Harness result |
| --- | --- | --- |
| Published 0.4 fixture, explicit policy | `ACCEPT` | `REFUSE` until external gates are independently evidenced |
| Signer omitted from explicit issuer allowlist | `REJECT` / `issuer_not_trusted` | `REFUSE` |
| Bundle spec changed to unsupported 0.5 | `REJECT` / `spec_not_accepted` | `REFUSE` |
| Caller requires absent `authority.succession` | `NEEDS_EVIDENCE` / `required_record_missing`; core remains `TRUSTED` | `REFUSE` |
| Bundle digest already present in simulated local replay ledger | `ACCEPT` | `REFUSE` / `caller_replay_ledger_hit` |
| No trusted time source/freshness evidence | `ACCEPT` | `REFUSE` |
| Simulated `PREPARED` operation without terminal recovery evidence | `ACCEPT` | `REFUSE` |
| Caller-side artifact bytes changed | `ACCEPT` for the unchanged receipt bundle | `REFUSE` / `external_artifact_hash_mismatch` |

The state-file example is
[`examples/independent-agent-pilot/sample-input.txt`](../examples/independent-agent-pilot/sample-input.txt),
with its separate expected hash in `artifact-manifest.json`. Neither file is
signed or referenced by the receipt bundle. They exercise only a caller-side
hash comparison. Likewise, replay and interrupted-recovery controls in the
script are simulated harness facts, not features of the consumer or core
protocol. Even if every hypothetical gate were marked complete, the dry-demo
harness returns `OPERATOR_REVIEW_REQUIRED` and performs no action.

## Opt-in local assessment write

The separate `examples/independent-agent-pilot/run_action.py` script performs
one actual local action: it writes a fixed `assessment.json` into a caller-
selected evidence directory. It does not execute the receipt's claimed action,
invoke tools, contact a network, pay, or change an external service. It
requires explicit expected raw SHA-256 pins for both the bundle and policy,
the actual consumer outcome `ACCEPT`, an existing owner-only output directory,
and caller freshness inputs (`--now-utc` plus `--max-age-seconds`). It checks
every signed `issued_at`, session pass `expires_at`, and agreement offer
`valid_until`. The report distinguishes the completed local file write from
execution of the receipt's claim and labels the supplied time as unauthenticated
operator input, not a trusted clock or oracle.

The old checked-in fixture and policy remain byte-for-byte preserved. Its
receipts are stale and its session pass is expired, so action mode refuses it.
The new `make_fresh_fixture.py` creates a reproducible synthetic signed 0.4
agreement bundle and policy for tests and a clean-host local reproduction. Its
deterministic public test keys are not real identity or authority. The runner's
Python tests independently exercise positive file write, issuer/spec/evidence
refusals, freshness refusal, replay, changed output, untracked output,
symlinked directory, interrupted `PREPARED` state, and concurrent callers.

### macOS source checkout procedure

Use the reviewed, committed handoff snapshot that includes the packet, the
pilot scripts, `tools/make_vectors.py`, and the hardened consumer source. The
consumer hardening is committed at `e03a268` but is not present in the
published 0.5.0 wheel; a package version alone is not an acceptable source
pin. Python 3.11 or later is required by `pyproject.toml`. From the clean
checkout root in macOS Terminal:

```sh
sw_vers
python3.11 --version
python3.11 -m venv .venv
.venv/bin/python -m pip install .
git rev-parse HEAD
git status --short
shasum -a 256 continuity_receipt/consumer.py continuity_receipt/verify.py continuity_receipt/canon.py continuity_receipt/strict_json.py continuity_receipt/records.py continuity_receipt/keys.py continuity_receipt/agreements.py continuity_receipt/bundle.py continuity_receipt/revocations.py
.venv/bin/python examples/independent-agent-pilot/run_pilot.py
.venv/bin/python examples/independent-agent-pilot/test_run_action.py
mkdir -m 700 -p /tmp/cr-pilot-input /tmp/cr-pilot-output
.venv/bin/python examples/independent-agent-pilot/make_fresh_fixture.py --output-dir /tmp/cr-pilot-input
date -u '+%Y-%m-%dT%H:%M:%SZ'
shasum -a 256 /tmp/cr-pilot-input/bundle.json /tmp/cr-pilot-input/policy.json
```

Copy the exact hashes and UTC reading from those commands into this action
command; do not substitute example values:

```sh
.venv/bin/python examples/independent-agent-pilot/run_action.py \
  --record-assessment \
  --bundle /tmp/cr-pilot-input/bundle.json \
  --policy /tmp/cr-pilot-input/policy.json \
  --bundle-sha256 sha256:<bundle-hash> \
  --policy-sha256 sha256:<policy-hash> \
  --now-utc <operator-UTC-reading> \
  --max-age-seconds 86400 \
  --output-dir /tmp/cr-pilot-output
```

Repeat the same command once. The first must write `/tmp/cr-pilot-output/assessment.json`;
the second must refuse as a replay. Preserve both command outputs and exit
codes, the JSON result and its SHA-256, the input bytes/hashes, OS/Python
versions, repository commit/status, and imported consumer path/source hashes.
The script's report captures its actual imported module path and source file
hashes. To demonstrate interrupted recovery, the test suite injects a failure
after durable `PREPARED`; the next attempt must refuse and must not recreate
the assessment output. The operator-selected output directory must already
exist with mode `700`; its final path must not be a symlink, and the operator
must trust its parent path and local filesystem. State and output files use
mode `600`, and SQLite's immediate transaction serializes simultaneous
attempts. These controls apply only to that one local directory and are not a
multi-host ledger.

For an installed-package reproduction, use a non-editable isolated install and
run the wrapper outside the checkout:

```sh
cd /tmp
/path/to/venv/bin/python \
  /path/to/continuity-receipt/examples/independent-agent-pilot/run_pilot.py \
  --installed-package
```

The wrapper rejects installed-package mode if the imported consumer resolves
to the repository checkout, and its report hashes files from the actual
imported package path.

## Independent operator procedure

1. Obtain the packet from a committed, reviewed source snapshot. Record its
   full Git commit, whether the tree is clean, and the signed `v0.5.0` tag
   verification result. Do not call the producer’s current working tree an
   independent source.
2. Use the committed, reviewed consumer source snapshot in an isolated Python
   3.11+ environment. The hardening at source commit `e03a268` is not present
   in the published `continuity-receipt==0.5.0` wheel; do not claim that wheel
   includes it. Record Python and OS versions, installed `cryptography`
   version, `continuity_receipt.consumer.__file__`, and SHA-256 of that module
   plus its verifier dependencies. The action runner captures imported paths
   and hashes. Package metadata alone is not a source pin.
3. Preserve exact raw `bundle.json` and `policy.json` bytes. Verify sizes and
   hashes above before assessment. Run the CLI and harness from outside the
   producer’s execution environment where practical. Retain the exact
   commands, stdout, stderr, exit codes, and output JSON.
4. Repeat each negative control and confirm its expected refusal. Keep the
   original fixture unchanged; use temporary copies for mutations. Record any
   discrepancy rather than editing expected outputs to fit it.
5. A separate reviewer should retrieve the raw inputs, source/package pins,
   and outputs and reproduce the hashes and material outcomes. Record the
   operator’s host/admin separation evidence and the reviewer’s method. An
   agent name or different hostname alone does not prove independent
   administration.

### Operator evidence record (to be completed by the operator)

```text
operator/agent identifier:
operator relationship to producer/maintainer:
host and OS/kernel:
Python version:
source snapshot/archive filename and SHA-256:
installed distribution version:
cryptography version:
imported consumer module path and SHA-256:
verifier dependency file hashes:
source repository commit and clean/dirty result:
raw bundle SHA-256 and bytes:
raw policy SHA-256 and bytes:
commands, exit codes, stdout/stderr artifact paths:
positive and negative scenario results:
reviewer and independent reproduction method:
caller-supplied freshness time and maximum age:
fixed local assessment output path and SHA-256:
unresolved deviations or limitations:
```

Until a real operator completes that record and a separate reviewer reproduces
the evidence, no claim of independent reliance, agent adoption, or action is
supported.

## Evidence the profile does not provide

The consumer does not provide:

- real-world identity binding, principal authorization, mandate scope, or
  resource-level permission enforcement;
- freshness, trusted time, nonce consumption, replay prevention, or revocation
  freshness;
- completeness of undisclosed records or independent confirmation that an
  event happened;
- recovery semantics, an idempotency ledger, or safe execution after a crash;
- validation that local/external state bytes match receipt claims, unless a
  caller separately supplies and checks those bytes;
- hosted verifier behavior, VPS security, sandbox enforcement, or protection
  from hostile receipt text.

Receipt fields and links remain untrusted data. A relying agent must separately
implement and evidence authority, action scope, freshness, replay and recovery
controls, exact-state binding, and human/operator approval for any consequential
action. Do not infer those controls from `TRUSTED`, `ACCEPT`, a DID string, or
the presence of a record type.

## Primary local review record — 2026-09-30

The primary independently ran all eight cases against the checkout and again
from `/tmp` with `--installed-package` against the extracted published0.5.0
wheel. Imported path and distribution metadata were checked; expected
consumer outcomes and refusal classifications matched. Wheel SHA256 matched
PyPI metadata: `9b0be02327759b3f95519967f4257ce37a3ee44468359a88f84480d28c5935ee`.
This remains local reproduction, not independent operation or adoption.
