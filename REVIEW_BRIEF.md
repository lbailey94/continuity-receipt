# Review brief: CPR verification and its trust boundary

Prepared 26 October 2026. This is a proposed technical review scope, not a
completed independent audit or an agreement to commission one.

Implementation baseline: `146c4d2439e4f11cc50776e754e98081bb41869e`.
Record `git rev-parse HEAD`, `git status --short`, interpreter/compiler
versions, and artifact hashes with every review run. A later source commit,
registry package, local receiver candidate, or hosted deployment needs its
own identity and evidence.

Repository: <https://github.com/lbailey94/continuity-receipt>.
Contact: `security@whitemagic.dev` for security findings.

## What is being reviewed

CPR verifies signed records and their disclosed commitments. The published
specification is `continuity-receipt/0.5`; Python and Rust package metadata
is 0.5.1, and the JavaScript package metadata is 0.1.1. Implementations also
accept experimental 0.6 authority records. Package acceptance does not make
the 0.6 draft normative.

The Python, Rust, and JavaScript verifiers are separate language
implementations maintained in this project. Their agreement is differential
test evidence, not three independent organizations auditing each other.
Fixture totals and expected outcomes live in the manifests; count them from
the selected checkout rather than copying a historical test tally.

### Known source/package mismatch: experimental head binding

On 26 October, the published PyPI 0.5.1 wheel
(`sha256:9268eeff8208a3ac3ee9425c9267a48632d59ddd7044097a5542ee4880183144`)
returned `TRUSTED` with exit 0 for `vectors/25b_head_mismatch.json`.
The implementation baseline above returned `UNTRUSTED`, `head_mismatch`,
exit 1 for the same bytes. Both report package version 0.5.1. This concerns
the experimental 0.6 `chain_head` behavior, not a failure of the published
0.5 signature rules.

Reproduce by installing the registry wheel and the selected source into
separate environments, then invoking `python -m continuity_receipt.verify`
on that fixture from outside either checkout. The full installed-package
smoke stops at the registry mismatch. Keep this release gate open: current
source tests cannot qualify the published package or a hosted runtime for
head binding. Shipping that behavior requires a separately identified,
versioned artifact and its acceptance evidence.

## First review scope

| Boundary | Code and evidence | Questions to try to falsify |
|---|---|---|
| Raw input to structured result | `continuity_receipt/strict_json.py`, `verify.py`; corresponding Rust/JS parsers; `tests/test_hostile_input.py` | Do duplicate members, invalid UTF-8, non-finite numbers, deep inputs, or oversized bundles crash, become ambiguous, or differ across languages? |
| Signed object to bundle verdict | `SPEC.md`, `canon.py`, `keys.py`, `records.py`; `vectors/manifest.json`, `manifest-0.5.json` | Can altered bytes, substituted references, bad signatures, or missing required evidence produce a clean verdict? |
| Verification receipt to recorded result | `VERIFICATION_RECEIPTS.md`, `verification.py`; `vectors/verification/manifest.json` | Are bundle digest, error codes, reasons, verdict, and revocation rules internally consistent? Does the caller pin the expected issuer separately? |
| Signed claim to consumer decision | `consumer.py`, `SPEC_0.6_DRAFT.md`, `THREAT_MODEL.md` | Are issuer assertions, caller policy, principal authority, execution, and freshness kept distinct? |
| Anchor representation to proof verification | `ANCHORING.md`, `anchor.py`, Rust anchor tooling | Does checking an anchor's shape or digest get confused with verifying its proof, trusted time, or a validated Bitcoin chain? |

## Reproduce from a clean checkout

Use an isolated environment and the selected source, with Python 3.11+, jq,
Node.js, and Rust/Cargo available for the respective language checks:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install . jsonschema
python -m unittest discover -s tests -v
python -m unittest discover -s examples/independent-agent-pilot -p 'test_*.py' -v
bash tools/audit_smoke.sh
cargo test --locked --manifest-path rust/Cargo.toml
cargo build --locked --manifest-path rust/Cargo.toml
python tools/differential_vectors.py
python tools/differential_vectors.py --manifest vectors/manifest-0.5.json
python tools/differential_vectors.py --manifest vectors/manifest-0.6.json
python tools/differential_verification_receipts.py
python tools/hostile_input_probe.py --sample 300 --require-parity
(cd js && npm ci --no-audit --no-fund && npm test && node tools/parity.mjs --strict)
```

Dependency installation may use the network. `audit_smoke.sh` performs only
local verification after installation, runs from a temporary empty working
directory, and rejects an import from this source checkout. It checks the
installed Python package against all three bundle manifests and the
verification-receipt manifest, including expected failure exit codes.
It is a fixture check, not fuzzing, an audit, or a hosted-service test.

## Explicit limits and useful negative controls

- `TRUSTED` is a verdict under CPR's implemented rules. A valid signature
  binds bytes to a key; the caller must establish the expected issuer and
  whether that issuer is authorized. It does not establish truthful events,
  complete capture, resource isolation, or consent.
- Restoring a genuine old bundle can preserve every signature. Currentness
  requires an independently retained expected head or policy outside the
  rolled-back data. A bundle's own state commitment is an issuer claim.
- The experimental checkpointed memory receiver is a separate candidate,
  absent from this baseline. It gates its named resume path; it does not
  intercept every WhiteMagic read. Restoring both old data and matching old
  trust state can recover previously accepted text. Secure deletion and
  universal non-resurrection are not established.
- Salted commitments and checking encrypted-state digests without a
  decryption key do not, by themselves, establish a zero-knowledge proof
  protocol.
- A SCITT mapping draft and a signed CPR verification receipt do not
  establish registration with a SCITT transparency service or COSE receipt
  interoperability. Those require separate wire examples and verification.
- Hosted key custody, deployed bytes, access control, caching, logging,
  payment handling, and availability are a separate review scope. Local
  results do not qualify that runtime.
- Pre-publication key compromise, withheld revocation statements, and
  issuer-asserted time remain trust-policy concerns described in
  `THREAT_MODEL.md`.

## Reviewer output

For each finding, record the exact commit/artifact, affected boundary,
reproducer, expected and actual result, severity rationale, and coverage
limits. Keep a finding open until its disposition and any claimed fix have
been checked against the revised artifact. Review effort, compensation,
access, and disclosure timing must be agreed separately before an engagement.
