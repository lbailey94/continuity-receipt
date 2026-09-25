# Spec 0.5 integration readiness gate (development)

**Status:** open. A passing test suite is evidence for a particular source tree,
not proof that a producer enforced its recorded claims. Spec 0.4 remains the
published and hosted surface. This gate does not authorize a tag, package
upload, hosted rollout, or website claim.

## Candidate identity

Before running the gate, record the exact commit and tree, dirty status,
Python/Rust package versions, vector-manifest digests, commands, and toolchain
versions. If the tree is dirty, record hashes of the changed files and qualify
that exact tree rather than naming only the commit. Keep the published
`vectors/manifest.json` and its 40 vectors byte-for-byte unchanged.

## Required evidence

| Gate | Acceptance evidence |
|---|---|
| Wire and parser behavior | Both CLIs reject duplicate JSON member names, including nested names; 0.5 state counts have one precisely specified, interoperable representation and boundary vectors; legacy 0.1–0.4 fixtures still verify. |
| Python/Rust conformance | Full suites, both bundle manifests, verification receipts, disclosure and anchor differentials, and hostile-input parity pass at the exact candidate tree. Record counts and any sampled-probe seed/size. |
| Local producer roundtrip | `tools/local_integration_probe.py` emits from bytes read at runtime, recomputes file and mandate digests independently, obtains matching Python/Rust verdicts, detects a signed-body edit, and demonstrates that an external file change requires consumer recomputation. This qualifies the example producer only. |
| Second producer capture | A named WhiteMagic, Mandala, or independent adopter runtime emits its own 0.5 bundle. Preserve exact bundle bytes and SHA-256, producer commit/configuration/invocation, key-custody description, and referenced state or snapshot. A separate reader recomputes the count and digest; both verifiers run from pinned builds. A fixture modeled from that runtime fails this gate. |
| Adversarial review | A reviewer independent of the implementation reports tested paths, reproducible findings, uncovered areas, and residual risk for 0.5 semantics, mixed versions, serialization, revocation/key lifecycle, and state-claim limits. Resolve or explicitly accept each finding before release qualification. |
| Package rehearsal | Build wheel, sdist, and crate from the same candidate; install in clean environments and exercise both CLIs on published and 0.5 vectors. Check that package contents and metadata match the candidate, with no dependency on local untracked files. |

All rows must pass to call the candidate **integration ready**. A red row or
missing evidence is reported as open with the exact failing command or missing
artifact. Published-package, hosted-service, and site readiness are separate
decisions after this gate.

## Reproduce the local portion

```sh
python3 -m unittest discover -s tests -v
cargo test --manifest-path rust/Cargo.toml
cargo build --manifest-path rust/Cargo.toml
python3 tools/differential_vectors.py
python3 tools/differential_vectors.py --manifest vectors/manifest-0.5.json
python3 tools/differential_verification_receipts.py
python3 tools/differential_disclose.py
python3 tools/differential_anchor.py
python3 tools/hostile_input_probe.py --sample 300 --require-parity
python3 tools/hostile_input_probe.py --vector-manifest vectors/manifest-0.5.json --sample 100 --require-parity
python3 tools/local_integration_probe.py
```

The local probe deliberately prints `local-file-snapshot-only`. Its PASS is
one row of this gate, not a substitute for the second producer capture or
independent review.
