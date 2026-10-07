# Spec 0.5 integration readiness gate (development)

**Status:** open — the 0.5.0/0.5.1 publications (2026-09-30 / 2026-10-01)
happened before this gate closed; see the gate ledger below. Spec 0.5 is
published (tooling 0.5.1); 0.6 remains an experimental candidate. As of
2026-10-07 the second-producer capture row is **done** (trust-without-cloud
gated-flow, distinct runtime/repo, same host/operator); independent
adversarial review remains open. A passing test suite is evidence for a
particular source tree, not proof that a producer enforced its recorded
claims. This gate does not authorize any further tag, package upload, hosted
rollout, or website claim.

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

## Gate ledger

Status of the rows as of **2026-10-07**:

| Gate | Status | Evidence |
|---|---|---|
| Second producer capture | **done** (2026-10-07) | The `trust-without-cloud` gated-flow harness (repo `lbailey94/trust-without-cloud`, producer commit `5ef0949`, branch `feat/second-producer-05`) emitted its own 0.5 bundle from the WhiteMagic Gen3 kernel on T4800-S: `docs/evidence/second-producer-trust-without-cloud-2026-10-07/` (bundle sha256 `a4e1f5fe…24ce39`, `state.commitment` `file-snapshot-v1` count 3, head `sha256:b6bfd995…f32a55`). `tools/qualify_adopter_capture.py` reports **PASS** (`qualification.json`): state recomputed from preserved files, verifier source pinned at `2212281` clean, Python/Rust both TRUSTED with equal error codes, tamper twin UNTRUSTED. Distinct runtime and repository, but same host and operator as the MandalaOS gate-lite capture; independent adoption remains open. |
| Independent adversarial review | **open** | Maintainer-side review only (`REVIEW_NOTES_05.md`, 2026-09-24/28). `REVIEW_BRIEF_05.md` is prepared; no reviewer independent of the implementation has reported findings. |

**Publication timing:** spec 0.5.0 shipped 2026-09-30 and tooling 0.5.1 on
2026-10-01 while both rows above were — and remain — open. The gate is
retrospective evidence for the 0.5 line; closing these rows still strengthens
the published record, and both remain prerequisites for freezing 0.6.

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
