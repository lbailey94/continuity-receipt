# Independent review brief — draft 0.5 candidate

**Status:** invitation prepared; no external review report is recorded for
this candidate. Spec 0.4 and packages 0.4.0 remain the published surface.
Draft 0.5 is unpublished and is not release-qualified.

## Candidate under review

Review the 0.5 implementation at commit
`73c2086` (`docs(0.5): resolve design questions D1-D4 with vectors 22r/22s`),
the exact candidate-state tree identified by that commit. Its published-vector
manifest SHA-256 is
`eac2c24d88129f19efed9ecf3712d33a537e651ba964e524d0725b0aa8a618b3`; the
separate 0.5 manifest SHA-256 is
`4b0c4bbca138e38d49887bb48c741784fb53ff9778b009fbc81c09cddbae24dc`.
Recompute these digests from the checkout before review. Do not include later
0.6 or evidence-exporter commits in this candidate. The current development
branch has those later commits as descendants; no branch rewrite is needed.

For an isolated checkout, use a detached worktree at the exact commit. Keep the
candidate and all reviewed input bytes unchanged; record any proposed fix as a
separate patch or follow-up commit. Before inviting the reviewer, capture
`git status --porcelain`, `git rev-parse HEAD`, tree hash, toolchain versions,
and both manifest digests. If any source changes, assign a new candidate
identity and repeat the relevant qualification.

## Review scope

Please independently examine draft 0.5 in `SPEC_0.5_DRAFT.md`, its schema,
the 0.5 vectors and manifest, Python and Rust verifiers, and the captured
producer example below. Focus on:

1. `state.commitment`: canonicalization, count and digest boundaries, scope
   semantics, missing/extra inputs, and whether independent recomputation is
   possible from the described evidence.
2. Execution claims: runner class and profile binding, sandbox labels, and
   whether wording separates issuer assertions from demonstrated isolation.
3. Mixed-version chains and compatibility with 0.1–0.4.
4. Duplicate JSON members, malformed/deep/oversized inputs, and Python/Rust
   verdict parity.
5. Whether examples and documentation overstate what the signature proves.

The 0.5 feature inventory includes the local execution vocabulary and runner
profile binding, `state.commitment`, carried agreement binding, and the
Mandala gate-lite producer capture. The example bundle is
`examples/02_gate_lite_state_commitment/gate_lite_bundle.json`; recorded hashes
for bundle, Python verdict, and Rust verdict are respectively:

```text
1c1947cb6da8f46fd85bbde57713ddfccdbc9f84281bc17361d4821ebb9774a2  gate_lite_bundle.json
67b0e0750f502c37855e14c884c9ac4d7eef4b19cda1dcf332c3c152130c178e  verdict.json
97dae76992ffe5af608ee9ee9ac0b58d4dd31138b1bb7333149fd4cc593b9e45  rust-verdict.json
```

The producer capture is same-host evidence, not independent adoption or
corroboration. See its README for source/capture provenance and limitations.

## Reproduction and evidence requested

Run from the pinned candidate checkout and report command output, environment,
and exact counts:

```sh
python3 -m unittest discover -s tests -v
cargo test --manifest-path rust/Cargo.toml
python3 tools/differential_vectors.py
python3 tools/differential_vectors.py --manifest vectors/manifest-0.5.json
python3 tools/differential_verification_receipts.py
python3 tools/differential_disclose.py
python3 tools/differential_anchor.py
python3 tools/hostile_input_probe.py --sample 300 --require-parity
python3 tools/hostile_input_probe.py --vector-manifest vectors/manifest-0.5.json --sample 100 --require-parity
python3 tools/local_integration_probe.py
```

Please provide findings as critical/major/minor/nit with minimal reproduction
steps, the surfaces not covered, and residual risk. No report should be
described as approval; the maintainer will disposition findings and update the
candidate before any release decision.

## Explicitly outside this invitation

Published 0.4 external-review scope, hosted-service operations, package
publication, legal compliance conclusions, producer honesty, runtime
confinement on a separate machine, and 0.6 authority semantics. Draft 0.6 is
not part of this pinned candidate.

## Candidate separation without branch surgery

The current 0.6 and exporter work is on descendant commits after `73c2086`.
Preserve it. For 0.5 review and qualification, create a temporary detached
worktree at `73c2086` when needed; develop any 0.5 fixes on a new reviewable
branch based on that candidate. Do not reset, rebase, or force-update the
current branch. After review, decide whether to forward-port selected fixes
into the 0.6 line or prepare a new 0.5 candidate from the reviewed base. The
separate 0.5 integration gate in `INTEGRATION_READINESS.md` remains open; this
brief does not declare readiness or authorize a tag, package, hosted rollout,
or website claim.
