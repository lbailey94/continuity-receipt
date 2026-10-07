# Second producer capture — trust-without-cloud gated-flow (2026-10-07)

Real `continuity-receipt/0.5` capture emitted by the `trust-without-cloud`
gated-flow harness on host **T4800-S**, qualifying
`INTEGRATION_READINESS.md` row **"Second producer capture"**. Same host and
operator as the earlier MandalaOS gate-lite capture; distinct runtime and
repository. This is not independent adoption.

## Producer

- Repo: `trust-without-cloud`, branch `feat/second-producer-05`,
  commit `5ef0949994cdead7538e3666c26d19f4a7658806` (unpushed).
- Flow: `gated-flow/run_flow.py` — signed gate-lite pass → deterministic
  policy decision (AgentJev advisory head unavailable on this host) →
  `wm remember` write to a Gen3 scratch store → recall → 0.5 receipts.
- Runtime: WhiteMagic Gen3 `wm` (`/home/lucas/.local/bin/wm`), gate-lite
  `/home/lucas/Desktop/front burner/MANDALA_OS/gate-lite`, candidate
  `continuity_receipt` 0.5 package from the pinned CR checkout.
- Command (also in `producer-metadata.json`):

  ```sh
  env PYTHONPATH="/home/lucas/Desktop/front burner/WHITEMAGIC/worktrees/cr-main" \
      GATE_LITE_PATH="/home/lucas/Desktop/front burner/MANDALA_OS/gate-lite" \
      WM_BIN="/home/lucas/.local/bin/wm" \
      python3 gated-flow/run_flow.py --advisory auto \
        --store /tmp/opencode/second-producer-2026-10-07/store \
        --out /tmp/opencode/second-producer-2026-10-07/out
  ```

- Key custody: the pass/agent Ed25519 keys are deterministic demo seeds
  generated in-process (`gate-lite-demo-v1`, `agent-demo-v1`); no private key
  material is written to disk or committed. Unedited producer output:
  `transcript.txt`.

## Bundle

- `bundle.json` — sha256
  `a4e1f5fe04c809cfa5f395e16c0be41c2dc5daf3d5e71d333f04a14eab24ce39`
- `task_id` `urn:uuid:61c24be4-0698-4f47-8125-2dbc54fa334d`; all five
  receipts are `continuity-receipt/0.5`: `session.pass.created`,
  `task.decision`, `task.execution` (`sandbox_class: "none"` — no OS
  confinement claim), `state.commitment`, `task.termination`.
- `state.commitment`: `state_kind=file-snapshot-v1`,
  `scope=trust-without-cloud.gated-flow.execution-state`, `count=3`,
  `head_digest=sha256:b6bfd995286e38a5bd83789a4b668d559d0d42f53a4ed1178e20df07d2f32a55`.
- Referenced state: `state.json` (sha256
  `6672e6c000630595fd65eaa74152360698fa368860783f29141a81a5e06161fb`) over
  the preserved files in `state-files/` (`pass-claims.json`,
  `decision.json`, `recall.txt`).

## Verification and qualification

- Offline CLI verification of the captured bytes: Python
  (`python3 -m continuity_receipt.verify`) and Rust
  (`rust/target/debug/continuity-receipt-verify`) both **TRUSTED**, exit 0 —
  `verify-bundle.python.json`, `verify-bundle.rust.json`.
- Negative control: the emitted `.state-tampered.json` twin (commitment
  `count` incremented) verifies **UNTRUSTED** (`bad_signature`) under both
  implementations — `verify-state-tampered.python.json`,
  `verify-state-tampered.rust.json`. The decision-tamper twin is retained as
  `bundle.json.decision-tampered.json` (flow transcript records UNTRUSTED).
- `tools/qualify_adopter_capture.py` → **PASS**
  (`qualification.json`): the assessor recomputed the file-snapshot count and
  head digest from `state-files/`, every referenced file matched size and
  SHA-256, the verifier source checkout matched pinned `source_commit`
  `221228190e22c63382c94fe06b1ddfdfb8971521` and was clean, both pinned
  verifier executables matched, both implementations returned equal TRUSTED
  verdicts/error codes, and the bundle bytes were unchanged during
  assessment.

## Limits

- Same host (T4800-S) and same operator (Lucas Bailey) as the earlier capture;
  this closes the runtime/repo gap, not the independent-adoption gap.
- The verifiers check shape, signatures, and the chain only; they do not
  prove store integrity, sandbox enforcement, or state completeness.
- The AgentJev advisory model was not exercised (service not running); the
  deterministic policy predicate decided the run and the receipt records
  `advisory.agentjev=unavailable`.
- Independent adversarial review (`INTEGRATION_READINESS.md`) remains open.
