# Example 02 — gate-lite state-commitment producer capture (0.5)

A real gate-lite execution emitting its own `continuity-receipt/0.5` bundle:
`task.execution` with a pinned `runner_profile` (`sandbox_class: "bwrap"`)
and a `state.commitment` over the orchestrator registry — `TRUSTED` from
both the Python and Rust 0.5 verifiers.

This serves the `INTEGRATION_READINESS.md` row **"Second producer capture"**.
It is a **same-host capture on the unpublished candidate**: not independent
adoption, and it does not authorize tagging, publishing, or hosted claims.

## Producer

- gate-lite, branch `codex/gate-lite-05-profile`, capture commit `cb0f721`
  (repo `lbailey94/mandala-os`, private).
- Evidence directory in that repo:
  `gate-lite/evidence/state-commitment-05-local-2026-09-28/` — `REPORT.md`,
  `bundle.json`, `verdict.json`, `rust-verdict.json`,
  `registry-after-exec.db`, `recompute.py`, `transcript.txt`.
- Continuity-receipt runtime: `0.5.0a0` from source at `d34c499`
  (this branch), installed editable.

## Bundle

- `gate_lite_bundle.json` — sha256
  `1c1947cb6da8f46fd85bbde57713ddfccdbc9f84281bc17361d4821ebb9774a2`
- Issuer: `did:key:z6MksimyjJhBvzyrB3Z5CMHDte8Ubvk1jx5P12ffRa4JptD2`
- Receipts: `session.pass.created`, `task.decision`, `task.execution`,
  `state.commitment`, `task.termination` (exec exit 0)
- `runner_profile`: wrapper digest
  `sha256:f7da8d6c…96411e`, invocation digest `sha256:37de8483…faf4a`
- `state.commitment`: `state_kind=gate-lite.registry-head`,
  `scope=gate-lite.registry`, `count=3`,
  `head_digest=sha256:836c0c55…f10c4e1`

## Independent recomputation

`recompute.py` in the producer evidence directory reports **ALL MATCH**:
wrapper executable digest; invocation digest over the canonical
`["--exec", envelope]` argv (schema/program/args/net/workspace/rw); and the
commitment count and head digest over the captured registry snapshot with
the one documented post-emission CAS reverted (slot `active` → `starting`;
the commitment is emitted before the slot's active transition).

## Verify

```bash
continuity-receipt-verify examples/02_gate_lite_state_commitment/gate_lite_bundle.json
```

Limits: the verifier checks signatures and shape only — it does not observe
Bubblewrap execution, recompute the digests, or prove state completeness.
