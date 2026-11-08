# AIC statutory rollback-freshness example (spec 0.6)

A worked example showing how a CPR bundle gives an agent-managed entity
(Delaware Ch. 51 draft "A.I.C." framing) the three freshness properties a
sandbox reviewer asks for: an **anchored chain head**, an **off-store state
commitment**, and a **refused rollback**.

> Scope note: the Delaware AIC/AMC Act is a *proposed* framework. This
> example demonstrates receipt mechanics only — it is not legal advice and
> does not assert statutory compliance.

## Files

| File | chain_head anchor | Expected `verify_bundle` |
|---|---|---|
| `aic_activity_bundle.json` | OpenTimestamps `proof_ref` | `TRUSTED` |
| `aic_activity_unanchored.json` | none | `PROVISIONAL` with `--require-anchor` (`head_anchor_missing`) |
| `aic_activity_rollback.json` | head regressed to prior receipt | `UNTRUSTED` (`head_mismatch`) |

## What the bundle commits to

- `session.pass.created` → `authority.grant` → `task.decision` →
  `task.execution` (with a `trace_guard` block as emitted by gate-lite's
  `mandala-ctl exec --trace`) → `state.commitment` → `task.termination`.
- `state.commitment` carries `state_kind: aic-activity-log/1.0`, an
  off-store `anchor_ref`, and an `aic` extension with the draft statutory
  disclosure fields (`member_entity`, `aic_registered_name`,
  `sandbox_disclosure`, `capitalization_floor_ok`,
  `chain_head_scitt_anchor`). Extension fields are issuer claims inside the
  signed body — they are evidence of what was declared, not proof the
  declarations are true.
- `chain_head` commits `seq` + `receipt_id` + canonical digest of the final
  receipt, with an `opentimestamps` anchor. An unanchored head is unsigned
  metadata; only the anchor (or transparency registration) makes it
  evidence.

## Verify

```bash
python3 -m continuity_receipt.verify examples/04_aic_statutory_bundle/aic_activity_bundle.json
python3 -m continuity_receipt.verify examples/04_aic_statutory_bundle/aic_activity_unanchored.json --require-anchor
python3 -m continuity_receipt.verify examples/04_aic_statutory_bundle/aic_activity_rollback.json
python3 examples/04_aic_statutory_bundle/verify_example.py
```

## Rollback story

`aic_activity_rollback.json` keeps every receipt signature valid but points
`chain_head` at the *previous* receipt — simulating a store restored to an
earlier snapshot. The verifier recomputes the canonical digest of the final
receipt and refuses with `head_mismatch`. Combined with the off-store
`anchor_ref` on `state.commitment` (and PACMI T07/T09 coverage in
`vectors/26_*`), this is the published freshness vector referenced by the
AIC readiness packet.

## Regenerate

```bash
python3 tools/make_aic_statutory_example.py
```

Output is deterministic (uuid5 ids, fixed timestamps).
