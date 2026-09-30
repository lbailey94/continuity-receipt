# Design note — compute delivery & SLA attestation profile (candidate, demand-gated)

**Status:** design note, 2026-09-30. Non-normative; candidate profile for a
future revision. Per the repo rule (every change ships with a vector,
acceptance test, or documented negative case) this stays a candidate until a
producer/adopter exists. Companion to `DESIGN_NOTE_EXTERNAL_EVIDENCE_REFS.md`
and the Pass 22/23 positioning work (compute-attestation wedge).

## Why now (observed 2026-09-30)

- GPU debt is a rated asset class (first IG GPU-backed deal, 2026-03);
  bankruptcy-remote SPVs, first-priority liens on serial-numbered GPUs,
  >$20B outstanding — **collateral legibility is the financing constraint**.
- Compute futures were gated by the CFTC to **>= Nov 9** (fragmentation /
  manipulation concerns); live margined activity is OTC; SF Compute runs an
  order book with a delivery-vs-payment ledger but is itself the
  counterparty; a formal clearing structure ("Compute Clear") is announced,
  not live.
- Escrow-until-verified is already an operational pattern: a $128.9M GPU
  facility (2026-09-23) holds capital until hardware is installed **and
  independently verified**.
- Benchmark integrity is the missing layer: four compute indices differed by
  ~$0.88/hr on the same GPU class (Apr 2026); attestation of *what was
  delivered* is the binding constraint for both settlement and credit.

The wedge: a bounded, offline-verifiable receipt for **what was delivered,
under which SLA, with what evidence** — not a market, not a price feed.

## What already maps (do not re-invent)

- **SLA terms exist off-receipt:** `agreement.offer` / `agreement.accept`
  (`terms_hash`, `valid_until`, `nonce`) already bind parties to private
  terms — an SLA (units, window, thresholds, benchmark reference) is exactly
  such a terms document; only its hash is signed.
- **Execution evidence exists:** `task.execution` carries `resources`
  (`cpu_ms`, `mem_peak_mb`, `disk_peak_mb`), `sandbox_class`, and the 0.5
  `runner_profile` (`profile_id`, `executable_digest`, `invocation_digest`).
- **Delivery shape exists:** `delivery.attestation` (`request_hash`,
  `response_hash`, optional counterparty signature, `spec_ref`,
  `quality_flags[]`) — `spec_ref` is where "what done means" lives.
- **Settlement binding exists:** `settlement` has `rail` (x402|invoice|
  stripe|offchain|none), `amount`, **`gated_on_delivery`**, and
  `dispute_window_s` — the escrow pattern needs no new record.
- **State/recovery exists:** `state.commitment` (chain-head + file
  snapshots) for instance/workload state; SCITT composition per the
  external-evidence note.
- **External evidence exists:** anchors (OpenTimestamps/public-chain) and
  the `external_ref` candidate (AER-1, TEE attestation, SCITT receipts).

## Candidate profile fields (if adopted)

- **`spec_ref` = `compute-sla/<version>`** on `delivery.attestation`; the
  thresholds themselves live in the offer/accept terms (off-receipt).
- **Metering body (new candidate record or a body variant):**
  `provider` (did/identifier), `node_ref` (device/serial digest — never raw
  serials on wire), `gpu_class`, `window` {`start`, `end`},
  `delivered` {`node_hours` | `gpu_hours`, `tokens`, `flops` as applicable},
  `utilization`, `benchmark` {`index_id`, `value`, `source_ref`},
  `measurement_class` (`provider_reported` | `gateway_observed` |
  `tee_attested`).
- **Environment attestation:** `environment_ref` → external TEE/RATS
  evidence (PTV or RATS attestation results), with the usual rule that a
  reference is evidence, not an upgrade.
- **SLA evaluation:** thresholds vs delivered → `outcome`
  (`delivered | shortfall | failed`), shortfall quantities, and
  `quality_flags[]` on the delivery attestation.
- **Recovery (optional):** `state.commitment` digests, plus a SCITT
  `external_ref` when a recovery event is registered.

## Verification rules (proposed shape)

1. **Totals coherence:** window entries are disjoint and sum to the
   contracted quantities; a missing window is `INSUFFICIENT_EVIDENCE`, not
   zero.
2. **Benchmark resolution:** when the SLA names a benchmark index, its
   `source_ref` must resolve to a digest-pinned snapshot; unresolvable
   reference → PROVISIONAL at best.
3. **Measurement class is never upgraded** (provenance-class discipline):
   `provider_reported` metering stays reported even if a TEE measurement is
   attached to a *different* axis.
4. **No equivalence claims:** the profile attests what was measured and
   signed; it never claims the recovered/substituted workload is
   semantically equivalent (the SCITT draft's §4.8 hazard applies here
   verbatim).
5. **Settlement gating:** `gated_on_delivery: true` requires a resolvable
   delivery attestation for the same agreement; shortfall outcomes leave
   the amount disputed, never silently zero.

## Non-goals

Not a compute market, not a price oracle, not hardware attestation itself,
not a financial instrument. Issuer honesty remains out of scope (the
receipts prove what was signed). Benchmark index integrity is a separate
attestation axis and a candidate for its own producer profile.

## Adopter gates (keep honest)

- **Lighthouse candidates:** a compute marketplace with settlement
  gating (escrow-until-verified operators), a financing-side auditor, or a
  dispute/arbitration surface.
- Do not wire-format anything until one of these asks; vectors and an
  acceptance test land together with any profile text.
- Watch: CME/CFTC decision (Nov 9) and comment docket (Oct 20); Nodal
  "Compute Clear" launch; any new escrow-until-verified facility.

## Open questions

1. Unit normalization across providers (GPU-hours vs node-hours vs tokens).
2. Sampling vs full metering: statistical delivery attestations need a
   sampling method in the terms document.
3. Privacy: utilization/metering data is commercially sensitive; prefer
   digest commitments + selective disclosure over raw series.
4. Multi-provider chains: one SLA over several providers needs
   per-provider delivery attestations plus a summary commitment.
5. Time source: windows need an anchor policy (issuer clock vs external
   timestamp) — reuse the existing anchor workflow.
