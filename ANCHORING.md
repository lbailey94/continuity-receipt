# Anchoring — policy and decision record

**Status:** decided 2026-09-18 (v0 policy). Applies to `continuity-receipt/0.1`–`0.2`.
**Scope:** the `anchors[]` bundle member and issuance practice; not a new protocol layer.

## Decision

Anchoring is **optional in the format and recommended in practice** when a
consumer needs an independent timestamp:

1. **OpenTimestamps (OTS) is the recommended default** issuance path. It is
   free, requires no custody, publishes only a hash, and is verifiable with
   open tooling. An OTS attestation proves the anchored digest existed no
   later than the Bitcoin block in which it was included.
2. **Public-chain anchoring is a supported peer type**, for counterparties
   that require a chain-reachable identifier (SAIHM's reference deployment is
   an example). The spec recommends no chain; the format stays
   ledger-agnostic, and the anchor object carries whatever identifier the
   counterparty's tooling needs.
3. **`custom` is the escape hatch** for private ledgers and registries. A
   consumer that cannot describe a custom anchor's verification MUST treat it
   as opaque metadata, not evidence.
4. **No mandatory anchoring.** A receipt verifies without anchors. A consumer
   that requires an anchor states that explicitly (`--require-anchor` →
   `PROVISIONAL` + `anchor_missing` when absent), so the requirement travels
   with the verdict instead of being assumed.
5. **Verification scope:** this repository's verifier checks anchor *shape and
   digest binding only* — `anchor.hash == receipt_digest(target)` and the
   declared type. Proof verification lives in the companion tool
   (`continuity_receipt.anchor` / `continuity-receipt-anchor`, landed
   2026-09-21): it replays a detached `.ots` proof from the file digest and
   checks a Bitcoin attestation against a caller-supplied 80-byte block
   header by exact merkle-root equality, reporting `verified` / `unverified`
   / `mismatch` / `invalid` with machine codes. `type: opentimestamps` remains
   a **claim** until that tool reports `verified`, and even then the header is
   not chain-validated (no proof-of-work, confirmation depth, or reorg
   checks) — supply the header from a source you trust and interpret
   `verified` as "this digest is the merkle root of that header".

## What an anchor proves — and what it does not

With a checked proof: the anchored digest existed no later than the anchor's
timestamp, and it was not altered afterwards. Transitively, anchoring a
chain's final receipt commits to every earlier receipt through the `prev`
links, provided the chain itself verifies.

It does **not** prove that statements inside the receipt are true. A
timestamp is evidence of existence and ordering, not of honesty. Erasure and
revocation semantics are separate (SPEC §6, §7) and are not affected by
anchoring.

## Options considered

| | OpenTimestamps | Public chain (tx/OP_RETURN) | Defer until asked |
|---|---|---|---|
| Cost | free | gas/tx fee | none |
| Custody | none | wallet + key custody | none |
| Latency | minutes to hours (block cadence) | seconds to minutes | — |
| Lock-in | none (federated calendars; Bitcoin anchors) | chain-specific tooling | none |
| Privacy | hash only; no identity attached | address/value linkability common | — |
| Dependency | calendar servers + Bitcoin headers | RPC/node/explorer | — |
| Fit with non-goals | strong (no custody, no payments) | weaker (custody, fee rail) | no anchor evidence |

Decision rationale: the format's non-goals exclude custody and payment rails,
so the default issuance path must not require either. OTS gives independent
timestamping at zero cost; chain anchoring remains available where a
counterparty demands it, without the spec blessing a chain.

## Issuance workflow (recommended)

1. Freeze the bundle. Compute the target receipt's digest exactly as the
   verifier does (canonical bytes excluding `sig`).
2. Prefer the **chain tip** as the anchor target: one anchor per task chain
   commits transitively to the earlier receipts and leaks less than anchoring
   every receipt.
3. `ots stamp <bundle-file>` (or the calendar API) and keep `<file>.ots`
   beside the bundle. **Never mutate the bundle afterwards** — any change to
   the anchored receipt invalidates the binding.
4. After Bitcoin confirmation, `ots upgrade` the proof and verify it with
   `ots verify`. Store the upgraded proof with the bundle.
5. Record the anchor in the bundle:

   ```json
   "anchors": [
     {
       "target": "urn:uuid:<receipt_id>",
       "hash": "sha256:<receipt_digest>",
       "anchor": { "type": "opentimestamps", "value": "https://<calendar>/..." }
     }
   ]
   ```

6. For a counterparty requiring chain anchoring, same shape with
   `"type": "public-chain"` and the chain-reachable identifier in `value`.

## Failure and renewal guidance

- **Calendar unavailability:** submit to more than one OTS calendar; any one
  sufficient proof is enough to verify.
- **Reorgs:** treat an anchor as settled only after the transaction has a
  small confirmation depth; long-range reorgs are the residual risk.
- **Long horizons:** keep the upgraded proof; re-upgrade against current
  headers before archiving if the proof references headers a later verifier
  may not have.
- **Mutated bundles:** the digest binding fails (`anchor_invalid`); re-issue
  under a new receipt, do not edit an anchored one.

## Open items

- **OTS proof verification** — **landed 2026-09-21** as the companion tool
  `continuity_receipt.anchor` (`continuity-receipt-anchor verify`), with the
  LEB128 wire-format parser and header check pinned by tests and 5 real
  example proofs under `vectors/anchor/`. Remaining: optional Rust parity.
  Header supply stays caller-owned; a header-source helper is possible but
  would add a dependency or network call.
- Bundle-root anchoring (one anchor for many chains) is not expressible in
  0.2; the schema binds anchors to receipts. Revisit if consumers need it.
- No chain recommendation is deliberate; revisit only with deployment demand.

## Interop note

SAIHM (`draft-saihm-memory-protocol-01`) mandates public-chain anchoring per
mutating operation and is chain-agnostic about the chain. Our `public-chain`
anchor type is the mapping surface: `value` carries the chain-reachable
identifier sufficient to reproduce the receipt independently, while the
digest binding stays ours. See the mapping note offered to the W3C AI Agent
Memory Interoperability CG.
