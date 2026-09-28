# Crosswalk: continuity-receipt ↔ IETF agent-receipt work

**Status:** informational, 2026-09-28. Not normative; not an endorsement or
adoption claim by any draft's authors. Drafts are works in progress and may
change. Companion interop probe: `tools/interop_sahu_vectors.py` (passing).

## 1. Interop result (independent reproduction)

We reproduced `draft-sahu-agent-action-receipts-00` Appendix A with an
independent implementation in this repository (probe run 2026-09-28):

- seed `01×32` derives the published public key — pass
- Ed25519 verifies over their canonical bytes for vectors 1 and 2 — pass
- SHA-256 of vector 1's serialized line equals vector 2's `prev_hash`
  (`18a2a7…`) — pass (their chain link digests transmitted octets)
- our canonical reconstruction is byte-identical to both published canonical
  sequences — pass
- tamper case (actor.user alice→mallory): signature rejected, chain link
  broken — pass

Meaning: their published bytes are reproducible by an outside implementation,
including their non-JCS canonical order. It does not mean either format can
consume the other's objects (see §5).

## 2. Field mapping — draft-sahu ↔ continuity-receipt

| sahu | continuity-receipt | note |
|---|---|---|
| `step_id` | receipt `id` | both are per-record identifiers |
| `action_id` | receipt type / body type (e.g. `task.execution`, `delivery.attestation`) | theirs is flat and namespaced; ours is a typed record with per-type fields |
| `params` | body fields (per type) | both bounded; ours is typed, theirs is free-form with sorting rules |
| `success` | per-type outcome (e.g. execution outcome) | present where our record type defines it |
| `ts_ms` | `issued_at` | format differs (ms epoch vs RFC 3339) |
| `actor{agent,user}` | issuer (did:key/did:web) + 0.5 `gate_id`/authority labels | **gap:** we do not carry a user/principal field; see §4 |
| `prev_hash` | `prev` | same concept; **different digest scope** — theirs: transmitted octets incl. signature; ours: JCS bytes excluding `sig` (their §6 vs our SPEC §4/§5) |
| `public_key` | did:key resolution (`did:key:z6Mk…`) | theirs inlines raw base16; ours resolves identity documents |
| `signature` | `sig` | both Ed25519; encoding differs (base16 vs base64url/JCS-signed bytes) |
| (no equivalent) | `agreements` (offer/accept binding), `disclosures`, revocations, anchors, verification receipts | our chain-level semantics have no sahu counterpart |

**Assessment:** sahu is a lean per-action log; CR is a per-task chain with
agreement, disclosure, and verification semantics. Their canonicalization is
deliberately not JCS and their chain binds signatures transitively at the
octet level — a robust choice we do not need to adopt (our signing-input
scope plus signature verification achieves the same end; see §5).

## 3. Field mapping — ACTA / asqav compliance profile ↔ continuity-receipt

`draft-farley-acta-signed-receipts` + `draft-marques-asqav-compliance-receipts-07`:

| ACTA/asqav | continuity-receipt | note |
|---|---|---|
| `type` (`protectmcp:decision`…) | receipt type | vocabulary differs; theirs is decision-oriented |
| `issued_at` | `issued_at` | alignment; asqav adds freshness window (reject >300s future) — adoptable check |
| `issuer_id` (LEI/EIN/CIK/DID, = `kid`) | issuer did | **gap:** we do not bind a legal entity |
| `payload_digest` (REQUIRED) | per-type content digests | we carry digests where the type defines them; asqav requires one always |
| `action_ref` (REQUIRED) | receipt id / digest fields | join-key concept |
| `sandbox_state` (enabled/disabled/unavailable) | 0.5 `sandbox_class` (bwrap/landlock/microvm-*/none) + `runner_profile` | **we are richer**; theirs is compliance-shaped, ours is claim-honest with digests |
| `iteration_id` | task/session identifiers | alignment |
| `previousReceiptHash` (JCS signing-input scope) | `prev` (JCS sans sig) | **same scope philosophy** — strong alignment |
| `signature{alg,kid,sig}`, EdDSA/ES256/ML-DSA | Ed25519 only | algorithm agility is a gap (asqav lists ML-DSA-65) |
| anchors REQUIRED (RFC3161 or OTS, 7-day OTS bound), `witness_policy` N-of-M | anchors optional; OTS recommended; hosted anchor store; OTS + RFC3161 already run nightly in our pipeline | **adopt:** status vocabulary, upgrade bound, quorum, anchor metadata |
| retention floors per regime | not specified | gap (compliance work) |
| Audit Pack (receipts + commitments + keys + anchor metadata + regime map) | bundles + verification receipts; no audit-pack export | **adopt:** pack export (plan C1) |
| multi-jurisdiction bindings (EU AI Act 12/26, DORA 17, NIST, CO, TX, NYDFS, HIPAA, SEC 17a-4, CIRCIA) | none | gap (plan F2, gated on demand validation) |
| capture topologies (SDK, proxy, browser, eBPF, MCP proxy, telemetry) | dispatch hook, MCP gateway, CLI | document ours in their vocabulary (plan D2) |

## 4. Gaps we will close (mapped to the implementation plan)

1. **Authority/principal** (plan B1): optional signed authority block —
   accountable entity (DID, optional LEI/EIN), mandate reference (scope,
   constraints, expiry), review gate. Sourced honestly from Mandala
   gate-lite passes; verifier checks shape/signature/reference-resolution
   only. This closes the biggest semantic gap (ActionReceipt and asqav both).
2. **Policy/action digests** (B1): require (where meaningful) `policy_ref`
   and `action_ref` digests so a verifier can resolve the policy artefact.
3. **Anchoring discipline** (B3): `anchored|pending|failed`, bounded upgrade
   window, dual-anchor metadata, optional witness quorum; surface in
   verification receipts.
4. **Audit/Dispute Pack** (C1/C2): export receipts + chain commitments +
   keys + anchor proofs + verifier output + human-readable certificate.
5. **Compliance profile** (F2, gated): Art. 12/26 + DORA mapping, retention
   notes — only after validation conversations.

## 5. Why we keep JCS and the signing-input chain scope

sahu digests transmitted octets to avoid depending on canonicalization
agreement; ACTA/asqav and CR both sign the JCS signing input. Our choice is
deliberate: JCS is a published RFC with a conformance corpus we already
exercise (40 frozen vectors), disclosure/redaction mutate the transmitted
form of bodies without breaking signatures, and our chain scope matches
asqav's — so chain-compatibility with the compliance profile is structural,
while sahu's construction is verifiable but object-incompatible. The probes
in §1 and the next one (ACTA envelope) are the evidence; we will not claim
compatibility we have not tested.

## 6. Next probes

- **ACTA envelope probe:** construct a minimal ACTA-shaped receipt, sign with
  JCS signing-input, and verify with our tooling (shape + signature), then
  document the fields asqav requires that we cannot yet supply honestly.
- **sahu negative corpus:** their draft specifies determinate failure
  positions; add two negative probes (broken link, unknown-signature) to the
  interop script.
- Once B1 lands: re-run both probes plus an authority-aware projection note
  (CR receipt → sahu/ACTA views, lossy fields documented).
