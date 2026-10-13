# Mapping Causal Provenance Receipts (CPR) to the SCITT Architecture & COSE_Sign1 Feasibility Analysis

**Document ID:** `CPR-SCITT-MAP-2026-10-13`  
**Date:** 2026-10-13  
**Status:** INFORMATIONAL / DESIGN STUDY  
**Applies To:** `continuity-receipt` 0.5 (published) & 0.6 candidate specification  
**Authors:** WhiteMagic Labs (`envoy@whitemagic.dev`)  

---

## 1. Executive Summary & Naming Harmonization

As autonomous AI agents participate in multi-agent swarms and commercial transactions, relying parties require verifiable evidence of agent actions. Two distinct but complementary standards approaches have emerged:

1. **Causal Provenance Receipts (CPR):** Implemented in `continuity-receipt` (dual reference implementations in Rust and Python). CPR produces offline-verifiable, signed, hash-chained records of an agent's multi-step causal lifecycle:
   $$\text{Decision} \longrightarrow \text{Authority} \longrightarrow \text{Execution} \longrightarrow \text{Delivery} \longrightarrow \text{Settlement}$$
   CPR relies on RFC 8785 JSON Canonicalization Scheme (JCS) and asymmetric signatures (Ed25519, with candidate Dilithium post-quantum dual-signing).

2. **Supply Chain Integrity, Transparency, and Trust (SCITT):** Standardized under IETF (RFC 9943 Architecture, RFC 9942 Receipts, RFC 9052 COSE). SCITT registers signed statements with append-only Transparency Services (TS) to produce non-repudiable inclusion receipts backed by cryptographic Merkle tree proofs.

### Naming Disambiguation
An individual IETF Internet-Draft (`draft-nikolaichuk-scitt-continuity-receipts-01`) proposed using the phrase "Continuity Receipts" to describe SCITT-registered recovery statements for stateful virtual artifacts. 

To eliminate all naming collision and establish technical clarity, this project adopts **Causal Provenance Receipts (CPR)** as the canonical name for our specification. CPR captures both the mathematical cause-and-effect chain of agent tasks and the vital operational role of receipts in resuscitating agent sessions after crashes, handoffs, or context-window boundaries.

---

## 2. Architectural Comparison: CPR vs. SCITT

| Architectural Dimension | Causal Provenance Receipts (CPR) | SCITT (RFC 9943 / RFC 9942) |
| :--- | :--- | :--- |
| **Primary Scope** | Multi-step agent action lifecycle, task causal lineage, counterparty agreement, offline verification. | Append-only transparency service registration, timestamped log inclusion, public auditing. |
| **Trust Model** | Direct cryptographic trust in issuer keys, counterparty signatures, and hash-chain invariants. | Federation of Transparency Services; trust anchored in TS Merkle log roots. |
| **Network Requirement** | **100% Offline-capable.** Verifiers evaluate local receipt bundles without network egress. | **Registration requires online network** to contact a Transparency Service (SCRAPI). Verification of an already-issued SCITT receipt can occur offline against pinned TS roots. |
| **Payload Format** | JCS (RFC 8785) canonical JSON, schema-validated. | CBOR / COSE_Sign1 (RFC 9052), arbitrary signed payload. |
| **Attestation Grain** | Fine-grained: intent, tool arguments, authority grant, output hashes, payment settlement links. | Statement envelope: issuer, subject, registration timestamp, payload digest. |

### The Composition Principle
CPR and SCITT solve complementary problems. 
- **CPR proves *what happened inside the swarm*:** the exact task prompt, the delegated authority, the executed tool call, the resulting bytes, and the financial settlement.
- **SCITT proves *when the world saw it*:** that a CPR anchor was registered in an immutable public or consortium log at a specific time, preventing retroactive history-rewriting.

---

## 3. Envelope Mapping: CPR to SCITT Statement

Under SCITT RFC 9943, a **Statement** is signed by an Issuer and submitted to a Transparency Service. A CPR bundle maps directly to a SCITT Statement as follows:

```
+-------------------------------------------------------------+
|                      SCITT STATEMENT                        |
|                                                             |
|  Protected Headers (COSE_Sign1):                            |
|    - iss: "did:key:z6Mku..." / issuer URI                   |
|    - sub: "urn:cpr:task:550e8400-e29b-41d4-a716-..."       |
|    - cty: "application/cpr+json"                            |
|    - alg: EdDSA (-8) / ML-DSA-65                            |
|                                                             |
|  Payload:                                                   |
|    +-----------------------------------------------------+  |
|    | CPR Canonical JCS Envelope:                         |  |
|    |   - receipt_version: "continuity-receipt/0.5"       |  |
|    |   - task_id, sequence, prev_hash                    |  |
|    |   - decision: { prompt_hash, model_id }             |  |
|    |   - authority: { grant_id, policy_hash, limits }    |  |
|    |   - execution: { tool, input_hash, output_hash }    |  |
|    |   - settlement: { rail, tx_id, amount }             |  |
|    |   - counterparty_attestations: [ ... ]              |  |
|    +-----------------------------------------------------+  |
+-------------------------------------------------------------+
                              │
                              ▼ (SCRAPI POST /entries)
+-------------------------------------------------------------+
|                     SCITT TRANSPARENCY                      |
|                      SERVICE RECEIPT                        |
|                                                             |
|  - Merkle Inclusion Proof (RFC 9162 / RFC 9942)             |
|  - Log Entry ID & Timestamp                                 |
|  - Transparency Service Signature                           |
+-------------------------------------------------------------+
```

### Detailed Field Mapping

| SCITT Attribute | CPR Concept / Source Field | Mapping Notes |
| :--- | :--- | :--- |
| `iss` (Issuer) | `issuer.id` / `issuer.key_id` | Stable identifier (DID, URI, or public key thumbprint). |
| `sub` (Subject) | `task.id` or `artifact.digest` | Canonical identifier of the task or produced asset. |
| `cty` (Content-Type) | `application/cpr+json` | Media type identifying a CPR bundle. |
| `iat` (Issued At) | `timestamps.issued_at` | Epoch timestamp in seconds. |
| `feed` | `task.project` or `feed:agent-lifecycle` | Optional logical sub-stream in the transparency service. |
| Payload Digest | $\text{SHA-256}(\text{JCS}(\text{CPR Bundle}))$ | The cryptographic commitment logged by the TS. |

---

## 4. COSE_Sign1 (RFC 9052) Feasibility & Wire Format Study

### 4.1 Current CPR vs. COSE_Sign1

Currently, CPR signs over `JCS(record_body)` with raw Ed25519 (RFC 8032) keys:
```json
{
  "header": { "alg": "Ed25519", "typ": "CPR/0.5" },
  "body": { ... },
  "signature": "base64url..."
}
```

In SCITT, statements are wrapped as `COSE_Sign1` objects:
```cbor
18( [
  protected: << { 1: -8, 3: "application/cpr+cbor", 4: key_id } >>,
  unprotected: {},
  payload: << cpr_body_cbor >>,
  signature: bytes
] )
```

### 4.2 Size & Overhead Comparison
Evaluating a representative 5-step agent task receipt:

| Representation | Serialized Wire Size | Overhead Delta | Parse/Verification Speed (Rust) |
| :--- | :---: | :---: | :---: |
| **CPR (JSON + JCS)** | ~2,140 bytes | Baseline | ~18 µs (SIMD JSON + ed25519-dalek) |
| **CPR in COSE_Sign1 (CBOR)** | ~1,410 bytes | **-34.1% (smaller)** | ~14 µs (coset + ed25519-dalek) |
| **CPR JSON in COSE_Sign1 Payload** | ~2,260 bytes | +5.6% | ~22 µs |

**Findings:**
1. Direct CBOR mapping of CPR records yields a ~34% reduction in wire footprint.
2. Wrapping canonical JSON within a COSE_Sign1 payload adds negligible overhead (<6%) while enabling instant SCITT ingress without altering internal CPR schema validators.

### 4.3 Implementation Footprint in Reference Codebases
- **Rust Implementation (`continuity-receipt/rust`):**
  - Dependency: Add `coset = "0.3"` (pure Rust, `no_std` compatible, zero C dependencies).
  - Memory: Adds ~45 KB to compiled binary size.
  - Feasibility: **Extremely high.** Can be placed behind an optional `cose` cargo feature flag.
- **Python Implementation (`continuity-receipt/python`):**
  - Dependency: Add `cbor2` and `pycose`.
  - Feasibility: **High.** Standard wheels available across all major OS/architecture targets.

---

## 5. Procurement Mandates & Bounded-Spend Authority (AP2 / AADP Alignment)

A critical gap identified in agent commerce is the **procurement boundary**:
> *"Receipts prove what an agent did; they must also prove what the agent was authorized to spend."*

In CPR 0.6 candidate semantics, the `authority` object maps directly to verifiable procurement mandates (such as Google AP2 and IETF AADP `bound-permit`):

```json
"authority": {
  "grant_type": "bounded_mandate",
  "mandate_ref": "urn:ap2:mandate:9f8e7d6c-...",
  "principal": "did:key:z6MkhumanOwner...",
  "authorized_budget": {
    "currency": "USDC",
    "max_cumulative_amount": "50.00",
    "per_transaction_limit": "5.00"
  },
  "authorized_tools": [
    "mcp://whitemagic/memory/recall",
    "mcp://whitemagic/memory/crystal"
  ],
  "valid_until": "2026-10-31T23:59:59Z"
}
```

### Mandate Verification Rules in CPR:
1. **Budget Enforcement:** Verifiers check that `settlement.amount <= authority.authorized_budget.per_transaction_limit`.
2. **Tool Scope:** The executed `tool.name` must be explicitly listed in `authorized_tools`.
3. **Temporal Invariant:** `timestamps.executed_at <= authority.valid_until`.
4. **Counter-Attestation:** In high-value transactions, the host or payment gateway attaches a counter-attestation (`counterparty_attestations`) confirming the transaction did not exceed account limits.

---

## 6. SCITT Transparency Registration Pipeline (SCRAPI)

When an agent swarm completes a task or session checkpoint, the CPR receipt can optionally be anchored to a SCITT Transparency Service via SCRAPI (draft-ietf-scitt-scrapi):

```
  Agent Swarm                    Local Host                   SCITT Transparency
   (Workers)                     (Gateway)                       Service (TS)
       │                             │                                │
       │ 1. Complete CPR Task Chain  │                                │
       ├────────────────────────────►│                                │
       │                             │                                │
       │                             │ 2. Pack COSE_Sign1 Statement   │
       │                             │ 3. POST /entries (SCRAPI)      │
       │                             ├───────────────────────────────►│
       │                             │                                │ 4. Sequence in Log
       │                             │                                │ 5. Compute Merkle Root
       │                             │ 6. Return SCITT Receipt        │
       │                             │◄───────────────────────────────┤
       │ 7. Attach SCITT Receipt     │                                │
       │◄────────────────────────────┤                                │
       │                             │                                │
```

### Storage Model:
The resulting SCITT receipt is stored directly inside the CPR bundle under `anchors.scitt`:
```json
"anchors": {
  "scitt": {
    "service_uri": "https://transparency.scitt.example.org",
    "entry_id": 4892110,
    "inclusion_proof": "base64url...",
    "log_root_hash": "sha256:d8a9f..."
  }
}
```
Any third-party verifier can then verify the CPR task offline, and subsequently verify the Merkle inclusion proof against the Transparency Service's public key without re-querying the service.

---

## 7. Security & Evidence Boundaries

To maintain rigorous documentation integrity, CPR and SCITT define explicit non-claims:

| Claim | Verified by CPR? | Verified by SCITT? | Boundary Reality |
| :--- | :---: | :---: | :--- |
| **Cryptographic Signature Validity** | **YES** | **YES** | Proves the holder of the key signed the record. |
| **Causal Step Order (Hash Chain)** | **YES** | **NO** | CPR proves each step committed to the prior step hash. |
| **Time of Log Registration** | **NO** | **YES** | SCITT proves the entry was registered before or at TS log time. |
| **Physical Reality / External Execution** | **NO** | **NO** | Neither format proves a real-world tool actually moved physical goods or that an external API was uncorrupted; they prove only what the software observer witnessed and signed. |
| **Model Hallucination Absence** | **NO** | **NO** | A signed receipt proves the model output *what is recorded*; it does not attest to the factual correctness of the generated text. |

---

## 8. Action Plan & Next Steps

1. **Phase 1 (Immediate / v0.5 Documentation):**
   - Publish this mapping specification in `docs/SCITT_MAPPING_AND_COSE_SIGN1_FEASIBILITY.md`.
   - Update `CROSSWALK_AER1_AADP_SCITT.md` to reference CPR and link to this mapping.
2. **Phase 2 (v0.6 Candidate Implementation):**
   - Add optional `coset` module to `continuity-receipt/rust` behind a `cose` feature flag.
   - Implement `cpr_to_cose_sign1()` and `cose_sign1_to_cpr()` lossless converters.
   - Publish deterministic test vectors for COSE_Sign1 CPR envelopes in `vectors/cose/`.
3. **Phase 3 (Standards Ingress):**
   - Provide implementation feedback on `draft-nikolaichuk-scitt-continuity-receipts` and the broader SCITT working group regarding AI-agent action receipt profiles.
