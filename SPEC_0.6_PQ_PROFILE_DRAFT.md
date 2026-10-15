# CPR (Causal Provenance Receipts) 0.6-pq Candidate Profile — Post-Quantum Dual-Signing

> **Status:** Candidate Profile Specification Draft (2026-10-11)  
> **Target:** W3C Agent Identity Registry Protocol CG & CCG Quantum-Safe Cryptosuites  
> **Companion Documents:** `SPEC_0.6_DRAFT.md`, `docs/DESIGN_NOTE_PQ_DUAL_SIGN_RECEIPTS_2026-10-08.md`, `docs/CROSSWALK_W3C_AGENT_IDENTITY_CG_v0.md`  
> **Reference Implementation:** Rust `crates/wm-gen3-core/src/mandala.rs` & Python `continuity_receipt`  
> **Nomenclature (2026-10-15):** CPR — Causal Provenance Receipts (formerly Continuity Receipts); wire identifiers remain `continuity-receipt/0.x`. The 2026-10-20 W3C Agent Identity CG agenda carries no CPR item (AOB §6 is the door; next meeting 2026-11-17).

---

## 1. Scope & Bounded Context

This profile defines an additive, backward-compatible dual-signature mechanism (`continuity-receipt/0.6-pq`) allowing CPR receipts to survive the migration to Post-Quantum Cryptography (PQC) without altering the underlying JCS canonicalization, record digest model, or historical verifiability of older receipt chains.

### Invariant Guarantees
1. **Identical Canonical Bytes:** Both classical (Ed25519) and post-quantum (ML-DSA / SLH-DSA) signatures are computed over the identical JCS canonical representation of the unsigned receipt.
2. **Offline Verifiability:** No cloud identity provider, key registry lookup, or network round-trip is required to evaluate dual signatures.
3. **Strict Policy Separation:** Receipts declare signatures; relying parties configure acceptance policies (`legacy-only`, `hybrid-preferred`, `pq-required`). Receipts do not dictate consumer policy.

---

## 2. Cryptographic Suites & Multicodec Identifiers

Public keys and signatures are expressed as `did:key` multikey identifiers utilizing registered W3C CCG multicodec prefixes:

| Algorithm | Standards Reference | Multicodec Prefix | Public Key Size | Signature Size |
| :--- | :--- | :--- | :--- | :--- |
| **Ed25519** (Classical) | RFC 8032 | `0xed` (varint `0xed 0x01`) | 32 B | 64 B |
| **ML-DSA-44** (Default PQ) | NIST FIPS 204 | `0x1200` | 1,312 B | 2,420 B |
| **ML-DSA-65** (High Margin PQ) | NIST FIPS 204 | `0x1201` | 1,952 B | 3,309 B |
| **SLH-DSA-SHA2-128s** (Stateless Hash) | NIST FIPS 205 | `0x1205` | 32 B | 7,856 B |

---

## 3. Envelope Syntax

In a `0.6-pq` receipt, the primary `sig` block retains classical Ed25519 compatibility, while an optional `dual_sig` block encapsulates the post-quantum signature:

```json
{
  "spec": "continuity-receipt/0.6",
  "receipt_id": "urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "task_id": "urn:uuid:6ba7b811-9dad-11d1-80b4-00c04fd430c8",
  "issued_at": "2026-10-11T19:30:00Z",
  "issuer": {
    "kind": "agent",
    "id": "did:key:z6MkhaXgBZDvotDkL5257faiz48Z8xG8Z8G8Z8G8Z8G8Z8G8"
  },
  "type": "task.execution",
  "seq": 1,
  "prev": null,
  "body": {
    "action": "mesh.sync",
    "status": "success"
  },
  "sig": {
    "alg": "ed25519",
    "key": "did:key:z6MkhaXgBZDvotDkL5257faiz48Z8xG8Z8G8Z8G8Z8G8Z8G8",
    "value": "base64-encoded-64-byte-ed25519-signature"
  },
  "dual_sig": {
    "pq_scheme": "ml-dsa-44",
    "pq_key": "did:key:zML44...",
    "pq_value": "base64-encoded-2420-byte-ml-dsa-signature",
    "sig_policy": "hybrid-preferred"
  }
}
```

---

## 4. Relying Party Policy & Verdict Semantics

A verifier MUST support three verification modes:

1. `legacy-only`: Evaluates only the classical Ed25519 signature in `sig`. Ignores `dual_sig` if present.
2. `hybrid-preferred`: Evaluates the classical signature. If `dual_sig` is present, it MUST also be valid. If `dual_sig` is absent, emits advisory code `pq_legacy_only`, but returns `TRUSTED`.
3. `pq-required`: Requires BOTH valid classical Ed25519 AND valid post-quantum signature. If `dual_sig` is missing, returns `UNTRUSTED` with code `pq_dual_sign_missing`. If invalid, returns `UNTRUSTED` with code `pq_dual_sign_invalid`.

### Distinct Verdict Codes
- `pq_dual_sign_missing`: Configured policy requires post-quantum signature, but none was provided.
- `pq_dual_sign_invalid`: Post-quantum signature verification failed against canonical record bytes.
- `pq_legacy_only`: Valid classical receipt evaluated under `hybrid-preferred` without PQ signature.
- `unknown_pq_scheme`: Unrecognized algorithm identifier; fails closed.

---

## 5. Cross-Language Conformance Mapping

| Component | Rust (`wm-gen3-core`) | Python (`continuity_receipt`) |
| :--- | :--- | :--- |
| Scheme Enum | `PqScheme::MlDsa44`, `MlDsa65`, `SlhDsa` | `PqScheme.ML_DSA_44`, `ML_DSA_65`, `SLH_DSA` |
| Policy Enum | `PqPolicy::LegacyOnly`, `HybridPreferred`, `PqRequired` | `PqPolicy.LEGACY_ONLY`, `HYBRID_PREFERRED`, `PQ_REQUIRED` |
| Envelope Field | `ContinuityReceipt05.dual_signature: Option<PqDualSignature>` | `receipt["dual_sig"]` |
| Canonical View | `unsigned_canonical_jcs_bytes(receipt)` | `records.canonical_bytes(unsigned_view(receipt))` |

---

## 6. Bounded Representation

Dual-signing certifies solely that the entities possessing the private keys corresponding to `sig.key` and `dual_sig.pq_key` signed the identical canonical record. It does not establish principal identity, human authorization, or hardware integrity.
