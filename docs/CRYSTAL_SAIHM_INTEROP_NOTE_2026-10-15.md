# Memory Crystals (`wm-crystal/1.0`) ↔ SAIHM (`draft-saihm-memory-protocol-03`) Interoperability Note

**Date:** 2026-10-15 · **Status:** Internal technical note (`I10` deliverable) · **Repos:** `lbailey94/whitemagic` (`df53c05`), `lbailey94/continuity-receipt` (`07fd89d`), `lbailey94/whitemagic-plugins` (`562ab70`).

---

## 1. Non-Custodial Profile Alignment

`draft-saihm-memory-protocol-03` (2026-10-11, §1.2) specifies the **custodial** profile (where the operator holds keys and performs cryptography on behalf of the client) and explicitly leaves the **non-custodial** profile ("holder keeps the keys, operator sees only ciphertext") outside its scope as a companion profile under the same cell shape.

WhiteMagic **Memory Crystals (`wm-crystal/1.0`)** implement that non-custodial cell pattern in running production code (`https://api.whitemagic.dev/crystals`), paired with **Causal Provenance Receipts (CPR)** for export-level head commitments and offline verification.

---

## 2. Side-by-Side Comparison (Post-I1–I9 Alignment)

| Dimension | `wm-crystal/1.0` (with I1–I9) | `draft-saihm-memory-protocol-03` | Interop Status |
|---|---|---|---|
| **Custody model** | **Non-custodial** (client holds KEK; server sees only AEAD ciphertext + public header) | **Custodial** in -03 core (non-custodial left out of scope in §1.2; `-pro` clients also seal client-side) | Complementary profile under identical cell semantics |
| **Cell / Crystal ID (`I1`)** | `sha256(uint32_be(id_kek_version) ‖ nonce ‖ ciphertext)` (with legacy `sha256(ciphertext)` fallback when `id_kek_version` is omitted) | `cellId = sha256(kekVersion_be32 ‖ cellNonce ‖ ciphertext)` | **Aligned** (both recompute on read and bind key generation + nonce + ciphertext) |
| **Per-Cell DEK & KEK Rotation (`I2`)** | Random 32-byte per-crystal DEK wrapped under client $\text{KEK}_v$ (`wrapped_dek`, `kek_version`, `id_kek_version`); `rotate_crystal_kek` re-wraps without changing `crystal_id` | Per-cell DEK wrapped under versioned KEK; re-wrap on rotation preserves `cellId` | **Aligned** |
| **AEAD & AAD Binding** | `AES-256-GCM` or `ChaCha20-Poly1305`; AAD binds `cipher \| tenant_hash \| parent_crystal_id \| created_at \| canonical_json(metadata_public)` | `AES-256-GCM` recommended; authenticated cell header | **Aligned** |
| **Signatures (`I4`)** | Optional `client_sig` supporting `ed25519`, `ml-dsa-65`, or hybrid `ed25519+ml-dsa-65` over JCS canonical envelope | Mandatory `ML-DSA-65` over cell fields | **Compatible via `0.6-pq` dual-sign profile** |
| **Lineage & Export Commitment (`I6`)** | Explicit `parent_crystal_id` DAG + signed `wm.crystal-set-commitment` (`count`, `ordered_crystal_ids_digest`, `head_crystal_id`, `retrieved_at`, `spec`) | Set of cells minus erasures + per-operation audit receipts | **Answers W3C CG export-commitment ask** |
| **Erasure Classes (`I3`)** | Two classes disclosed in `/info` and signed `wm.crystal-erasure` receipts:<br>1. `access_control_and_ciphertext_purge` (`DELETE /crystals/<id>` unlinks ciphertext + records tombstone)<br>2. `cryptographic_client_dek_plus_ciphertext_purge` (`destroy_crystal_dek` + server purge) | Two classes required (cryptographic vs access-control; operator must state which) | **Aligned** |
| **Host Sandbox (`I5`)** | Linux kernel **Landlock** (`enforced_abi_v6` on VPS `/info`) confining writes to `STATE_DIR` + systemd `ProtectSystem=strict`, `NoNewPrivileges=true` | Operator-defined storage isolation | **Verified live on VPS** |
| **MCP Tool Surface (`I9`)** | `whitemagic-crystals-mcp` (`crystal_remember`, `crystal_recall`, `crystal_forget`, `crystal_status`) + REST `/crystals*` | 8 MCP tools (`REMEMBER`, `RECALL`, `FORGET`, `STATUS`, `KEY`, `SHARE`, `REVOKE`, `PROPOSE`/`VOTE`) | **Core 4-tool lifecycle aligned** |

---

## 3. Measured Conformance Evidence (`I7` & `I8`)

1. **`agmi` Nine-Edit Storage Integrity Matrix (`ops/interop-evidence/agmi-row/`):**
   - `whitemagic-crystals` (default local commitment): **8/9 rejected on read path (Level L3)**.
   - `whitemagic-crystals+anchor` (off-store commitment): **9/9 rejected on read path (Level L4)**, catching `T9` whole-store snapshot rollback via `CrystalRollbackError`.
2. **`probity` `anchored-record-chain/v1` External Verifier Harness (`ops/interop-evidence/anchored-chain-conformance-report-2026-10-15.json`):**
   - `tools/verify_anchored_chain.py` executed via the external rail: **14/14 cases conformant, 0 disagreements, 0 suite refusals**.
