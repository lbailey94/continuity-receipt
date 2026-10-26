# agmi Row Submission Packet — WhiteMagic Memory Crystals (`wm-crystal/1.0`)

**Rows measured (ten edits, including T10 erasure resurrection):**

| Row | Anchor location | Anchor content | Read-path verdicts |
|---|---|---|---|
| `whitemagic-crystals` | inside `store-<ctx>/` | erasure-aware | 8/10 rejected (T9, T10 served) |
| `whitemagic-crystals+anchor` | outside the store | erasure-aware | **10/10 rejected** |
| `whitemagic-crystals+l5` | outside the store | erasure-aware | **10/10 rejected without the KEK** |

Measured 2026-10-22 against agmi `cee8a66` (ten edits, `AT_REST_ATTACKS_WITH_ERASE`),
`crystal_client` `wm-crystal/1.0` with the erasure-aware commitment below.

## Two variables, held apart

The row separates two independent things, which the earlier nine-edit run
conflated:

1. **Anchor location** separates T9. A commitment inside the store rolls back
   with a restored copy; one outside it does not.
2. **Anchor content** separates T10. A high-water count alone cannot catch an
   erased record coming back: erasure *lowers* the count, so a restored
   pre-erasure copy is a superset of what the anchor recorded and passes a
   `len(store) >= count` check.

Counterfactual, same store and same off-store anchor location, changing only
the commitment content:

```text
old high-water commitment    snapshot_rollback  -> safe
old high-water commitment    erase_resurrect    -> VULNERABLE
erasure-aware commitment     snapshot_rollback  -> safe
erasure-aware commitment     erase_resurrect    -> safe
```

The erasure-aware commitment binds `erasure_count`,
`erased_crystal_ids_digest`, and `revision = len(cells) + len(erasures)` (which
increases on add and stays level — never decreasing — when one live cell is
converted to one tombstone, while `erasure_count` and
`erased_crystal_ids_digest` distinguish the transition). The erasure list itself
stays in the store and rolls back with it; only the off-store anchor makes the
difference visible.

### W3C 4-Field Conformance Result Mapping (`T9` & `T10`)

| Case | 1. Property | 2. Evidence | 3. Result | 4. Detection point & treatment |
|---|---|---|---|---|
| **T9 (`snapshot_rollback`)** | Rollback rejection of an older authentic store snapshot | Off-store monotonic state commitment retained outside the restored store boundary | Colocated anchor: `unobservable`<br>Off-store anchor: `verified` | `read-time` / `rejected` (pass) vs `accepted` (fail) |
| **T10 (`erase_resurrect`)** | Non-resurrection of an erased cell on backup restore | Off-store state commitment binding `erasure_count`, `erased_crystal_ids_digest`, and `revision` | Colocated anchor: `unobservable`<br>Off-store count-only: `unverified`<br>Off-store erasure-aware: `verified` | `read-time` / `rejected` (pass) vs `accepted` (fail) |

---

## Step 1 — Answers to the Five Questions (`docs/adding-a-row.md`)

1. **What exactly is the store?**
   A per-tenant directory (`store-<ctx>/`) holding `crystals.json` (an ordered sequence of `wm-crystal/1.0` AEAD-sealed crystal envelopes) and `commitment.json` (an Ed25519-signed `wm.crystal-set-commitment` high-water export commitment binding `count`, `ordered_crystal_ids_digest`, `head_crystal_id`, `tenant_hash`, `spec`, and `retrieved_at`). In `whitemagic-crystals`, `commitment.json` sits inside `store-<ctx>/` on the same disk; in `whitemagic-crystals+anchor`, it sits outside the store directory (`offstore-anchors/<ctx>-commitment.json`).

2. **What is one record?**
   One slot entry containing a `wm-crystal/1.0` JSON envelope (`crystal_id`, `parent_crystal_id`, `tenant_hash`, `cipher`, `nonce`, `ciphertext`, `size_bytes`, `created_at`, `kek_version=1`, `id_kek_version=1`, `wrapped_dek`, `metadata_public`).

3. **Where does the untrusted editor stand?**
   Reads and writes the store directory (`store-<ctx>/`) directly on disk. Holds neither the client's 32-byte Key Encryption Key (`KEK`) nor the Ed25519 commitment signing key.

4. **What is the read path?**
   `crystal_client.verify_and_unseal_crystal_set(crystals, key, expected_tenant_hash, expected_commitment=..., anchor_public_key=...)` (`detection_point = "read"`). Before returning memories to the agent, the read path:
   - verifies the signed `wm.crystal-set-commitment` high-water count, head ID, and ordered ID digest;
   - checks `tenant_hash == expected_tenant_hash` (context binding);
   - verifies parent lineage links (`parent_crystal_id` DAG from genesis `None` through each predecessor `crystal_id`);
   - recomputes `crystal_id = sha256(id_kek_version_be32 || nonce || ciphertext)` (SAIHM-aligned cellId binding);
   - unwraps the per-crystal 32-byte DEK under `KEK` v(1) and AEAD-decrypts `ciphertext` with bound AAD (`cipher|tenant_hash|parent_crystal_id|created_at|metadata_public`).

5. **What is pinned?**
   `whitemagic crystal_client wm-crystal/1.0` at commit `586ed21` (`0fe89e3`, `lbailey94/whitemagic`, `WMv10/scripts/crystal_client.py`), Python 3.12 + `cryptography`.

---

## Step 3 — Nine-Line Output (Both Configurations)

### `whitemagic-crystals` (Default — Commitment on Same Disk)
```text
tamper               safe        detected on reload (ValueError: crystal content-address verification failed: sha256:bc6cbf
truncate             safe        detected on reload (CrystalRollbackError: store rollback or truncation detected: store has
delete_middle        safe        detected on reload (CrystalLineageError: lineage link broken at index 2: parent_crystal_id
reorder              safe        detected on reload (CrystalLineageError: lineage link broken at index 1: parent_crystal_id
forge                safe        detected on reload (InvalidTag: )
cross_replay         safe        detected on reload (CrystalContextError: cross-context crystal replay at index 4: tenant_h
rollback_replay      safe        detected on reload (CrystalLineageError: duplicate crystal_id at index 4: sha256:b508c022a
metadata_tamper      safe        detected on reload (InvalidTag: )
snapshot_rollback    VULNERABLE  the older copy opened as current; the newest genuine record is gone without an error
erase_resurrect      VULNERABLE  the restored copy opened as current; the record the store had erased is served again
```

### `whitemagic-crystals+anchor` (Commitment Anchored Off-Store)
```text
tamper               safe        detected on reload (ValueError: crystal content-address verification failed: sha256:6c9404
truncate             safe        detected on reload (CrystalRollbackError: store rollback or truncation detected: store has
delete_middle        safe        detected on reload (CrystalLineageError: lineage link broken at index 2: parent_crystal_id
reorder              safe        detected on reload (CrystalLineageError: lineage link broken at index 1: parent_crystal_id
forge                safe        detected on reload (InvalidTag: )
cross_replay         safe        detected on reload (CrystalContextError: cross-context crystal replay at index 4: tenant_h
rollback_replay      safe        detected on reload (CrystalLineageError: duplicate crystal_id at index 4: sha256:b1dd7b7c0
metadata_tamper      safe        detected on reload (InvalidTag: )
snapshot_rollback    safe        the store noticed it was older than its last committed state (CrystalRollbackError: store 
erase_resurrect      safe        the store noticed that a record it had erased was back (CrystalRollbackError: erasure_count
```
