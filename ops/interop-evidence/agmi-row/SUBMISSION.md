# agmi row submission — WhiteMagic Memory Crystals (`wm-crystal/1.0`)

**Status:** prepared 2026-10-22, not yet opened upstream.
**Submitter:** Lucas Bailey, maintainer of WhiteMagic and of this store.
**Declaration:** this row is submitted by the tool's own maintainer. Per
`docs/adding-a-row.md`, that must be marked as such on the scorecard, and the
accepted cells are left exactly as measured.

Measured against agmi `cee8a66` with `AT_REST_ATTACKS_WITH_ERASE` (ten edits).

---

## Step 1 — The five questions

**1. What exactly is the store?**

A per-context directory `store-<ctx>/` containing:

- `crystals.json` — an ordered list of slot entries, each holding one
  `wm-crystal/1.0` envelope (`crystal_id`, `parent_crystal_id`, `tenant_hash`,
  `cipher`, `nonce`, `ciphertext`, `created_at`, `kek_version`,
  `id_kek_version`, `wrapped_dek`, `metadata_public`, optional `client_sig`);
- `erasures.json` — the erasure list: one tombstone per erased `crystal_id`
  (SAIHM -03 §2.7 keeps this list separate from the cells);
- `commitment.json` — a signed `wm.crystal-set-commitment` over the cells *and*
  the erasure list (`count`, `ordered_crystal_ids_digest`, `head_crystal_id`,
  `erasure_count`, `erased_crystal_ids_digest`, `revision`, `tenant_hash`,
  `spec`, `retrieved_at`).

**2. What is one record?**

One slot entry in `crystals.json` — one sealed crystal envelope. The erasure
list is not a record for these edits; it is part of what the commitment binds.

**3. Where does the attacker stand?**

Reads and writes `store-<ctx>/` directly on disk, with the tool closed. Holds
neither the client's 32-byte KEK nor the Ed25519 commitment signing key. Does
not hold `offstore-anchors/` when that configuration is measured.

**4. What is the read path?**

`crystal_client.verify_and_unseal_crystal_set(crystals, key, tenant_hash,
expected_commitment=..., anchor_public_key=..., erasures=...)` — the call made
before a session resumes and any memory reaches the agent. It verifies the
signed commitment (including the erasure binding), context binding, the
`parent_crystal_id` DAG, the per-crystal content address
`sha256(id_kek_version_be32 ‖ nonce ‖ ciphertext)`, unwraps each DEK and
AEAD-decrypts over bound AAD. Detection point: **read**, in a fresh process.

**5. What exactly is pinned?**

`crystal_client.py` from `github.com/lbailey94/whitemagic`, `WMv10/scripts`,
commit `0fe89e3`; Python 3.12, `cryptography`. The checkout is not on a package
index, so the module skips unless `AGMI_WHITEMAGIC_CRYSTAL_CLIENT` names it, as
the Recallspection and HDP rows do.

**6. Configurations**

Three rows from the same store. Default is `whitemagic-crystals` (commitment
beside the store, as it ships).

| Row | Commitment location | Verdicts on ten edits |
|---|---|---|
| `whitemagic-crystals` | inside `store-<ctx>/` | 8/10 — T9 and T10 served |
| `whitemagic-crystals+anchor` | outside the store | **10/10** |
| `whitemagic-crystals+l5` | outside the store, verifier without the KEK | **10/10** |

---

## Step 3 — The ten lines

### `whitemagic-crystals`

```text
tamper               safe        detected on reload (ValueError: client_sig Ed25519 verification failed: )
truncate             safe        detected on reload (CrystalRollbackError: crystal set: revision mismatch: store )
delete_middle        safe        detected on reload (CrystalRollbackError: crystal set: revision mismatch: store )
reorder              safe        detected on reload (CrystalLineageError: lineage link broken at index 1: parent_)
forge                safe        detected on reload (CrystalRollbackError: crystal set: revision mismatch: store )
cross_replay         safe        detected on reload (CrystalContextError: cross-context crystal replay at index 4)
rollback_replay      safe        detected on reload (CrystalLineageError: duplicate crystal_id at index 4: sha256)
metadata_tamper      safe        detected on reload (ValueError: client_sig Ed25519 verification failed: )
snapshot_rollback    VULNERABLE  the older copy opened as current; the newest genuine record is gone without an e
erase_resurrect      VULNERABLE  the restored copy opened as current; the record the store had erased is served a
```

### `whitemagic-crystals+anchor`

```text
tamper               safe        detected on reload (ValueError: client_sig Ed25519 verification failed: )
truncate             safe        detected on reload (CrystalRollbackError: crystal set: revision mismatch: store )
delete_middle        safe        detected on reload (CrystalRollbackError: crystal set: revision mismatch: store )
reorder              safe        detected on reload (CrystalLineageError: lineage link broken at index 1: parent_)
forge                safe        detected on reload (CrystalRollbackError: crystal set: revision mismatch: store )
cross_replay         safe        detected on reload (CrystalContextError: cross-context crystal replay at index 4)
rollback_replay      safe        detected on reload (CrystalLineageError: duplicate crystal_id at index 4: sha256)
metadata_tamper      safe        detected on reload (ValueError: client_sig Ed25519 verification failed: )
snapshot_rollback    safe        the store noticed it was older than its last committed state (CrystalRollbackErr)
erase_resurrect      safe        the store noticed that a record it had erased was back (CrystalRollbackError: cr)
```

### `whitemagic-crystals+l5`

```text
tamper               safe        detected on reload (CrystalVerificationError: crystal signature verification fai)
truncate             safe        detected on reload (CrystalRollbackError: crystal set (third-party): revision mi)
delete_middle        safe        detected on reload (CrystalRollbackError: crystal set (third-party): revision mi)
reorder              safe        detected on reload (CrystalLineageError: lineage link broken at index 1: parent_)
forge                safe        detected on reload (CrystalRollbackError: crystal set (third-party): revision mi)
cross_replay         safe        detected on reload (CrystalContextError: cross-context crystal replay at index 4)
rollback_replay      safe        detected on reload (CrystalLineageError: duplicate crystal_id at index 4: sha256)
metadata_tamper      safe        detected on reload (CrystalVerificationError: crystal signature verification fai)
snapshot_rollback    safe        the store noticed it was older than its last committed state (CrystalRollbackErr)
erase_resurrect      safe        the store noticed that a record it had erased was back (CrystalRollbackError: cr)
```

---

## Two variables, held apart (the reason for this row)

Recallspection already contributes the anchor-on/off pair for T9. This row adds
a second, independent variable, because **an off-store anchor is necessary but
not sufficient for erasure**.

A high-water cell count catches T9 and cannot catch T10: erasure *lowers* the
count, so a restored pre-erasure copy is a superset of what the anchor recorded
and passes a `len(store) >= count` check. Measured, same store, same off-store
anchor location, changing only the commitment content:

```text
old high-water commitment    snapshot_rollback  -> safe
old high-water commitment    erase_resurrect    -> VULNERABLE
erasure-aware commitment     snapshot_rollback  -> safe
erasure-aware commitment     erase_resurrect    -> safe
```

The commitment therefore also binds `erasure_count`,
`erased_crystal_ids_digest` and `revision = len(cells) + len(erasures)`, which
strictly increases on every add **and** every erase. The erasure list stays in
the store and rolls back with it; only the off-store anchor makes the
difference visible.

**Trade-off, stated plainly:** an erasure-aware commitment is a
*current-state* commitment, not a high-water one. A consumer holding an older
anchor will see a revision mismatch on a store that has legitimately grown and
must refresh it. Commitments without the erasure fields keep the old
prefix/high-water behaviour exactly.

**Mechanism note:** because the revision binding covers the whole state, count
and per-record edits (`truncate`, `delete_middle`, `forge`) are now refused by
the commitment before the lineage/content-address checks fire. The verdicts are
unchanged; the first failing check is earlier.

---

## Step 6 — Exact commands

```bash
git clone https://github.com/tech4biz-yasha/agent-memory-integrity agmi
cd agmi && git checkout cee8a66
cp <continuity-receipt>/ops/interop-evidence/agmi-row/whitemagic_crystals.py agmi/adapters/
cp <continuity-receipt>/ops/interop-evidence/agmi-row/test_whitemagic_crystals.py tests/

export AGMI_WHITEMAGIC_CRYSTAL_CLIENT=<whitemagic>/WMv10/scripts/crystal_client.py
PYTHONPATH=. python3 -m pytest tests/test_whitemagic_crystals.py -q   # 5 passed

PYTHONPATH=. python3 -c "
from agmi.adapters.whitemagic_crystals import WhiteMagicCrystalsAnchoredAdapter as A
from agmi.attacks.at_rest import AT_REST_ATTACKS_WITH_ERASE as X
for c in X:
    r = c().run(A())
    print(f'{r.attack:20} {r.status:11} {(r.guard or r.detail or r.error or \"\")[:90]}')
"
```

## Remaining work before the PR

- [ ] Register in `agmi/full_runner.py` and `agmi/agent/at_rest_hunt.py`
- [ ] `CHANGELOG.md` entry: T10 measured; high-water vs erasure-aware counterfactual
- [ ] Open PR from a fork with the five answers, ten lines and commands above
