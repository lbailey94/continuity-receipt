# Supplied witness custody and publication outcomes

This is an experimental local receiver implementation contract. It does not
change CPR bundle wire verification or establish an independently operated
witness, network freshness protocol, audit, or deployed-service guarantee.

## Required reads and independently retained pins

`--witness-file` means that the file must exist and validate before recall.
Missing, unreadable, malformed, empty, oversized, nonregular or symlinked inputs
refuse delivery. An explicitly empty option value is an error; it cannot select
the legacy no-witness path. The same rule applies to explicitly empty profile
and predicate paths.

The accepted witness object has required `sequence` and `checkpoint_digest`
fields, and optional `generation_id`:

```json
{"sequence":2,"checkpoint_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","generation_id":"22222222222222222222222222222222"}
```

Sequence is an exact positive integer, excluding booleans. Digests use lowercase
SHA-256 syntax; a supplied generation is 32 lowercase hex characters. Unknown
fields, including observation timestamps, are rejected. A timestamp would not
establish that a reference is the newest one.

The object is a **floor**: below-floor local sequences are refused; at the floor,
checkpoint and any supplied generation must match. A newer local sequence is
permitted. A valid historical witness can therefore match a jointly restored old
store. Schema validation cannot discover later state independently.

Use `--expected-witness-checkpoint` to bind the loaded file to a checkpoint digest
retained separately by the caller. `--require-witness` requires both that pin and
a witness file. An authentic S1 witness cannot satisfy a separately retained S2
pin. Deriving the pin from the same mutable file immediately before reading it
adds no independent knowledge.

```bash
cpr-memory resume --data-root /lab/data --trust-db /lab/trust/receiver.sqlite3 \
  --context example --scope example --public-key /lab/operator-public.pem \
  --memory-path notes.txt --witness-file /retained/witness.json \
  --require-witness \
  --expected-witness-checkpoint sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
```

Omitting witness options preserves the explicit legacy behavior. Supplying a
valid witness without a separate pin provides only its declared floor. Neither
mode proves global latest-state knowledge or independent custody.

CLI resume decisions use policy version 2. The policy digest binds the selected
memory path, semantic predicate, receiver profile and witness requirement,
expected checkpoint and actual loaded reference. Identical delivered bytes under
different witness requirements do not silently share one policy identity.

## Publication is two durable steps

With a witness target, publication preflights the existing parent and target,
acquires a cooperating sidecar lock and stages a private file before advancing
the local store. A current witness ahead of or conflicting with local retained
state prevents publication. Witness replacement uses file fsync, atomic rename
and directory fsync. Cooperating publishers cannot silently lower the witness
sequence or replace an equal sequence with a conflicting checkpoint.

SQLite publication and a separate file replacement are not one atomic
transaction. The CLI emits one final JSON result, after context cleanup:

| Condition | `local_committed` | Witness outcome | Meaning |
|---|---|---|---|
| Preflight fails | `false` | `NOT_ATTEMPTED` | Local publication was not started. |
| Local publication rejects | `false` | `NOT_ATTEMPTED` | No accepted new local reference was returned. |
| Both steps and cleanup complete | `true` | `COMPLETE` | The returned local reference was also written and synced to the witness file. |
| Witness update fails after local success | `true` | `INCOMPLETE` | The result includes the actual committed local reference; exit is nonzero. |
| Store publication raises without a clear result | `null` | Usually `NOT_ATTEMPTED` | `local_commit_status` is `UNKNOWN`; inspect retained state. |

If only context cleanup fails after a completed witness write, the operation
still exits nonzero, while the reported witness state can remain `COMPLETE`.
An error after rename may leave the new file visible with uncertain directory
durability; `INCOMPLETE` does not claim that either file or local state rolled
back. Cleanup attempts every descriptor close even if staged-file removal fails,
and preserves an earlier operation exception.

After any incomplete or unknown outcome, retain the complete result and inspect
`status` plus the witness file. Do not treat the first success-like field as a
combined-publication approval or blindly replay an old expected-reference CAS.
The caller must reconcile the returned/observed reference with its independently
retained expectation before further approval or delivery.

The sidecar lock coordinates callers using this helper and target. Noncooperating
writers, restoring the lock or reference together with all trust inputs, and
publication outside this protocol remain caller trust-boundary obligations.
These tests inject failures and reopen files/SQLite; they are not power-loss or
independent-provider qualification.

## Evidence and compatibility

The new flags and publication-status fields are local CLI additions. Strict
witness validation and optional floor behavior remain as documented. The named
policy digest version changes because its bound inputs now include witness
obligations. Existing signed bundle fixtures and normative manifests remain
unchanged. `vectors/receiver-witness-policy-v1.json` is an implementation-only
validation corpus exercised by the witness-file tests.
