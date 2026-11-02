# Recover a partial witness publication without publishing again

This procedure is for the experimental local `cpr-memory` receiver. It repairs
the supplied witness file from an already accepted, fully verified local
snapshot. It creates no new local generation, advances no sequence, and emits
no snapshot payload. It requires an independently retained checkpoint
expectation and the installed candidate's `witness-reconcile` command.

The local SQLite commit and witness replacement are separate durable steps.
This procedure does not turn them into one transaction. Its tests inject errors,
close files, and reopen the receiver in fresh processes; they do not establish
power-loss durability, an independent operator, or an independent witness
provider.

## Decide whether recovery has enough evidence

Retain the **entire** original publication result, exit status, and stderr before
retrying anything. Preserve any existing witness and its custody record. Do not
blindly repeat `publish`, copy an older witness over a newer one, or edit the
trust database or retained generation to make a check pass.

| Original publication result | Operator action |
|---|---|
| `local_committed:true`, a returned `reference`, witness `INCOMPLETE` | Establish that this returned checkpoint is the intended publication using the separately retained operator record. Then follow the procedure below. |
| `local_committed:true`, witness `COMPLETE`, nonzero exit | Cleanup may have failed after witness completion. Retain the error; the same exact-pin reconciliation and verification can be retried. |
| `local_committed:false` | Local publication did not return an accepted new reference. Investigate the refusal and original expected-reference CAS before deciding on a new publication. This is not a witness-only recovery of that attempt. |
| `local_committed:null`, `local_commit_status:UNKNOWN`, or no final result after interruption | Stop automatic recovery. `status` can identify the observed local reference but cannot establish that it is the intended publication. Follow the UNKNOWN section. |

The expected pin must come from a record retained separately from the mutable
witness and restored receiver, such as the complete partial-publication result
captured by the operator before recovery, together with the operator's expected
publication record. A second copy on the same host is useful for retention but
does not establish independent custody. Extracting the pin from the current
witness or `status` alone would merely approve the state being questioned.

## Copy-paste procedure for a known committed reference

Use the artifact virtual environment qualified for this candidate, with its
installed CLI, rather than running Python from a source checkout. Replace every
`/ABSOLUTE/...` value first. Choose a new evidence directory. Preserve the same
context, scope, public key, maximum age and optional receiver profile used for
the original receiver. The commands use the real clock; do not backdate `--now`
or raise `--max-age` to rescue expired evidence.

Quiesce other writes and restore jobs for this receiver during recovery. The
sidecar lock coordinates publishers using `WitnessPublication` and this exact
target. It does not coordinate arbitrary database writes, publishers that omit
this witness, or writes through a different witness target. Ensure the witness
parent is the intended existing directory on the intended mount. Repairing an
unavailable mount or permissions is a separate operator action; do not replace
a missing mount with a new local directory and call it restored custody.

The block stops on any failed check and retains command output for inspection:

```bash
bash <<'RECOVERY'
set -euo pipefail
umask 077
ARTIFACT_VENV='/ABSOLUTE/PATH/TO/qualified-artifact-venv'
DATA_ROOT='/ABSOLUTE/PATH/TO/receiver-data'
TRUST_DB='/ABSOLUTE/PATH/TO/receiver-trust.sqlite3'
PUBLIC_KEY='/ABSOLUTE/PATH/TO/operator-public.pem'
WITNESS_FILE='/ABSOLUTE/PATH/TO/retained/witness.json'
PARTIAL_RECEIPT='/ABSOLUTE/PATH/TO/separately-retained/partial-publication.json'
EVIDENCE='/ABSOLUTE/PATH/TO/new-recovery-evidence-directory'
RECEIVER_CONTEXT='replace-with-original-context'
RECEIVER_SCOPE='replace-with-original-scope'
MAX_AGE_SECONDS='3600'
MEMORY_PATH='replace-with-accepted-relative-memory-path'
CLI="$ARTIFACT_VENV/bin/cpr-memory"

mkdir -m 700 -- "$EVIDENCE"
cp -- "$PARTIAL_RECEIPT" "$EVIDENCE/original-partial-publication.json"
"$ARTIFACT_VENV/bin/python" -I -c \
  'import importlib.metadata,continuity_receipt; print(importlib.metadata.version("continuity-receipt")); print(continuity_receipt.__file__)' \
  > "$EVIDENCE/installed-identity.txt"

COMMON=(--data-root "$DATA_ROOT" --trust-db "$TRUST_DB"
        --context "$RECEIVER_CONTEXT" --scope "$RECEIVER_SCOPE"
        --public-key "$PUBLIC_KEY" --max-age "$MAX_AGE_SECONDS")
# If the receiver uses a pinned profile, uncomment and set its retained path:
# COMMON+=(--profile '/ABSOLUTE/PATH/TO/retained-receiver-profile.json')

jq -e '.local_committed == true and
       (.reference.checkpoint_digest | type == "string" and test("^sha256:[0-9a-f]{64}$")) and
       (.reference.sequence | type == "number" and . >= 1 and floor == .) and
       (.reference.generation_id | type == "string" and test("^[0-9a-f]{32}$"))' \
  "$PARTIAL_RECEIPT" > "$EVIDENCE/partial-receipt-shape-check.txt"
PIN=$(jq -er '.reference.checkpoint_digest' "$PARTIAL_RECEIPT")
printf '%s\n' "$PIN" > "$EVIDENCE/expected-checkpoint.txt"

"$CLI" status "${COMMON[@]}" > "$EVIDENCE/status-before.json" 2> "$EVIDENCE/status-before.stderr"
jq -e --slurpfile receipt "$PARTIAL_RECEIPT" \
  '.outcome == "ACCEPT" and .reference == $receipt[0].reference' \
  "$EVIDENCE/status-before.json" > "$EVIDENCE/observed-reference-check.txt"

# A missing witness is allowed here. An existing witness is preserved verbatim.
if test -e "$WITNESS_FILE" || test -L "$WITNESS_FILE"; then
  cp -P -- "$WITNESS_FILE" "$EVIDENCE/witness-before"
fi

"$CLI" witness-reconcile "${COMMON[@]}" --witness-file "$WITNESS_FILE" \
  --expected-reference "$PIN" > "$EVIDENCE/reconcile.json" 2> "$EVIDENCE/reconcile.stderr"
jq -e --slurpfile receipt "$PARTIAL_RECEIPT" \
  '.operation == "witness-reconcile" and .outcome == "ACCEPT" and
   .local_publication_performed == false and
   .witness_publication.outcome == "COMPLETE" and
   .verified_reference == $receipt[0].reference' \
  "$EVIDENCE/reconcile.json" > "$EVIDENCE/reconcile-check.txt"
cp -- "$WITNESS_FILE" "$EVIDENCE/witness-after.json"

# Retry the same operation: same checkpoint, same witness bytes, no new publish.
"$CLI" witness-reconcile "${COMMON[@]}" --witness-file "$WITNESS_FILE" \
  --expected-reference "$PIN" > "$EVIDENCE/reconcile-retry.json" 2> "$EVIDENCE/reconcile-retry.stderr"
jq -e --slurpfile first "$EVIDENCE/reconcile.json" \
  '.outcome == "ACCEPT" and .local_publication_performed == false and
   .witness_publication.outcome == "COMPLETE" and
   .verified_reference == $first[0].verified_reference' \
  "$EVIDENCE/reconcile-retry.json" > "$EVIDENCE/retry-check.txt"
cmp -- "$EVIDENCE/witness-after.json" "$WITNESS_FILE"
"$CLI" status "${COMMON[@]}" > "$EVIDENCE/status-after.json" 2> "$EVIDENCE/status-after.stderr"
jq -e --slurpfile before "$EVIDENCE/status-before.json" \
  '.outcome == "ACCEPT" and .reference == $before[0].reference' \
  "$EVIDENCE/status-after.json" > "$EVIDENCE/no-sequence-change-check.txt"

# Only this final step emits selected snapshot bytes, into a private evidence file.
"$CLI" resume "${COMMON[@]}" --memory-path "$MEMORY_PATH" \
  --witness-file "$WITNESS_FILE" --require-witness \
  --expected-witness-checkpoint "$PIN" \
  > "$EVIDENCE/approved-memory.txt" 2> "$EVIDENCE/resume-decision.json"
jq -e --slurpfile receipt "$PARTIAL_RECEIPT" \
  '.outcome == "ACCEPT" and .reference == $receipt[0].reference' \
  "$EVIDENCE/resume-decision.json" > "$EVIDENCE/resume-check.txt"
printf 'Recovery verified; evidence retained at %s\n' "$EVIDENCE"
RECOVERY
```

If task-specific approval requires a semantic predicate, add its retained
`--predicate-file` to the final `resume` command. Reconciliation validates the
signed snapshot, retained reference, receiver policy and exact expected pin;
it does not approve a task's semantics or invoke an application. The final
`resume` policy should still apply the application's required checks. Treat the
private `approved-memory.txt` as approved only if the final command and its
decision check both succeed; a failed command can leave an empty redirected
file.

An already `COMPLETE` witness can be reconciled again. Retrying is logically
idempotent: its canonical file bytes, local generation and sequence stay the
same. The witness inode and modification time can change because the command
performs another safe replacement.

## Nonzero reconciliation and stop conditions

`witness-reconcile` prints one final metadata JSON object to stdout and returns
0 for `ACCEPT`, 1 for `NEEDS_EVIDENCE`, or 2 for rejection/error. It never prints
snapshot files. `local_publication_performed:false` applies to this recovery
operation; it does not retract the original publication's local commit.
`verified_reference`, when present, identifies a snapshot that passed the
decision at the receiver's SQLite commit point.

| Reconciliation result | Meaning and next step |
|---|---|
| Witness `NOT_ATTEMPTED` | Preflight, snapshot verification, expected pin or existing witness conflict prevented replacement. Preserve the evidence and resolve the specific cause. |
| Witness `INCOMPLETE` with `verified_reference` | Snapshot verification succeeded, but witness replacement/sync did not complete. The new witness may already be visible. Retain the failure, inspect the intended mount/permissions, and retry the exact same retained pin after correcting the file failure. |
| Witness `COMPLETE`, nonzero exit | Replacement/sync completed but cleanup failed. Retain the error and retry the same exact-pin operation after resolving cleanup. |
| `NEEDS_EVIDENCE`, expired snapshot, wrong key/context/scope/profile, corrupt generation | Stop approval and delivery. Obtain valid evidence or repair through a separately reviewed recovery path. Do not alter freshness settings or trust inputs to make this command pass. |
| Observed reference differs from retained intended reference | Stop. Another publication, a restore or the wrong receiver may be involved. Establish the intended state before selecting a new pin. |
| Existing witness ahead of local state, equal-sequence fork, malformed witness or symlink | Stop and preserve both sides. The command refuses to erase this evidence. Investigate custody/restore/path selection; quarantine or replacement requires a separately justified operator decision. |

After a nonzero result, the block above intentionally stops before strict
resume. Keep that evidence directory and use a **new** directory for a corrected
attempt so the first failure remains visible. A changed snapshot or expired
receipt is not remedied by repeatedly retrying witness replacement.

## UNKNOWN or interrupted publication

If local commit status is unknown, first retain the interrupted process output,
the original expected-reference CAS, the intended input/payload records, the
observed `status`, and any witness bytes. Do not manufacture a partial receipt
containing `local_committed:true`. A status query reports retained state; it
cannot tell which attempted publication the operator intended.

An operator can proceed only after independently binding the observed reference
to the intended signed snapshot and publication, including the relevant
checkpoint, sequence, context, scope, trusted key and application expectation.
If that evidence establishes the intended accepted checkpoint, retain a written
operator decision and that checkpoint separately, then use `witness-reconcile`
with its exact digest. Its full snapshot verification still runs. The known-commit
block deliberately accepts only an actual `local_committed:true` partial receipt;
an UNKNOWN case needs a separately reviewed evidence path rather than editing
that receipt to fit the block.

If the independently retained evidence cannot establish the intended reference,
leave the outcome UNKNOWN and stop delivery. Neither an authentic old witness
nor a green `status` or receipt check resolves that missing knowledge.

## What completion establishes

Completion means that the intended retained checkpoint passed full local
verification, the exact-pin recovery wrote and synced its witness file, a repeat
preserved logical state, and a fresh strict resume accepted the same reference
without an intervening publication. The supplied witness remains a floor. The
verified read linearizes at its SQLite commit; the later file replacement is
separate. The lock protects cooperating publishers for this target only.
Noncooperating changes after that commit remain the operator's obligation, and
no step establishes globally latest state or external custody by itself.
