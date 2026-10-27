# Experimental receiver checkpoint gate

This separate versioned prototype imports CPR 0.5 receipt context only after
checking the production CPR verifier result and a signed checkpoint against
receiver-retained trust inputs. It does not change CPR syntax or the existing
consumer profile. It does not authorize an action or claim SCITT conformance.

```sh
python3 -m pytest -q tests/test_receiver_checkpoint.py
python3 tools/receiver_checkpoint_demo.py
```

`receive_bundle()` assesses immutable input bytes and releases a parsed copy
of those exact bytes to the receiving sink only on acceptance. The caller
cannot supply an unrelated context string or a fabricated assessment to that
release function. `assess_import()` alone is a diagnostic interface.
Inputs are captured from their byte buffers before parsing, so a `bytes`
subclass cannot substitute different data through overridden conversion or
decode methods between verification and release.

The receiver supplies its pinned Ed25519 public key, accepted checkpoint
digest, expected context, evaluation instant and maximum age separately from
the imported material. It verifies the checkpoint signature, canonical
signature representation, bundle-byte digest, context, version and freshness.
The accepted digest identifies a full signed checkpoint; a valid older
checkpoint remains historical even while its age is within the allowed window.
Missing checkpoint or reference gives NEEDS_EVIDENCE. Contradictory,
malformed, stale or unsupported evidence gives REJECT. Only ACCEPT reaches
the sink. Native core results are preserved when core verification is invoked;
raw parse failures have a separate structured diagnostic.

The prototype accepts only CPR 0.5. A core TRUSTED result does not establish
real-world signer authority. The separately pinned checkpoint signer is the
receiver's trust boundary for this narrow receipt-context import.

The process demo starts from the published vector
`vectors/22_local_state_commitment.json`. It appends a real signed settlement
receipt to the terminated task, preserving every earlier signed receipt and
linking the new record to the prior digest. Both bundles verify. Every case
runs in a new Python subprocess against disposable input files. The observed
sink contains identifiers read from the actual accepted receipt bundle.

| Case | Result | Sink delivery |
|---|---|---|
| Valid current bundle/checkpoint/reference | ACCEPT | Actual bundle |
| Missing checkpoint or accepted reference | NEEDS_EVIDENCE | None |
| Wrong key, altered signature, wrong context | REJECT | None |
| Expired authentic checkpoint | REJECT | None |
| Authentic older checkpoint within its age window against newer reference | REJECT | None |
| Signed append with old checkpoint | REJECT | None |
| New checkpoint with old retained reference | REJECT | None |
| Signed append after explicit trusted reference refresh | ACCEPT | Actual later bundle |

The demo asserts outcome, native reason and sink contents for all eleven
cases. It reports exact fixture hashes and a control establishing that the
append preserved the old signed prefix. Inputs use fixed test keys and frozen
time; expected answers are visible. This is the same machine and
implementation, not independent-operator evidence.

The reference is never refreshed automatically. The example demonstrates an
explicit trusted reference update, not a production refresh/custody protocol,
atomic storage, concurrent writers or multi-device coordination. It is a
controlled receipt-context sink, not a live LLM, hosted API, grant-revocation
engine or erasure mechanism. Full-state completeness, content truth,
authorization and destruction of every backup/key copy remain separate claims.

Compute current reproduction identities after source changes:

```sh
sha256sum continuity_receipt/*.py tools/receiver_checkpoint_demo.py \
  tests/test_receiver_checkpoint.py vectors/22_local_state_commitment.json
python3 --version
python3 -m pip show cryptography
```
