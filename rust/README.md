# continuity-receipt (Rust)

Second, independent implementation of the Continuity Receipt verifier for
`continuity-receipt/0.1`-`0.2` bundles. The Python implementation in
`../continuity_receipt/` remains the reference; this crate exists for the
two-independent-implementations bar, native embedding, and single-binary
deployment.

It re-implements the pinned JCS subset (`canon.rs`), `did:key` Ed25519
verification (`didkey.rs`), and the full verification algorithm with the same
error codes, verdict precedence, and JSON output shape as
`continuity_receipt.verify` (`verify.rs`).

## Run

```sh
cargo run --bin continuity-receipt-verify -- ../vectors/02_happy_full.json
cargo run --bin continuity-receipt-verify -- ../vectors/10b_anchor_missing.json --require-anchor
```

The binary prints the same JSON shape as the Python CLI (`verdict`, `errors`,
`provisional_reasons`, `insufficient_reasons`, `summary`) and exits `0` iff the
verdict is `TRUSTED`, else `1`.

## Tests

```sh
cargo test
```

The vector runner reads `../vectors/manifest.json` and checks all 20 vectors
against their expected verdict and error code. Malformed-bundle smoke cases
(empty object, non-object, missing receipts) are included so the verifier
returns structured errors instead of panicking.

## Intentional, documented differences from Python

- Floats and canonicalization failures produce a structured `malformed` (or
  the relevant check's) error instead of a Python exception/traceback.
- Invalid JSON input to the CLI prints a structured `malformed` result and
  exits `1` instead of raising.
- Non-list `anchors`/`revocations` values and other deeply malformed shapes
  are failed closed with the corresponding structured error where Python would
  raise.
