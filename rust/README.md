# continuity-receipt (Rust)

Second, independent implementation of the Continuity Receipt verifier for
`continuity-receipt/0.1`-`0.3` bundles and verification receipts (companion
v1). The Python implementation in `../continuity_receipt/` remains the
reference; this crate exists for the two-independent-implementations bar,
native embedding, and single-binary deployment.

It re-implements the pinned JCS subset (`canon.rs`), `did:key` Ed25519
verification (`didkey.rs`), and the full verification algorithm with the same
error codes, verdict precedence, and JSON output shape as
`continuity_receipt.verify` (`verify.rs`) and
`continuity_receipt.verification` (`verification.rs`).

## Install

```sh
cargo add continuity-receipt        # library
cargo install continuity-receipt    # CLIs: verify, disclose, anchor, verify-receipt
```

The crate tracks `continuity-receipt/0.1`-`0.3` bundles; the Python
implementation in this repository remains the reference. Publication
runbook: [`PUBLISH.md`](PUBLISH.md).

## Run

```sh
cargo run --bin continuity-receipt-verify -- ../vectors/02_happy_full.json
cargo run --bin continuity-receipt-verify -- ../vectors/10b_anchor_missing.json --require-anchor
```

The binary prints the same JSON shape as the Python CLI (`verdict`, `errors`,
`provisional_reasons`, `insufficient_reasons`, `summary`) and exits `0` iff the
verdict is `TRUSTED`, else `1`.

## Selective disclosure

`continuity-receipt-disclose` mirrors `continuity_receipt/disclose.py`
(`redact` / `verify` / `reveal` / `check`):

```sh
cargo run --bin continuity-receipt-disclose -- redact \
  --bundle ../vectors/02_happy_full.json \
  --path receipts[3].body.spec_ref \
  --out /tmp/redacted.json --map /tmp/map.json --gate-key /tmp/gate.key

cargo run --bin continuity-receipt-disclose -- verify \
  --bundle /tmp/redacted.json --map /tmp/map.json

cargo run --bin continuity-receipt-disclose -- reveal \
  --bundle /tmp/redacted.json --map /tmp/map.json \
  --path receipts[3].body.spec_ref --out /tmp/package.json

cargo run --bin continuity-receipt-disclose -- check \
  --salt <hex> --value '["quality-ok"]' --commit sha256:...
```

The gate-key file is the raw 32-byte Ed25519 seed. Redaction re-signs the
modified receipt and every receipt after it, so the signer must be the
chain's issuer; redacting a cross-checked field (for example `spend_cap`)
fails closed to `UNTRUSTED` because a commitment cannot prove the claim.

## Verification receipts

`continuity-receipt-verify-receipt` mirrors
`continuity_receipt/verification.py`: shape and consistency checks
(`error_codes` equals the codes in `errors`; the verdict equals the class
implied by the errors/reasons), the Ed25519 signature over the canonical view
minus `sig`, optional bundle-digest and issuer-revocation checks.

```sh
cargo run --bin continuity-receipt-verify-receipt -- \
  ../vectors/verification/01_valid.json --bundle ../vectors/verification/bundle.json
cargo run --bin continuity-receipt-verify-receipt -- \
  ../vectors/verification/12_revoked_issuer.json \
  --bundle ../vectors/verification/bundle.json \
  --revocations ../vectors/verification/12_revoked_issuer.revocations.json
cargo run --bin continuity-receipt-verify-receipt -- \
  ../vectors/verification/01_valid.json --canonical /tmp/receipt.canonical   # prints the anchor digest
```

Exit `0` iff the receipt is valid. `--revocations` reads a local revocation
document (the Python CLI also accepts URLs).

## OpenTimestamps anchors

`continuity-receipt-anchor` mirrors `continuity_receipt/anchor.py`: replay a
detached `.ots` proof from the file digest and verify a Bitcoin attestation
against a supplied 80-byte block header by exact merkle-root equality.

```sh
cargo run --bin continuity-receipt-anchor -- verify proof.ots \
  --digest sha256:<hex> [--header <80-byte hex> --height <n>] [--json]

cargo run --bin continuity-receipt-anchor -- verify proof.ots \
  --bundle ../vectors/08_redacted_disclosed.json --target <receipt_id> --json
```

Statuses `verified` / `unverified` / `mismatch` / `invalid` with the same
machine codes as Python; exit `0` iff `verified`. Header chain validation is
out of scope by design (`../ANCHORING.md`): the header is trusted input, not a
substitute for proof-of-work or confirmation checks.

## Tests

```sh
cargo test
```

The vector runner reads `../vectors/manifest.json` and checks all 26 bundle
vectors against their expected verdict and error code; `tests/verification.rs`
does the same for the 20 verification-receipt vectors
(`../vectors/verification/manifest.json`), including consistency violations
and receipt digests. Malformed-bundle smoke cases
(empty object, non-object, missing receipts) are included so the verifier
returns structured errors instead of panicking. `tests/disclose.rs` covers
redaction, tail re-signing, refusal cases, and commitment recomputation
against the frozen vectors. `tests/fuzz_corpus.rs` mutates every vector
(deterministic seed) plus synthetic malformed shapes and byte truncations:
every case must yield a structured verdict with coded errors and never
panic. Set `CR_FUZZ_CORPUS_DIR=<dir>` to write the generated corpus to disk.

`tests/anchor.rs` covers synthetic proofs (LEB128 varuints, reverse/prepend,
truncation, keccak refusal) and the five real `.ots` fixtures, including the
published keccak negative case.

The Python↔Rust differentials run in CI after `cargo build`:

```sh
python3 tools/differential_vectors.py               # verdict + error-code parity
python3 tools/differential_disclose.py              # maps, signatures, cross-verification
python3 tools/differential_anchor.py                # status/code/confirmed parity
python3 tools/differential_verification_receipts.py # validity/codes/digest parity
```

## Intentional, documented differences from Python

- Floats and canonicalization failures produce a structured `malformed` (or
  the relevant check's) error instead of a Python exception/traceback.
- Invalid JSON input to the CLI prints a structured `malformed` result and
  exits `1` instead of raising.
- Non-list `anchors`/`revocations` values and other deeply malformed shapes
  are failed closed with the corresponding structured error where Python would
  raise.
- `disclose redact` additionally accepts repeatable `--salt <path>=<hex>` for
  reproducible commitments; the Python CLI always randomizes salts.
- `disclose verify` does not accept `--revocations` until the Rust
  revocation-list loader lands; external lists remain Python-only. The
  verification-receipt CLI accepts local revocation documents (no URLs).
- `anchor verify` human (non-`--json`) output prints attestations as compact
  JSON rather than Python dict reprs; the `--json` shape is identical.
