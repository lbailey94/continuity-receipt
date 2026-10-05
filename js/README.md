# continuity-receipt (JavaScript/TypeScript verifier)

Offline verifier for [continuity-receipt](https://github.com/lbailey94/continuity-receipt)
bundles, covering spec versions 0.1 through 0.6, plus verifier for the
companion verification receipts. This is an independent port of the Python
reference implementation (`continuity_receipt/`), intended to reproduce its
verdicts and error codes for the published vector corpus.

- Pure ESM, no runtime dependencies.
- RFC 8785-subset (JCS) canonicalization matching the Python reference.
- Ed25519 `did:key` verification through WebCrypto (`crypto.subtle`), with a
  `node:crypto` fallback on runtimes whose WebCrypto lacks Ed25519.
- Whole-bundle shape checks, chain links, cross-record rules, agreements,
  authority grants, redactions/commitments, attestations, provenance,
  revocations, and anchor presence semantics.
- Verification-receipt shape/consistency/signature checks, digest binding to
  the verified bundle, and optional issuer revocation.
- CLIs: `continuity-receipt-verify` and `continuity-receipt-verify-receipt`.

## Install

```sh
npm install continuity-receipt
```

## CLI

```sh
npx continuity-receipt-verify ../vectors/01_happy_minimal.json
npx continuity-receipt-verify --require-anchor bundle.json
npx continuity-receipt-verify --revocations https://example.com/revocations.json bundle.json
```

Prints the full result as JSON. Exit codes: `0` TRUSTED, `1` any other
verdict (including parse/size failures), `2` unreadable bundle file.

### Verification receipts

```sh
npx continuity-receipt-verify-receipt receipt.json --bundle bundle.json
npx continuity-receipt-verify-receipt receipt.json --revocations revocations.json
npx continuity-receipt-verify-receipt receipt.json --digest
npx continuity-receipt-verify-receipt receipt.json --canonical receipt.canonical
```

Prints `{valid, errors, issuer, verdict, verified_at, bundle_digest,
digest_match}` as JSON and exits `0` iff the receipt is valid, `1` otherwise,
`2` when the receipt or `--bundle` is unreadable or not valid JSON. `--digest`
prints the anchoring digest (SHA-256 of the JCS view minus `sig`);
`--canonical PATH` writes that view to `PATH` and prints its digest. The same
`--revocations PATH|URL` loader as the bundle CLI is used (repeatable).

## API

```ts
import { verifyBundle, verifyFile } from "continuity-receipt";

const result = await verifyFile("bundle.json", { requireAnchor: false });
console.log(result.verdict);          // TRUSTED | PROVISIONAL | INSUFFICIENT_EVIDENCE | UNTRUSTED
console.log(result.codes());          // ["bad_signature", ...]
console.log(result.asDict());         // serializable full result
```

`verifyBundle(bundle, options)` accepts an already-parsed JSON value.
`verifyFile(path, options)` reads and strictly parses the file first
(duplicate JSON members are rejected; `bundle_too_large`, `malformed`,
`nesting_too_deep`, and `io_error` are returned as results).

Options:

- `requireAnchor` — when true, a bundle with no anchors is PROVISIONAL
  (`anchor_missing`).
- `externalRevocations` — array of self-signed revocation statements to merge
  with the bundle's `revocations`.

Verification receipts:

```ts
import {
  verifyVerificationReceipt,
  verificationReceiptDigest,
} from "continuity-receipt";

const result = await verifyVerificationReceipt(receipt, bundle, revocations);
console.log(result.valid, result.errors);   // error-code strings
console.log(result.digest_match);           // true | false | null (no bundle)

await verificationReceiptDigest(receipt);   // "sha256:..." over JCS view minus sig
```

`bundle` may be a parsed object, JSON string, or bytes; `revocations` is an
array of self-signed statements (0.2 §7.5 shape) or `null` to skip the check.

Lower-level exports include `canonicalBytes`, `commitField`, `receiptDigest`,
`verificationReceiptDigest`, `parseStrictJson`, `didKeyToPublicKey`,
`verifyEd25519`, `verifyStatements`, `mergeStatements`,
`loadRevocationStatements`, and the spec constants (`SUPPORTED_SPECS`,
`RECORD_TYPES`, `REQUIRED_FIELDS`, ...).

## Build and test

```sh
npm install
npm run build
npm test              # node --test against the built dist
npm run parity        # bundle vector table; add --strict for Python code/reason diffs
npm run parity:receipts  # verification-receipt table vs. Python baseline
```

The package requires Node >= 18.17 (or any runtime with WebCrypto Ed25519).
`type: module`; TypeScript declarations ship in `dist/`.

## Parity and known gaps

The verifier is validated against the reference `vectors/` corpus (manifests
0.4/0.5/0.6). `npm run parity` prints the expected-versus-got table and exits
non-zero on any verdict mismatch. `npm run parity:receipts` does the same for
the 21 verification-receipt vectors in `vectors/verification/`, comparing
validity and the exact error list against `test/python-baseline-receipts.json`
recorded from `continuity-receipt-verify-receipt` (Python reference).

Known deviations from the Python reference (documented, not silent):

- **Parser fidelity.** Python's `json` keeps arbitrary-precision integers and
  arbitrary-size floats. This port preserves integers exactly (`bigint`) but
  represents float literals with a marker object; receipts cannot be encoded
  with floats either way, so verdicts agree, but error details may differ for
  inputs that mix floats into otherwise verifiable records.
- **Invalid calendar timestamps.** Python's `datetime.fromisoformat` raises on
  values that pass the RFC 3339 regex but are not real dates (for example
  `2026-99-99T00:00:00Z`); this port treats them as incomparable instead of
  throwing. No published vector exercises this.
- **External revocation URLs.** `https://` and loopback `http://` fetches are
  supported; plain `http://` non-loopback hosts are refused
  (`revocations_insecure_url`), matching the reference tooling's policy.
- **OpenTimestamps anchor proof replay** (`continuity_receipt/anchor.py`) is a
  separate companion tool and is not part of bundle verification; only anchor
  presence/binding semantics are implemented here.

## Conformance

The hosted conformance referee graded this implementation over the pinned
corpus on 2026-10-05: **CONFORMANT** — 40/40 bundles, 21/21 verification
receipts, 208/208 hostile inputs, zero mismatches. The signed report is
[`CONFORMANCE_REPORT.json`](CONFORMANCE_REPORT.json); verify it offline from
the repository root with:

```sh
python3 tools/conformance_submit.py --verify-report js/CONFORMANCE_REPORT.json
```

Submit a build of this verifier to the referee with
`python3 tools/conformance_submit.py --js` (requires `npm run build`).

## License

Apache-2.0. See `LICENSE`.
