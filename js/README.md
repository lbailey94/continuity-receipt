# continuity-receipt (JavaScript/TypeScript verifier)

Offline verifier for [continuity-receipt](https://github.com/lbailey94/continuity-receipt)
bundles, covering spec versions 0.1 through 0.6. This is an independent
port of the Python reference implementation (`continuity_receipt/`), intended
to reproduce its verdicts and error codes for the published vector corpus.

- Pure ESM, no runtime dependencies.
- RFC 8785-subset (JCS) canonicalization matching the Python reference.
- Ed25519 `did:key` verification through WebCrypto (`crypto.subtle`), with a
  `node:crypto` fallback on runtimes whose WebCrypto lacks Ed25519.
- Whole-bundle shape checks, chain links, cross-record rules, agreements,
  authority grants, redactions/commitments, attestations, provenance,
  revocations, and anchor presence semantics.
- CLI: `continuity-receipt-verify`.

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

Lower-level exports include `canonicalBytes`, `commitField`, `receiptDigest`,
`parseStrictJson`, `didKeyToPublicKey`, `verifyEd25519`, `verifyStatements`,
`mergeStatements`, and the spec constants (`SUPPORTED_SPECS`, `RECORD_TYPES`,
`REQUIRED_FIELDS`, ...).

## Build and test

```sh
npm install
npm run build
npm test          # node --test against the built dist
npm run parity    # vector table; add --baseline for Python code/reason diffs
```

The package requires Node >= 18.17 (or any runtime with WebCrypto Ed25519).
`type: module`; TypeScript declarations ship in `dist/`.

## Parity and known gaps

The verifier is validated against the reference `vectors/` corpus (manifests
0.4/0.5/0.6). `npm run parity` prints the expected-versus-got table and exits
non-zero on any verdict mismatch.

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

## License

Apache-2.0. See `LICENSE`.
