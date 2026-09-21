# Anchor fixtures — real OpenTimestamps proofs

Real `.ots` detached proofs used by `tests/test_anchor.py`. Source:
[`opentimestamps/opentimestamps-client`](https://github.com/opentimestamps/opentimestamps-client)
`examples/` (MIT), retrieved 2026-09-21. Headers in `headers.json` were
fetched from the [Blockstream Esplora API](https://blockstream.info/api) the
same day (`/block-height/<height>` → `/block/<hash>/header`); header bytes are
the 80-byte wire form, merkle root at bytes 36..68.

| Fixture | File hash | Reaches | Expected verdict |
|---|---|---|---|
| `hello-world.txt.ots` | sha256 | bitcoin @ 358391 | `verified` with header; digest equals sha256 of `hello-world.txt` |
| `bitcoin.pdf.ots` | sha1 | bitcoin @ 465751 | `verified` with header (sha1 path) |
| `gdp2q25-2nd.pdf.ots` | sha256 | bitcoin @ 912095 | `verified` with header (2025 issuance) |
| `known-and-unknown-notary.txt.ots` | sha256 | pending + unknown | `unverified` / `anchor_pending`; both attestations listed |
| `different-blockchains.txt.ots` | sha256 | keccak256 path | `invalid` / `unsupported_op` — published negative case |

These are not spec vectors (no `manifest.json` entry, not run by the
conformance CLI); they pin the companion tool against real calendar output.
The keccak fixture is kept deliberately: keccak256 is not implemented, and
the tool must fail loudly rather than silently skip the operation.

Header chain validation remains out of scope (ANCHORING.md): the headers are
supplied inputs, not a substitute for proof-of-work or confirmation checks.
