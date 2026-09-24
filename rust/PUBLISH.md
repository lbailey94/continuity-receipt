# Publishing `continuity-receipt` to crates.io

**Status:** published through `0.3.3` (0.3.1 anchor parity; 0.3.2 spec 0.3
offer/accept parity; 0.3.3 verification-receipt parity). The crate is at
`0.4.0` — release candidate, publication pending. This runbook is the
procedure for the 0.4.0 publication and future versions.

Operator runbook. The crate is publish-ready (`cargo publish --dry-run`
passes); publication itself is a human action because it needs the crates.io
token and is irreversible (a version can be yanked, never replaced).

## Preconditions

- `cargo test --manifest-path rust/Cargo.toml` green, including
  `tests/fuzz_corpus.rs`; the Python↔Rust differentials (bundle 40/40,
  verification receipts 21/21, disclosure, anchor) and
  `tools/hostile_input_probe.py --require-parity` green in CI.
- The crate is owned by this project and published through `0.3.3`;
  confirm the crates.io token has publish rights before releasing.

## Version

The crate is at `0.4.0` (release candidate; `Cargo.toml`). The 0.3.0 alpha
sequence already validated the pipeline — publish `0.4.0` directly once the
release candidate is frozen (tagged, checked, changelog promoted).

Do not publish with `alpha` or `rc` in the version: crates.io sorts
pre-releases below the release, and `cargo install continuity-receipt` would
not pick it up.

## Steps

```sh
cd rust
cargo login                 # token stays in ~/.cargo/credentials.toml; never commit
cargo publish --dry-run     # already passes; re-run after any edit
cargo publish               # from rust/; publishes the library and the
                            # verify, disclose, anchor, and verify-receipt binaries
```

## Post-publish verification

```sh
cargo install continuity-receipt --version 0.4.0
continuity-receipt-verify ../vectors/02_happy_full.json          # TRUSTED, exit 0
continuity-receipt-disclose check --salt <hex> --value '["quality-ok"]' --commit <sha256:...>
cargo search continuity-receipt
```

Also check the docs.rs build, then update:

- `ROADMAP.md` — mark the 0.4.0 publication landed.
- `CHANGELOG.md` — promote the Unreleased 0.4.0 entries.
- the repository README's version matrix and second-implementation bullet.

## Not included

- `--revocations` on the Rust disclose CLI (Python-only until the Rust
  revocation-list loader lands); the Rust receipt CLI accepts local
  revocation documents only (no URLs).
- Wire changes beyond spec 0.4: 0.4.0 is a spec 0.4 release.
