# Publishing `continuity-receipt` to crates.io

**Status:** `0.3.0-alpha.1` and `0.3.0` published 2026-09-21 (alpha first to
validate the pipeline, then the release). This runbook remains the procedure
for future versions.

Operator runbook. The crate is publish-ready (`cargo publish --dry-run`
passes); publication itself is a human action because it needs the crates.io
token and is irreversible (a version can be yanked, never replaced).

## Preconditions

- `cargo test --manifest-path rust/Cargo.toml` green, including
  `tests/fuzz_corpus.rs`, plus both Python↔Rust differentials in CI.
- The name `continuity-receipt` is still available (checked free on
  2026-09-21) — re-check before publishing.

## Version

The crate is at `0.3.0-alpha.1`. Recommended sequence:

1. Publish `0.3.0-alpha.1` as-is first if you want to validate the pipeline
   end-to-end (an alpha can be superseded without yanking).
2. Then set `version = "0.3.0"` once the alpha is confirmed: disclose and the
   fuzz corpus are the last planned 0.3 features.

Do not publish the final release with `alpha` in the version: crates.io sorts
pre-releases below the release, and `cargo install continuity-receipt` would
not pick it up.

## Steps

```sh
cd rust
cargo login                 # token stays in ~/.cargo/credentials.toml; never commit
cargo publish --dry-run     # already passes; re-run after any edit
cargo publish               # from rust/; publishes lib + both binaries
```

## Post-publish verification

```sh
cargo install continuity-receipt --version 0.3.0
continuity-receipt-verify ../vectors/02_happy_full.json          # TRUSTED, exit 0
continuity-receipt-disclose check --salt <hex> --value '["quality-ok"]' --commit <sha256:...>
cargo search continuity-receipt
```

Also check the docs.rs build, then update:

- `ROADMAP.md` — mark the 0.3.0 publication landed.
- `CHANGELOG.md` — move the 0.3.0 entries out of Unreleased.
- the repository README's second-implementation bullet.

## Not included

- `--revocations` on the Rust disclose CLI (Python-only until the Rust
  revocation-list loader lands).
- Any spec change: this is a tooling release on spec 0.2.
