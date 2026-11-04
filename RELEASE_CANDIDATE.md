# Artifact qualification

Python 0.5.4, Rust 0.5.2 and JavaScript 0.1.2 were published on 2026-11-04 after
the tests in [PR #21](https://github.com/lbailey94/continuity-receipt/pull/21)
passed. The code-bearing source is `993cbd7d78bfcd959dcf7ed6805f91a8c433bbee`,
integrated by merge commit `4958c371a6730c33f4c0f8ad109d4ebd69596cb2`.

| Registry artifact | SHA-256 |
|---|---|
| PyPI `continuity_receipt-0.5.4-py3-none-any.whl` | `394f5a2e614f0169dcaaaf3bcbffc0805888d0084f7b241c4ceb98551967e06c` |
| PyPI `continuity_receipt-0.5.4.tar.gz` | `86743c3e7cb9c471ed641bbe7a70257ac146c44c1e35e8c29fe277d0536103cb` |
| crates.io `continuity-receipt-0.5.2.crate` | `a1fc304976e56a8d0e23200a329c893ba72d65497ec7b1f745c1dc0b56ef6014` |
| npm `continuity-receipt-0.1.2.tgz` | `e35be24d7c9fb1320641525f41027a3912794537addfb96f8966e9b3e865bce8` |

The existing `v0.5.4` source tag predates the packaging work and was not moved.
Use the registry artifact versions/hashes and source commits above for this
qualification. The Rust package records the clean code-bearing source commit,
not an earlier dirty-checkout archive. The Python wheel installed from PyPI
passed 44 checks across 47 retained calls, including deliberate refusals.

For subsequent releases, keep candidate qualification and observed publication
separate until the new artifacts are actually available from their registries.

Build a wheel/sdist with `python -m build`, an npm tarball after `npm ci && npm
test`, and a crate with `cargo package --manifest-path rust/Cargo.toml --locked`.
Retain hashes, build logs and the source diff with each candidate. Install the
wheel into a fresh venv and use `tools/installed_witness_journey.py` with the
exact wheel and installed Python. Test npm's extracted dist entry points and
CLI version outside the checkout. Run the full Rust suite on the extracted
crate; its fixtures are shipped under `rust/fixtures` so it never relies on
the original repository's parent directory.

The copies under `rust/fixtures` are package test inputs, not an independently
authored conformance set. CI compares them byte-for-byte to the owning root
vectors/fixtures and tests the extracted package. Update both when changing
an owning fixture; do not relabel fixture agreement as independent validation.

The installed receiver/witness journey is a synthetic local qualification.
For another-operator qualification, supply the exact wheel hash, source ref,
new output directory and independent retained witness state. Keep identity,
raw outputs and failures. A second process or agent on this same host does
not establish a second administered host or independent adoption.
