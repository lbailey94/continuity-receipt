# Artifact candidate qualification

Source candidates: Python 0.5.4, Rust 0.5.2, JavaScript 0.1.2. Preserve published
registry pins until the exact artifacts are separately approved and published.

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
