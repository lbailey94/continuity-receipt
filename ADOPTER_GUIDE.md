# Adoption and evidence guide

## 1. Verify an existing bundle (published 0.5)

Clone this repository for the frozen vectors, or install the published package. Pin the implementation if results will be cited:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install continuity-receipt==0.5.0
continuity-receipt-verify vectors/02_happy_full.json
```

A TRUSTED result establishes format, signature, chain, and selected policy checks. It does not independently establish that the issuer's narrated task occurred. For a signed statement about a verification run, see VERIFY_IN_5_MIN.md; verify the underlying bundle again yourself.

## 2. Emit a minimal local bundle (0.5)

Spec 0.5 is published (2026-09-30). Use this checkout and its Python dependencies to try the producer script against a file you control:

```sh
openssl genpkey -algorithm ED25519 -out /tmp/cr-example-key.pem
printf 'I authorize this local demonstration\n' > /tmp/cr-example-mandate.txt
printf 'example state\n' > /tmp/cr-example-state.txt
python3 tools/emit_file_snapshot.py /tmp/cr-example-state.txt \
  --mandate /tmp/cr-example-mandate.txt \
  --key-pem /tmp/cr-example-key.pem --scope demo:state \
  --output /tmp/cr-example-bundle.json
python3 -m continuity_receipt.verify /tmp/cr-example-bundle.json
```

The script reads the file, computes its byte count and SHA-256, and signs a five-record chain with local authority and no OS confinement. The mandate file is hashed into the pass. The CLI checks its own output before writing. The private key stays in your PEM file; for production, choose a managed signing-key lifecycle and protect it accordingly. This script does **not** enforce the mandate or isolate execution. The recipient must receive the snapshot and mandate separately to verify their hashes and decide whether the issuer had authority.

The generated bundle is a runtime-produced statement by this small script about the bytes it read. It does not claim WhiteMagic or Mandala runtime provenance.

## 3. Capture a project runtime bundle

To make an integration claim reviewable, retain:

1. The producer source revision, configuration, and command or event that triggered emission.
2. The exact bundle bytes and SHA-256, plus a description of signing-key custody and issuer identity.
3. The referenced input/output artifacts needed to recompute digests, when disclosure is possible.
4. Offline Python and Rust verifier versions, commands, verdicts, and error codes.
5. External corroboration, if claiming enforcement, delivery, termination, or state completeness beyond the issuer's signed statement.

Use the following labels in examples and reports:

| Label | What it establishes |
|---|---|
| Modeled fixture | The producer code can build a valid format example from chosen facts. |
| Captured runtime artifact | A named runtime emitted these exact bytes under a recorded invocation. |
| Independently corroborated | A separate observer or recomputation supports a specified body claim. |

A locally developed cross-generation example contains one captured WhiteMagic Gen2 bundle and two modeled Gen3 fixtures. The Gen3 fixtures must not be presented as Gen3-emitted evidence; that example is not part of this guide or the public release.

## 4. Conformance and version boundaries

Published spec 0.5 ships in package 0.5.0. Its 21 bundle vectors are in
`vectors/manifest-0.5.json`. Published 0.4 retains the frozen 40-vector bundle
corpus in `vectors/manifest.json` and 21 verification-receipt vectors.

The 0.5.0 Python and Rust packages also contain experimental verifier behavior
for draft spec 0.6 and its 10-vector corpus (`vectors/manifest-0.6.json`),
which is present in the signed `v0.5.0` source tag. There is no standalone
normative 0.6 release. The offline Python consumer policy assessment supports
receipt specs 0.1–0.4 only. The hosted information endpoint advertises its
conformance corpus separately from its verifier's reported version support;
see [the capability matrix](docs/CAPABILITY_MATRIX.md) for dated observations
and limits. An unauthenticated information response does not establish
authenticated public request behavior.
