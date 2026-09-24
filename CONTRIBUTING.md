# Contributing

## Ground rules

1. **Small specification, testable changes.** A change to `SPEC.md` lands only with a vector, an acceptance test, or a documented negative case — and a row in `CONFORMANCE_TABLE.md` mapping the rule to its checks and vectors. If it cannot be tested, it is a discussion item, not a spec change.
2. **Additive within 0.x.** Breaking changes require a new minor version and a new vector set (see `SPEC.md` §10).
3. **Interop beats elegance.** When a choice exists, align with the neutral venues (W3C AI Agent Memory Interoperability CG; IETF agentproto) and with existing implementations.
4. **Failures publish.** Rejected designs and known gaps are documented in `SPEC.md` §11 and `THREAT_MODEL.md`, not hidden.

## How to contribute

- **Issues first** for spec questions, field-mapping suggestions, or proposed vectors.
- **Pull requests** must:
  - add or update vectors and manifests via `tools/make_vectors.py` / `tools/make_verification_vectors.py` when behavior changes (new behavior gets new vector files; published fixtures stay byte-for-byte frozen);
  - keep `python3 -m unittest discover -s tests -v` green (vectors, schema, primitives);
  - update `SPEC.md`, `CHANGELOG.md`, and `THREAT_MODEL.md` when semantics change.
- **Developer Certificate of Origin (DCO).** Contributions are accepted under the DCO 1.1: sign off commits with `git commit -s` to certify you wrote the contribution or have the right to submit it. No separate CLA is required. (Decision recorded 2026-09-18; revisit only if the work moves to a foundation.)
- **License.** By contributing you agree your contribution is licensed under Apache-2.0.

## Running the suite

```bash
pip install 'cryptography>=42' jsonschema
python3 tools/make_vectors.py            # regenerates vectors + manifest (non-deterministic ids/timestamps)
python3 -m unittest discover -s tests -v # 40 bundle + 21 receipt vectors + schema + primitives
```

Note: regenerating vectors rewrites files with fresh random IDs and timestamps; that is expected for the working set, but **published fixtures are frozen** — once a vector ships, its bytes are not regenerated in place; new behavior gets new files (see `vectors/manifest.json` history).

## Scope guidance

- Spec text, schema, vectors, and the reference verifier are in scope.
- Gate/orchestrator machinery (the broader MandalaOS project) is out of scope here.
- Interoperability discussion belongs in the open standards venues; this repository tracks concrete text, code, and vectors.
