# Security policy

## Scope

This repository publishes the `continuity-receipt` format (spec, JSON Schema,
test vectors, reference verifier in Python, second verifier in Rust). Security
here means:

- **Verifier soundness** — a forged, reordered, truncated, or re-signed
  receipt being accepted as `TRUSTED`.
- **Canonicalization and signature handling** — JCS, Ed25519, `did:key`
  parsing, bundle/chain semantics.
- **Fail-closed behavior** — unusable revocation lists, withheld salts, or
  erased content must not silently upgrade a verdict.
- **Supply chain** — the `continuity-receipt` package on PyPI and the
  `continuity-receipt` crate.

The threat model and the assumptions that are explicitly out of scope live in
[`THREAT_MODEL.md`](THREAT_MODEL.md); read it before reporting — it is part of
the specification.

## Reporting a vulnerability

Please report suspected vulnerabilities privately:

1. GitHub Security Advisory (preferred) — repository → **Security** →
   **Report a vulnerability**.
2. Email <lbailey94@protonmail.com>.

Do not open a public issue for a vulnerability. Include a minimal
counterexample if you can: a receipt bundle, the command run, the observed
verdict, and the verdict you believe is correct. For spec-level ambiguities
(where the text permits two implementations to disagree), say so explicitly —
ambiguity reports are treated as security-relevant.

## What to expect

- Acknowledgment within 48 hours.
- An assessment (accepted / needs more information / not a vulnerability,
  with reasoning) within 7 days.
- Fixes are published with a new spec revision and vectors where the format
  is affected; a `verifier-capabilities.json` disclosure identifies what a
  given verifier version checks.

## Out of scope

- Test keys in `vectors/` are deterministic and public by design — never use
  them for real receipts; using them is not a vulnerability.
- Deployments that misstate what a verdict means (for example, treating
  `PROVISIONAL` as `TRUSTED`); the semantics are normative in `SPEC.md` §7.
- Chain-of-custody of supplied Bitcoin headers — anchor verification compares
  against a caller-supplied header by design and does not validate proof of
  work or chain state (`ANCHORING.md`).
