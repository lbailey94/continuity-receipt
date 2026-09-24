# Worked example: a receipt for an AI answer over an open-data portal

**Status:** explanatory note, not normative. The specification is
[`SPEC.md`](SPEC.md); this document shows how its six stages map onto a
concrete civic use case. No adoption claim is made.

## The scenario

A person asks a question of an AI assistant that answers over an open-data
portal (a CKAN-style catalog, reached through MCP — the pattern being piloted
by OKFN with CGU and AGESIC). The answer arrives with citations. The question
this document addresses is the one the answer does not cover:

> How do we know *how* the answer was produced, *who* authorized it, and that
> the record of it was not quietly rewritten later?

A continuity receipt is a signed, hash-chained record of one governed task.
It is designed to be verified offline by any third party — without trusting
the issuer.

## Stage mapping

| Receipt stage | Open-data analogue |
|---|---|
| `decision` | The question as received, and the interpretation the agent acted on (hashed, not necessarily disclosed) |
| `authority` | Who asked, and what the agent was permitted to do (e.g. read-only portal scope, rate limits, a mandate reference) |
| `execution` | The tool calls made (MCP), the dataset identifiers and queries used, and their hashes |
| `delivery` | The answer artifact hash, plus provenance back to the source datasets and retrieval records |
| `termination` | Proof the task stopped — including failure paths: timeout, refusal, partial answer |
| `settlement` | For a free portal, no payment; the field still anchors the hand-off (SLA, human review, or nothing) |

## What a receipt proves — and what it does not

It proves **integrity and sequence**: the record has not been altered, the
stages occurred in order, and the authority claim is the one that was signed.
It does **not** prove the answer is correct, and it does not certify the data.

Verdicts distinguish missing evidence from false evidence:
`TRUSTED` · `PROVISIONAL` · `INSUFFICIENT_EVIDENCE` · `UNTRUSTED`.
`INSUFFICIENT_EVIDENCE` is explicitly not the same as false. The full limits
are in [`THREAT_MODEL.md`](THREAT_MODEL.md).

## Composition with third-party attestation

A hash chain is internal integrity — it shows the issuer's record is
internally consistent. It is not third-party certification, and it does not
claim to be ("you cannot self-certify"). External attestation (for example a
TypedStandards-style signed package with a public timestamp) composes on top:
the receipt carries the internal chain; the external signature anchors it.

## Verify in five minutes

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install continuity-receipt
continuity-receipt-verify vectors/02_happy_full.json          # TRUSTED
continuity-receipt-verify vectors/10b_anchor_missing.json --require-anchor
continuity-receipt-verify vectors/07_redacted_no_disclosure.json
```

The 40 vectors in [`vectors/`](vectors/) cover the happy path, tampering,
missing termination, redaction with and without disclosure, erasure, anchor
failures, succession, attestations, and revocation semantics.

## Honest gaps

- Revocation distribution is static-list tooling with per-statement signatures; succession multi-signatures remain deferred (`SPEC.md` §11).
- Anchoring policy is public ([`ANCHORING.md`](ANCHORING.md)); proof verification ships as the companion tool.
- The format versions independently of any product; it is not endorsed by the
  W3C CG or IETF, and no adoption is claimed.

## Discussion

Open an issue for mappings, vectors, or feedback. Interoperability discussion
belongs in the open standards venues; this repository tracks concrete text,
code, and vectors.
