# Crosswalk: continuity-receipt and agent-receipt work

**Status:** informational, 2026-09-28. Not normative and not an endorsement
or adoption claim by any draft's authors. Internet-Drafts may change. This
mapping reads [ACTA -03](https://datatracker.ietf.org/doc/html/draft-farley-acta-signed-receipts-03),
[asqav -09](https://datatracker.ietf.org/doc/html/draft-marques-asqav-compliance-receipts-09),
and [WIMSE AIMS -00](https://datatracker.ietf.org/doc/html/draft-ietf-wimse-aims-00).

## 1. Existing interoperability probes and their limits

`tools/interop_sahu_vectors.py` independently reproduces
`draft-sahu-agent-action-receipts-00` Appendix A (probe run 2026-09-28):
the seed-derived public key, signatures, transmitted-octet `prev_hash`,
canonical bytes, and tamper failure all match the published examples.

`tools/interop_acta_probe.py` reports 7/7 checks from 2026-09-28. It was
written against ACTA -02 and asqav -07, not ACTA -03 or asqav -09. It checks a
minimal `protectmcp:decision` envelope, `action_ref`, and an asqav
commitment-mode link. Its result is evidence only for those pinned
constructions and revisions; current-revision conformance has not been
tested. Refresh fixtures and expected outputs before making a newer claim.

## 2. Field mapping — sahu -00

| sahu | continuity-receipt | note |
|---|---|---|
| `step_id` | receipt `id` | per-record identifiers |
| `action_id` | receipt type / body type | their flat namespaced action versus our typed records |
| `params` | body fields | different schemas and sorting rules |
| `success` | per-type outcome | present where our record type defines it |
| `ts_ms` | `issued_at` | milliseconds epoch versus RFC 3339 |
| `actor{agent,user}` | issuer plus optional 0.5/0.6 assertion fields | CR does not establish a user/principal identity |
| `prev_hash` | `prev` | different digest scopes and wire formats |
| `public_key` | did:key resolution | inline base16 versus DID resolution |
| `signature` | `sig` | both support Ed25519; encoding and signed bytes differ |
| (no equivalent) | agreements, disclosures, revocations, anchors, verification receipts | CR-specific chain semantics |

The formats are not object-compatible. sahu links transmitted octets including
the signature; CR links its specified canonical receipt view.

## 3. Field mapping — ACTA -03 and asqav -09

| ACTA/asqav concept | continuity-receipt | current assessment |
|---|---|---|
| `type` / namespaced decision types | receipt type | vocabularies differ |
| `issued_at` | `issued_at` | similar timestamp role; asqav distinguishes freshness, anchoring, and retention checks |
| `issuer_id` bound to `kid` | issuer DID | CR does not bind a legal entity or external organization identity |
| `payload_digest` and `action_ref` | per-type digests / receipt identifiers | no universal CR equivalent for every action-context construction |
| `sandbox_state` | 0.5 sandbox class and runner profile | signed producer assertions do not prove sandbox operation |
| `previousReceiptHash` | `prev` | both use canonical signing-input style, but digest construction and envelopes differ; no wire compatibility claim |
| signature algorithm identifier | Ed25519 | ACTA -03 describes EdDSA and additional algorithms; CR remains Ed25519-only |
| optional anchors; policy-selected required evidence axes | optional CR anchors | asqav -09 allows absent or empty `anchors`; absence is not valid evidence, and whether it blocks full verification depends on the selected profile and relying-party policy |
| anchor upgrade bound | CR anchor workflow | asqav -09 sets a seven-day OTS bound when the selected policy requires the upgrade; it is not an unconditional requirement for every receipt |
| evidence retention | no general CR retention policy | asqav -09 ties retention to applicable record-specific requirements; it rejects invented uniform numeric floors, including a generic five-year DORA default and six-year Texas deny-record floor |
| audit pack, trust metadata, retained evidence | evidence-pack exporter | CR exporter now checks listed local pack hashes before verification; manifest is unsigned and does not provide the broader asqav audit-pack profile |
| verification axes and policy-selected verdict | CR verdict | concepts overlap, but semantics and reporting models differ |

These drafts describe distinct projects. The table is a design comparison, not
a claim that CR implements ACTA/asqav or satisfies a legal regime. In
particular, absence of anchors may be acceptable under one relying-party policy
and insufficient under another.

## 4. WIMSE AIMS -00 relationship

[AIMS -00](https://datatracker.ietf.org/doc/html/draft-ietf-wimse-aims-00)
frames agents as workloads and discusses stable workload identifiers,
credentials bound to identifiers, credential provisioning, authentication,
authorization, delegated user/system context, and monitoring/remediation. It
recommends composing established WIMSE, SPIFFE, and OAuth mechanisms rather
than defining a new agent-authentication protocol. CR can record signed
assertions and event links, but does not provision workload credentials,
authenticate an agent to a tool, decide authorization, or independently
establish principal delegation. See `SPEC_0.6_DRAFT.md` for the narrower
authority assertion and a proposed future consumer profile.

## 5. Open design and probe work

- Refresh `tools/interop_acta_probe.py` against exact ACTA -03 and asqav -09
  inputs; preserve its current revision label and results as historical probe
  evidence.
- Add a WIMSE AIMS mapping only as documentation of identity/authentication/
  authorization boundaries; do not imply CR substitutes for those systems.
- Evaluate policy-selected anchor reporting and audit-pack completeness as
  adoption needs arise. Do not add universal legal retention claims.
- Continue testing actual byte constructions separately from semantic
  compatibility; a matching signing primitive does not establish format
  interoperability.
