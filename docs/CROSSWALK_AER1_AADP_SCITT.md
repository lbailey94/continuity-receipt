# Crosswalk and triage: AER-1, AADP bound permits, and SCITT Continuity Receipts

**Status:** informational, checked 2026-09-30. This is a local comparison of
working drafts and repository evidence. It is not normative, an endorsement,
an adoption statement, or evidence of author or group agreement. Internet-
Drafts can change. Companion: `CROSSWALK_SAHU_ACTA_ASQAV.md`.

**Drafts checked:** [AER-1 -05](https://datatracker.ietf.org/doc/html/draft-zambo-aer1-05)
(Independent, intended Informational; dated 2026-09-30);
[AADP bound permits -00](https://datatracker.ietf.org/doc/html/draft-saha-aadp-bound-permit-00)
(individual Internet-Draft, intended Standards Track; dated 2026-09-29),
read with its base [AADP -04](https://datatracker.ietf.org/doc/html/draft-saha-aadp-04);
and [SCITT Continuity Receipts -01](https://datatracker.ietf.org/doc/html/draft-nikolaichuk-scitt-continuity-receipts-01)
(individual Informational Internet-Draft, dated 2026-09-29). These are work in
progress, not IETF standards. SCITT's registration API is separately described
in [SCRAPI -05](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-05).

## 1. Short comparison

| Work | Object and stated scope | Possible relationship to continuity-receipt | Evidence boundary |
|---|---|---|---|
| AER-1 -05 | A portable record of one agent tool execution; §§7–8 add a hash-chained job timeline and a workflow receipt over ordered step receipts. | Fine-grained execution evidence could be referenced by a CR record, if a future digest profile is defined. | Its hash procedure confirms committed bytes and recorded links, not external outcomes or events it did not observe. The checked-in probe is a single live fixture check, not AER-1 conformance. |
| AADP bound permit -00, with AADP -04 | A short-lived PDP-signed decision permit bound to one recipient, presenter key, HTTP request and action instance; a referenced mandate remains separately evaluated. | A later CR record could refer to a permit that a recipient actually checked. | AADP requires recipient-owned scope/currentness policy. The permit alone does not override recipient policy or establish broader principal identity, adoption, or exactly-once effect. No AADP probe or integration is evidenced here. |
| SCITT Continuity Receipts -01 | A recovery statement about a stateful artifact registered in a SCITT transparency service; the returned receipt proves registration and log position. | An agent-state recovery could be a separate registration or a CR could carry a SCITT receipt reference after its profile is defined. | A SCITT receipt does not prove recovery occurred, recovered bytes match, or an attestation was verified/favourable. No CR-to-SCITT registration or interoperability is evidenced here. |

## 2. Keep the three CR surfaces distinct

The following are related repository surfaces, not interchangeable claims:

| CR surface | Current checked state | What it does not establish |
|---|---|---|
| Core protocol and verifier | `SPEC.md` describes published `continuity-receipt/0.5`. The 0.5.0 Python and Rust packages also accept 0.6 verifier behavior; 0.6 is still a development draft with no standalone 0.6 release. See `CAPABILITY_MATRIX.md`. | Package acceptance of a draft version does not make 0.6 normative, an external standard, or interoperable with any draft below. Core `TRUSTED` verifies the disclosed bundle under the implemented CR rules; it is not a general action authorization or proof that issuer claims happened. |
| Local Python consumer assessment | The unsigned `continuity-consumer` profile is separately versioned, local policy assessment for CR 0.1–0.4. It checks configured issuer/spec lists and optional record presence after core verification; it does not fetch or discover evidence. | `ACCEPT` does not authenticate the real-world identity or independent key custody of an issuer, establish execution or freshness, check external revocation, or authorize an action. This is not a cross-host adopter result. |
| 0.6 authority candidate | `SPEC_0.6_DRAFT.md` and its local candidate vectors cover `authority.grant` as a signed issuer/operator assertion and optional in-bundle linkage. The verifier behavior is present experimentally in the 0.5.0 packages. | The record does not prove that its signer was authorized by the named principal. It is not a recipient-checked AADP permit, policy decision, delegated identity credential, or independent authorization path. The authority-required consumer profile is proposed, not implemented. |

Consequently, a crosswalk to AADP describes a possible future composition
between separate decisions and records. It does not upgrade any of the three
CR surfaces above or turn CR into an authorization protocol.

## 3. AER-1 -05

AER-1 -05 defines a small execution receipt with an identifier, creation time,
tool and caller scope, provenance class, `canonical_bytes`, and an
`output_hash`. The hash is SHA-256 over the exact UTF-8 bytes represented by
`canonical_bytes`; the verifier must reproduce those bytes before confirming
the output commitment. The receipt's bytes/commitment are not the digest of the
whole AER-1 record. The draft also requires provenance to remain visible and
says verification cannot turn a report into an observation (§§3–6).

Sections 7 and 8 cover, respectively, hash-chained job timelines and workflow
receipts. Those links can show tampering in the recorded sequence; they do not
make a reported action executed or prove business effects. Section 9 defines
public resolution as a format requirement; that requirement is not evidence
that a third-party service is currently available.

| AER-1 element | Nearest CR concept | Limit |
|---|---|---|
| `id`, `created_at` | CR record identifier, `issued_at` | Identifiers, schemas, and signed bytes differ. |
| `tool` and caller scope | Execution context in a CR task record | No field-level compatibility is defined. |
| `provenance_class` | Issuer claims and any counterparty attestation | Conceptual analogy only; CR has no equivalent AER-1 provenance enum. |
| `canonical_bytes` / `output_hash` | A CR record's own signed/canonical body and digest | Different objects and digest scopes. AER-1 hashes execution output bytes; it does not define a digest of the whole receipt for use as a CR external reference. |
| §§7–8 job/workflow links | CR `prev` chain and agreement/lifecycle links | Structures and checks differ; neither implies the other's semantics. |

**Probe bound.** `tools/interop_aer1_probe.py` is labelled against -04 and the
crosswalk's original dated probe record concerns one live example. Its code
checks public URL HTTP 200, requested `id`, the `verification_status` string,
base64 decoding, strict UTF-8, SHA-256 equality against `output_hash`, and
`canonical_byte_length` only when that extra field is present. The dated
crosswalk record reports one fixture (`130da435-e157-498e-af90-605866a86a27`)
whose recomputed output hash matched
`sha256:0492c18e09059aa2e30ba0864f6aada2ef08475a5b35944cbf2a9ce46d12b9f1`.
That observation is tied to 2026-09-30 and does not establish current service
availability. It does not verify a general AER-1 corpus, job-chain or workflow
receipt, anchor, observed provenance, real-world action, service availability
over time, or independent implementation. As of this review, upstream is -05;
this review did not requalify the existing -04-labelled probe against -05. No
AER-1 adoption or endorsement is claimed.

## 4. AADP bound permits -00: recipient scope and currentness

The bound-permit draft extends the base AADP -04 cross-boundary. It says the
permit carries the issuer's per-action decision; a named mandate is a separate
reference that the recipient evaluates when required. The permit does not
replace the recipient's own policy. The following details are from bound-
permit -00 §§3.3, 6–7. Every permit declares one currentness mode, and the
recipient's record states which mode applied:

- **Issuer scope belongs to the recipient (§6).** A recipient maintains its
  own issuer table with keys, permitted action types, per-field limits,
  `not_after`, and a minimum accepted currentness mode. Every permit's
  `authorization_details` entry must fit the configured action type and its
  comparison-rule limits. An issuer's published metadata can inform that
  table but never grants scope; the recipient's table is authoritative and
  changes only by recipient action. The draft recommends recording who
  changed a scope, when, and what changed.
- **Time-bounded mode (§7.2).** The permit is treated as current until `exp`
  with no further status query. Revocation of the mandate or supersession of
  policy before expiry is not detected, so this leaves a declared, bounded
  exposure window. The recipient may accept this mode only where its issuer
  table allows it. Under §3.3, when `execute_within` is absent, `exp - iat`
  must not exceed 120 seconds (an action-type registration may lower that
  ceiling, not raise it); when `execute_within` is present, `exp` cannot be
  later than its deadline. Short expiry bounds time; it does not close the
  revocation/supersession window before expiry.
- **Status-checked mode (§7.2).** At verification time, the recipient must
  establish that the permit, policy version, and mandate have not been revoked
  or superseded. The draft defines an issuer status-list option and an
  issuer-signed stapled freshness statement; its recommended stapled age is
  no more than 30 seconds, subject to the recipient's configured freshness
  window. If status is unavailable, unparsable, or stale, refusal with
  `status-unavailable` is required unless a locally configured, audited
  fail-open policy explicitly applies to that risk class and is recorded.

This is only a standards crosswalk. CR does not implement AADP verification,
recipient scope tables, permit consumption, mandate evaluation, currentness,
or AADP confirmations. A CR field containing a permit digest would establish
only a reference/commitment under a future, defined profile; it would not
itself establish that a recipient checked or accepted the permit.

## 5. SCITT Continuity Receipts -01

The SCITT draft's “Continuity Receipt” is an ordinary RFC 9942 receipt
returned after registering a signed recovery statement about a stateful
artifact under the RFC 9943 architecture. Its §3.3 boundary is explicit: the
receipt proves that a particular issuer-signed recovery statement was
registered at a position in a particular transparency service's append-only
log. It does not prove recovery occurred, bytes matched the original,
attestation results were verified or favourable, or the log's registration
policy checked those facts.

The name therefore overlaps with this repository's “agent continuity
receipt” wording, while the objects and claims differ. Use “agent continuity
receipt” when context needs to distinguish this CR project. This is naming
hygiene, not a claim of conflict, priority, endorsement, or adoption.

The potential join is at the state-evidence layer, not wire compatibility:
CR `state.commitment` could be a payload/reference for a separately authored
recovery statement if its meaning and the SCITT registration policy fit; a
SCITT receipt could be carried as external evidence once a CR reference
profile is agreed. SCRAPI -05 provides registration and query endpoints, but
does not settle authentication (out of scope) or establish that a particular
service's policy is suitable. No service integration or registration has been
tested for CR.

## 6. Open issue: external-reference digest and verdict effect

`DESIGN_NOTE_EXTERNAL_EVIDENCE_REFS.md` is explicitly a non-normative
candidate. It sketches `digest: sha256:<hex>` but leaves the digest scope open:
exact referenced-object bytes versus a specified canonical JSON view, and
which object is covered for formats such as AER-1. AER-1's `output_hash` is
not automatically the digest of its receipt record. This crosswalk makes no
choice between raw serialization bytes and canonical JSON and does not define
a canonicalization rule.

The candidate note also sketches a verdict effect (unresolved references as
insufficient evidence; a checked digest mismatch as untrusted). That effect
is not a rule in published CR 0.5, not part of the local 0.1–0.4 consumer
profile, and not yet approved as 0.6+ candidate semantics. Whether an
unavailable reference affects the core verdict, a separate consumer
assessment, or neither; and whether a checked mismatch is a core failure or
profile-specific outcome remain open decisions. No wire or runtime behavior
is proposed by this crosswalk.

## 7. Bounded follow-ups

1. Decide and document the external-reference object's byte scope and any
   canonicalization, per kind, before defining a field or interoperability
   vector.
2. Separately decide whether unresolved or mismatched references affect core
   verdicts or only a consumer profile. Do not infer either from this note's
   candidate prose.
3. If AADP composition is pursued, keep the recipient's issuer/action scope,
   accepted currentness modes, status-unavailable policy, and actual permit
   verification evidence explicit. A reference alone is not authorization.
4. Assess SCITT registration policy and a concrete SCRAPI service before
   claiming a registration path works.
5. Keep future proposal, test, and implementation claims separately labelled;
   no draft author or working group has endorsed this crosswalk.
