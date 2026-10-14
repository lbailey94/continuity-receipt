# Design note: external evidence references (0.6+ candidate)

**Status:** design recommendation for review, 2026-09-30. This is not an
approved wire standard, a change to published `continuity-receipt/0.5`, or an
implemented feature. It defines no runtime behavior. The recommendations are
for a separately versioned future consumer profile and, only after review, a
future spec revision. See `CROSSWALK_AER1_AADP_SCITT.md` for the standards
comparison.

## 1. Recommendation

Make a versioned digest of the **exact artifact bytes** the default for an
external evidence reference. The bytes are the complete referenced artifact
selected by its kind and profile, exactly as captured or supplied to the
consumer. Do not silently canonicalize JSON or substitute a digest embedded
inside the referenced object.

Keep canonical JSON as a separate, explicitly selected digest profile. A
canonical-JSON digest must name the media type, artifact schema/profile and
version, and the exact canonicalization profile/version. A consumer must not
guess the profile from a URL, file extension, JSON field names or embedded
digest. Raw artifact bytes and canonicalized JSON are different digest scopes
and must not share an unlabeled `sha256` value.

Candidate notation only:

```json
{
  "kind": "aer1-receipt",
  "id": "external-object-id",
  "artifact_media_type": "application/json",
  "artifact_profile": "aer1-receipt-v1",
  "digest": "sha256:<64 lowercase hex characters>",
  "digest_scope": "artifact-bytes-v1",
  "locator": "https://example.invalid/receipt"
}
```

`kind`, `artifact_media_type`, and `artifact_profile` identify what the
reference claims to address; `digest_scope` identifies the bytes whose digest
is being compared. `locator` is optional advisory metadata. The exact field
names, media/profile registry, wire location, and schema version remain for
later specification work.

### Digest-scope tags

| Scope tag | Candidate meaning | Requirements |
|---|---|---|
| `artifact-bytes-v1` | SHA-256 over the complete, exact byte sequence of the selected artifact. Recommended default. | The artifact's media type and format/profile version must be identified. A JSON response's received body bytes count as bytes; no parsing and reserialization happens before hashing. |
| `canonical-json-v1` | SHA-256 over a JSON artifact after a specifically named canonicalization profile. | The reference must identify `application/json`, the artifact schema/profile version, and the canonicalization profile/version. Duplicate members, invalid UTF-8, and unsupported values must be rejected under that profile. The exact canonicalization algorithm and conformance vectors must be selected before implementation; this note selects none. |
| kind-specific inner commitment | A digest defined by the referenced format for a particular inner payload. | This is not a digest of the whole artifact. The scope tag and kind-specific mapping must say exactly which inner bytes are covered and cite the source profile. It must never be substituted for `artifact-bytes-v1`. |

The `sha256:` text prefix may be retained as a display encoding in a future
schema, but by itself it does not identify the digest scope. A versioned scope
tag is required even when only SHA-256 is supported.

## 2. The artifact is not an embedded output commitment

An external reference must distinguish the whole object being referenced
from a commitment inside that object. Examples:

- AER-1 `output_hash` commits to the execution output bytes represented by
  that receipt's `canonical_bytes`. It is not a commitment to the complete
  AER-1 receipt document. A reference to the whole receipt therefore uses the
  exact receipt artifact bytes under `artifact-bytes-v1`, or a separately
  selected whole-document canonical-JSON profile.
- An AADP permit may be identified by its compact JWT serialization. Its
  request `Content-Digest` and `action_digest` have their own protocol scopes;
  neither is automatically a whole-permit digest.
- A SCITT reference must identify whether it points to the COSE Receipt, the
  signed recovery statement, or another object. A proof of registration is
  not interchangeable with the signed statement that was registered.

Matching the selected artifact digest establishes only byte integrity for
that selected object. It does not establish its signature validity, issuer
trust, status/currentness, authorization, or truth. Those checks require a
separately named verifier and an explicit relying-party policy. In particular,
a reference to an AADP permit is not evidence that the recipient verified or
accepted that permit.

## 3. Candidate consumer-assessment effect

Keep published core verification unchanged. Core verification neither
retrieves external objects nor adds a network dependency. A reference that
the caller's consumer policy does not require is informational and has no
effect on the core verdict or consumer outcome.

For a **separately versioned** consumer-assessment profile, recommend an
explicit caller opt-in to require external-reference integrity. Only under
that requirement:

| Assessment result | Candidate condition |
|---|---|
| `NEEDS_EVIDENCE` | A required reference, artifact, supported scope/profile, or enough bytes to perform the check is absent, unavailable to the assessment, malformed, or unsupported. |
| `REJECT` | The assessment checked the required bytes under the declared scope and the digest did not match. |
| requirement satisfied | The checked digest matches. This satisfies only that byte-integrity requirement; it does not upgrade CR core `TRUSTED`, prove semantic validity, or authorize an action. |

An opted-out assessment does not perform these checks and must not imply they
passed. No outcome mapping is added to published CR 0.5 or the existing
`continuity-consumer` profile, which targets 0.1–0.4. A future assessment
version, its policy syntax, and its reason codes need independent review and
tests before implementation.

This is a concrete candidate recommendation, not an approved verdict rule.
The user/project owner still needs to approve the future profile and decide
whether a checked mismatch should be called `REJECT` or another assessment
label before any public specification or runtime adopts it. Regardless of
that naming choice, core `TRUSTED` remains the result of core checks only.

## 4. Offline, retrieval, size, and privacy boundaries

- A locator never causes an implicit fetch by the CR core verifier or the
  candidate consumer assessment. The caller supplies the exact artifact
  bytes as local evidence. If bytes are unavailable, a required check reports
  `NEEDS_EVIDENCE` under the proposed assessment mapping.
- This keeps CR verification offline and avoids SSRF through receipt fields.
  A future network resolver would be a separate, explicit tool and policy;
  its URL scheme/host rules, DNS and redirect handling, private-network
  blocking, credentials, and audit behavior require separate design and must
  not be inherited from an arbitrary `locator`.
- Any future profile that accepts artifacts must define per-artifact and
  aggregate byte limits, reference-count limits, parse-depth limits, and
  allowed media/profile combinations. This note selects no numeric limits and
  adds no such runtime bounds. Existing bundle/input limits do not by
  themselves define limits for a future sidecar evidence set.
- Locators and stable identifiers can disclose context or be guessable.
  They are optional navigation hints, never authority. A digest of guessable
  content can also disclose equality or support guessing; deployments should
  avoid embedding sensitive low-entropy values directly.
- External-object revocation and currentness are not inherited by a digest
  reference. If a relying party needs those properties, its separate profile
  must specify which issuer status source is trusted, freshness, unavailable
  behavior, and how the result affects that assessment.

## 5. Candidate placements and non-goals

Candidate locations such as `task.execution`, `delivery.attestation`, or
`task.decision` are illustrative only. A future schema must define which
record types may carry each reference and what its `kind` and scope mean.
Presence of a reference must not itself upgrade a verdict.

Potential composition remains conditional:

- An AER-1 receipt could provide per-execution evidence if a consumer supplies
  and checks the selected receipt artifact and any separately required AER-1
  fields.
- An AADP permit could be referenced for audit only. Recipient scope,
  currentness, mandate evaluation, request binding, one-time consumption and
  signed confirmation remain AADP/recipient responsibilities.
- A SCITT receipt could be referenced as registration evidence only after the
  target object (receipt versus statement) and service registration policy
  are identified. No SCITT registration integration is implemented here.

These candidate refs do not define an identity system, a revocation network,
an authorization decision, a hosted lookup service, or new core verdict
semantics. Compute SLA and attestation extensions remain demand-gated.

## 6. Decisions still required before implementation

1. Approve or revise the default raw-artifact-byte recommendation.
2. Select an exact canonical-JSON algorithm/profile and matching vectors, if
   canonical JSON support is needed.
3. Define a per-kind artifact map, including whether each reference denotes a
   complete AER-1 receipt, an AADP compact permit, a SCITT Receipt, or another
   precisely named object.
4. Approve the future consumer-assessment opt-in and its missing/mismatch
   labels. Do not change core verdicts.
5. Set artifact count/size/depth bounds in that consumer profile, and decide
   whether references inherit any external currentness policy.
6. Only after those decisions, write a versioned field definition and test
   vectors. No schema, code, or wire change is made by this note.
