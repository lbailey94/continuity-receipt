# Continuity Receipt 0.6 candidate — authority

**Status:** development draft; there is no standalone 0.6 specification or
package release. The published 0.5.0 Python and Rust packages already contain
experimental verifier support for 0.6; `SPEC.md` remains the published 0.5
specification. The 0.6 schema and 10-vector corpus are included in the signed
`v0.5.0` source tag. The hosted service self-description and dated observations
are summarized in [`docs/CAPABILITY_MATRIX.md`](docs/CAPABILITY_MATRIX.md);
they do not close external review or independent adopter qualification.

All 0.4 and 0.5 rules remain in force. A 0.6 receipt uses the same envelope,
canonical view, signatures, verdicts, agreement binding, and 0.5 vocabulary.
Mixed bundles retain per-receipt semantics.

## Authority claim levels

This draft distinguishes two materially different claims:

1. **Agent/operator assertion (what this candidate can verify):** an agent or
   operator key signs an `authority.grant` record containing a principal
   identifier and declared scope/window. The verifier can establish that the
   signing key signed those bytes and that the bundle's local reference and
   chronology rules hold. It cannot establish that the principal controls or
   authorized that key, that the principal identity is real, or that scope or
   constraints were enforced. A principal name inside a signed record is not
   principal authorization.
2. **Principal-authorized delegation (not implemented):** a relying party
   would need independent evidence that the grant signer is authorized by the
   named principal, plus a configured trust path, revocation/freshness policy,
   and enforcement policy for the requested action. This document proposes
   that as a separate consumer profile; it does not define a credential or
   trust-discovery system.

Accordingly, the current `authority.grant` is an assertion record only. Do
not describe it as proving who stands behind an agent or as authorizing an
action.

## authority.grant

0.6 adds one record type and one optional member. The claim limits and open
design questions are recorded in this draft and in the candidate vectors.

A signed `authority.grant` body records an agent/operator assertion about a
principal, a grantee, and declared limits:

- `grant_id` — opaque, nonempty.
- `principal` — `{id, assurance}`: an opaque identifier and `self_asserted` or
  `issuer_verified`. Both values are assertions in this profile; even
  `issuer_verified` is not independently verified by the receipt verifier.
- `agent` — the grantee identifier. Bound receipts must be signed by it.
- `scope` — nonempty list of nonempty dot-notation labels.
- `granted_at` — RFC 3339 UTC; authority is effective from the later of this
  and the grant receipt's own `issued_at`.
- Optional: `expires_at`, `constraints` (object), `review_policy`
  (`none|flagged|full`, shape-validated; enforcement deferred to the
  review.record design), `policy_ref` (sha256), `gate_ref` (e.g. a Mandala
  gate-lite pass identifier).

Bound records (`task.decision`, `task.execution`, `delivery.attestation`,
`settlement`) may carry `authority_ref` — the digest of a grant in the bundle.

## Verifier rules

- `authority.grant` is valid only under `continuity-receipt/0.6`
  (`unknown_type` otherwise; 0.5 records cannot use it).
- A bound record with `authority_ref` must resolve to a grant in the bundle
  (absent → `missing_authority`, INSUFFICIENT_EVIDENCE — missing linkage is
  not false linkage).
- The bound record must not predate the authority's effective time
  (`authority_before_grant`, UNTRUSTED).
- The bound record's issuer must be the grant's `agent`
  (`authority_agent_mismatch`, UNTRUSTED).
- The bound record must fall inside the window when `expires_at` is set
  (`authority_expired`, UNTRUSTED).
- A grant nothing references is PROVISIONAL (`authority_unreferenced`).
- `scope` and `constraints` are labels, not enforcement: the verifier checks
  shape only; consumers compare them out-of-band (same posture as the
  state.commitment `scope` label).

## Proposed authority-required consumer profile (not normative / not implemented)

A relying party that needs principal-authorized delegation should reject a
bundle unless its own policy selects this profile and all required external
checks succeed. A future profile must name the accepted principal identity
sources, establish an authorization path from that principal to the grant
signing key, define revocation and freshness, bind the delegation to audience
and action, and state how scope/constraints are enforced. Until those
decisions are specified and implemented, consumers must treat the current
grant only as a signed issuer assertion. `authority_ref` is optional and does
not make authority mandatory for every action. A required-authority consumer
must impose that requirement out of band and fail closed when the required
grant or external trust evidence is absent.

Replay protection is also not claimed. The receipt id/digest makes records
addressable, but there is no verifier-maintained replay cache, principal
challenge, audience binding, or uniqueness service in this draft. A consumer
must define those controls if replay would be consequential.

## Conformance

Schema `schema/continuity-receipt-0.6.schema.json` (derived additively from
0.5 by `tools/make_06_schema.py`); vectors `24`–`24j` and
`vectors/manifest-0.6.json` (generated by `tools/make_06_vectors.py`);
Python and Rust suites both run the corpus. Published 0.1–0.5 fixtures and
manifests remain byte-for-byte unchanged.

## Open questions

- `review.record` shape and enforcement (currently shape-only).
- Whether `gate_ref` should carry a digest instead of a label.
- Which independent principal-to-signer trust mechanism and action-binding
  inputs a future authority-required profile should consume.
- Whether/how to gate the experimental 0.6 implementation already exposed by
  the 0.5.0 packages is a compatibility decision; evaluate it with explicit
  Python/Rust parity coverage. The normative 0.6 specification remains draft
  pending external review and a release decision in `ROADMAP.md`.
