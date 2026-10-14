# Design note: continuity scheme registry (minimal operated instance + federation)

**Status:** development draft for WhiteMagic / Lucas review, 2026-10-08.
is implied; no instance has been stood up. Operator target: WhiteMagic-hosted,
content-free, read-only manifest under `www.whitemagic.dev/.well-known/`.
**Decision context:** History Layer plan §12 item 4 — "minimal operated
instance now; federated design first; PQ scheme-transition records as its
first job." Companion: `docs/DESIGN_NOTE_PQ_DUAL_SIGN_RECEIPTS_2026-10-08.md`.

## 1. Purpose and non-purpose

**Purpose (v0):** publish a small, machine-readable manifest of receipt-scheme
ids, their status, verifier pointers, and scheme transitions — so a relying
party (human or agent) can answer "is this receipt's scheme still verifiable,
and what superseded it?" Content-free and read-only.

**Not (v0):** a global census, an identity registry, an authorization service,
a revocation authority, or a place where receipt contents are stored.

## 2. Content-free rules (hard)

1. No receipt bodies, prompts, memory content, or per-user linkage, ever.
2. Counts are aggregate only; publish with a minimum-k floor (k≥20 per cell)
   to avoid reconstructing low-volume activity.
3. Public artifacts are static and cacheable; raw events (if any) stay private
   with a retention policy.
4. Every field answers "what is true without knowing who did what": scheme,
   status, verifier, dates, aggregate counts.

## 3. Minimal operated instance (v0)

| Surface | Content | Source |
|---|---|---|
| `/.well-known/continuity-registry.json` | Manifest: registry id, operator, updated, `schemes[]`, `transitions[]`, `counters{}` (nullable until wired), `federation{}` | Generated; static file (same pattern as `pricing.json`, `demand-attestation.json`) |
| `/trust#registry` (human view) | Rendered table of the manifest + scope statement | Site page reading the JSON |
| `/verify` (exists) | Verifier entry; usage counters (aggregate) | Existing lane |
| Schema | `urn:whitemagic:schema:registry-manifest:v0` JSON schema in this repo (`schema/`) | This repo |

Scope statement (must ship in the manifest and page, verbatim):
"Counts receipts issued by WhiteMagic-operated lanes and verifications
performed via its public verifier. This is not a global census; other
registries may publish their own."

### Counters semantics

- `issued`: receipts emitted by WhiteMagic-operated tooling (hosted lanes,
  CLI receipts where the operator opts in to aggregate stats only).
- `verified`: verification calls made through the public verifier.
- Both are **operator self-attestations** — stated as such; no proof of
  completeness is implied. A future `issued_attested` field may carry a signed
  daily digest if demand appears.

## 4. Manifest example (v0)

See `docs/REGISTRY_MANIFEST_EXAMPLE_v0.json`. Key shapes:

- `schemes[]`: `{id, status: active|candidate|superseded|deprecated|planned,
  spec, verifier, first_seen, notes}`.
- `transitions[]`: `{date, from, to, policy, note, cross_sign}` — the PQ
  migration record (see PQ note §4). Empty until the first transition.
- `counters{}`: aggregate; nulls until wired; includes `window` and `min_k`.
- `federation{}`: `{mode: publish-only, peers: [], manifest_schema}`.

## 5. Federated design (sketch, not built)

- **Namespace:** each registry id is a URI; manifests reference peers by URI.
  No global naming authority in v0 — collision handling is explicit: two
  registries may both list a scheme id and disagree; relying parties choose.
- **Exchange:** publish-only first (fetch peers' manifests on a timer; store
  last-seen copies privately for drift detection). No gossip protocol in v0.
- **Scheme-id alignment:** ids are spec URIs + version
  (`continuity-receipt/0.6-pq`); a transition record references ids, not
  registry-local numbers.
- **Trust:** each registry is authoritative for **its own** counters only;
  no cross-endorsement is implied by listing a peer.
- **Collision/failure representation:** presence of conflicting statuses for
  the same id across registries is reported as `contested`, never silently
  merged (mirrors the verifier's missing-vs-contradictory distinction).
- **Privacy:** federation exchanges manifests only — never counters below the
  min-k floor, never raw events.

## 6. Threat model (v0)

| Risk | Handling |
|---|---|
| Inflated counters | Self-attestation is stated; no ranking implied; optional signed digests later |
| Privacy re-identification via counts | min-k floor; aggregate windows only |
| Manifest tampering | Serve over TLS; optionally sign the manifest with the existing operator key (nice-to-have v1); Git-tracked history for diffs |
| Squatting scheme ids | Ids are spec URIs controlled by their spec repo; registry lists, never mints |
| Availability | Static file on existing CDN — no new service to fail |

## 7. Build order

1. **This repo:** schema + example + transitions semantics (done in draft).
2. **Site lane:** generate the manifest from this repo's schemes + hosted
   counters (content-free audit), publish `/.well-known/continuity-registry.json`
   + `/trust#registry`; add to site gates (`check-surfaces`).
3. **Wire counters** (min-k enforced) once the write-path lane stabilizes.
4. **First transition record** when `0.6-pq` lands (dual-sign + re-attestation).
5. **Federation:** implement publish-only fetch once a second registry exists.

## 8. Bounded claims

The registry proves: what its operator published, when. It does not prove:
that counts are complete, that any receipt is authentic (verification does
that, offline), that a scheme is secure, or that an issuer is authorized.
