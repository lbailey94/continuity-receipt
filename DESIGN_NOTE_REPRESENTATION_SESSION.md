# Design note — representation-session / delegation profile (candidate, demand-gated)

2026-09-26 · opencode (Lucas) · status: design input, not a spec change
Source: Pass 19 read of **Harmonic** (MIT; about.harmonic.social; `ibis-coordination/Harmonic`) — a social agency platform for humans + AI agents.

Purpose: capture what an external accountability system implies for CR, so a later session can decide whether a profile lands. Per the repo selection rule (every change ships with a vector, acceptance test, or documented negative case), this stays a candidate until an adopter/producer exists.

## What Harmonic has (observed 2026-09)

- **TrusteeGrant:** `granting_user → trustee_user`, `permissions` (action => boolean, derived from a capability registry), `collective_scope` (`all | include | exclude`), lifecycle pending → accepted/declined → revoked, optional `expires_at`; an auto-accepted parent grant is created for every AI agent.
- **RepresentationSession:** 1-hour expiry; XOR between collective representation (`collective_id`) and user representation (`trustee_grant_id`); actions attributed to the effective user; `confirmed_understanding` recorded at start.
- **RepresentationSessionEvent:** per action (`action_name`, polymorphic resource + context, `request_id` grouping), stored as platform DB rows; session log rendered human-readable and visible internally.

## What already maps onto CR (do not re-invent)

- **Two-sided consent exists:** `agreement.offer` / `agreement.accept` + `agreement_ref` carried on `task.decision` / `task.execution` (0.4). A grant acceptance maps onto that shape.
- **Authority binding exists:** signed decision/execution receipts already carry pass → dispatch → termination bindings; a representation session is a **lease window**, its events the receipt stream.
- **Revocation exists:** signed revocation statements + `--revocations` distribution cover grant revocation when the grant is keyed/identified; global/root lists stay demand-gated.

## Candidate profile fields (if adopted)

- `session`: id, representative (`did:key`), effective principal (granting user/collective identity), `mandate_ref`/`grant_ref`, scope (`all | include | exclude` + refs), began_at / ended_at / expires_at.
- `events[]` or a **session summary committing to a merkle root of events**: action_name, resource ref/digest, context ref, `request_id` group, occurred_at; per-event ref vs one session-level ref (decide).
- Verdict mapping: missing/expired mandate_ref → `INSUFFICIENT_EVIDENCE`/`UNTRUSTED` (offer_expired pattern); scope mismatch → `UNTRUSTED`; unsigned event stream → `PROVISIONAL` (never `TRUSTED` without a signature).
- Grouping: one logical act → one nonce → one receipt, many effects (mirrors Mandala P9 and Harmonic's `request_id`).

## Open questions before any profile

- Summary receipt vs per-event receipts (bandwidth vs granularity); a merkle-root commitment of an event list is the likely middle.
- Privacy: an event stream is surveillance-shaped and correlates actors (`THREAT_MODEL.md` #13). Scope evidence to actions/mandates; never content.
- Signer identity: representing actor, platform, or both? A platform-signed log is weaker than actor-signed receipts.
- Adopter demand: Harmonic is a candidate integration, not yet an adopter. Do not build ahead of one (CBOR precedent: adopt with demonstrated need).
