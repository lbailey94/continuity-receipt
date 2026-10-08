# Crosswalk: Continuity Receipts ↔ W3C Agent Identity CG themes (v0)

**Status:** preparation draft for Lucas's review, 2026-10-08. Nothing here has
been sent to the CG; no agenda item, correspondence, or commitment exists. Not
endorsed by W3C or any draft author. Language is bounded deliberately — keep it
that way if anything from here is ever spoken or posted.
**Target:** W3C Agent Identity Registry Protocol CG, next meeting 2026-10-20.
**Related:** `docs/W3C_AGENT_IDENTITY_CG_BRIEF_2026-10-06.md`,
`docs/CROSSWALK_AER1_AADP_SCITT.md`, `docs/CROSSWALK_SAHU_ACTA_ASQAV.md`,
`docs/DESIGN_NOTE_SCHEME_REGISTRY_2026-10-08.md`.

## 1. Bounded description of CR (reuse verbatim)

`continuity-receipt/0.5` is a published format for signed agent-task records
with offline-verifiable record integrity, chain links, agreement references,
and optional revocation and anchor evidence. The verifier checks the signed
claims and their configured bindings; it does not prove that issuer claims
correspond to real-world events. CR's issuer identifier and `did:key`-form
signature key support verification within the receipt format; they do not
establish a real-world principal, an identity-provider account, independent
key custody, organizational authorization, workload attestation, or permission
to act. Missing and contradictory evidence remain distinct verdict states.

## 2. Theme-by-theme crosswalk (what CR can and cannot say)

| CG theme | What CR provides (bounded) | What CR does not claim |
|---|---|---|
| Identifier binding (registry side) | Receipts bind an issuer identifier + key to signed records; verification is offline against the format. | That the identifier maps to a real principal, org, or account; any particular root (DNS/PKI/ledger). |
| Collisions / resolution failure (§4.6) | Verifier vocabulary keeps `missing` vs `contradictory` evidence distinct; unknown issuer/key material fails closed. | Any solution to registry collisions; no "prior art" framing. |
| Revocation & currentness | Optional revocation record + anchor evidence in-bundle; verifier can require configured freshness. | Distributed revocation discovery; relying-party authorization decisions. |
| Delegation / mandate boundaries (§4.5) | 0.6 `authority.grant` candidate records a **signed issuer/operator assertion** with declared scope/window; `authority_ref` links records to a grant. | That the signer was authorized by the named principal; permit verification or cross-org authorization (AADP comparison only). |
| Provenance vs content (§4.4) | Receipts are content-free: canonical claims + digests; no C2PA integration tested. | Synthetic-media provenance; content truth; business outcomes. |
| Naming (§4.7) | Use "agent continuity receipt" to avoid collision with SCITT's recovery-registration receipt. | — |

## 3. Two proposals we could offer (bounded, if invited)

### 3.1 State/receipt portability across issuers ("continuity")
A signed **migration record** shape: `from_issuer → to_issuer`, subject
identifier, state digest, prior receipt-chain head, policy flags, dual
signatures. It can prove: both issuers signed the same canonical migration
statement at a time. It cannot prove: completeness of carried state, identity
continuity of a principal, or authorization. Portability is a natural registry
artifact (issuer namespace + scheme versions), not an authorization claim.

### 3.2 Scheme-transition records (registry-side)
Registries will need to express "this scheme was superseded by that scheme on
this date, under this cross-signing policy" once post-quantum profiles arrive
(entity keys migrate; verifiers must keep old receipts verifiable). A minimal
`schemes[] + transitions[]` manifest is sketched in
`docs/DESIGN_NOTE_SCHEME_REGISTRY_2026-10-08.md` — offered as an example shape,
not a standard.

## 4. Questions we might engage on (one ask max, from the brief)

1. What evidence/governance should a registry bind to an identifier, and how
   should resolution failures be represented?
2. How should revocation/currentness be distributed to relying parties without
   implying authorization?
3. Where are the boundaries between identifier, workload attestation,
   mandate/delegation, and recipient policy?

## 5. Reminders

- No claims of adoption, endorsement, or prior art; crosswalks are
  informational local comparisons.
- Anything said must stay within §1's boundaries; the 0.6 `authority.grant` is
  an assertion record, not authorization.
- If PQ comes up, use `docs/DESIGN_NOTE_PQ_DUAL_SIGN_RECEIPTS_2026-10-08.md`
  for bounded wording (format-level dual-signature profiles; not identity).
