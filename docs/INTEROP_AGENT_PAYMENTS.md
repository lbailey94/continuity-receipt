# Interop: agent-payment rails → continuity-receipt

**Status:** design note (2026-10-05). Not a spec change. Proposes mappings,
an external-evidence member, and interop vectors. Claim discipline applies:
every statement below about other projects is dated and sourced; wire shapes
in this space move weekly.

## Why this note

A continuity receipt attests a governed task lifecycle (decision → authority →
execution → delivery → termination → settlement). The payment rails now
standardizing around agents attest *payment* and *authorization* but stop
there. The two layers compose cleanly if the digests line up: the payment
side's offer/receipt/mandate artifacts become CR agreement/authority/
settlement evidence, and the CR chain gives them the lifecycle they lack.

## Landscape snapshot (verified 2026-10-04/05)

- **x402 (Linux Foundation since 2026-07-14).** V2 uses `PAYMENT-REQUIRED` /
  `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE` headers. The `offer-receipt`
  extension signs a per-`accepts[]` **offer** on the 402 and a **receipt**
  (`resourceUrl, payer, network, issuedAt, txHash?`) on the 200; signatures
  are EIP-712 or JWS (`did:pkh` / `did:web`). The spec marks the wire shape
  **unstable** ("may change to align with x402 canonical extension
  architecture"). TS SDK only today.
- **AP2 (Google → FIDO Alliance, donated 2026-04-28).** SD-JWT verifiable
  mandates (checkout, payment) with key binding, plus three signed receipt
  types: **Mandate Receipt** (verifier verdict over a presented mandate),
  **Checkout Receipt**, **Payment Receipt**. FIDO harmonization targets end
  2026; first consolidated FIDO spec mid-2027. Crypto is ES256/JWT, not
  Ed25519.
- **MPP (Stripe + Tempo, 2026-03-18).** HTTP 402 flow with an **unsigned,
  optional** `Payment-Receipt` header (`{method, reference, status,
  timestamp, externalId?}`). IETF-targeted specs at paymentauth.org.
- **ACP (OpenAI/Stripe/Meta, beta).** Shared Payment Tokens for delegated
  payment; **no signed receipt artifact** in the published spec.
- **Community drafts:** `draft-vauban-x402-stark-receipts` proposes an
  `action_ref` (SHA-256 of JCS `{action_type, agent_id, scope,
  timestamp_ms}`) binding a payment receipt to a work event — unadopted, but
  the *shape* is the right seam. A formal-analysis paper (arXiv 2609.00060)
  finds 40 consistency issues across x402/MPP/ACP/AP2; none of the rails
  produces an offline-verifiable execution/termination artifact.

**Consequence:** CR is the lifecycle layer; the rails are the settlement
layer. Do not compete with mandates or offers — consume them as evidence.

## Mapping tables

Byte domains differ per source and must be pinned explicitly (CR: JCS minus
`sig`; x402 offer: JCS of the signed offer payload; AP2: base64url of the
compact SD-JWT per AP2's own hash rules; MPP: SHA-256 of the base64url JSON
receipt).

### x402 → CR

| x402 artifact | CR target | Mapping |
|---|---|---|
| Signed **offer** (per `accepts[]`) | `agreement.offer` | `terms_hash` = SHA-256(JCS(offer payload)); `offeree` = payer wallet as `did:pkh:eip155:<chain>:<addr>`; `valid_until` = `validUntil`; issuer = resource-server signer |
| Signed **receipt** | `delivery.attestation` (+ `settlement`) | `spec_ref` = `resourceUrl`; `counterparty.id` = server DID; carry the JWS/EIP-712 artifact via external evidence (below) rather than re-signing |
| `PAYMENT-RESPONSE` / batch voucher | `settlement` | `rail:"x402"`; `rail_ref` = `txHash` or `payment_hash`; `amount` = integer minor units + currency; `settled_at` = receipt `issuedAt` |
| Draft `action_ref` | `task.execution` ↔ `settlement` join | use CR `task_id` + final chain-head digest as the payment's `action_ref` payload (covers the whole lifecycle, not one record) |

### AP2 → CR

| AP2 artifact | CR target | Mapping |
|---|---|---|
| Open checkout/payment mandate | `authority.grant` (+ `agreement.offer`) | `principal.id` = user-credential subject; agent = mandate `cnf` key; scope = constraint labels; `expires_at` = `exp`/`execution_date`; `policy_ref` = SHA-256(compact open mandate) |
| Closed mandate | `agreement.accept` / bound records | `terms_hash` = SHA-256(compact final SD-JWT); `authority_ref` = the derived grant digest |
| **Mandate Receipt** | external verification evidence | `result` ↔ allow/deny; `reference` ↔ `policy_ref`; issuer = AP2 verifier |
| **Payment Receipt** | `settlement` | `rail` per flow; `rail_ref` = `payment_id`; `psp_confirmation_id`/`network_confirmation_id` in a reconciliation map |
| **Checkout Receipt** | `delivery.attestation` | `spec_ref` = `order_id`/checkout hash; `counterparty.id` = merchant |

### MPP → CR

| MPP artifact | CR target | Mapping |
|---|---|---|
| `Payment-Receipt` header | external evidence → `settlement` | digest = SHA-256(base64url JSON); `rail` additive value `mpp`; `rail_ref` = `reference`; note the receipt is **unsigned** — record it as a claim, never as a signature |

## What CR should add (proposals, in order)

1. **External-evidence member** (design note exists:
   `DESIGN_NOTE_EXTERNAL_EVIDENCE_REFS.md`). `{external_type, media_type,
   digest, digest_domain, issuer, issuer_key_ref, verification_status}` with
   per-type byte-domain rules. This is the only clean way to carry ES256
   SD-JWT, EIP-712, and unsigned MPP artifacts past an Ed25519-only verifier.
   Optionally a bridge attestation: a CR-signed countersignature over the
   external digest, so the evidence is at least tamper-linked inside the chain.
2. **Rail/field extension (additive).** Add `mpp` (and optionally `ap2`,
   `card`) to `settlement.rail`, plus optional `payment_id`, `payer`,
   `network` members. Unknown-member tolerance already permits safe extension.
3. **Authority-required consumer profile** (post-0.6): accept AP2 closed
   mandates and/or OIDC on-behalf-of evidence as the principal-authorization
   path, with explicit checks for audience/action binding, freshness,
   revocation, and replay — closing the 0.6 open list.
4. **Interop vectors** (cheap, high-signal; add when (1) lands):
   - CR `terms_hash` equals the digest of a synthetic signed x402 offer.
   - CR `settlement.rail_ref` resolves to a synthetic x402 `PAYMENT-RESPONSE`.
   - AP2 Mandate Receipt `reference` equals CR `policy_ref` (synthetic).
   - MPP receipt digest carried as external evidence; verdict unchanged.
5. **Engagement.** x402 Foundation extensions process (wire shape is
   explicitly unstable = low-cost window) and FIDO Payments TWG (position CR
   as the post-payment lifecycle layer AP2 lacks). Both need operator
   approval before any message is sent.

## Open questions

- Do we define `action_ref` ourselves, or accept whichever shape the x402
  Foundation lands? (Prefer accepting theirs; store it opaquely meanwhile.)
- AP2's `reference` digests are base64url-of-JSON, not JCS — the external
  evidence record must carry the domain, not assume JCS.
- Does a settlement record require a signature from the payer, or is the
  server-side receipt sufficient? (CR's settlement is issuer-signed; payer
  countersignature is not in 0.5.)

## Sources (verified 2026-10-04/05)

x402 Foundation: https://www.linuxfoundation.org/press/linux-foundation-announces-operational-launch-of-x402-foundation-to-standardize-internet-native-payments-for-ai-agents-and-applications ·
offer-receipt spec: https://github.com/x402-foundation/x402/blob/main/specs/extensions/extension-offer-and-receipt.md ·
AP2: https://ap2-protocol.org/ · FIDO: https://fidoalliance.org/fido-alliance-to-develop-standards-for-trusted-ai-agent-interactions ·
MPP receipts: https://mpp.dev/protocol/receipts ·
ACP: https://github.com/agentic-commerce-protocol/agentic-commerce-protocol ·
vauban drafts: https://www.ietf.org/archive/id/draft-vauban-x402-stark-receipts-01.html ·
formal analysis: https://arxiv.org/abs/2609.00060
