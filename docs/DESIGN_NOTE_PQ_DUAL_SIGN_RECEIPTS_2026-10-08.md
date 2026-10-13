# Design note: post-quantum dual-sign receipts (candidate profile)

**Status:** development draft for review, 2026-10-08. No package change is
implied; no external representation has been made. Intended home if adopted:
profile candidate alongside `SPEC_0.6_DRAFT.md`; W3C contribution candidate
(aligned with CCG Quantum-Safe Cryptosuites v0.3, 2026-04-22).
**Motivation (2026 context, bounded):** AI-assisted cryptanalysis is measurably
improving against *undeployed* designs (e.g., a NIST candidate withdrawn after
key-strength reduction) while deployed ECC/RSA/TLS remain untouched; PQC
migration is already policy (NIST IR 8547: deprecate 2030 / disallow 2035; NSA
CNSA 2.0: PQ support for new national-security systems from 2027). Receipts
should not become unverifiable history when signatures migrate. This is
format-level readiness, not a claim that today's signatures are broken.

## 1. Scope

Define an optional **dual-signature** form for CR records so that receipts
remain verifiable across a signature-scheme transition, without changing the
receipt envelope, canonicalization (JCS), digest, or verdict model.

## 2. Design (candidate: `continuity-receipt/0.6-pq`)

- **Canonical bytes unchanged.** Both signatures cover the identical JCS
  canonical record bytes; only the signature set changes.
- **Bundled verification methods.** The issuer publishes both public keys as
  did:key **multikey multicodecs** (per CCG Quantum-Safe Cryptosuites v0.3):
  Ed25519 (legacy) + **ML-DSA-44** (default) or **ML-DSA-65** (higher margin).
- **Policy field.** `sig_policy: legacy-only | hybrid-preferred | pq-required`.
  A relying party configures the minimum it accepts; receipts never assert
  which policy is correct.
- **Verdicts.** Extend vocabulary with distinct states:
  `pq_dual_sign_missing`, `pq_dual_sign_invalid`, `pq_legacy_only` (valid but
  below configured policy). Missing vs contradictory evidence stays distinct;
  unknown multicodec fails closed.
- **Revocation/anchors.** Optional anchor signatures (e.g., OpenTimestamps)
  may also be dual-signed; anchoring remains append-only.
- **SLH-DSA fallback.** For hash-based-only environments, allow SLH-DSA
  (stateless) as an alternative PQ method; not combined with ML-DSA in v0.

## 3. Sizes and costs (planning numbers)

| Item | Ed25519 | ML-DSA-44 | ML-DSA-65 |
|---|---|---|---|
| Public key | 32 B | 1,312 B | 1,952 B |
| Signature | 64 B | 2,420 B | 3,309 B |
| Verify cost | 1x | ~10x (order) | ~10x (order) |

Logs grow KB-scale per receipt; verification stays offline. Libraries: liboqs/
oqs providers, Rust crates, Apple CryptoKit (ML-DSA availability per platform).
ML-KEM is **confidentiality only** and is not a receipt signature.

## 4. Scheme transitions and re-attestation

- **Old receipts stay verifiable** under their historical scheme; verifiers
  must not require PQ for records signed before a transition.
- **Transition records** (see scheme-registry note): scheme id, status
  (`active | superseded | deprecated`), effective date, cross-sign policy.
- **Re-attestation**: a holder may re-sign a *digest* of an old bundle with the
  new scheme (new envelope, `reattests` reference to the prior bundle digest)
  without altering the original bundle. This preserves the old chain and adds
  PQ-era attestation — the registry's first job (see §5).
- **Anchors**: when anchor signatures migrate, cross-sign anchors; keep the
  original anchor proof alongside.

## 5. Relationship to the registry (decision 4)

The scheme registry manifest (`docs/DESIGN_NOTE_SCHEME_REGISTRY_2026-10-08.md`)
records scheme ids, statuses, and transitions. Receipts reference scheme ids;
re-attestation records reference prior bundle digests. Neither operation needs
receipt contents, keeping the registry content-free.

## 6. Work required to adopt (ordered)

1. Spec text + schema additions (`signatures[]`, `sig_policy`, verdicts).
2. Verifier: Python + Rust support behind a feature flag; **differential
   vectors** (dual-sign valid; one-side invalid; wrong key; unknown multicodec;
   legacy-only under pq-required).
3. An example dual-signed bundle in `examples/`; conformance rows.
4. CCG-facing wording (one page) for the Oct 20 meeting; no claims of
   standardization.

## 7. Bounded claims (do not exceed)

The profile proves: signatures over the same canonical bytes by the listed
keys, under a stated policy. It does not prove: principal identity,
authorization, real-world events, execution environment, or that any specific
hardware ran a specific algorithm. PQ readiness ≠ quantum resistance of an
entire system (transport, storage, key custody all matter).
