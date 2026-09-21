# Revocation distribution — policy and decision record

**Status:** decided 2026-09-21 (0.3 tooling; wire format unchanged).
**Scope:** how revocation statements reach verifiers outside a bundle; not a
new record type. Companion to `ANCHORING.md`; closes part of
`THREAT_MODEL.md` #7.

## Decision

1. **Static JSON document is the 0.3 default.** A revocation list is a stable
   HTTPS URL (or a shipped file) carrying the same self-signed statements the
   bundle format already accepts (0.2 §7.5):

   ```json
   {
     "kind": "continuity-receipt-revocations",
     "version": 1,
     "issued_at": "2026-09-21T00:00:00Z",
     "statements": [
       {"key": "did:key:z6Mk…", "revoked_at": "2026-09-20T12:00:00Z", "sig": {"alg": "ed25519", "value": "…"}}
     ]
   }
   ```

2. **Authenticity is per statement, not per channel.** Each statement is
   self-signed by the key it revokes. A hostile mirror cannot forge a
   revocation for a key it does not control; it can only **withhold** one.
   Distribution integrity is therefore a freshness problem, not a trust
   problem — which is why the document needs no envelope signature and stays
   trivially cacheable.

3. **CLI:** `continuity-receipt-verify --revocations <path|https-url>`
   (repeatable; also on `continuity-receipt-disclose verify`). Bundle
   statements and external lists are merged and deduplicated. Verification
   semantics are unchanged: a receipt whose issuer key was revoked at or
   before its `issued_at` fails with `key_revoked`; earlier receipts remain
   valid.

4. **Fail closed on a supplied list.** Unreachable source, document over
   1 MiB, invalid JSON, wrong `kind`/`version`, or malformed statements abort
   verification with `INSUFFICIENT_EVIDENCE` at the CLI — never a silent skip.
   When no list is supplied, behavior is exactly as before.

5. **HTTPS required.** `http://` is accepted only for loopback hosts
   (`127.0.0.1`, `localhost`, `::1`) for local testing.

6. **Monitoring guidance.** High-stakes verification should fetch at
   verification time. Cached lists should carry a bounded TTL (≤24h
   recommended) and a recorded retrieval time; a withholding attack is bounded
   by polling cadence, not by cryptography.

## Options considered

| | Static file (chosen) | Transparency log | Gossip / P2P | Monitoring service |
|---|---|---|---|---|
| Cost | none (CDN-friendly) | log operation + monitors | none | subscription |
| Freshness evidence | retrieval time | append-only inclusion proofs | peer consistency | provider SLA |
| Forgery resistance | per-statement signatures | per-statement signatures | per-statement signatures | per-statement signatures |
| Withholding resistance | polling only | monitors detect omission | partial | provider-dependent |
| Dependency | HTTPS | log + monitor ecosystem | peers | vendor |
| Fit with non-goals | strong (no custody, no payments) | medium (new infrastructure) | weak (availability) | weak (vendor lock) |

The static file is sufficient because the hard problem (forgery) is already
solved per statement; the remaining problem (withholding) is a monitoring
problem that a transparency log would only partially solve at the cost of new
infrastructure.

## Threat-model mapping

- **Closes part of #7 (key compromise):** a consumer that polls a published
  list learns of a revocation without the bundle being re-issued, so
  receipts issued after publication are correctly rejected.
- **Does not close:** the window between compromise and publication
  (monitoring cadence bounds it); withholding by a mirror (polling and
  multiple mirrors bound it); compromise of the revoked key before any
  statement is signed (undecidable from the format).
- **Does not weaken:** a malicious list cannot revoke an honest key — every
  statement must verify under the key it revokes.

## Open items

- **Global/root lists** (one list covering many issuers) need an issuer
  registry; out of scope for 0.3.
- **Transparency-log inclusion proofs** — adopt only with a consumer that
  needs omission evidence; the format already leaves room (the statement is
  the leaf).
- **List-level freshness metadata** is informational in `issued_at`; a
  signed freshness header would need a key that issuers do not share — not
  proposed.
