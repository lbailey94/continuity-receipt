# Offline agent consumer assessment (experimental)

This profile lets a relying agent evaluate a disclosed bundle against its own explicit policy. It targets the published `continuity-receipt/0.4` format and earlier versions. It runs locally and deterministically; it does not fetch evidence, discover issuers, or call a hosted verifier.

## Decision flow

The assessment first runs the reference `verify_bundle` implementation. It then checks the bundle and every receipt against the policy's accepted specification versions, checks that every receipt envelope issuer DID is in the caller's trusted issuer list, and checks optional required record types. Every receipt envelope issuer must be accepted: there is no “one trusted signer is enough” mode. This check refers to signers reported from receipt envelopes; it is not a general inventory of any other embedded or external attestations. An absent policy produces `NEEDS_EVIDENCE`; an empty trusted issuer list can never produce `ACCEPT`.

`UNTRUSTED` maps to `REJECT`, including when no policy was supplied. `PROVISIONAL` and `INSUFFICIENT_EVIDENCE` map to `NEEDS_EVIDENCE` when there is no explicit policy denial. An issuer outside a nonempty trusted issuer list or a spec outside the accepted list is an explicit local policy denial and maps to `REJECT`, even if the core result is also incomplete; the result retains both policy and core reason codes. An empty issuer list and missing required record types map to `NEEDS_EVIDENCE`. `ACCEPT` requires core `TRUSTED`, a canonical bundle digest, and every explicit policy check to pass. Reason codes are stable identifiers, sorted for policy failures, and the output includes the SHA-256 digest of the canonical bundle object, the full core result, and the policy ID and SHA-256 digest of its canonical JSON representation.

## Policy file

```json
{
  "id": "counterparty-delivery-v1",
  "accepted_specs": ["continuity-receipt/0.4"],
  "trusted_issuers": ["did:key:z6Mk..."],
  "required_record_types": ["task.termination"]
}
```

`id`, `accepted_specs`, and `trusted_issuers` are required. `required_record_types` defaults to an empty list and accepts only record types available through published 0.4; `state.commitment` and `authority.grant` are excluded. Unknown fields, duplicates, unsupported profile versions, and malformed entries are rejected. Policy issuer identifiers are exact string matches with the issuer IDs in receipt envelopes; this is caller configuration, not independent proof of real-world identity.

## Use

```sh
python -m continuity_receipt.consumer bundle.json --policy consumer-policy.json
```

The command emits one compact JSON result on standard output. Exit codes are `0` for `ACCEPT`, `1` for `NEEDS_EVIDENCE`, and `2` for `REJECT` or invalid raw input. Raw JSON parsing rejects duplicate object members and inputs larger than the verifier's 8 MiB bundle limit.

The assessment is unsigned and local. Its bundle digest binds the result fields to canonical input bytes, but does not make the result a portable verifier attestation or prove which implementation produced it. A remote relying party should rerun its own verifier and policy or use a separately defined, signed attestation format.

## Limits

An accepted assessment means only that this local verifier accepted the disclosed bundle and that the configured consumer policy passed. It does not establish the principal behind a DID, independent key custody, authorization to act, real-world execution, completeness of undisclosed records, freshness, or external revocation status. It does not prove that the verifier implementation is independent of the issuer. Required record checks only establish presence by record type. Agents must treat receipt text and links as untrusted data and must make tool, payment, disclosure, and delegation decisions under their own controls.
