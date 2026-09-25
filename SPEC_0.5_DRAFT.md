# Continuity Receipt 0.5 candidate

**Status:** development candidate in this checkout. Spec 0.4 remains the published release in SPEC.md and the signed v0.4.0 tag. The Python and Rust prerelease builds here accept 0.1–0.5. Neither the hosted service nor the 0.4.0 packages are claimed to support 0.5.

All 0.4 rules remain in force. A 0.5 receipt uses the same envelope, canonical view, signatures, verdicts, and 0.4 agreement binding. Mixed bundles retain per-receipt semantics. The new record type is valid only when that receipt's spec is continuity-receipt/0.5.

## Local authority and execution

- session.pass.created.mandala_class gains local. The historical field name stays on the wire for compatibility. Local means a local issuer created the pass; it does not claim Mandala gate enforcement. gate_id identifies the issuer or scope. The verifier checks the enum, signature, and existing cross-record rules, not whether the issuer enforced policy.
- task.execution.sandbox_class gains none: the issuer claims no OS confinement for that execution. Application authorization may still apply. Other values remain bwrap-landlock, microvm-ch, and microvm-fc. The verifier checks the enum, not the sandbox's existence.

## state.commitment

A 0.5 task chain may include a signed state.commitment body with required nonempty state_kind and scope labels, an unsigned 64-bit integer count, and a sha256: head_digest. An optional merkle_root is either null or a merkle-sha256: digest. The concrete shape is in schema/continuity-receipt-0.5.schema.json and vector 22.

The verifier checks field shape, issuer signature, and task chain. It **does not** retrieve underlying logs or snapshots, recompute the count/head/root, or prove state completeness. A consumer needs the referenced state and its own recomputation for that stronger claim.

The first use case is WhiteMagic's captured karma-chain head bundle, which uses delivery.attestation under spec 0.2 because this type did not exist. The 0.5 vector is a deterministic modeled fixture, not a migrated runtime artifact. A second independent producer case is still needed before this candidate is frozen.

## Conformance and open design questions

Schema 0.5, vectors 22–22g and 23/23b, and Python/Rust checks define this candidate. Positive vector 22 covers local, none, and state.commitment. Negatives cover unknown authority/sandbox values, bad count/head, and use of the new type by a 0.4 receipt. Agreement vectors 23 and 23b show a 0.5 accepted agreement carried through decision and execution, plus a missing execution reference that remains PROVISIONAL. Published 0.1–0.4 vector bytes remain frozen.

Review the field name mandala_class, the meaning of scope, and whether chain-head and snapshot profiles need distinct required fields before release.
