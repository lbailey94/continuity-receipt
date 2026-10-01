# Crystal customer recovery procedure

**Status: proposed procedure; synthetic rehearsal only.** The owner-unknown
production envelope remains in root-only quarantine. This document does not
record a customer identity, locator, credential, path, or payload. No production
ownership determination, registry change, or restoration has occurred.

The deployed access model uses `wm-crystal/1.0`. In that format the legacy
`tenant_hash` participates in the authenticated-encryption additional data
(AAD). The current gateway registry uses a 64-character hex `owner_id`, and
the API storage scope is `sha256:<owner_id>`. The v1 tenant locator is
`sha256:<digest>`, and the exact locator string is in AAD; its digest must
therefore equal the registry `owner_id` for the existing object to be
retrievable through the deployed owner-scoped API. Recovery requires an
explicit reviewed mapping from the verified customer to that *existing
locator digest*. Assigning a different owner ID or rewriting the envelope
would break the locator/AAD relationship and is outside this procedure. If the
claimant cannot be tied to the legacy locator under an approved recovery
policy, keep the envelope quarantined and access closed.

## Recovery evidence and decision

Recovery has two distinct decisions: **who owns the existing legacy locator**
and **whether that authenticated customer consents to restore ciphertext
access**. Record both decisions and their evidence references in a protected,
access-controlled audit record. Do not put personal evidence, credential
material, public locators, object IDs, or customer details in public tickets,
CI logs, or this repository.

Evidence should connect a claimant to a pre-existing customer relationship and
to the exact legacy locator through an approved, independently reviewable
process. Examples to assess under that policy include an existing verified
account record with historical locator assignment, customer-controlled
cryptographic continuity tied to a pre-agreed account record, or another
pre-existing signed record. Use an authenticated support channel already
associated with the account to confirm intent. Require a second authorized
reviewer to approve the final mapping and restoration record.

These facts **do not establish ownership by themselves**: knowledge of a
tenant locator, crystal/content ID, ciphertext, public metadata, or storage
path; a payment or payer record without an independently verified binding to
the pre-existing account and locator; possession of an API credential or
session pass that is not already owner-mapped; or possession of an encryption
key without a trusted link to the prior owner record. Historical successful
reads are not reliable ownership evidence because the former read path was
keyless. Do not make a first-reader claim or infer ownership from timing,
device, email display name, or a staff member's recollection.

Do not ask a customer to send plaintext, an AEAD key, a bearer credential, or
an unredacted envelope through a support message. A customer-held key may be
used locally by the customer to confirm that they can decrypt after authorized
access is restored, but the service must never receive that key. Key
possession alone does not bind a person to this legacy locator. Restoration
returns encrypted bytes; it cannot recover a lost client key or prove the
customer's plaintext is intact.

The following must all be explicit before a production operation is designed:

1. Independent review concludes that the evidence binds the authenticated
   customer to this exact pre-existing locator under the recovery policy.
2. Authenticated customer consent identifies the action and confirms they want
   ciphertext access restored to their mapped account.
3. An operator verifies that the proposed `owner_id` equals the 64-character
   digest inside the exact legacy `sha256:<digest>` locator required by
   `wm-crystal/1.0`, and that it is not already assigned to another principal
   or in conflict with an existing owner account. Any conflict,
   missing binding, ambiguity, or unsupported evidence means **refuse and
   preserve quarantine**.
4. A second authorized reviewer approves the exact mapping, source digest,
   destination scope, and audit entry. Approval is not permission to rewrite,
   decrypt, inspect, or delete the envelope.

## Controlled restoration sequence

The existing `quarantine_legacy.py` helper only plans/applies quarantine; it
does not restore customer data. The tested script in
`ops/crystal-customer-recovery/recovery_harness.py` is a synthetic rehearsal,
not a production recovery tool. Do not point it at live paths. A production
implementation needs its own reviewed change and exact source/destination
preconditions before any use.

For an approved future operation:

1. Install and verify a reviewed temporary public Crystal-route deny at the
   edge before changing the registry or storage. Keep that deny in force
   throughout mapping and copy. Recheck that no different principal is mapped
   to the same owner ID and no existing locator collision is present. Do not
   expose the locator in routine output. A registry mapping can authorize
   access as soon as it exists, so “unmapped” alone is not a sufficient hold
   once this operation begins.
2. Verify the protected backup and quarantine record by their protected
   operator-side evidence. Read only the opaque encrypted file bytes needed to
   compute and compare a cryptographic digest. Do not parse envelope fields,
   request a client key, decrypt, or copy plaintext.
3. Preserve the quarantined source. Copy the exact bytes into an exclusive
   same-filesystem temporary destination, fsync it, compare its digest to the
   approved source digest, and publish with atomic no-overwrite semantics.
   Never replace an existing destination. On a matching already-published
   copy, a retry may report it as already restored; on differing bytes or a
   stale temporary file, stop for manual review.
4. Commit the explicit registry mapping only through the normal reviewed
   ownership process while the edge deny remains active. Because registry and
   crystal storage are not one transaction, do not lift the deny until both
   the mapping and byte-identical copy are independently confirmed. A crash
   must leave the protected quarantine copy intact and the public route denied.
   If ordering or rollback cannot preserve denial and the original bytes, do
   not proceed.
5. After the second reviewer confirms mapping and copy digests, enable the
   ordinary owner-authenticated route for that principal. Run only a bounded
   authenticated retrieval check that does not log or display the response
   body; confirm status/cache behavior and compare the returned ciphertext
   digest. The customer can then verify/decrypt locally using their own key.
6. Keep the quarantined source until a separately approved retention decision.
   Do not delete it as part of recovery. Record operator identities, approval
   references, timestamps, old/new state digests, and outcome in a protected
   audit record without recording secrets or unnecessary customer content.

If any check fails, keep the route denied, preserve the quarantine source,
avoid blind state rollback, and record a minimal failure reason. If a partial
restore produced an identical destination, verify it by digest and resume
only from a reviewed state. If the destination differs, do not overwrite it;
preserve both artifacts and investigate under restricted access.

## Synthetic rehearsal

The local harness creates a temporary JSON-shaped fixture with a synthetic
`sha256:<64-hex>` locator and opaque fake ciphertext bytes. Its copy routine
validates the exact locator syntax and requires its digest to equal the mapped
owner ID. The harness uses the existing quarantine
planner/apply primitive against that temporary tree, then rehearses a gated
copy-only restore. It never accesses a VPS, service credential, production
registry, real quarantine, or customer envelope. It tests wrong-owner and
locator mismatch refusal, missing approval refusal, tampered source refusal,
conflicting destination protection, and a **simulated** existing-principal
mapping conflict refusal. That conflict gate is only a boolean in the
synthetic control flow; no real registry was queried, so production collision
status remains untested.

For interruption coverage, a child Python process calls `os._exit` (bypassing
`finally` cleanup) after the staged file and parent-directory fsyncs, and
after destination publication plus parent-directory fsync. Before publication, the test confirms
that the quarantine source and stale staged bytes survive, and that an
automatic retry refuses the stale stage. The test then compares both digests,
removes the synthetic stale stage as an explicit reconciliation step, and
retries. After publication, the test confirms the destination, same-byte stale
hard link, and quarantine source survive; retry recognizes the matching
destination and removes only the verified identical temporary link. This is
process-termination simulation on a disposable local filesystem, not a VPS,
power-loss, kernel-crash, registry transaction, or production recovery test.

Run from the repository root:

```bash
python3 -m unittest discover -s ops/crystal-customer-recovery -v
python3 ops/crystal-customer-recovery/recovery_harness.py
```

Passing this rehearsal validates only local control-flow behavior for the
synthetic fixture. It does not establish the real customer's identity,
ownership, consent, availability of the decryption key, production path
permissions, registry collision state, or VPS recovery safety. Those remain
unresolved until separately evidenced and reviewed.
