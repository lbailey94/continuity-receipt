# Human-review brief: W3C Agent Identity Registry Protocol CG — 2026-10-06

**Status:** preparation draft for Lucas's review, checked 2026-09-30. It makes
no commitment on behalf of the project or any participant. No correspondence,
agenda submission, or follow-up has been sent as part of preparing this note.

## 1. What we can accurately say

`continuity-receipt/0.5` is a published format for signed agent-task records
with offline-verifiable record integrity, chain links, agreement references,
and optional revocation and anchor evidence. The verifier checks the signed
claims and their configured bindings; it does not prove that issuer claims
correspond to real-world events. The CR issuer identifier and `did:key`-form
signature key support verification within the receipt format. They do not by
themselves establish a real-world principal, identity-provider account,
independent key custody, organizational authorization, workload attestation,
or permission to act.

There are three distinct surfaces if implementation status comes up:

- The published CR 0.5 format and verifier behavior.
- The Python-only local consumer assessment, which uses caller-supplied
  issuer/spec policy for CR 0.1–0.4 and is not a portable authorization
  decision.
- The 0.6 `authority.grant` candidate, which records a signed issuer/operator
  assertion. Its authority-required consumer profile is proposed, not
  implemented; the assertion does not prove that its signer was authorized
  by the named principal. See `CAPABILITY_MATRIX.md` and `SPEC_0.6_DRAFT.md`.

The 0.5.0 packages also accept 0.6 verifier behavior, while the 0.6
specification remains draft and has no standalone release. Package support
should not be described as standards status or as a completed authority
integration.

## 2. What is available to discuss if relevant

- `CROSSWALK_SAHU_ACTA_ASQAV.md` and
  `CROSSWALK_AER1_AADP_SCITT.md` are local informational comparisons of
  individual drafts. They are not endorsed by their authors or by W3C/IETF.
- `tools/interop_aer1_probe.py` checks one published AER-1 fixture's public
  URL, identifier, reported verification status, UTF-8 bytes, output hash,
  and optional length. It is not a conformance suite, adopter result, or
  verification of job/workflow chains, provenance truth, or business outcome.
  The script is labelled for AER-1 -04; upstream is -05 as of this brief.
- `DESIGN_NOTE_REPRESENTATION_SESSION.md` is a local design note that may be
  relevant if the group discusses delegated human representation.

A safe description of bounded proof is: a receipt verifier checks integrity
and signatures over the claims present; the receipt alone does not prove the
events those claims describe. Missing evidence and contradictory evidence
remain distinct in CR's verifier vocabulary. Do not present that as an
identity or authorization decision.

## 3. Published meeting agenda and possible listening points

The [published 2026-10-06 agenda](https://github.com/w3c-cg/agent-identity/blob/main/meetings/2026/2026-10-06-agenda.md)
lists the meeting for Tue 6 October at 15:00 UTC, chaired by Adolfo Grego
Micha. It says the listed topics are suggestions and the group sets the order
and time on the call. Its summary of 22 September says no formal action items
were assigned. A separate minutes file at the URL previously listed in the
repository draft returned 404 during this review.

| Agenda suggestion | A bounded connection, if the group invites it |
|---|---|
| §4.2 Landscape document | Offer the local crosswalks only if requested; identify them as informational working notes. |
| §4.3 DNS and alternative roots | CR verifies its receipt keys/issuer identifiers under its own format; it has no position on which identity root the group should choose. |
| §4.4 C2PA alignment | Ask whether content provenance and action receipts have a useful interface; no CR/C2PA integration has been tested here. |
| §4.5 Authorization scope across organizations | AADP bound-permit -00 is a relevant work-in-progress comparison. Its recipient config owns issuer scope/currentness; CR does not implement permit verification or cross-organization authorization. |
| §4.6 Identifier collisions that fail open | This is a possible discussion of identifier binding. CR can describe its own issuer/key checks and their limits, without calling them prior art or claiming to solve registry collisions. |
| §4.7 ARIA / WAI-ARIA disambiguation | Naming clarity may be relevant; use “agent continuity receipt” when CR's receipt could be confused with the SCITT draft's recovery-registration receipt. |

No agenda item asks for a CR presentation. Treat these as listening notes, not
claims that the CG requested, accepted, or plans to adopt CR material.

## 4. Questions for human consideration

If discussion makes them relevant, consider asking:

1. What evidence and governance does the group expect an identifier registry
   to bind, and how should resolution failures be represented?
2. How should revocation/currentness information be distributed and checked
   by a relying party without implying that an identifier or signed record
   grants authorization?
3. Are there agreed boundaries between agent identity, workload
   attestation, mandate/delegation, and the recipient's authorization policy?

These are questions for the human participant to choose from. This note does
not authorize or send messages, propose agenda text, or imply a project
position beyond the bounded description above.

## 5. References

- [W3C Agent Identity Registry Protocol CG](https://www.w3.org/community/agent-identity/)
- [2026-10-06 agenda](https://github.com/w3c-cg/agent-identity/blob/main/meetings/2026/2026-10-06-agenda.md)
- [AER-1 -05](https://datatracker.ietf.org/doc/html/draft-zambo-aer1-05),
  [AADP bound permits -00](https://datatracker.ietf.org/doc/html/draft-saha-aadp-bound-permit-00),
  [AADP -04](https://datatracker.ietf.org/doc/html/draft-saha-aadp-04), and
  [SCITT Continuity Receipts -01](https://datatracker.ietf.org/doc/html/draft-nikolaichuk-scitt-continuity-receipts-01)
  are IETF Internet-Drafts. The reviewed agenda/materials do not establish
  their adoption or endorsement by this W3C CG.
