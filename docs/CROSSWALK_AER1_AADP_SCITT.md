# Crosswalk & Triage: AER-1 · AADP bound permits · SCITT Continuity Receipts

**Status:** informational triage, 2026-09-30. Not normative; not an endorsement
or adoption claim by any draft's authors. Internet-Drafts may change. Companion
to `CROSSWALK_SAHU_ACTA_ASQAV.md`.

Reads: [AER-1 -04](https://datatracker.ietf.org/doc/html/draft-zambo-aer1-04)
(Zambo, Independent/Informational, 2026-09-29) ·
[AADP bound permits -00](https://datatracker.ietf.org/doc/html/draft-saha-aadp-bound-permit-00)
(Saha, Independent/Standards Track, 2026-09-29) ·
[SCITT Continuity Receipts -01](https://datatracker.ietf.org/doc/html/draft-nikolaichuk-scitt-continuity-receipts-01)
(Nikolaichuk, Independent/Informational, 2026-09-29). Full texts read, not
titles; disposition before the W3C Agent Identity CG call (2026-10-06).

## 1. Verdict table

| draft | family | what it actually is | relation to continuity-receipt | disposition |
|---|---|---|---|---|
| AER-1 -04 | execution receipt | one tool call, portable, public URL, SHA-256 output commitment, provenance classes, job chains, workflow (Merkle) receipts | sibling at finer granularity; evidence source for our chain; explicitly leaves decision/authority/settlement to other specs | **compose + probe** (live probe below) |
| AADP bound permit -00 | authority / permit | PDP-signed permit bound to one recipient, presenter key, HTTP request, and decided action instance; mandate reference; fail-closed | complements our local dispatch-seam governance with cross-boundary request binding; Mandala supplies the mandate side | **compose + track** |
| SCITT Continuity Receipts -01 | recovery attestation | registration of a *recovery event* of a stateful artifact in a transparency log (COSE receipt over RFC 9943/9942) | same name, different object (artifact recovery, not agent session continuity); concept twins at our `state.commitment` layer | **differentiate the name; compose at the commitment layer** |

No fatal collisions. All three are compose targets.

## 2. AER-1 -04 (Zambo)

**What it is.** A deliberately small interoperable core for one tool call:
`id` (UUID), `receipt_schema_version`, `created_at` (RFC 3339), `tool{name,
version, scope}`, `provenance_class`, `canonical_bytes` (base64 of the exact
UTF-8 bytes hashed), `output_hash` (`sha256:` + hex), `verification_status`.
The public URL is a resolution rule, not a stored member (§3, §9). Revision 04
adds hash-chained job timelines (§7) and workflow receipts: an ordered step
sequence bound to one goal with a Merkle root (§8), bidirectionally linked.

**Maturity.** Reference implementation deployed (`zambo.dev`); conformance kit
with seven language runners, 43/43 vectors, frozen v1.4.0 corpus; receipts
anchored to Nostr relays with a Bitcoin-anchored challenge exercised; three
independent agent verifications reported (§Implementation Status).

**Overlap and differences.** Their provenance classes — `EXECUTED BY <system>`,
`OBSERVED VIA GATEWAY`, `LOGGED BY AGENT`, with "verification MUST NOT upgrade
a report into an observation" — are the same epistemic discipline as our
disclosure/counterparty-attestation rules, applied per call. Differences:
public-URL/online verification versus our bundle/offline recomputation;
Nostr/Bitcoin anchors versus our OpenTimestamps/public-chain anchor types;
raw-output digests versus our canonical-view digests.

**Field map (provisional).**

| AER-1 | continuity-receipt | note |
|---|---|---|
| `id` | receipt `id` | both stable identifiers; CR ids are per-record within bundles |
| `created_at` | `issued_at` | same role, same format |
| `tool{name,version,scope}` | `task.execution` body fields | CR carries per-type bodies; schemas differ |
| `provenance_class` | nearest: disclosure + counterparty attestation | concept aligned; no field-level mapping |
| `canonical_bytes` / `output_hash` | per-type content digests | AER-1 commits raw output bytes; CR digests canonical receipt views |
| `verification_status` | CR verdict | single-record check versus chain verdict |
| §7 chains / §8 workflows | `prev` links / agreements | job timeline + workflow versus session lifecycle |

**Live interop probe (2026-09-30, from this repo's tooling).** Fetched the
machine verifier for a live receipt and recomputed the commitment:

```
GET https://zambo.dev/api/receipt/130da435-e157-498e-af90-605866a86a27/verify
sha256(base64_decode(canonical_bytes)) == output_hash  ->  MATCH
(sha256:0492c18e09059aa2e30ba0864f6aada2ef08475a5b35944cbf2a9ce46d12b9f1)
```

**Compose path.** §15 states AER-1 "leaves decision semantics, authorization,
and settlement bindings to other specifications" — that is our profile's
territory. Path: (a) `tools/interop_aer1_probe.py` replicating the probe
above; (b) optional 0.6 evidence-reference: `task.execution` /
`delivery.attestation` bodies carrying AER-1 receipt id + URL + digest as
fine-grained execution evidence; (c) a short draft comment offering the
crosswalk (provenance-class alignment is worth mutual citation).

## 3. AADP bound permits -00 (Saha)

**What it is.** The third of three questions at a trust boundary ("was this
exact request decided, under the sender's current authorization state, and is
what arrived the request that was decided?"). A bound permit is a short-lived
envelope signed by the AADP Policy Decision Point, bound to one recipient, one
presenter key, one HTTP request (HTTP Message Signatures + Content-Digest) and
one decided action instance (`action_digest`), optionally referencing a
mandate the recipient evaluates itself; verification is fail-closed with
explicit refusal reasons; multi-hop decision chains are refused in this
revision; recipient confirmation is recorded.

**Relation to us.** Our governance is strong at the *local dispatch seam*
(gate-lite passes, Mandala authority, Dharma/karma). AADP addresses the layer
our stack does not: carrying a per-action decision across an organizational
boundary. Mandala supplies the mandate; AADP binds the exact request to the
decision about it. Composition, not competition: a CR `task.decision` could
carry the permit digest that governed a cross-org `task.execution`.

**Provisional map.** permit envelope ↔ gate-lite pass (`mandala_pass`);
`action_digest` ↔ the argument/action commitment our gate validates;
mandate reference ↔ authority grants / `authority.succession`; recipient
confirmation ↔ `delivery.attestation` (nearest).

**Caveats.** Author name `Saha` is distinct from the `sahu` agent-action-
receipts draft we already probe (`tools/interop_sahu_vectors.py`); confirm
whether the AADP -00 author family overlaps before asserting any relationship.
Draft is Standards Track — read §6 issuer scope and §7 currentness before
relying on any constructions; no probe attempted yet (HTTP Message Signatures
make it heavier than AER-1).

## 4. SCITT Continuity Receipts -01 (Nikolaichuk)

**What it is.** The SCITT forward path (what an artifact was built from) has a
durable shape (RFC 9943 logs, RFC 9942 receipts). This draft covers the second
path: stateful assets (models, databases, indexes, key hierarchies) that are
sealed, moved, lost, and re-created, leaving no independently checkable trace.
A **Continuity Receipt** is the Receipt obtained when a *recovery statement*
(CDDL `continuity-claims`: `recovered-digest`, `sealed-material`,
`policy-id`, `recovery-environment` with TEE family/measurement, RATS
`attestation-ref` in referenced/embedded/registered modes, `freshness`,
`outcome`, `prev-event` chains, optional `equivalence` byte-identical/
operational/none) is registered in a transparency service. It proves exactly
one thing: that statement was registered at a log position — it does NOT prove
the recovery occurred, the bytes match, or the attestations were favourable
(§3.3, normative).

**Name reality.** The term "continuity receipt" now names two different
objects: theirs (artifact/workload recovery registration) and ours
(agent-session lifecycle and authority/settlement evidence). The concept
families are adjacent, not identical. Practical guards: use "agent continuity
receipt" in external copy; keep the `continuity-receipt/0.5` identifier; add a
cross-reference note; consider a courtesy engagement with the author — §1
cites ephemeral TEE gateway receipts (in-memory TTL, no transparency
integration) as an unsolved durability gap, which is the same gap our hosted
verifier and anchoring answer from the other side.

**Compose path.** `state.commitment` (0.5: chain-head and file-snapshot
commitments) is the natural interface: a CR state commitment could be
registered as a recovery statement payload (or referenced) so agent
continuity gains a transparency-log anchor; conversely a SCITT receipt could
be carried as a CR external anchor (sibling to OpenTimestamps/public-chain).
Feasibility depends on the SCITT registration API (`draft-ietf-scitt-scrapi`)
and the registration policy (§7); assess before proposing anything.

## 5. Landscape map — where CR sits

| layer | draft family | examples | CR relationship |
|---|---|---|---|
| per-execution evidence | execution receipts | AER-1, sahu | embed as evidence refs |
| per-decision authorization | permits | AADP, vaara, AATR | bind decision digests into our chain |
| compliance / audit | audit receipts | ACTA, asqav | compare semantics; no wire compat (see companion doc) |
| workload identity | attestation | WIMSE AIMS, PTV (RATS) | map identity; future `runner_profile` attestation |
| transparency registration | SCITT | RFC 9943/9942, this draft | anchor/registration interface |
| lifecycle chain | **ours** | continuity-receipt/0.5 | the chain that binds offer→accept→decision→execution→delivery→settlement→revocation |

PTV (`draft-anandakrishnan-rats-ptv-agent-identity-01`) is a thin RATS
request/response profile proving an agent is bound to an enrolled attestation
key and authorized configuration — a future compose for attesting execution
environments, not a receipts competitor. `draft-intra-handshake-fail-50`
(purported early-attestation CVEs; unverified) reinforces the field's turn to
continuous attestation and careful claims — our disclosure rules already
follow that discipline.

## 6. Recommendations (before 2026-10-06)

1. **AER-1:** add `tools/interop_aer1_probe.py` (the probe above is the
   fixture); optional 0.6 evidence-ref note; a draft comment offering the
   crosswalk.
2. **AADP:** no code yet; add to this crosswalk set; revisit after §6/§7 are
   studied; watch for a -01 (Standards Track drafts move).
3. **SCITT:** name guards now (docs cross-reference; "agent continuity
   receipt" in external copy); assess SCRAPI registration feasibility for
   `state.commitment`; consider author contact only after feasibility.
4. **Oct 6 CG call:** this cluster is identity-adjacent; the CG brief should
   note the crosswalk work exists (sahu probe + this triage) without claiming
   endorsements.
5. **Do not adopt formats wholesale.** CR's differentiators remain offline
   verification, chain semantics, agreement/settlement binding, and
   revocation; everything above composes into that, not over it.
