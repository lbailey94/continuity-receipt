# Demand crosswalk: insurance, procurement, and regulation → continuity-receipt

**Status:** design note (2026-10-05). Not a spec change. Maps external
requirements (dated, sourced) onto CR records and names the gaps. Every
crosswalk here is a candidate review artifact — none is an adoption claim.

## 1. EU AI Act

- **Art. 50 transparency is live (since 2026-08-02).** The July 2026
  guidelines (C(2026) 5054) state agents must disclose their artificial
  nature and **the person on whose behalf they act**, "considering the need
  for transparency of the origin and the **delegation of authority** and
  accountability for the consequences of their actions," including
  multi-agent architectures. CR's `authority.grant` is an *assertion* record
  (declared principal, scope, window, signed by the agent/operator) — which
  is exactly the honest level this disclosure needs, provided the limits are
  stated.
- **High-risk logging (Arts. 12, 19, 26) applies from 2026-12-02-2027 /
  2028** (Annex III 2 Dec 2027; Annex I 2 Aug 2028, per the Digital Omnibus,
  Reg (EU) 2026/1744). Art. 12 requires automatic event logging over the
  system lifetime; Art. 19/26(6) require retention **≥ 6 months**; Art. 18
  technical documentation **10 years**. The right position: CR is the
  verifiable evidence layer *attached to* mandatory logs, not the log store.
- **Gap to name:** a **regulated-retention profile** — erasure/redaction
  mechanics must not remove fields a retention obligation requires; document
  "anchor before erasure" so a verifier can prove an anchor existed.

## 2. US finance and audit-trail standards

- **FINRA 2026 Annual Regulatory Oversight Report** (GenAI section, agent
  subsection): names autonomy without validation, scope/authority overreach,
  and **auditability/transparency of multi-step reasoning**; suggests firms
  "track agent actions and decisions" under existing rules (3110
  supervision, 4510, Reg BI).
- **SEC Exchange Act Rule 17a-4(f)** (2022 amendments): the audit-trail
  alternative to WORM requires a complete, timestamped audit trail of
  modifications/deletions, **identity of the person** creating/modifying/
  deleting, and the **capacity to re-create the original record** in
  human-readable form. CR covers timestamp + issuer identity + chain
  integrity; it does **not** provide record reconstruction (redaction, not
  replay) — name this limit in any finance-facing mapping.
- **IOSCO FR/02/2026 Supervisory Toolkit** adds "Recordkeeping & Audit
  Trail" as a supervisory area for AI outcomes.

## 3. Insurance (the strongest near-term fit)

- **AIUC-1** (AI Underwriting Company; $55M Series A 2026; audited by
  Schellman/Coalfire; policies up to $50M; ElevenLabs first live AI-agent
  policy, 2026-02-11). Requirement **E015 "Log AI system activity"**:
  - E015.1/.3 (mandatory): inputs/processing/outputs/metadata logging;
    storage with retention, access control, PII sanitation.
  - **E015.2 (supplemental): agent execution chains** — provenance
    metadata, tool-call parameters/results, **sub-agent delegation chains
    with identity/context/outcome**, **approval/authorization records**,
    reasoning traces.
  - **E015.4 (supplemental): tamper-evident, independently verifiable
    logs** — WORM, cryptographic hashing, append-only, sequence-integrity
    (gaps/omissions/reordering detectable). AIUC explicitly accepts
    **alternative evidence**.
- **Armilla/Chaucer Vanguard AI** (2026-02-10): coordinated cyber + tech E&O
  with standalone AI cover ($25M+ AI limits) explicitly including **"AI agent
  actions"**; loss allocation requires reconstructing whether harm came from
  cyber, tech failure, or AI behavior. A **claim-time evidence pack**
  (bundle + verification receipt + anchor proof + retention statement) is the
  natural artifact.

**Honest limit for underwriters:** a receipt attests what its issuer signed,
not that events occurred. Underwriting value is highest when the issuer is
the vendor whose agents are insured (as in AIUC certification), not a
self-attested third party.

## 4. Enterprise procurement

- **Drata questionnaire data (2026-06)**: AI-specific questions +30% in nine
  months, clustering into five: (1) which agents run; (2) what they may do;
  (3) who they run as; (4) whether they behave as expected; (5) **can you
  prove it**. CR mapping: (1) issuer/agent identity binding; (2)
  `authority.grant.scope`; (3) `authority.grant.principal/agent`; (4)
  execution/delivery/termination records; (5) offline verification +
  verification receipts.
- **GSA proposed GSAR 552.239-7001** (2026): for AI using "reasoning,
  retrieval, or agentic processes," requires summarized **intermediate
  processing actions and decision points**, **model routing decisions with
  rationale**, and **data-retrieval methods with source attribution**,
  accessible via output, audit trail, and UI. CR has decision/execution
  records and hashes but not these narrative fields — either a companion
  artifact or a profile extension must carry them.
- **ISO 42001 A.6.2.8 / NIST AI RMF MEASURE 2.4/2.8 / CSA AICM LOG-* /
  OWASP AIVSS "Agent Untraceability"** are the vocabulary auditors use; the
  crosswalk table should cite them row by row.

## 5. Mapping table (requirement → CR)

| Requirement | CR record/field | Gap |
|---|---|---|
| Acting-on-behalf disclosure (AI Act Art. 50) | `authority.grant.principal/agent` | none (assertion level, documented) |
| Event logging over lifetime (Art. 12) | receipt chain (decision→termination) | not a log store; position as evidence layer |
| Retention ≥ 6 months / 10 years (Arts. 19/26/18) | redaction/erasure + anchors | **regulated-retention profile missing** |
| Identity of modifier (17a-4) | `issuer.id`, signatures | record reconstruction missing |
| Delegation/approval records (AIUC E015.2) | `authority.grant`, `authority_ref` | sub-agent chains not first-class |
| Tamper-evident, sequence-integrity (AIUC E015.4) | hash chain + anchors + verification receipts | **head commitment missing (truncation)** |
| Who/which/allowed/behaving/prove (Drata) | grant + chain + verification receipts | principal authorization is assertion-only |
| Decision points / routing rationale / retrieval attribution (GSA) | `task.decision`, `task.execution` | narrative fields absent |
| Underwriting claim reconstruction | bundle + verification receipt + anchor | claim-pack profile not written |

## 6. Prioritized actions from this crosswalk

1. **AIUC-1 E015.2/E015.4 alternative-evidence mapping** (one page) + a
   claim-pack profile. Strongest near-term revenue logic; AIUC accepts
   alternative evidence.
2. **Final chain-head commitment** (see `DESIGN_NOTE_HEAD_COMMITMENT.md`) —
   directly answers E015.4's sequence-integrity requirement.
3. **Regulated-retention profile** (Art. 19/26, 17a-4): erasure rules,
   anchor-before-erasure, retention labels.
4. **Procurement one-pager** (Drata five questions + GSA fields) for the 0.6
   review brief.
5. **Authority-required profile** consuming external principal evidence
   (AP2/OIDC/VC) — the "who stands behind the agent" line item buyers press.

## Sources (verified 2026-10-04/05)

EU AI Act timeline: https://ai-act-service-desk.ec.europa.eu/en/ai-act/timeline/timeline-implementation-eu-ai-act ·
Art. 12: https://artificialintelligenceact.eu/article/12/ · Art. 50 guidelines: https://ec.europa.eu/commission/presscorner/detail/en/ip_26_1653 ·
FINRA 2026 report: https://www.finra.org/rules-guidance/guidance/reports/2026-finra-annual-regulatory-oversight-report/gen-ai ·
SEC 17a-4: https://www.sec.gov/files/rules/final/2022/34-96034.pdf · IOSCO: https://www.iosco.org/library/pubdocs/pdf/IOSCOPD823.pdf ·
AIUC-1 E015: https://standard.aiuc-1.com/accountability/log-model-activity · AIUC: https://aiuc.com/ ·
Chaucer/Armilla: https://www.chaucergroup.com/news/press-release-chaucer-and-armilla-ai-launch-vanguard-ai-coordinated-insurance-structure ·
Drata: https://drata.com/about/news/drata-extends-trust-management-platform-to-continuously-monitor-and-govern-ai-agents ·
GSA draft: https://buy.gsa.gov/interact/system/files/GSA_Federal_Acquisition%20Service%20Proposed%20Government%20AI%20System%20Terms%20and%20Conditions.pdf
