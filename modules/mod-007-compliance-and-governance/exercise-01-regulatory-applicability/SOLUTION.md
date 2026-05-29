# SOLUTION — Exercise 01: Regulatory Applicability Matrix

> Read this *after* attempting the learning-side exercise. The matrix below is
> a worked example for a hypothetical mid-stage SaaS that ships an ML feature
> processing customer data; treat it as a template to adapt, not a verdict on
> any specific company.

## 1. Solution overview

The learner is asked to produce a regulatory applicability matrix: given the
company's product, data, geography, and customers, which obligations actually
attach? The deliverable is a defensible *first-pass* mapping that drives the
rest of the module (GDPR plan in exercise-02, SOC 2 readiness in exercise-03,
etc.).

Why this matters: most compliance programs fail before they start by either
(a) treating every framework as in-scope ("we'll do them all") which dilutes
focus, or (b) treating the obvious ones as the only ones ("we're B2B SaaS so
we just need SOC 2"). A matrix forces an explicit, reviewable judgment per
regime.

The matrix has three layers:

1. **Trigger facts** — the operational properties of the system that drive
   applicability (data subject location, data class, sector, contracting
   model, deployment region).
2. **Regimes considered** — each candidate regulation/framework.
3. **Disposition** — in-scope / partially in-scope / out-of-scope, with the
   triggering fact cited.

## 2. Implementation

### 2.1 Example system profile

| Property | Value |
|---|---|
| Product | Self-serve ML-powered customer-support routing SaaS |
| Customers | B2B; tenants include US healthcare, EU consumer, UK financial |
| End users (data subjects) | Customer-service agents (B2B), end consumers (B2C via tenant) |
| Personal data processed | Name, email, support transcript text, IP address, optional voice |
| Special-category data | Tenant-dependent; may contain health info (US healthcare tenants) |
| Training data | Aggregated, anonymized transcripts (per tenant opt-in) |
| Hosting | US-East primary, EU-West replica; vendor sub-processors in US/EU |
| Automated decisioning | Yes — routing decisions; no consequential decisions about consumers |
| Government customers | Not yet |

### 2.2 Applicability matrix

| # | Regime | Disposition | Triggering fact | Primary obligations to scope |
|---|---|---|---|---|
| 1 | GDPR (EU 2016/679) | In scope | EU data subjects via EU consumer tenants | Lawful basis, DPIA for ML routing, DSARs, transfer mechanism, records of processing |
| 2 | UK GDPR + DPA 2018 | In scope | UK financial tenants → UK data subjects | Same as GDPR plus UK-ICO specifics |
| 3 | CCPA / CPRA (California) | In scope | California consumers reachable via US tenants | Notice at collection, opt-out of sale/share, sensitive-PI handling, consumer rights |
| 4 | HIPAA | Partially in scope | US healthcare tenants may transmit PHI through support flows | Business Associate Agreement, breach notification, safeguards (admin/physical/technical) |
| 5 | SOC 2 (AICPA TSC) | In scope | B2B customers contractually require an attestation | Security (mandatory) plus Confidentiality, Availability, Privacy as elected |
| 6 | EU AI Act | Partially in scope | Routing is not high-risk under Annex III as described, but transparency duties may apply | Risk classification, transparency for AI-mediated interactions, GPAI obligations if a general-purpose model is used (confirm against the current EU AI Act text and final Annex III list at review date) |
| 7 | NIST AI RMF | Out of scope (mandatory) — in scope (voluntary) | Useful as the governance scaffolding even if not legally required | MAP / MEASURE / MANAGE / GOVERN |
| 8 | NIST AI 600-1 (Generative AI Profile) | In scope if a generative model is in the routing/summarization pipeline | Use of LLM for ticket summarization | Risk-action mapping per NIST AI 600-1 |
| 9 | PCI DSS | Out of scope | No card data processed by the ML service | n/a — confirm card flow is segregated |
| 10 | FedRAMP | Out of scope (today) | No federal government customers | Re-evaluate before signing first federal tenant |
| 11 | ISO/IEC 27001 | Optional | Often paired with SOC 2 for international customers | Defer unless a customer asks |
| 12 | ISO/IEC 42001 (AI management systems) | Optional | New standard; some enterprise buyers ask | Defer; align via NIST AI RMF first |
| 13 | State AI laws (e.g., Colorado AI Act, NYC Local Law 144) | Partially in scope | Depends on whether routing constitutes a "consequential decision" affecting consumers | Track jurisdiction-specific employment / consumer rules (verify which state AI laws are in force at review date and which trigger for support routing) |
| 14 | Sector-specific (GLBA, FERPA, COPPA) | Out of scope today | No financial-account, education, or under-13 data flows | Re-evaluate per new tenant onboarding |

### 2.3 How to fill the matrix in your own organization

The defensible process — not the table above — is what's being graded:

1. **List the trigger facts before the regimes.** If you start from "we
   should be HIPAA compliant" you will reverse-engineer the data flow to
   justify the conclusion. Start from the data and let it carry you to the
   regimes.
2. **Be explicit about the unit of analysis.** A multi-product company has
   multiple matrices, one per data flow.
3. **Date the matrix.** Regulatory scope decays — new tenants, new regions,
   new models change the answer. Re-baseline at minimum quarterly.
4. **Distinguish legal scope from customer-required scope.** SOC 2 is
   typically a contractual requirement, not a law; this distinction governs
   how you triage findings.
5. **Mark every "no" with a triggering fact.** "Out of scope because we
   don't have federal customers" is reviewable; "out of scope" alone is not.

## 3. Validation steps

A peer reviewer should be able to:

1. **Trace each disposition to a trigger fact.** If any row says "in scope"
   or "out of scope" without a specific operational fact, that row fails
   review.
2. **Stress-test with a hypothetical onboarding.** Pose: "We just signed a
   French health system." Reviewer should see which rows flip and which
   stay.
3. **Verify the official source for any framework claim.** Each in-scope
   regime in the matrix should link to its authoritative text (e.g., the
   GDPR text on eur-lex, the AICPA TSP section 100, the NIST AI RMF page).
4. **Confirm the matrix discriminates.** A matrix that says "yes" to
   everything is not a matrix. At least one regime should be eliminated
   with a stated reason.
5. **Confirm the date and review owner.** A matrix without an owner or a
   next-review date is a snapshot, not a control.

## 4. Rubric / review checklist

| Criterion | Weight | Pass condition |
|---|---|---|
| Triggering facts enumerated up front | 15% | A data/operations fact table precedes the matrix |
| All regimes given a disposition | 15% | Every row has in/partial/out, not blank |
| Each disposition cites a triggering fact | 20% | No row contains an unjustified conclusion |
| Both legal and contractual regimes covered | 10% | At least one of each appears (e.g., GDPR and SOC 2) |
| EU AI Act and NIST AI RMF/600-1 specifically addressed | 10% | Cannot be omitted — these are the module focus |
| Geographic and sectoral edge cases acknowledged | 10% | At least one row explicitly considers extraterritorial reach |
| Open questions flagged explicitly as research items | 5% | Unknowns are flagged, not papered over |
| Review cadence and owner declared | 5% | Date stamp + owner role present |
| Avoids hallucinated facts | 10% | No invented case studies, citations, or fines |

Pass ≥ 70%. Below 50% means the learner has not internalized that
applicability is *fact-driven*, not framework-driven, and they should redo
the trigger-fact section.

## 5. Common mistakes

- **Citing fines or case studies to justify scope.** "We have to comply
  because Company X was fined." Unless the learner can produce the
  enforcement decision text, the assertion is unsafe.
- **Treating NIST AI RMF as a regulation.** It is voluntary guidance; it
  belongs in the matrix as scaffolding, not as a legal trigger.
- **Confusing "we use a vendor that is X-certified" with "we are X-compliant."**
  Vendor certifications are inputs to your own compliance, not your
  compliance.
- **Omitting the EU AI Act for a "low-risk" system.** Transparency and GPAI
  duties can attach even when Annex III classification does not.
- **Hard-coding the matrix.** A matrix without a review date and named
  owner becomes wrong silently.
- **Mixing scope with implementation.** "We do encryption at rest, so PCI
  is out of scope" is wrong reasoning: encryption is a control, not a
  scoping rule. Scope is about *what data* you handle, not how.

## 6. References

- OWASP Machine Learning Security Top 10 — context for ML-specific risks
  that may attract sectoral regulator attention.
  https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS — adversarial threat tactics that compliance programs should
  recognize as in scope when assessing AI risk.
  https://atlas.mitre.org/
- NIST AI Risk Management Framework (AI RMF 1.0) — the governance
  scaffolding cited in row 7.
  https://www.nist.gov/itl/ai-risk-management-framework
- NIST AI 600-1: Generative AI Profile — risk actions for generative
  systems referenced in row 8.
  https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- VeriSwarm Trust Center — practitioner example of how a vendor publishes
  applicability and certification status; useful as a model for the
  *output* of a maturity matrix, not as authoritative legal interpretation.
  https://veriswarm.ai/trust

Statute and framework texts (e.g., the GDPR, the EU AI Act, the AICPA Trust
Services Criteria, HIPAA, CCPA/CPRA) should be cited from their
authoritative publishers when the learner builds the real matrix. Avoid
secondary "GDPR for engineers" blog posts as primary citations.
