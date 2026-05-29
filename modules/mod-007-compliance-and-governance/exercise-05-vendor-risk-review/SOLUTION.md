# SOLUTION — Exercise 05: Vendor Risk Review

> Read this *after* attempting the learning-side exercise. This is a
> worked vendor risk review for a hypothetical third-party AI provider.
> It models the artifact a security and procurement function would
> produce before approving a vendor, with emphasis on AI-specific
> risk surfaces.

## 1. Solution overview

Vendor risk reviews are how a company decides whether to take on a
third party's risk. Two things make AI-vendor reviews different from
generic SaaS reviews:

1. **Data flows often include training-grade material.** Prompts,
   files, conversation history, and feedback may be retained by the
   vendor and used to improve their models unless contractually
   excluded.
2. **The supply chain has more links.** AI vendors typically depend
   on a model provider, an inference provider, an evaluation
   provider, and a data-annotation provider; the company inherits all
   of them.

The deliverable is a review memo with:

- Vendor profile and proposed use case.
- Data flow diagram, including training-use disposition.
- Risk findings keyed to OWASP ML Top 10 / MITRE ATLAS / NIST AI RMF.
- Required contractual and technical mitigations.
- An approve / approve-with-conditions / reject decision.
- A reassessment cadence.

## 2. Implementation

### 2.1 Vendor profile (hypothetical)

| Field | Value |
|---|---|
| Vendor name | "Acme Embeddings Co." (hypothetical) |
| Use case | Generate text embeddings of customer support transcripts for similarity search |
| Data sent to vendor | Transcript text (may include PII), tenant ID, request metadata |
| Data returned | Vector embedding (1536 dim), token count, latency |
| Vendor hosting region | US-East (primary); EU region available with surcharge |
| Sub-processors disclosed | Cloud provider, observability vendor, datacenter operator |
| Model | Vendor-hosted proprietary embedding model |
| Pricing | Per-token, monthly invoice |
| Term | Initial 12-month, auto-renew |

This profile is reviewed *against the use case the company intends*,
not a generic vendor capability statement.

### 2.2 Data flow assessment

```
[App service] -- transcript + tenant_id --> [Vendor API]
[Vendor API] -- embedding --> [App service]
[App service] -- log: hash(transcript), latency --> [audit store]
```

Critical questions answered against vendor documentation
(citations from vendor docs would be specific in a real review;
unknown answers are flagged):

| Question | Answer | Source |
|---|---|---|
| Is request content retained at rest? | Yes, 30 days for abuse monitoring | Vendor Trust page (e.g., a sub-processor list / data retention statement; cite vendor docs in real review) |
| Is request content used to train vendor models? | Default opt-out for enterprise tier (must be contractually confirmed) | Vendor enterprise terms (confirm against current vendor terms at review date) |
| Are responses logged by the vendor? | Metadata only by default | Vendor docs |
| Where is data processed? | US-East unless EU region is contracted | Vendor docs |
| Are sub-processors disclosed and change-notified? | Yes (list + 30-day notice) | Vendor sub-processor list |
| Is data segregated per tenant? | Logical isolation; no per-tenant encryption keys without higher tier | Vendor security docs |
| Encryption in transit | TLS | Vendor docs |
| Encryption at rest | Provider KMS, vendor-managed | Vendor docs |
| Independent attestations | SOC 2 Type 2 available under NDA | Vendor docs |
| Breach notification SLA | 72 hours | Vendor terms |
| Data deletion on contract end | Within 30 days; certificate available on request | Vendor terms |
| Cross-tenant attack surface in their service | Acknowledged; mitigated via per-request rate limits and content filters | Vendor docs |

### 2.3 Risk findings

| ID | Risk | Mapped to | Severity | Likelihood | Mitigation required |
|---|---|---|---|---|---|
| V-01 | Transcripts contain PII; without contractual training opt-out, PII could become model parameters | OWASP ML — training data poisoning / leakage; NIST AI RMF MAP-2 | High | Medium | Contract explicit training opt-out; technical signal (`X-Train-Opt-Out` header or vendor enterprise toggle) verified |
| V-02 | 30-day vendor-side retention extends the data perimeter | NIST AI RMF GOVERN-5 (third-party data); GDPR Article 28 | High | High | DPA in place; pseudonymize transcripts before send (subject identifiers tokenized) |
| V-03 | Sub-processor list extends to a datacenter operator outside vendor's primary trust boundary | NIST AI RMF GOVERN-6; GDPR transfer impact | Medium | High | Confirm sub-processor list flows into our public sub-processor page; SCCs cover datacenter operator |
| V-04 | No customer-controlled encryption keys at base tier | OWASP — confidentiality | Medium | Medium | Accept-with-monitoring for current data class; revisit if data class escalates |
| V-05 | Embedding inversion / training-data extraction is a known research area; vendor's defenses unstated | MITRE ATLAS (exfiltration / model inversion patterns); OWASP ML | Medium | Low | Add an outbound DLP control on what transcript content is sent; cap or hash high-sensitivity fields |
| V-06 | Vendor depends on a single cloud provider with no documented multi-region failover for our region | NIST AI RMF MANAGE-4 (resilience) | Medium | Low | Document acceptable downtime; have an offline fallback (BM25) for tier-1 paths |
| V-07 | Vendor's SOC 2 is under NDA only; not yet reviewed | NIST AI RMF GOVERN-6 | Medium | Medium | Sign NDA; review report; capture any deviations in this register |
| V-08 | Auto-renew with insufficient exit timeline | Procurement; GDPR Article 28 termination duties | Low | High | Negotiate 60-day non-renew notice and explicit data return / deletion clauses |

### 2.4 Contractual mitigations checklist

- DPA with Article 28 clauses (sub-processors, instructions,
  cooperation, return/deletion).
- Data Processing Schedule listing the categories of personal
  data sent and the purpose.
- Training-use opt-out clause naming the vendor's mechanism and
  confirming it is the default.
- Audit / inspection rights (right to audit annually,
  or to rely on independent attestations with deviations
  reported).
- Breach notification within a stated timeframe consistent with
  our regulatory clock (≤ 72 hours for personal-data breaches).
- Sub-processor disclosure with prior notice period and a
  reasonable objection mechanism.
- Termination and data return: explicit deletion certificate
  process; embeddings derived from our data also deleted.
- Service levels including security service levels (e.g., max
  patch SLA for critical vulns).
- Limitation on the vendor's right to use our data for
  benchmarking or marketing.
- Cross-border transfer mechanism (SCCs / adequacy / BCRs) per
  data flow.

### 2.5 Technical mitigations checklist

- Outbound content filter: redact / hash specified PII fields
  before sending to the vendor.
- Per-tenant scoping in the request path (vendor cannot
  cross-contaminate tenants on our side even if their isolation
  fails).
- Rate limiting and circuit breakers so a vendor incident does
  not propagate to our SLOs.
- Independent monitoring of vendor responses for anomaly
  patterns (e.g., embeddings outside expected distribution).
- Egress audit log showing what content actually crossed the
  boundary, integrity-protected (see exercise-04 evidence plane).
- Documented offline fallback for the highest-criticality flows.
- Quarterly reconciliation of our sub-processor page vs. the
  vendor's published list.

### 2.6 Decision

**Approve with conditions.** Approval contingent on V-01, V-02, and
V-08 mitigations being in the executed contract; V-05 outbound DLP
filter implemented before traffic enabled. V-07 reviewed within 30
days; downgrade or re-evaluate if SOC 2 reveals material gaps.

| Item | Owner | Due |
|---|---|---|
| Negotiate training opt-out in contract (V-01) | Procurement + Legal | Pre-signature |
| DPA with sub-processors + transfer mechanism (V-02, V-03) | Legal | Pre-signature |
| Outbound DLP for transcript fields (V-05) | App platform | Pre-go-live |
| Sign NDA, review vendor SOC 2 (V-07) | Security | T+30 |
| Renegotiate auto-renew terms (V-08) | Procurement | Pre-signature |
| Reassessment | Vendor risk | T+12 months or on material change |

### 2.7 Reassessment triggers

- Vendor sub-processor change (notified per contract).
- Material vendor incident or breach disclosure.
- Material change in our use of the vendor (new data class, new
  region, new use case).
- Regulator action affecting the vendor.
- Contract renewal.
- Public reporting that contradicts the data flow assessment.

## 3. Validation steps

1. **Trace the data flow against actual code.** Pull the egress
   code path that sends to this vendor and confirm only the
   approved fields cross the boundary. Variance is a finding.
2. **Verify the vendor's training-use posture programmatically.**
   For vendors with API headers / enterprise toggles, the request
   path should always assert the opt-out signal. Add a
   continuous-compliance check (exercise-04) for it.
3. **Walk a sub-processor change.** Confirm the vendor's
   change-notification flows into our sub-processor page and our
   customer notification within the contractual window.
4. **Tabletop a vendor incident.** Run a simulated vendor breach;
   verify our breach clock, our subject-notification path, and
   our fallback activation.
5. **Confirm the exit path.** Could the company terminate this
   vendor in 30 days and continue serving customers? If not,
   add to V-06 mitigations.
6. **Re-run the review against the live contract.** A frequent
   failure mode is the review memo describing terms that were
   negotiated *out* during signature.

## 4. Rubric / review checklist

| Criterion | Weight | Pass condition |
|---|---|---|
| Vendor profile is specific to the proposed use case | 5% | Not generic capability description |
| Data flow diagram with retention and training-use disposition | 10% | Both retention and training use addressed |
| Sub-processors and cross-border flows enumerated | 10% | Both listed, not assumed |
| Risk findings mapped to OWASP ML Top 10 / MITRE ATLAS / NIST AI RMF | 15% | Mappings cited explicitly per finding |
| Contractual mitigations checklist present | 10% | Includes Article 28 / training opt-out / breach SLA / deletion |
| Technical mitigations checklist present | 10% | Includes egress DLP / monitoring / fallback |
| Decision is explicit with conditions and owners | 10% | "Approve / approve with conditions / reject" stated |
| Reassessment triggers defined | 5% | Both cadence and event-driven triggers |
| AI-specific risks addressed (training-use, model inversion, supply chain) | 10% | Cannot be omitted — these are the module focus |
| Cross-references to exercise-02, -03, -04 | 5% | Reuses controls; does not duplicate work |
| No invented vendor facts | 10% | Unknowns flagged explicitly as open items, not fabricated |

Pass ≥ 70%. Reviews with mitigation lists but no decision row
are incomplete; the point of the review is to produce a decision.

## 5. Common mistakes

- **Treating the vendor's marketing page as the source of truth.**
  Posture statements need to be tied to contractual obligations
  or independent attestations. "We don't train on your data" on a
  homepage does not bind the vendor.
- **Ignoring the sub-processor chain.** A direct vendor with
  excellent posture can still introduce risk via a sub-processor
  with weaker controls.
- **Missing the training-use question entirely.** This is the
  single most consequential AI-vendor question and the one most
  often skipped.
- **Approving without an exit plan.** Vendors fail, get acquired,
  change terms. A review without a documented exit path is
  unsafe.
- **Letting the contract drift from the review.** The review and
  the executed contract must match; otherwise the review is
  fiction.
- **Conflating SOC 2 with comprehensive assurance.** SOC 2 covers
  what it covers; it does not, for example, attest to AI-specific
  controls. Read the report for scope and exceptions.
- **Treating the assessment as one-time.** Vendor risk decays;
  reassessment cadence and event triggers are mandatory.
- **Assuming "we'll just switch vendors" when the vendor stores
  embeddings derived from our data.** Derived data is data; the
  exit plan must include destruction of derivatives.

## 6. References

- OWASP Machine Learning Security Top 10 — vendor-relevant risk
  categories (training data leakage, model serialization,
  evaluation poisoning).
  https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS — adversary tactics that may target the vendor
  surface (model inversion / extraction / supply-chain).
  https://atlas.mitre.org/
- NIST AI Risk Management Framework — GOVERN function explicitly
  addresses third-party / supply-chain AI risk; used to map V-01
  through V-08.
  https://www.nist.gov/itl/ai-risk-management-framework
- NIST AI 600-1: Generative AI Profile — risk actions relevant to
  generative-AI vendors (content provenance, training-data
  documentation, abuse monitoring) extend the checklist when the
  vendor is a generative model provider.
  https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- VeriSwarm Trust Center — practitioner example of the *vendor
  side* of this review: how a vendor publishes the very
  information this exercise asks the learner to demand
  (sub-processor list, sub-processor change cadence, attestation
  status). Useful as a model for what a "good" vendor disclosure
  looks like, *not* as authoritative validation of any other
  vendor.
  https://veriswarm.ai/trust
- For statute and standard text (GDPR Article 28, AICPA TSC,
  SCCs, EU AI Act provider duties), cite the authoritative
  publishers in the real review; this document does not quote
  specific wording.
