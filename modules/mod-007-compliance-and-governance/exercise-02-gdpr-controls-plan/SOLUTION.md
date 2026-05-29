# SOLUTION — Exercise 02: GDPR Controls Implementation Plan

> Read this *after* attempting the learning-side exercise. This document
> walks through a *worked* GDPR controls plan for an ML system that
> processes EU personal data. It is a reference design, not legal advice;
> the production version of this plan must be reviewed by qualified counsel
> and your DPO.

## 1. Solution overview

The learner has scoped GDPR as in-scope in exercise-01. The job here is to
turn that scoping decision into a concrete implementation plan: which
controls, owned by whom, validated how, on what schedule. The plan must
cover the lifecycle of personal data through an ML system — collection,
training, inference, retention, deletion — because ML breaks several
naïve assumptions GDPR was originally written for (most notably,
*purpose limitation* and the *right to erasure*).

The plan is organized around four GDPR-derived workstreams:

1. **Lawfulness, fairness, transparency** — the legal-basis stack and the
   notice surface.
2. **Data subject rights** — the operational pipeline for requests.
3. **Security of processing** — technical and organizational measures
   (TOMs), risk assessments, breach response.
4. **Accountability** — records, governance, vendor management.

Each workstream lists controls, owner, evidence, validation cadence.

## 2. Worked answer

### 2.1 In-scope processing inventory (input to the plan)

| Processing activity | Personal data | Lawful basis | Special category? | Cross-border? |
|---|---|---|---|---|
| Account / sign-in | Email, name, IP | Contract | No | Yes (US sub-processors) |
| Support transcript ingestion | Transcript text, may include incidental special category | Legitimate interests + tenant contract | Tenant-dependent | Yes |
| Model training on opted-in transcripts | Aggregated transcript text | Consent (tenant-flowed) or legitimate interests with DPIA | Tenant-dependent | Yes |
| Inference (routing decisions) | Current transcript, tenant ID | Contract | No | Yes |
| Telemetry / audit logs | Request metadata, user ID | Legal obligation + legitimate interests | No | Yes |

Each row drives one or more controls below.

### 2.2 Workstream A — Lawfulness, fairness, transparency

| Control ID | Description | Owner | Evidence | Cadence |
|---|---|---|---|---|
| A-1 | Maintain a lawful-basis register keyed to the processing inventory; review every controller decision against Article 6 and (if applicable) Article 9. | DPO + Eng lead | `compliance/lawful-basis.yaml` checked into the repo, signed off | Per new processing |
| A-2 | Publish a layered privacy notice covering ML-specific facts: training data, retention, profiling, automated-decision logic in meaningful terms. | Legal + Product | Live URL with version + diff history | At each material change |
| A-3 | For consent-based processing, capture consent with metadata (when, what version, what scope) and provide an equally easy withdrawal path. | Eng (consent service) | Consent ledger entries, withdrawal latency dashboard | Continuous |
| A-4 | Tenant data-processing agreement (DPA) defines controller/processor roles and includes Article 28 clauses. | Legal | Executed DPA per tenant | Per onboarding + renewal |
| A-5 | Profiling & automated-decision notice where Article 22 applies; provide a route to human review. | Product + Legal | Notice copy + ticket queue for human-review escalations | Continuous |

### 2.3 Workstream B — Data subject rights

The GDPR rights to support: information (Articles 13/14), access (15),
rectification (16), erasure (17), restriction (18), portability (20),
object (21), and the special handling for automated decisions (22).

| Control ID | Description | Owner | Evidence | Cadence |
|---|---|---|---|---|
| B-1 | Single intake endpoint (web form + email alias) that creates a ticketed DSAR with SLA timers. | Privacy Ops | Ticketing system audit; intake-to-acknowledgment ≤ 72h | Continuous |
| B-2 | Identity verification proportional to request risk; documented procedure with non-PII fallbacks. | Privacy Ops | Verification SOP, sampled tickets | Quarterly review |
| B-3 | Subject-to-record mapping. A central resolver translates an identity (email, customer ID) into all primary-key locations across services and feature stores. | Eng platform | `data-map.yaml`; resolver test suite | Each new service |
| B-4 | Erasure pipeline that propagates a delete request to: OLTP records, derived analytics, feature store entries, embedding indices, model artifacts (where personal data is embedded), and logs (subject to retention obligations). | Eng platform | Erasure runbook + replayable test for a seeded subject | Quarterly drill |
| B-5 | "Right to be informed" surface for *training* data: a process to determine whether a given subject's data was used to train an in-production model, and a documented decision tree for what to do (retrain, machine unlearning, suppression). | ML platform + DPO | Trained-on register; per-model lineage | Per model release |
| B-6 | Automated-decision objection route (Article 22) with documented human-review SLA. | Product | Escalation queue, review log | Monthly audit |
| B-7 | Response within 1 month, extendable to 3 months for complex requests with subject notification. | Privacy Ops | SLA report | Monthly |

### 2.4 Workstream C — Security of processing (Article 32 TOMs)

The TOMs below are necessary; sufficient depends on the risk assessment.

| Control ID | Description | Owner | Evidence | Cadence |
|---|---|---|---|---|
| C-1 | Encryption in transit (TLS 1.2+) and at rest (provider-managed KMS with documented key rotation). | Infra | Configuration export, KMS audit log | Quarterly attestation |
| C-2 | Pseudonymization of training data: subject identifiers replaced with opaque per-tenant tokens before reaching the training pipeline. | ML platform | Pipeline contract test; sample audit | Per pipeline change |
| C-3 | Access control with least privilege, MFA, and break-glass logging on production data. | Infra + SecOps | IAM policy, access review | Quarterly access review |
| C-4 | DPIA for any high-risk processing (new model family, new data class, large-scale profiling). Template aligned with Article 35. | DPO | Signed DPIA documents | Per qualifying change |
| C-5 | Personal-data breach playbook with 72-hour notification clock to the lead supervisory authority and risk-based subject notification. | SecOps + DPO | Playbook + tabletop record | Annual tabletop |
| C-6 | Logging covers access to and modification of personal data; logs are append-only and integrity-protected. (See `projects/project-2-compliance/SOLUTION.md` for the hash-chain pattern referenced by the curriculum.) | SecOps | Log integrity verification | Continuous + spot checks |
| C-7 | Backup encryption + restore tests that confirm erasure has propagated (a restored backup cannot reintroduce deleted subjects beyond retention windows). | Infra | Restore-test report | Quarterly |

### 2.5 Workstream D — Accountability and governance

| Control ID | Description | Owner | Evidence | Cadence |
|---|---|---|---|---|
| D-1 | Article 30 Records of Processing Activities (RoPA) kept current per controller/processor role. | DPO | RoPA register | Quarterly review |
| D-2 | Sub-processor list published; tenants notified of changes per DPA. | Legal | Public sub-processor page; change log | Per change |
| D-3 | International data transfer mechanism documented per route: SCCs + transfer impact assessment, adequacy decision, or BCRs. | Legal + DPO | Per-route TIA file | Per new route or regulator change |
| D-4 | DPO designated and contactable; communicated to supervisory authorities where appointment is mandatory. | Legal | DPO appointment record; public contact | Annual review |
| D-5 | Annual GDPR program review covering controls, incidents, DPIAs, complaints, supervisory contacts. | DPO + ELT | Program report | Annual |
| D-6 | Training: role-based GDPR training for engineers handling personal data and for support staff handling DSARs. | People + DPO | Training records | Annual + on hire |

### 2.6 ML-specific risks the plan must address explicitly

These are the points where ML practice and GDPR rub against each other.
A plan that ignores them is incomplete:

1. **Erasure from trained models.** A subject's personal data may be
   *implicit* in model parameters or in vector indexes. The plan must
   state the company's chosen position: retraining on demand,
   suppression at inference, certified machine unlearning, or a
   risk-based legitimate-interests argument. NIST AI RMF and NIST AI
   600-1 reference unlearning and data-provenance practices that
   inform this decision.
2. **Purpose limitation under reuse.** Training data collected for
   "service operation" cannot be silently reused to train an unrelated
   model. The DPIA in C-4 must explicitly assess compatibility.
3. **Profiling and Article 22.** Even ostensibly "low risk" routing can
   become automated decision-making with significant effects depending
   on use; document the test you applied.
4. **Output as personal data.** A generated summary that names a
   subject is itself personal data; logs of it inherit retention and
   erasure duties.
5. **Adversarial extraction.** Membership-inference and training-data
   extraction risks (OWASP ML Top 10; MITRE ATLAS) are technical
   threats with GDPR consequences — an extracted training record is a
   personal-data breach. Note the cross-reference; the technical
   defenses live in `mod-006-adversarial-ml`.

## 3. Validation steps

1. **Cross-walk the plan to the processing inventory.** Every row in 2.1
   should map to at least one A/B/C/D control. Orphan processing rows
   indicate scope gaps.
2. **Tabletop a DSAR.** Pick a seeded test subject and walk the full
   erasure flow (B-3 → B-4 → C-7 backup test). The plan passes if a
   reviewer can identify the owner and evidence at each hop.
3. **Tabletop a breach.** Run a simulated personal-data incident; verify
   the 72-hour clock, the regulator notification path, and the subject
   notification trigger.
4. **Independence check on the DPO.** Confirm the DPO does not
   simultaneously own decisions they are required to advise on
   independently (e.g., the head of product cannot also be the DPO for
   high-risk profiling decisions).
5. **Evidence-by-default audit.** Pick five controls at random; verify
   the evidence exists *outside the reviewer's head* — in a register,
   ticketing system, or signed document.

## 4. Rubric / review checklist

| Criterion | Weight | Pass condition |
|---|---|---|
| Processing inventory drives the plan | 10% | Each control traces back to a processing row |
| Lawful-basis stack is explicit | 10% | Every processing has a basis; consent vs. legitimate interests distinguished |
| DSAR pipeline covers ML-specific surfaces | 15% | Plan addresses feature stores, embeddings, model artifacts, not just OLTP |
| Article 32 TOMs concrete, owned, evidenced | 15% | Each TOM has owner + evidence column filled |
| DPIA process defined with trigger conditions | 10% | "When do we DPIA?" answer is operational, not aspirational |
| International transfers handled per route | 5% | TIA mechanism specified |
| Breach response runs to 72-hour clock | 10% | Specific notification path + escalation owner |
| RoPA and sub-processor register live | 5% | Both registers exist and have a review cadence |
| Training-data unlearning / suppression position taken | 10% | Plan states the chosen approach rather than punting |
| Plan is dated, owned, and reviewable | 5% | Owner and next review date present |
| No invented enforcement examples | 5% | Avoids citing fictional fines or anecdotes |

Pass ≥ 70%. Plans that pass C-1 through C-3 but fail B-4 and B-5 are
typical "lift and shift" plans that miss the ML-specific risk surface;
flag for redo.

## 5. Common mistakes

- **Treating GDPR as a security checklist.** Article 32 is one of many
  articles; controls without a lawful-basis register and DSAR pipeline
  are not a GDPR program.
- **Naming "the team" as the owner.** Owners are roles or people, not
  teams. Diffuse ownership becomes no ownership.
- **Designing erasure as an OLTP-only operation.** If the plan doesn't
  describe what happens in the feature store, embedding index, and
  model artifacts, it will fail the first real DSAR involving a
  training-data subject.
- **Confusing the legitimate-interests basis with "we want to do
  this."** Article 6(1)(f) requires a documented balancing test.
- **Ignoring extraterritoriality.** Non-EU establishments still trigger
  GDPR when targeting EU subjects (Article 3(2)).
- **Citing SCCs as a complete answer for transfers.** SCCs require a
  transfer impact assessment; the plan must capture the assessment, not
  just the contract.
- **Conflating DPO independence with reporting line.** A DPO can report
  high in the org and still lack independence if they own the
  processing decisions.

## 6. References

- NIST AI Risk Management Framework — governance scaffolding for the
  accountability workstream.
  https://www.nist.gov/itl/ai-risk-management-framework
- NIST AI 600-1: Generative AI Profile — risk actions especially
  relevant to training-data provenance and content provenance
  obligations that map to GDPR transparency.
  https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- OWASP Machine Learning Security Top 10 — threats whose realization is
  a personal-data breach under GDPR (membership inference, training
  data extraction).
  https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS — adversary tactics relevant to the Article 32 risk
  assessment.
  https://atlas.mitre.org/
- VeriSwarm Trust Center — practitioner example of publishing a privacy
  posture (sub-processors, transfer mechanism, contact paths) consistent
  with GDPR's transparency duties.
  https://veriswarm.ai/trust
- For the GDPR text itself, cite the consolidated regulation on
  EUR-Lex when producing the real plan; this document does not quote
  specific recitals or article wording to avoid drift from the
  authoritative text.
