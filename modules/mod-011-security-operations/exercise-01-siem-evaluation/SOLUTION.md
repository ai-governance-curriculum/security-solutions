# Exercise 01 — SIEM Evaluation (Reference Solution)

> Read after attempting the learner exercise. This solution is a
> worked decision document for the SmartRecs scenario described in
> [`lessons/mod-011-security-operations/exercises/exercise-01-siem-evaluation.md`](../../../../ai-infra-security-learning/lessons/mod-011-security-operations/exercises/exercise-01-siem-evaluation.md).

## 1. Solution overview

The exercise asks for a defended SIEM choice given a small team
(6 engineers), modest log volume (~30 GB/day), an $80k all-in
budget, and an existing Datadog footprint. The reference answer
recommends **Elastic Security (Elastic Cloud)** as the primary SIEM
with a deliberate trade-off: Datadog Cloud SIEM stays on as the
correlation layer for infrastructure telemetry the engineers
already read daily.

Why this shape of answer:

- A SIEM decision is rarely about which product has the most
  features. It is about staffing, retention, and integration with
  the way the team *already* operates. NIST AI RMF GOVERN-1.5 and
  MANAGE-2.1 both point at organizational capacity as a leading
  constraint, not tooling.[^nist-ai-rmf]
- The exercise rubric rewards picking *one* SIEM and defending it
  against the obvious alternative. A two-product answer is only
  acceptable if the second product has a different job (here:
  product observability, not security analytics) and stays inside
  the $80k cap.
- "Free" candidates (Wazuh) almost always lose on operational cost
  for a 6-engineer team; this needs to be argued, not asserted.

## 2. Implementation (worked answer)

The worked answer below is written in the exact format the exercise
requires so a learner can read it as a model.

---

```
# SIEM Evaluation: SmartRecs

## Audience
Engineering leadership (CTO, head of platform), founding security
engineer, and the compliance lead preparing the SOC 2 Type 2 audit.

## TL;DR
Adopt **Elastic Security on Elastic Cloud** as the SmartRecs SIEM.
Keep Datadog Cloud SIEM disabled for security analytics but retain
Datadog for application/infra observability. Annual cost target:
~$55k for Elastic Cloud + Logstash/Beats agents, ~$15k held back
for ingestion overruns and one paid Elastic support seat. Total
projected first-year SIEM spend: **~$70k**, leaving ~$10k headroom
inside the $80k envelope.

Rejected alternatives:
- **Datadog Cloud SIEM** — competitive on time-to-value but ingest-
  priced data volumes and SIEM SKU together push the all-in cost
  above $80k once HIPAA/GDPR retention is added.
- **Microsoft Sentinel** — strongest content library, but the
  workload is AWS-native and the org has no Azure tenancy; the
  cross-cloud egress and identity provisioning cost is unjustified
  at this scale.
- **Wazuh self-hosted** — license is free; the operational cost
  (on-call ownership of a clustered OpenSearch backend) consumes
  more than 0.5 FTE of the only security engineer. Rejected on
  staffing, not licensing.
- **Splunk Cloud** — included for reference. Excluded on cost; the
  ingest-priced model is incompatible with the budget at 30 GB/day.

## Selection criteria

| Criterion | Weight | Why |
|---|---|---|
| Total cost of ownership at 30 GB/day for 12 months | 20% | Budget is a hard constraint. |
| Operational load on one security engineer | 20% | The biggest hidden cost; 0.5 FTE of platform care is real money. |
| Sigma / portable detection support | 10% | Detections from Module 11 Exercise 02 must deploy without rewrite. |
| AWS + Kubernetes + Falco + Cilium integration | 10% | All telemetry sources are AWS-native or k8s-native. |
| Retention compatible with HIPAA (≥6 yr available for the audit log subset) and GDPR data-subject controls | 10% | Compliance gates the SOC 2 evidence. |
| Compliance evidence quality (immutable storage, exportable audit trails) | 10% | SOC 2 Type 2 auditors want raw evidence, not screenshots. |
| Time-to-value (default content + onboarding effort) | 10% | A 90-day SOC 2 window does not tolerate a 6-month rollout. |
| Future-proofing (multi-cloud, scale to 100 engineers) | 10% | 12-month horizon, not 36; do not over-pay for scale. |

Weights chosen to make cost + operational load dominant (40% combined). The
remaining criteria break ties. Cosmetic features (dashboards, ML add-ons)
intentionally left out — they bias toward incumbents and away from fit.

## Candidates

### Elastic Security (Elastic Cloud)
- Pros: Native Sigma support via the detection engine; hot/warm/cold
  tiers make HIPAA retention affordable; AWS, Kubernetes audit,
  Falco, and Cilium have first-party or community-maintained
  integrations; rule content library (Elastic prebuilt rules) is
  reasonable; managed Elastic Cloud removes most of the
  self-hosted operational burden.
- Cons: Detection Engine query language (ES|QL/EQL/KQL) is yet
  another DSL the on-call must learn; field mappings between
  CloudTrail, k8s audit, and Falco need ECS normalization work
  early; cost rises non-linearly above ~50 GB/day.
- Cost estimate: ~$3.5–4.5k/month for ~30 GB/day with 30-day hot,
  90-day warm, and a 1-year cold tier for audit-chain subset
  (~$50k/yr). One support seat adds ~$5k/yr. Confirm against
  current Elastic Cloud Standard pricing at the exact SKU/region
  SmartRecs uses before signing the contract; the figures here
  are order-of-magnitude only.
- Integration effort: 2–3 weeks for ingest + ECS normalization +
  initial Sigma rule conversion.

### Datadog Cloud SIEM
- Pros: Already deployed for observability; minimal new agent
  rollout; correlation across logs/metrics/traces is real; Sigma
  rule import is supported via Datadog detection rules; SOC 2
  evidence exports are clean.
- Cons: Datadog's pricing combines log ingestion with the SIEM
  SKU; at 30 GB/day with a year of retention the all-in cost is
  routinely above $80k. Custom retention (Flex Logs) helps but
  shifts query latency, which makes IR slower. Validate against
  current Datadog Cloud SIEM list pricing for the 30 GB/day +
  multi-year audit retention requirement before deciding; this
  conclusion is sensitive to recent pricing changes.
- Integration effort: ~1 week. Lowest of all candidates.

### Microsoft Sentinel
- Pros: Strongest default content library in the market; Sigma
  is well supported via Uncoder.io or the open-source Sentinel
  rule converters; Log Analytics retention is flexible; Logic
  Apps gives the eventual SOAR path without buying a second tool.
- Cons: Org has no Azure tenant. Standing one up just for Sentinel
  adds identity, billing, and network engineering cost. AWS
  CloudTrail and k8s audit ingestion is technically supported but
  the data-egress bill is real.
- Cost estimate: Sentinel ingest at 30 GB/day is competitive
  ($1.5–2.5k/month before commitment tiers), but the Azure
  surrounding cost (subscription, identity, egress) and the
  organizational cost of running a second cloud push this out of
  scope for a 6-person team. Pricing here uses current Sentinel
  pay-as-you-go list rates per GB ingested; reconfirm commitment
  tier pricing before any procurement decision.
- Integration effort: 4–6 weeks for first useful detections,
  accounting for cross-cloud ingestion plumbing.

### Wazuh (self-hosted on AWS)
- Pros: License-free; SmartRecs already runs Kubernetes, so
  hosting Wazuh manager + OpenSearch on k8s is mechanically
  feasible; Sigma is supported via the Wazuh ruleset translator
  or sidecar agents; community detection content is reasonable
  for endpoint and container telemetry.
- Cons: Operational ownership is non-trivial. OpenSearch clusters
  fail in non-obvious ways under ingest spikes; backups, index
  lifecycle, certificate rotation, and Wazuh manager upgrades
  fall on the security engineer. Realistic staffing cost: 0.5
  FTE of the only security engineer (~$60–80k loaded). That
  exceeds the SaaS license fee of every other candidate.
- Cost estimate: ~$10–15k/yr for AWS infrastructure (EC2 +
  EBS/S3 for cold storage) before factoring labor; ~$70–90k/yr
  total including the operational labor honestly accounted.
- Integration effort: 3–5 weeks for ingest + content; ongoing
  operational tax does not end.

### Splunk Cloud (reference only)
- Excluded on cost. Ingest-priced model places list pricing for
  ~30 GB/day above the $80k envelope before retention is added.
  Splunk's content library and operator quality are best-in-class
  but irrelevant when the budget is decided. Confirm against
  current Splunk Cloud Workload Pricing tiers; even in the
  workload-priced SKU, the floor generally exceeds this budget.

## Side-by-side

| Criterion (weight) | Elastic | Datadog | Sentinel | Wazuh |
|---|---|---|---|---|
| Cost (20%) | 4 | 2 | 3 | 5 (license) / 2 (loaded) |
| Operational load (20%) | 3 | 4 | 3 | 1 |
| Sigma / portable detections (10%) | 4 | 4 | 5 | 3 |
| AWS + k8s + Falco + Cilium fit (10%) | 4 | 5 | 3 | 4 |
| HIPAA/GDPR-compatible retention (10%) | 4 | 3 | 4 | 3 |
| Compliance evidence quality (10%) | 4 | 4 | 5 | 3 |
| Time-to-value (10%) | 3 | 5 | 2 | 2 |
| Future-proofing (10%) | 4 | 4 | 4 | 3 |
| **Weighted total** | **3.7** | **3.7** | **3.5** | **2.8 (loaded)** |

Elastic and Datadog tie on the raw weighted total. The tiebreak is
the cost ceiling: Datadog blows past $80k once HIPAA retention is
priced in. Elastic stays inside the envelope.

## Recommendation

Adopt **Elastic Security on Elastic Cloud** as SmartRecs' SIEM.
Keep Datadog for observability only; explicitly do not pay for the
Datadog Cloud SIEM SKU. The on-call already lives in Datadog for
service health, so security correlation across the two systems
remains possible by joining on tenant ID and request ID at
investigation time.

## Trade-offs accepted

1. The on-call learns ES|QL/KQL in addition to Datadog query
   syntax. This is the largest hidden cost in this decision.
2. Field normalization across CloudTrail, k8s audit, Falco, and
   Cilium is real engineering work in week 1–3 and cannot be
   skipped. We accept it because it pays back every detection
   afterwards.
3. We give up some default content quality versus Sentinel. We
   compensate by porting Sigma rules from public repos and
   maintaining the SmartRecs-specific ruleset from Exercise 02.
4. We give up the convenience of a single product for
   observability and security. We accept it because the cost
   ceiling is binding.

## Migration plan (high-level)

- **Week 1**: Provision Elastic Cloud in the same AWS region as
  the primary EKS cluster; stand up Logstash on EKS for
  CloudTrail, k8s audit, and Falco; agree ECS field mapping.
- **Week 2**: Land CloudTrail + k8s audit + Cilium Hubble flow
  logs. Verify retention tiers (hot 30d, warm 90d, cold 1yr for
  the SOC 2 audit subset).
- **Week 3**: Convert the Exercise 02 Sigma ruleset into Elastic
  Detection Engine rules; configure alert routing to PagerDuty
  for high/critical and Slack for medium.
- **Week 4**: Run the first tabletop (Exercise 04 Scenario A)
  end-to-end against the live SIEM; collect SOC 2 evidence
  exports.
- **Weeks 5–8**: Tune the noisiest rules; backfill Hubble +
  application audit; capture SOC 2 evidence for SI-4 and AU
  controls.
- **Quarterly thereafter**: Re-cost the deployment; rotate
  tabletop scenarios; revisit the decision against the
  re-evaluation triggers below.

We deliberately do not promise "deploy in week 1." A SIEM that is
live but unmonitored is worse than no SIEM at all for SOC 2
evidence — auditors will treat empty queries as a control failure.

## Re-evaluation triggers

Re-evaluate the SIEM choice if any of the following becomes true:

- Daily ingest sustains above 100 GB/day for a quarter.
- Headcount crosses 50 engineers (operational load on a single
  security engineer is no longer the dominant constraint).
- A second cloud (Azure or GCP) becomes primary, not auxiliary.
- Elastic Cloud annual run-rate crosses $90k for two consecutive
  quarters.
- A regulatory regime (FedRAMP Moderate, EU AI Act high-risk
  classification) adds a constraint that the current deployment
  cannot satisfy with reasonable effort.
- The team consistently fails to meet MTTD goals because the
  query language is the bottleneck — this is a usability signal
  worth respecting.
```

---

## 3. Validation steps

To check a learner's submission against this reference:

1. Confirm the document picks **one** SIEM and names it in the
   TL;DR. A submission that says "it depends" without committing
   fails the rubric.
2. Verify the criteria table has weights that sum to 100% and
   that cost + operational load together exceed 30% of total
   weight. Anything less means the budget constraint is not being
   taken seriously.
3. Spot-check at least one rejected candidate: there must be a
   concrete reason (budget number, missing integration, staffing
   model) and not a feature comparison.
4. Confirm the migration plan does not declare the SIEM "live"
   before week 3 at the earliest. SOC 2 auditors require evidence
   of *operating* controls, not just deployed ones.
5. Confirm the re-evaluation triggers are *measurable* (numbers,
   not vibes).

## 4. Rubric or review checklist

| Aspect | Strong (3) | Adequate (2) | Weak (1) |
|---|---|---|---|
| Picks one SIEM | One product, named, defended | Names a product, weak defense | Hedged ("either is fine") |
| Cost realism | All-in cost calculated, inside budget | List price only, no labor | "Free / it depends" |
| Operational load argument | 0.5 FTE staffing math shown | Mentions labor, no number | Ignores labor |
| Sigma / detection portability | Names the conversion path | Mentions Sigma | Omits |
| AWS + k8s + Falco + Cilium fit | Each source mapped to an integration | Vague "supports AWS" | No integration analysis |
| Regulatory retention | HIPAA + GDPR addressed with retention tiers | One regime addressed | Not addressed |
| SOC 2 evidence quality | Names the auditor artifact (export, immutable storage) | Mentions auditors | No SOC 2 mention |
| Migration realism | Phased, ≥3 weeks to first useful detections | Vague schedule | "Week 1: deploy" |
| Re-evaluation triggers | Measurable thresholds | Generic ("if things change") | Missing |

Passing threshold: ≥18/27 with no individual axis scored 1 on
"picks one SIEM" or "cost realism".

## 5. Common mistakes

- **"Splunk because it's best."** True on features, false on
  budget. The exercise penalizes ignoring the constraint.
- **"Wazuh because it's free."** Confuses license cost with total
  cost. Operational labor is the binding constraint for a six-
  engineer team.
- **"Datadog because we already have it."** A reasonable starting
  point but it must be costed against the SOC 2 retention
  requirement, not just convenience.
- **No weights on the criteria.** Without weights, the comparison
  table is pros/cons in a costume. Weights make trade-offs
  explicit.
- **Migration that declares "live in week 1."** Production SIEM
  deployments take weeks for ingest plus content plus tuning.
  Auditors will not credit an SIEM with no queries running.
- **Missing the existing Datadog implication.** Either commit to
  Datadog *or* explicitly address why a second tool is acceptable.
  Silence on this question fails the "defend against the obvious
  alternative" criterion.
- **No re-evaluation triggers.** A SIEM choice that cannot be
  unwound is a procurement disaster waiting for its 18-month
  anniversary.

## 6. References

- NIST AI Risk Management Framework (AI RMF 1.0) — particularly
  the GOVERN and MANAGE functions on organizational capacity and
  incident response context.[^nist-ai-rmf]
- MITRE ATLAS — for the ML-specific threat tactics SmartRecs is
  buying the SIEM to detect.[^atlas]
- OWASP Machine Learning Security Top 10 — for the categories of
  ML-specific risk the SIEM detections in Exercise 02 must
  cover.[^owasp-ml]
- Sigma project — the portable detection rule format that anchors
  the "do not buy SIEM lock-in" argument. (Sigma is open-source;
  the recommendation is conditional on the chosen SIEM supporting
  Sigma conversion either natively or through Uncoder.io / sigma-
  cli tooling.)

[^nist-ai-rmf]: NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>
[^atlas]: MITRE ATLAS — <https://atlas.mitre.org/>
[^owasp-ml]: OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>
