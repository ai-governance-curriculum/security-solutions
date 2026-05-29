# Exercise 02 — ML-Specific Detection Ruleset (Reference Solution)

> Read after attempting [`exercise-02-ml-detection-ruleset.md`](../../../../ai-infra-security-learning/lessons/mod-011-security-operations/exercises/exercise-02-ml-detection-ruleset.md).
> This reference ships 11 Sigma rules, mapped to MITRE ATLAS and
> ATT&CK, plus the coverage analysis, integration notes, and
> tuning plan the rubric requires.

## 1. Solution overview

The ruleset's job is to catch the *ML-specific* attacker behaviors
described by MITRE ATLAS[^atlas] and OWASP Machine Learning
Security Top 10[^owasp-ml] — not generic infrastructure
detections, which belong elsewhere in the security program. A good
ruleset:

- Anchors every detection to an attacker tactic (ATLAS or ATT&CK).
- Uses signals SmartRecs can actually emit (audit-chain events,
  Falco events, k8s audit, Cilium Hubble flows, inference gateway
  metrics).
- Names false-positive scenarios *honestly* — every rule will
  produce them.
- Provides a tuning lever per rule so the on-call has a path to
  reduce noise without disabling the detection entirely.

The reference here is written in Sigma's experimental status by
design: rules in this domain need 30–60 days of baseline data
before they should be promoted to `stable`.

## 2. Implementation (worked answer)

### Rule index

| ID | Title | Severity | ATLAS / ATT&CK |
|---|---|---|---|
| ML-DET-001 | Per-tenant query rate spike (extraction probe) | high | atlas.t0024.002, attack.t1213 |
| ML-DET-002 | Per-tenant LLM cost spike | high | atlas.t0034 |
| ML-DET-003 | Direct prompt-injection pattern at gateway | high | atlas.t0051.000 |
| ML-DET-004 | Indirect prompt-injection signal in RAG context | high | atlas.t0051.001 |
| ML-DET-005 | Unauthorized write to model artifact directory | critical | atlas.t0020, attack.t1565.001 |
| ML-DET-006 | Membership-inference probe pattern | medium | atlas.t0024.000 |
| ML-DET-007 | Training-data distribution shift on retraining | medium | atlas.t0020 |
| ML-DET-008 | Per-model accuracy regression in production | high | atlas.t0031 |
| ML-DET-009 | Per-tenant cross-tenant feature-access anomaly | high | attack.t1078, atlas.t0035 |
| ML-DET-010 | Notebook egress to non-allowlisted destination | high | attack.t1041 |
| ML-DET-011 | Cosign signature verification failure at admission | critical | attack.t1195.002 |

Before merging into production, confirm each AML.T#### technique
ID against the current ATLAS technique list at
<https://atlas.mitre.org/techniques/>. ATLAS reorganizes
sub-techniques periodically; the IDs above reflect the snapshot
as of the curriculum source date and should be re-checked.

### Detections

#### ML-DET-001 — Per-tenant query rate spike (extraction probe)

```yaml
title: Per-tenant query rate spike (possible extraction probe)
id: 5c1b1c0e-2f3a-4e9d-9b6a-1b3d7c4e0a01
status: experimental
description: |
  Per-tenant inference-gateway query rate exceeds 5x the rolling
  14-day P95 baseline for that tenant over a 10-minute window.
  Catches the staging phase of a model-extraction attack as
  described in MITRE ATLAS technique "Extract ML Model".
references:
  - https://atlas.mitre.org/techniques/AML.T0024
  - https://owasp.org/www-project-machine-learning-security-top-10/
author: smartrecs-soc
date: 2026-05-29
logsource:
  product: smartrecs
  service: ml-gateway
detection:
  selection:
    event.kind: 'inference_request_aggregate_10m'
    tenant.id|exists: true
    request.rate_per_minute_10m|gte: '{{ tenant_p95_baseline * 5 }}'
    request.count_10m|gte: 500
  filter_allowlist:
    tenant.tag|contains: 'planned_batch'
  condition: selection and not filter_allowlist
falsepositives:
  - Tenant ran a planned batch operation (annotated by the
    customer-success team via the tenant_tag field).
  - Tenant launched a new product feature that drove organic
    traffic (announced in #product-launches).
  - Synthetic load test from the platform team.
level: high
tags:
  - atlas.t0024.002
  - attack.t1213
```

- **False-positive scenarios**: planned tenant batches, product
  launches, platform load tests, customer-side cache invalidation.
- **Triage steps**:
  1. Pull the tenant's 24-hour query timeline from the inference
     gateway logs; confirm the spike persists or normalized.
  2. Diff the input distribution: cosine-similarity entropy of
     recent prompts. Extraction probes typically maximize input
     diversity to cover the decision boundary.
  3. Cross-check `tenant_tag` for `planned_batch` or
     `load_test` annotations.
  4. Contact the customer-success owner for the tenant; ask
     whether a planned activity is underway.
  5. If unexplained: apply a temporary per-tenant rate cap (see
     playbook 1 in Exercise 03) and open a SEV3 incident.
- **Tuning levers**: per-tenant baseline window length (default
  14 days; raise to 30 for tenants with bursty workloads);
  multiplier (5x → 7x for noisy tenants); add `tenant.tier`
  weighting (free-tier tenants warrant lower threshold).

#### ML-DET-002 — Per-tenant LLM cost spike

```yaml
title: Per-tenant LLM cost spike (possible cost-amplification attack)
id: 5c1b1c0e-2f3a-4e9d-9b6a-1b3d7c4e0a02
status: experimental
description: |
  Per-tenant inference cost (token spend) over a rolling hour
  exceeds 8x the prior 14-day P95 baseline. Catches cost-
  amplification attacks where an adversary spams expensive
  prompts to inflict financial damage on the platform.
references:
  - https://atlas.mitre.org/techniques/AML.T0034
author: smartrecs-soc
date: 2026-05-29
logsource:
  product: smartrecs
  service: llm-gateway
detection:
  selection:
    event.kind: 'llm_cost_aggregate_1h'
    tenant.id|exists: true
    cost.usd_1h|gte: '{{ tenant_p95_baseline_usd * 8 }}'
    cost.usd_1h|gte: 25
  condition: selection
falsepositives:
  - Tenant migrated to a more expensive model variant (model.id
    differs from baseline).
  - Tenant turned on a new feature that uses long-context prompts.
level: high
tags:
  - atlas.t0034
```

- **FP scenarios**: model upgrades, new long-context features,
  bug in client SDK that retries failed requests aggressively.
- **Triage steps**:
  1. Pull the tenant's token-spend breakdown by model and by
     prompt template.
  2. Identify whether one template dominates the spike — most
     legitimate spikes are even across templates.
  3. Inspect request prompts for adversarial input markers
     (repeating tokens, very long prefixes, prompt-injection
     strings).
  4. Throttle the tenant via the LLM gateway's hard cap.
  5. Open a SEV3 if intent is unclear; SEV2 if abuse is
     confirmed.
- **Tuning levers**: multiplier (8x baseline), absolute floor
  ($25/hr) to suppress alerts on tiny tenants, per-template
  cost ceilings.

#### ML-DET-003 — Direct prompt-injection pattern at gateway

```yaml
title: Direct prompt-injection pattern at LLM gateway
id: 5c1b1c0e-2f3a-4e9d-9b6a-1b3d7c4e0a03
status: experimental
description: |
  User-supplied input to the LLM gateway matches a curated
  pattern set of direct prompt-injection markers (e.g.
  'ignore previous instructions', system-prompt impersonation,
  role-override strings). Companion to OWASP ML08:2023.
references:
  - https://atlas.mitre.org/techniques/AML.T0051.000
  - https://owasp.org/www-project-machine-learning-security-top-10/
author: smartrecs-soc
date: 2026-05-29
logsource:
  product: smartrecs
  service: llm-gateway
detection:
  selection_keywords:
    request.user_input|re|i: '(?:ignore (?:all )?(?:previous|prior) instructions|disregard (?:all )?(?:above|prior) (?:instructions|context)|you are now [^,.]{0,40}(?:admin|root|developer|jailbroken)|system: .{0,200}override)'
  selection_roles:
    request.user_input|contains|i:
      - 'assistant:'
      - 'system:'
      - '### system'
  condition: selection_keywords or selection_roles
falsepositives:
  - Customers writing prompts about prompt engineering or
    security (educational content).
  - Customer-support replies that include quoted system messages.
level: high
tags:
  - atlas.t0051.000
```

- **FP scenarios**: meta-content (customer is themselves an LLM
  developer), support transcripts.
- **Triage steps**:
  1. Inspect the surrounding request context — was the injection
     repeated, or a single match in a long input?
  2. Pull the LLM response and the post-response action chain.
     Did the model take an action it should not have?
  3. Check the same tenant for additional matches in the prior
     24h.
  4. If response or action was harmful: escalate to playbook 3
     in Exercise 03 (confirmed prompt-injection harm).
  5. If clean: leave the alert closed-no-action and add the
     prompt to the FP corpus for tuning.
- **Tuning levers**: pattern set ownership (refreshed monthly
  from the published prompt-injection corpus); per-tenant
  allowlist for verified meta-content users.

#### ML-DET-004 — Indirect prompt-injection signal in RAG context

```yaml
title: Indirect prompt-injection signal in retrieved RAG context
id: 5c1b1c0e-2f3a-4e9d-9b6a-1b3d7c4e0a04
status: experimental
description: |
  Retrieved RAG chunk delivered to the LLM contains a high-
  entropy block that matches indirect-injection markers (zero-
  width characters, unusual unicode classes, or hidden HTML/
  markdown directives instructing the model). Catches the
  indirect prompt-injection class described by MITRE ATLAS
  AML.T0051.001 and OWASP ML08.
references:
  - https://atlas.mitre.org/techniques/AML.T0051.001
author: smartrecs-soc
date: 2026-05-29
logsource:
  product: smartrecs
  service: rag-orchestrator
detection:
  selection_hidden_chars:
    chunk.text|re: '[​-‏ - ﻿]{3,}'
  selection_markers:
    chunk.text|re|i: '(?:</?(?:script|style)|<!--[\s\S]{0,200}-->|new instructions:|priority override:)'
  selection_entropy:
    chunk.text_shannon_entropy|gte: 5.5
    chunk.text_length|gte: 200
  condition: selection_hidden_chars or selection_markers or selection_entropy
falsepositives:
  - Legitimate documents containing code samples or markup.
  - Encrypted or base64-encoded payloads in technical
    documentation.
level: high
tags:
  - atlas.t0051.001
```

- **FP scenarios**: technical documentation with code blocks,
  base64 attachments, multilingual content with mixed scripts.
- **Triage steps**:
  1. Identify the source document for the flagged chunk.
  2. Check whether the source is tenant-owned (uploaded recently)
     or from a shared corpus.
  3. Inspect the chunk for hidden text outside the visible
     rendering.
  4. Quarantine the source document; rerun the affected
     conversation through the LLM without the chunk to compare
     outputs.
  5. If exploitation confirmed: invoke playbook 3.
- **Tuning levers**: entropy floor (5.5 → 6.0 for codebase-heavy
  corpora); per-corpus allowlists; downgrade to medium for
  technical-content tenants once baseline is understood.

#### ML-DET-005 — Unauthorized write to model artifact directory

```yaml
title: Unauthorized write to model artifact directory
id: 5c1b1c0e-2f3a-4e9d-9b6a-1b3d7c4e0a05
status: experimental
description: |
  Falco rule fires when a process not in the
  approved-publisher list writes to a model-artifact path
  (/var/lib/models, s3://smartrecs-models). Possible model-
  poisoning or supply-chain attack.
references:
  - https://atlas.mitre.org/techniques/AML.T0020
author: smartrecs-soc
date: 2026-05-29
logsource:
  product: falco
  category: file_integrity
detection:
  selection:
    rule: 'Write below model artifact dir'
    proc.name|not:
      - 'mlflow-publisher'
      - 'model-promotion-controller'
      - 'cosign'
  condition: selection
falsepositives:
  - New publisher binary added without updating the Falco
    allowlist (process hygiene problem).
  - Manual hotfix during incident response (should be logged as
    such in the audit chain).
level: critical
tags:
  - atlas.t0020
  - attack.t1565.001
```

- **FP scenarios**: forgotten allowlist updates after a CI
  refactor, IR-time manual writes.
- **Triage steps**:
  1. Identify the pod, image digest, and service account that
     performed the write.
  2. Verify the cosign signature on the resulting artifact; if
     unsigned, freeze the artifact in s3 with object-lock.
  3. Compare the writing identity to the audit-chain record of
     who triggered the write.
  4. Roll the model serving deployment back to the prior known-
     good digest if the artifact reached production.
  5. Open a SEV2 (or SEV1 if the artifact is already serving).
- **Tuning levers**: maintain the publisher allowlist in source
  control; auto-PR generation when a new publisher is added in
  CI.

#### ML-DET-006 — Membership-inference probe pattern

```yaml
title: Membership-inference probe pattern
id: 5c1b1c0e-2f3a-4e9d-9b6a-1b3d7c4e0a06
status: experimental
description: |
  Tenant submits queries against narrow record neighborhoods
  with confidence-score harvesting behavior — many queries that
  request top-k probabilities or include `return_logits=true` on
  records matching personally identifying patterns. Possible
  membership-inference attack against training data.
references:
  - https://atlas.mitre.org/techniques/AML.T0024
author: smartrecs-soc
date: 2026-05-29
logsource:
  product: smartrecs
  service: inference-gateway
detection:
  selection:
    request.return_confidences: true
    request.confidence_request_count_24h|gte: 200
    request.target_neighborhood_size|lte: 50
  condition: selection
falsepositives:
  - Research tenant performing model evaluation.
  - Tenant evaluating recommendation quality before rolling out
    to end users.
level: medium
tags:
  - atlas.t0024.000
```

- **FP scenarios**: documented evaluation workflows, internal
  staging tenants.
- **Triage steps**:
  1. Identify the tenant and confirm whether evaluation mode is
     declared.
  2. Inspect the target records — do they reference real customer
     identifiers or anonymized sample data?
  3. Disable `return_confidences` for the tenant if not justified.
  4. Engage privacy lead if real customer records are involved.
  5. Open a SEV3.
- **Tuning levers**: per-tenant `eval_mode` flag exempts the
  detection; neighborhood size threshold tightens as legitimate
  evaluation workflows are characterized.

#### ML-DET-007 — Training-data distribution shift on retraining

```yaml
title: Training-data distribution shift on retraining
id: 5c1b1c0e-2f3a-4e9d-9b6a-1b3d7c4e0a07
status: experimental
description: |
  Population-Stability-Index (PSI) between the current training
  batch and the prior batch crosses 0.25 on any monitored
  feature, or label distribution shifts more than 5 percentage
  points. Input to the poisoning-detection workflow.
references:
  - https://atlas.mitre.org/techniques/AML.T0020
  - https://owasp.org/www-project-machine-learning-security-top-10/
author: smartrecs-soc
date: 2026-05-29
logsource:
  product: smartrecs
  service: training-pipeline
detection:
  selection:
    event.kind: 'training_batch_drift_report'
    drift.psi_max|gte: 0.25
  selection_label:
    drift.label_shift_pp|gte: 5
  condition: selection or selection_label
falsepositives:
  - Intentional data refresh (new geography, new product
    category).
  - Seasonal effects (holiday traffic).
level: medium
tags:
  - atlas.t0020
```

- **FP scenarios**: planned dataset expansions; documented
  seasonal drift.
- **Triage steps**:
  1. Pull the PSI per feature; identify the top three drifted
     features.
  2. Compare against the change log of the data sources — was a
     new source added?
  3. Sample 100 rows from the new batch and inspect for adversary
     markers (label-flipping, target injection).
  4. Pause the retraining pipeline pending review.
  5. Open a SEV3; escalate to playbook 2 in Exercise 03 if
     poisoning is suspected.
- **Tuning levers**: per-feature thresholds (recommendation
  scores need wider tolerance than identity features); a
  documented "expected drift event" registry suppresses planned
  drifts.

#### ML-DET-008 — Per-model accuracy regression in production

```yaml
title: Per-model production accuracy regression
id: 5c1b1c0e-2f3a-4e9d-9b6a-1b3d7c4e0a08
status: experimental
description: |
  Production-served model's online accuracy (or proxy: human-
  reviewed acceptance rate, click-through, conversion) drops
  more than 3 standard deviations from the 30-day rolling mean
  for a sustained 6-hour window. Possible poisoning,
  distribution drift, or upstream data pipeline failure.
references:
  - https://atlas.mitre.org/techniques/AML.T0031
author: smartrecs-soc
date: 2026-05-29
logsource:
  product: smartrecs
  service: model-monitoring
detection:
  selection:
    event.kind: 'model_quality_6h_window'
    quality.delta_sigma|lte: -3.0
    quality.sample_count|gte: 1000
  condition: selection
falsepositives:
  - Upstream data pipeline outage (feature store missing values).
  - Successful product A/B test that intentionally degraded a
    control arm.
level: high
tags:
  - atlas.t0031
```

- **FP scenarios**: feature-store outages, controlled
  experiments, planned model rollbacks.
- **Triage steps**:
  1. Check the feature-store health dashboard. Many regressions
     are upstream pipeline failures.
  2. Pull the experiment registry — is an A/B test active?
  3. Compare the regressed model digest to the last known-good
     digest in the model registry.
  4. Roll back to the prior digest if the regression persists
     after upstream is ruled out.
  5. Open a SEV2; escalate to playbook 2 if poisoning is
     suspected.
- **Tuning levers**: sample-size floor (rejects tiny samples);
  experiment registry integration to suppress known A/B tests.

#### ML-DET-009 — Per-tenant cross-tenant feature-access anomaly

```yaml
title: Per-tenant feature-access pattern anomaly (multi-tenant probe)
id: 5c1b1c0e-2f3a-4e9d-9b6a-1b3d7c4e0a09
status: experimental
description: |
  Inference request requests a feature-store key whose tenant
  prefix does not match the calling tenant's identity. Or the
  request pattern shows enumeration of another tenant's key
  space (sequential ID scan).
references: []
author: smartrecs-soc
date: 2026-05-29
logsource:
  product: smartrecs
  service: feature-store-gateway
detection:
  selection_cross:
    request.tenant_id|exists: true
    feature_key.tenant_prefix|notequal: '{{ request.tenant_id }}'
  selection_enum:
    request.feature_key|re: '^tenant-[0-9a-f]{8}/.*'
    request.distinct_tenant_prefixes_5m|gte: 5
  condition: selection_cross or selection_enum
falsepositives:
  - Shared-model evaluation jobs that pull features across
    tenants by design (named service accounts).
  - Platform admin scripts performing audits.
level: high
tags:
  - attack.t1078
  - atlas.t0035
```

- **FP scenarios**: documented shared evaluation jobs; admin
  audit scripts.
- **Triage steps**:
  1. Confirm the calling identity (service account) and tenant.
  2. Pull the keys requested in the prior 1 hour; correlate with
     audit-chain to identify the originating user.
  3. Engage the customer-success owner for any *other* tenants
     whose data was accessed.
  4. Rotate the tenant's API keys; freeze the service account
     if compromise is suspected.
  5. SEV1 if cross-tenant data exfiltration is confirmed;
     escalate to playbook 4.
- **Tuning levers**: explicit allowlist of platform service
  accounts authorized for cross-tenant access; enumeration
  threshold widened or tightened as baseline matures.

#### ML-DET-010 — Notebook egress to non-allowlisted destination

```yaml
title: Notebook egress to non-allowlisted destination
id: 5c1b1c0e-2f3a-4e9d-9b6a-1b3d7c4e0a10
status: experimental
description: |
  Cilium Hubble flow log shows a connection from a notebook pod
  to a destination not in the data-science allowlist (Hugging
  Face, PyPI mirror, internal artifact store, etc.). Catches
  notebook abuse and data exfiltration from experimentation
  environments.
references: []
author: smartrecs-soc
date: 2026-05-29
logsource:
  product: cilium
  service: hubble-flow
detection:
  selection:
    source.namespace: 'notebooks'
    flow.direction: 'egress'
    destination.fqdn|notexists_in: 'notebook_egress_allowlist'
    flow.bytes_sent|gte: 1048576
  condition: selection
falsepositives:
  - Newly approved data source not yet added to the allowlist.
  - Researcher fetching a public dataset (should be allowlisted).
level: high
tags:
  - attack.t1041
```

- **FP scenarios**: pending allowlist entries; legitimate
  public-dataset fetches.
- **Triage steps**:
  1. Identify the notebook owner from the pod labels.
  2. Inspect the connection: protocol, destination, byte
     volume, repeating pattern.
  3. Quarantine the notebook namespace (NetworkPolicy default-
     deny) while investigating.
  4. Contact the notebook owner for context; treat silence as
     an escalation signal.
  5. SEV3 unless byte volume is large or sensitive data is in
     the namespace.
- **Tuning levers**: allowlist source-of-truth in git; per-
  research-team allowlists; minimum byte threshold (1 MB) to
  suppress DNS-only noise.

#### ML-DET-011 — Cosign signature verification failure at admission

```yaml
title: Cosign signature verification failure at admission
id: 5c1b1c0e-2f3a-4e9d-9b6a-1b3d7c4e0a11
status: experimental
description: |
  Kubernetes admission controller logged a cosign verification
  failure for a model-serving image. Either a misconfigured
  image (unsigned promotion) or an attempted unsigned-artifact
  promotion.
references: []
author: smartrecs-soc
date: 2026-05-29
logsource:
  product: kubernetes
  service: admission-controller
detection:
  selection:
    event.kind: 'admission_denied'
    denial.reason|contains: 'cosign signature'
    request.namespace|in:
      - 'serving'
      - 'training'
  condition: selection
falsepositives:
  - Misconfigured signing pipeline (process gap, not attack).
  - Manual deployment by an engineer who bypassed CI.
level: critical
tags:
  - attack.t1195.002
```

- **FP scenarios**: signing pipeline misconfigurations, manual
  deployments outside CI.
- **Triage steps**:
  1. Identify the image digest and the namespace.
  2. Cross-reference with the recent CI build log; is the
     image traceable?
  3. Check Rekor for any matching entry; absence is a strong
     signal of unauthorized promotion.
  4. Engage the engineer who attempted the deployment (if a
     person triggered it).
  5. SEV2 by default; SEV1 if the image was successfully
     loaded into a serving pod.
- **Tuning levers**: maintain an exception window for staging
  namespaces; investigate every production-namespace event.

### Coverage analysis

Coverage mapped against MITRE ATLAS tactics:[^atlas]

| ATLAS tactic | Rules |
|---|---|
| Reconnaissance | ML-DET-001 partial (probe behavior is reconnaissance + staging) |
| Resource Development | (gap — see below) |
| Initial Access | ML-DET-003 partial; ML-DET-011 partial |
| ML Model Access | ML-DET-001, ML-DET-006, ML-DET-009 |
| Execution | ML-DET-005 partial |
| Persistence | (gap) |
| Privilege Escalation | (gap) |
| Defense Evasion | ML-DET-011 partial |
| Credential Access | (gap) |
| Discovery | ML-DET-006, ML-DET-009 (enumeration) |
| Collection | ML-DET-009, ML-DET-010 |
| ML Attack Staging | ML-DET-001, ML-DET-003, ML-DET-004 |
| Exfiltration | ML-DET-010, ML-DET-009 |
| Impact | ML-DET-002 (cost), ML-DET-005 (integrity), ML-DET-008 (model quality), ML-DET-007 (poisoning input) |

### Coverage gaps

Named honestly, because the rubric requires it:

1. **Resource Development** (adversary developing capabilities,
   acquiring infrastructure) — no detection because the signals
   live outside SmartRecs' environment.
2. **Persistence** in compromised serving pods — relies on the
   container-escape detection living in Module 08, not in this
   ruleset.
3. **Credential Access** — covered by the general infrastructure
   security program (CloudTrail anomaly detections), not the
   ML-specific ruleset.
4. **LLM Plugin / Tool Abuse** (AML.T0053-like) — SmartRecs does
   not yet expose tool-use; add a detection when the product
   ships LLM tool calls.
5. **Training-pod data exfiltration** (distinct from notebook
   egress) — currently relies on the same Hubble flow logs but
   the namespace is different; ML-DET-010 should be cloned for
   `training` namespace once we baseline its egress patterns.

### Integration with the SIEM

Assuming Elastic Security per Exercise 01:

- All rules deploy as Elastic Detection Engine rules via the
  Sigma → Elastic converter; deviations from canonical Sigma
  (the `{{ tenant_p95_baseline * 5 }}` expression in ML-DET-001
  and ML-DET-002) implement as Elastic ES|QL aggregations
  referencing a baseline transform.
- High/critical alerts route to PagerDuty (Slack mirror in
  `#sec-alerts`); medium routes to Slack only.
- The audit-chain integration: every alert opens an incident
  ticket whose ID is appended to the audit chain so future
  investigators can pivot from an alert to the immutable record.

### Tuning plan

| Rule | Expected baseline volume | Monthly review trigger |
|---|---|---|
| ML-DET-001 | 1–3 fires/week after tuning | >10/week → raise multiplier |
| ML-DET-002 | 1–5 fires/week | >2 confirmed FPs from one tenant → add allowlist |
| ML-DET-003 | 5–15 fires/week | >50% known meta-content → tighten regex |
| ML-DET-004 | 0–2 fires/week | rising trend → audit corpus uploads |
| ML-DET-005 | <1/quarter | any fire warrants a fresh control review |
| ML-DET-006 | 0–1/week | >5/week → check eval_mode coverage |
| ML-DET-007 | 1–4/quarter | every fire → confirm whether drift was planned |
| ML-DET-008 | 0–2/quarter | any fire → check upstream pipeline first |
| ML-DET-009 | <1/month | any fire is SEV1-eligible |
| ML-DET-010 | 5–20/week initially, dropping as allowlist matures | >40/week → expand allowlist |
| ML-DET-011 | 1–3/quarter | every fire → review CI signing pipeline |

Each rule is reviewed monthly by the on-call security engineer;
the FP corpus seeds the next month's tuning. A rule that has not
fired in 6 months is reviewed for retirement — silent rules give
false confidence.

## 3. Validation steps

To validate a learner's submission against this reference:

1. Confirm at least 10 Sigma rules are present and each has
   `title`, `id`, `status`, `description`, `detection`,
   `falsepositives`, `tags`, `level`.
2. Confirm each rule has *at least one* ATLAS or ATT&CK tag and
   the tag references a real technique. (Bad smell: tags like
   `atlas.unknown` or fictitious IDs.)
3. Confirm each rule has triage steps that name commands,
   queries, or specific actions — not "investigate the alert".
4. Confirm the coverage analysis identifies at least two gaps.
   A submission that claims complete coverage is failing.
5. Confirm the tuning plan associates each rule with a review
   cadence or volume threshold.
6. Run the Sigma files through `sigma-cli` (or equivalent) to
   verify syntax. The reference rules above pass canonical
   syntax, with the exception of the `{{ baseline }}` template
   substitutions which require either a transform or per-rule
   parameterization in the chosen SIEM.

## 4. Rubric or review checklist

| Aspect | Strong (3) | Adequate (2) | Weak (1) |
|---|---|---|---|
| Count | ≥10 rules, distinct attacker behaviors | 10 rules, some overlap | <10 |
| Sigma correctness | Parses cleanly, complete fields | Parses, missing fields | Pseudo-YAML |
| ATLAS / ATT&CK mapping | Real technique IDs, justified | One IDs, generic | Missing or fabricated |
| False-positive scenarios | Realistic, ≥2 per rule | Generic, ≥1 per rule | Missing |
| Triage steps | 3–5 specific actions, names tools | Generic IR steps | "Investigate" |
| Tuning levers | Per-rule lever named | Some rules have levers | None |
| Coverage analysis | Honest gaps named | Claims partial coverage | "All covered" |
| Tuning plan | Per-rule cadence + threshold | Generic cadence | None |
| Integration with SIEM | Names routing + alert tiers | Mentions SIEM | None |

Passing threshold: ≥18/27; no axis scored 1 on count, ATLAS
mapping, or triage steps.

## 5. Common mistakes

- **Generic detections.** "Failed login spike" is not an ML
  detection. Anchor every rule to an ML-specific tactic.
- **Pseudo-YAML.** Rules that look like Sigma but don't parse
  fail the rubric. Run them through `sigma-cli` or equivalent
  before submitting.
- **Fabricated technique IDs.** Pick real ATLAS / ATT&CK
  techniques. If unsure, mark with a `TBD` comment and a link
  to the ATLAS index rather than invent.
- **"Investigate the alert" triage.** Specific commands or
  queries are the bar.
- **Glossed-over coverage gaps.** Claim no gaps and you fail
  the honesty test. Every ruleset has gaps; name them.
- **No tuning plan.** Rules degrade. A ruleset without a
  retirement and review schedule will become noise within a
  year.
- **Cost detections priced in tokens but never in dollars.** The
  whole point of cost-amplification detection is dollar impact;
  show the dollar floor.

## 6. References

- MITRE ATLAS — Adversarial Threat Landscape for AI Systems
  (tactics + techniques used for the rule tags).[^atlas]
- OWASP Machine Learning Security Top 10 — particularly ML02
  (Data Poisoning), ML05 (Model Theft), ML06 (Model Inversion),
  ML08 (Prompt Injection).[^owasp-ml]
- NIST AI RMF 1.0 — MEASURE-2 sub-functions on monitoring AI
  system performance and security.[^nist-ai-rmf]
- Sigma project — rule format specification.

[^atlas]: MITRE ATLAS — <https://atlas.mitre.org/>
[^owasp-ml]: OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>
[^nist-ai-rmf]: NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>
