# SOLUTION — Capstone Exercise 03: ML-Specific Controls

> Read this *after* attempting the exercise. The goal here is not to
> re-enumerate generic infrastructure controls (those belong in
> Exercise 02) but to specify the controls that exist *because the
> system processes machine learning*.

## 1. Solution overview

The exercise asks for a complete set of ML-specific controls, mapped
to recognised ML threats, with each control described concretely
enough that a platform engineer could implement it. A passing answer
must:

- Use the OWASP Machine Learning Security Top 10 as the spanning
  index of risks — every item is either addressed or explicitly
  marked out of scope with a reason.
- Use MITRE ATLAS technique IDs to give precise threat-to-control
  traceability where ATLAS covers the threat.
- For each control, state: where it sits in the lifecycle
  (data / training / registry / serving / monitoring), what it
  detects or prevents, how to know it is working, and what its
  failure mode is.
- Distinguish between *preventive* controls (stop the threat) and
  *detective* controls (notice the threat happened) for every risk;
  ML risks need both.

A common failure on this exercise is to write a glossary of
techniques ("adversarial training", "input sanitization", "differential
privacy") with no statement of *when* or *why* each is applied.

## 2. Implementation

### 2.1 OWASP ML Top 10 → controls cross-walk

For each item, the table names the in-scope risks, a representative
ATLAS technique, the preventive control, the detective control, and
a residual-risk note.

| OWASP ML | Threat in scope (capstone system) | ATLAS | Preventive control | Detective control | Residual |
|----------|-----------------------------------|-------|--------------------|-------------------|----------|
| ML01 Input Manipulation (Adversarial) | Crafted inputs evade fraud-scoring classifier. | AML.T0015 | Input validation against domain constraints; adversarial-training of the production model; ensembling with a second model that uses disjoint features. | Score-distribution monitor: alert when daily fraction of low-confidence-but-approved cases exceeds historical baseline by N sigma. | Model still has bounded robustness — accepted, monitored. |
| ML02 Data Poisoning | Upstream-injected events corrupt feature distributions during training. | AML.T0020 | Schema-validated, signed event ingestion; per-source quotas; statistical sanity checks before features are committed. | Training-time outlier detection on per-source feature distributions; drift alert vs. last green training run. | Slow-moving poisoning (within tolerance) — mitigated by drift review at retrain. |
| ML03 Model Inversion | Inference response leakage reveals training data. | AML.T0048 | Suppress raw confidence vectors externally; differentially-private training where the dataset is sensitive; tightly-bounded per-query information output. | Per-key query-pattern detection: alert on systematic probing of single-class boundaries. | Bounded by epsilon budget — recorded as a control parameter. |
| ML04 Membership Inference | Attacker determines whether a record was in the training set. | AML.T0044 (partial) | Differentially-private training; large-batch training; output of class probability only (not logits). | Per-caller query velocity monitor; suspicious correlation between input and known training samples. | Reduced but not eliminated — documented. |
| ML05 Model Theft / Extraction | High-volume querying reconstructs decision boundary. | AML.T0044 | Per-tenant rate limits; output quantization; watermarking high-value models for post-hoc theft proof. | Query-volume + entropy detection (Module 11 rule `model-extraction.yml`). | Determined attacker with budget — accepted; treated by detection + legal. |
| ML06 ML Supply Chain Vulnerability | Compromised pretrained weights, dataset, or training library. | AML.T0010 | Pinned dependency manifest; SBOM at training; signed datasets; Cosign-verified weights; in-toto attestation for training run. | Continuous SBOM diff vs. registry baseline; CVE alerting on training base images. | Unknown novel CVE — accepted; treated by patching SLO. |
| ML07 Transfer-Learning Attack | Malicious fine-tune of a pretrained model carries a backdoor. | AML.T0018 | Provenance attestation for every fine-tune step; held-out canary inputs evaluated before promotion. | Trigger-input scanner that probes known backdoor patterns at registry promotion. | Novel backdoor designs — accepted; treated by canary expansion. |
| ML08 Model Skewing | Long-term drift caused by adversarial feedback loops. | (not directly named) | Bounded feedback ingestion (capped fraction of new training data from auto-labelled outputs); human-in-loop sampling. | Drift alert on feature and label distributions per cohort; weekly slice-based fairness review. | Slow accumulation — controlled by review cadence. |
| ML09 Output Integrity Attack | Response is intercepted and altered between model and consumer. | (not directly named in ATLAS) | mTLS between model and consumer; signed response envelopes for high-stakes decisions. | Consumer-side hash verification; mismatches paged. | Mid-stream tampering — bounded by transport integrity. |
| ML10 Model Poisoning (Insider) | An operator pushes a model with hidden behaviour. | AML.T0018 | Four-eyes promotion via OPA gate; signed promotion attestation tied to operator identity; held-out evaluation set the trainer cannot see. | Promotion event diff alert; statistical comparison vs. champion model on holdout. | Collusion among reviewers — partially treated by separation of duties. |

OWASP ML categories are referenced from the project's published list.

### 2.2 Control specifications (preventive — detail)

#### CTRL-P-01: Signed-and-attested model promotion

- **Layer:** registry.
- **What it does:** rejects model artifacts that do not carry both a
  Cosign signature from the build pipeline and an in-toto attestation
  matching the expected training step DAG.
- **Implementation:** OPA admission policy on the registry's webhook;
  policy bundle includes the allow-listed signer identities; the
  attestation predicate validates `materials` (data hash, code hash)
  match the manifest the requester is promoting.
- **How to know it works:** synthetic unsigned artifact pushed weekly
  must be rejected; rejection events are visible in the audit log.
- **Failure mode:** if the signer key is rotated incorrectly, the
  control fails *closed* (no promotion). The runbook covers emergency
  signer rotation with two-person review.

#### CTRL-P-02: Tenant-scoped feature-store access

- **Layer:** data + training.
- **What it does:** training jobs may only read feature prefixes that
  match their tenant identity; cross-tenant reads return 403.
- **Implementation:** SPIFFE workload identity carries the tenant
  selector; the feature-store admission policy maps the selector to a
  prefix allow-list; the bucket IAM enforces the same prefix.
- **How to know it works:** continuous synthetic cross-tenant read
  must return 403 and produce an alert.
- **Failure mode:** if SPIRE is unavailable, training jobs fail to
  start; treated by SPIRE HA + restart-policy.

#### CTRL-P-03: Schema-validated, signed event ingestion

- **Layer:** data ingest.
- **What it does:** Kafka producers must present a valid mTLS
  identity *and* publish events whose schema matches the registered
  contract version; mismatches are rejected.
- **Implementation:** SASL+mTLS at the broker; schema registry pinned
  per topic; producer SDK rejects schema diffs at publish.
- **How to know it works:** schema-breaking canary message is
  rejected; rejection rate per producer visible in dashboard.
- **Failure mode:** schema-registry outage — producers buffer up to
  configured window; downstream pipeline pauses but does not
  silently accept malformed events.

#### CTRL-P-04: Per-tenant inference rate-limit + output rate

- **Layer:** serving.
- **What it does:** caps queries-per-second per tenant key and
  suppresses output of confidence vectors except for callers on an
  explicit allow-list.
- **Implementation:** API gateway + sidecar policy; bucket per
  caller-identity, not per IP.
- **How to know it works:** synthetic burst exceeds limit and is 429'd;
  rate-limit metrics published.
- **Failure mode:** legitimate batch traffic blocked — runbook for
  emergency allow-list expansion with revocation timer.

#### CTRL-P-05: Differentially-private training (selectively applied)

- **Layer:** training.
- **What it does:** trains models on sensitive datasets with a stated
  epsilon budget per release.
- **Implementation:** DP-SGD with per-sample gradient clipping;
  privacy accountant records cumulative epsilon; release blocked when
  budget is exceeded.
- **How to know it works:** privacy accountant value matches expected
  given the recorded hyperparameters; reproducible via a stored seed.
- **Failure mode:** if epsilon is set too low, accuracy collapses; the
  capstone solution documents the epsilon used and the accuracy
  cost.

### 2.3 Control specifications (detective — detail)

#### CTRL-D-01: Model-extraction detection

- **What it does:** alerts on high-volume, high-similarity, or
  high-entropy query bursts against a single served model from a
  single tenant identity.
- **Implementation:** Sigma rule (`model-extraction.yml`) shipped in
  Module 11.
- **Signal:** queries-per-key/minute > threshold AND entropy of
  inputs above per-day baseline.
- **Tuning:** initial threshold from p99 of historical benign tenant
  traffic; re-tuned after first month.

#### CTRL-D-02: Training-time poisoning detection

- **What it does:** flags training runs whose per-source feature
  distribution drifts beyond N sigma from the prior green run.
- **Implementation:** dataset profiling job runs before each training
  job; produces a structured report stored alongside the training
  artifact; gate on green status before training proceeds.
- **Signal:** KL divergence per feature × source > threshold.
- **Failure mode:** silent baseline drift — caught by quarterly
  manual review of the baseline values.

#### CTRL-D-03: Promotion-event drift

- **What it does:** for every model promotion, compares the candidate
  against the current champion on a fixed holdout set; promotions
  whose error rate jumps disproportionately on any protected slice are
  paged for review.
- **Implementation:** evaluation step in the promotion pipeline writes
  results to the audit log; OPA gate consumes the result.
- **Failure mode:** evaluator drift — caught by an independent
  evaluation set rotated quarterly.

### 2.4 Trade-off and decision notes

- **Why DP only for sensitive datasets, not everywhere.**
  Differential privacy degrades accuracy; applying it universally
  hides the cases where it matters. Decision: DP for datasets
  labelled `restricted` in the data inventory; standard training for
  others.
- **Why detection plus prevention, not detection alone.** A purely
  detective program responds; an attacker who completes the attack
  before detection has already won. Prevention buys time and reduces
  the attack surface available to detection.
- **Why we suppress confidence vectors by default.** Confidence
  vectors carry far more information than the predicted label and
  directly feed extraction and inversion attacks; default-off is a
  safer posture than per-feature audits later.

### 2.5 What is out of scope at this tier (with reason)

- **Federated learning controls.** The capstone system does not
  perform federated training.
- **TEEs for training-data confidentiality.** Not justified by the
  risk register at this tier.
- **Watermarking every model.** Only models above a stated business
  value threshold are watermarked; below the threshold the cost
  exceeds the recovery value.

## 3. Validation steps

1. **OWASP ML closure.** Confirm all ten OWASP ML categories appear
   in §2.1; any "out of scope" must cite a reason and the risk
   register.
2. **Two-control rule.** For every High-rated ML risk, confirm at
   least one preventive *and* one detective control are listed.
3. **Specificity check.** Read each control as a stranger; can a
   platform engineer implement it without further questions? If
   "input validation" appears as a control with no constraints, the
   row is not detailed enough.
4. **Failure mode named.** Every preventive control names what
   happens when it fails (open / closed / degraded).
5. **Synthetic-evidence plan.** Confirm at least one continuous
   synthetic test is named per preventive control (so the absence of
   alerts is informative, not silence).

## 4. Rubric / review checklist

| Criterion | Weight | Pass condition |
|-----------|--------|----------------|
| All OWASP ML Top 10 addressed or scoped out | 15 | Each item appears in §2.1 with disposition. |
| ATLAS techniques cited where applicable | 10 | Each row in §2.1 cites an `AML.Tnnnn` ID or states "not directly in ATLAS". |
| Preventive + detective for each High risk | 15 | Two-control rule holds. |
| Controls are concrete | 15 | Each control names the chokepoint, the mechanism, and the policy/parameter. |
| Failure modes named | 10 | Every preventive control says what happens when it fails. |
| Synthetic-evidence plan present | 5 | Each preventive control names a continuous test that proves it is on. |
| Trade-offs documented | 10 | Differentially-private training, suppression of confidence, etc. each carry a stated cost. |
| Out-of-scope choices justified | 5 | Items declared out of scope cite the risk register. |
| Cross-reference to Exercise 02 architecture | 10 | Each control is locatable on the architecture diagram from Ex-02. |
| References cited | 5 | Official sources linked. |

## 5. Common mistakes

- **Listing techniques without a chokepoint.** "Use input
  validation" is not a control; "API gateway rejects payloads that
  exceed length or fail JSON-schema validation" is.
- **Only preventive controls.** ML threats include adversarial
  evolution; detective controls catch the cases prevention missed.
- **DP everywhere.** Applying differential privacy by default
  damages models that have no privacy risk and exhausts the team's
  budget for the cases where DP actually matters.
- **No failure mode.** A control that fails open and is not
  documented as such is worse than no control, because operators
  assume coverage.
- **Confidence vectors exposed by default.** Information leakage
  routinely enables ML02/ML03/ML05.
- **Missing supply chain (ML06).** A common omission in submissions;
  ML06 typically maps to the most impactful incidents in industry
  reports.
- **No cross-reference to architecture.** Controls that "exist
  somewhere" cannot be located by a reviewer.

## 6. References

- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>
- MITRE ATLAS — <https://atlas.mitre.org/>
- NIST AI Risk Management Framework (AI RMF 1.0) — <https://www.nist.gov/itl/ai-risk-management-framework>
