# Exercise 01 — Adversarial Robustness Assessment

> Read this *after* attempting the assessment yourself. This file is a
> reference assessment, the rationale behind each choice, and the
> rubric you (or a reviewer) can grade your own work against.

## 1. Solution overview

The exercise asks the learner to produce a structured adversarial-ML
robustness assessment for a deployed model. A complete assessment has
four pieces:

1. **System description** — what the model does, where it lives in the
   stack, who can reach it, and what attacker positions are realistic.
2. **Threat enumeration** — a mapping from the attacker's *goal* to a
   concrete *technique*, anchored in MITRE ATLAS, and cross-referenced
   to the relevant OWASP ML Top 10 category.
3. **Test plan** — for each in-scope threat, the attack(s) you will
   actually run (or the artifacts you will inspect), the success metric,
   and the threshold at which the model is considered "robust enough."
4. **Findings + recommendations** — what failed, what the residual risk
   is, and which of NIST AI RMF's *Govern / Map / Measure / Manage*
   functions each recommendation addresses.

The point of the assessment is **not** to attack the model with every
known technique — it is to produce a defensible, threat-modeled answer
to the question "which attacks can this model actually survive in
production?"

## 2. Worked answer — implementation

The worked example below uses a deliberately generic local scenario
(image classifier behind a tenant-facing inference API) so the
methodology generalizes. Specific numeric thresholds are deliberately
left to the practitioner to measure or cite from their own deployment
context.

### 2.1 System description (local exercise context)

- **Model under assessment**: a CNN-based image classifier exposed at a
  REST endpoint. Multi-tenant; query rate is per-tenant but otherwise
  unconstrained.
- **Asset value**: the model encodes proprietary labeling effort and a
  proprietary dataset.
- **Realistic attacker positions**:
  - *External tenant* with valid API credentials and unlimited budget
    for queries.
  - *Internal* with read access to training data buckets but not to
    training code.
  - *Supply-chain* attacker who can land a PR against a public
    upstream dataset the team mirrors.

These three positions exhaust the attack surface for this system. The
"insider with model weights" position is explicitly excluded from
*this* assessment because it is covered by the access-control review
the learner does on the model registry.

### 2.2 Threat enumeration

The table below is the deliverable. It is the minimum useful form: each
row ties an attacker goal to an ATLAS technique and an OWASP ML Top 10
category, so that downstream defense work has a single source of truth.

| # | Attacker goal | ATLAS technique (representative) | OWASP ML Top 10 | In scope? | Why |
|---|---|---|---|---|---|
| T1 | Force misclassification on a single chosen input | ML Attack Staging → Craft Adversarial Data → Evasion | ML01 Input Manipulation Attack | Yes | Tenant attacker can submit crafted images directly. |
| T2 | Force misclassification on many inputs (transfer) | Initial Access → ML Supply Chain Compromise → Model | ML01 Input Manipulation Attack | Yes | Upstream pretrained backbone is in the chain. |
| T3 | Recover training-set membership for a known record | ML Attack Staging → Inference API → Membership Inference | ML04 Membership Inference Attack | Yes | API returns confidence scores; queries are unbounded. |
| T4 | Reconstruct a clone of the model from queries | Exfiltration → Exfiltration via ML Inference API → Extract ML Model | ML05 Model Theft | Yes | Endpoint returns top-k probabilities; no per-tenant query cap. |
| T5 | Cause persistent misbehavior via training data | Resource Development → Poison Training Data | ML02 Data Poisoning | Yes (supply-chain position) | Upstream dataset is mirrored without signed manifests. |
| T6 | Backdoor activated by a trigger pattern | ML Attack Staging → Backdoor ML Model | ML10 Model Poisoning | Yes | Same poisoning vector; backdoor variant. |

ATLAS technique names follow the framework's *Tactic → Technique → Sub-technique*
hierarchy. Map to whatever revision of ATLAS is current at assessment
time; the framework is updated and individual technique IDs occasionally
move. Confirm exact technique IDs against the current ATLAS matrix at
https://atlas.mitre.org/matrices/ATLAS.

OWASP ML Top 10 categories above follow the project's ML01–ML10
labeling. Confirm category names match the latest OWASP ML Top 10
release at https://owasp.org/www-project-machine-learning-security-top-10/.

### 2.3 Test plan (one row per in-scope threat)

| Threat | Test | Success metric | "Robust enough" threshold |
|---|---|---|---|
| T1 Evasion | PGD-L∞ attack on a held-out test set, ε ∈ {2/255, 4/255, 8/255}, 40 steps | Robust accuracy under attack | Defined per-deployment; record the curve, do not pick a fixed bar without product context |
| T2 Transfer evasion | PGD adversarial examples generated on a public surrogate model, replayed against the target | Transfer attack success rate | Same — record the rate, defend the threshold against product risk |
| T3 Membership inference | Shadow-model attack (Shokri et al. style) replicated against the target | Attack AUC | AUC near 0.5 is good (no signal); higher is leakage |
| T4 Model extraction | Query-and-clone with active sampling; measure agreement between target and clone on a held-out set | Clone agreement after N queries | Defender chooses N; the curve is the deliverable, not a single bar |
| T5 Data poisoning | Static review of dataset ingestion: are upstream sources signed? Is there a diff-on-merge gate? Is provenance recorded? | Pass/fail per control | All controls present; gaps are explicitly accepted in writing |
| T6 Backdoor | Spectral-signature / activation-clustering scan of training-set activations | Detection rate of injected trigger samples on a known seeded test | All seeded triggers detected on the test set |

Why no fixed numeric thresholds across the board: robust-accuracy
thresholds are a product-risk decision. A spam classifier and a medical
imaging triage model with identical PGD robustness can have wildly
different acceptable risk. The assessment **records the curve** and
hands it to the product/risk owner.

### 2.4 Findings + recommendations (example)

This is the section reviewers grade the hardest. Each finding must have
a severity, the evidence it rests on, and a mapped recommendation.

| ID | Finding | Severity | Evidence | Recommendation | NIST AI RMF function |
|---|---|---|---|---|---|
| F-01 | Robust accuracy at ε = 8/255 dropped well below clean accuracy under PGD | High | `pgd_eval.json` | Adopt PGD-based adversarial training (see exercise-02) | Manage |
| F-02 | Membership inference AUC measurably above 0.5 on shadow-model test | Medium | `mi_eval.json` | Apply DP-SGD with budgeted ε (see exercise-04) | Manage |
| F-03 | API returns top-5 probabilities; per-tenant query rate uncapped | High | API spec + nginx config | Cap query rate per tenant; truncate output to top-1 label or apply output noise | Manage |
| F-04 | Upstream dataset mirror is not signed | High | bucket policy review | Require signed manifests; introduce diff-on-merge for training data | Govern + Manage |
| F-05 | No process for re-assessing after model updates | Medium | observed cadence | Tie this assessment to the CI pipeline; block release on threshold regressions | Govern |

NIST AI RMF defines four functions — Govern, Map, Measure, Manage —
intended to be applied across the AI lifecycle. The mapping in the
last column is the assessor's responsibility, not the framework's;
reviewers should confirm the mapping is defensible.

### 2.5 What a strong assessment also documents

- **Out of scope, by name.** The assessor lists which threats were not
  evaluated and why (cost, no realistic attacker position, covered by a
  different review). Silence is not the same as "low risk."
- **Reproducibility.** Each test produces a JSON artifact with the seed,
  the attack hyperparameters, and the dataset hash. Without this, the
  assessment cannot be re-run after a model update.
- **Time bound.** Adversarial ML moves fast; the assessment is stamped
  with a re-assess-by date and the conditions that should trigger an
  earlier re-run (e.g. new backbone, new tenant class).

## 3. Validation steps

A solution to this exercise is valid if a reviewer can answer "yes" to
each of these:

1. Does the system description name *who* can attack and *from where*?
2. Does every in-scope threat map to both an ATLAS technique and an
   OWASP ML Top 10 category?
3. Does every in-scope threat have at least one concrete test, with a
   metric and an artifact path?
4. Are out-of-scope threats called out by name, with a reason?
5. Are findings tied to evidence (not just opinion), and do they each
   map to an NIST AI RMF function?
6. Is there a re-assessment trigger / cadence stated?

If any answer is "no," the assessment is incomplete regardless of
whether the technical content is correct.

## 4. Rubric

Total points: 30. Suggested cut: ≥24 to pass, ≥27 for "ready for an
external auditor."

| Section | Criterion | Points |
|---|---|---|
| System description | Attacker positions enumerated and bounded | 3 |
| Threat enumeration | Each threat mapped to ATLAS + OWASP ML Top 10 | 5 |
| Threat enumeration | Out-of-scope threats called out with reason | 2 |
| Test plan | Each in-scope threat has a concrete test + metric | 5 |
| Test plan | Test artifacts are reproducible (seed, hash, config) | 3 |
| Findings | Severity assigned and defended | 3 |
| Findings | Each finding maps to an NIST AI RMF function | 3 |
| Findings | Each finding has a concrete recommendation (not "improve robustness") | 3 |
| Process | Re-assessment trigger / cadence documented | 3 |

## 5. Common mistakes

- **"Threats" that are just attack names.** "PGD" is not a threat; it
  is a technique. The threat is *the attacker goal* it serves
  (force misclassification, etc.).
- **Skipping the supply-chain attacker position.** Most learner answers
  cover the tenant attacker and stop. ATLAS treats supply-chain
  compromise as a first-class initial-access tactic and so should the
  assessment.
- **Picking robustness thresholds with no product context.** "Robust
  accuracy must be ≥X%" is a product decision, not a security one. The
  assessment supplies the curve; the product owner picks the bar.
- **Confusing the OWASP ML Top 10 with the OWASP LLM Top 10.** They
  are different projects. For LLM-specific work, see exercise-05.
- **One-shot assessments.** If there is no re-assessment trigger, the
  document is stale the moment the next model version ships.

## 6. References

- OWASP Machine Learning Security Top 10 —
  https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS (Adversarial Threat Landscape for AI Systems) —
  https://atlas.mitre.org/
- NIST AI Risk Management Framework (AI RMF 1.0) —
  https://www.nist.gov/itl/ai-risk-management-framework
- Sibling project: `projects/project-3-adversarial-defense/SOLUTION.md`
  for the worked benchmark implementation behind several of the tests
  named above.
- Sibling exercise: `exercise-02-defense-plan/SOLUTION.md` for the
  defense-side counterpart of this assessment.
