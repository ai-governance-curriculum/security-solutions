# Exercise 03 — Poisoning Detection Design

> Read this *after* attempting the exercise yourself. This file is a
> reference design, the rationale behind each placement, and the
> rubric you can use to grade your own answer.

## 1. Solution overview

The exercise asks the learner to design *detection* (not prevention)
for the poisoning-attack family across an ML training pipeline.
"Poisoning" here is the OWASP ML Top 10 ML02 / ML10 family and the
MITRE ATLAS "Poison Training Data" / "Backdoor ML Model" techniques.

A complete design has four pieces:

1. **A pipeline map** — where data and models flow from "outside the
   org" to "in production," with the inspection points marked.
2. **A detector inventory** — for each inspection point, the
   detector(s) running there, what they detect, and what they cannot.
3. **A response playbook** — what happens when a detector fires:
   who is paged, what is quarantined, and what the rollback path is.
4. **A coverage matrix** — a table that proves the design covers the
   distinct poisoning sub-threats (label flipping, clean-label,
   backdoor with explicit trigger, supply-chain pretrained-model
   poisoning).

The point is **defense in depth across the pipeline**, not a single
clever detector. Each detector is fallible; the design is sound iff
no single failure leaves a sub-threat uncovered.

## 2. Worked answer — implementation

### 2.1 Pipeline map (inspection points)

```
[ Upstream sources ]        # public datasets, partner data, scraped data
       │
       ▼
[ A. Ingest gate ]           # signature / provenance / schema checks
       │
       ▼
[ Raw object store ]
       │
       ▼
[ B. Pre-processing diff ]   # diff-on-merge vs. last accepted version
       │
       ▼
[ Curated dataset version ]
       │
       ▼
[ C. Pre-training scan ]     # static analysis of training set
       │
       ▼
[ Training job ]
       │
       ▼
[ D. Post-training scan ]    # activation clustering / trigger search on the trained model
       │
       ▼
[ Model registry ]
       │
       ▼
[ E. Inference-time canary ] # canary triggers + behavior monitoring in prod
       │
       ▼
[ Serving endpoint ]
```

There are exactly five inspection points and they map cleanly to the
attacker's progression. A design that names fewer points is
under-instrumented; a design that names many more is usually
duplicating coverage.

### 2.2 Detector inventory (per inspection point)

**A. Ingest gate.**
- *What it catches:* untrusted source (no signature), schema drift,
  obvious volume anomalies, wrong checksum.
- *Detectors:* cryptographic verification of dataset manifests
  (see `project-4-secure-cicd` for the signing infrastructure); a
  schema validator that fails closed on unknown columns / shape; a
  volume check vs. the last accepted version.
- *Blind spots:* anything that arrives correctly signed by an
  upstream that itself was compromised.

**B. Pre-processing diff.**
- *What it catches:* small, targeted edits to a previously-accepted
  dataset (this is the canonical clean-label poisoning vector — small
  changes in label or feature values for a small fraction of samples).
- *Detectors:* a deterministic `diff` of the new curated version
  against the prior accepted version, surfaced for human review on
  every change; reviewer rubric requires at least one approver who
  did not produce the change.
- *Blind spots:* very large legitimate updates where the
  signal-to-noise of a human reviewer is poor.

**C. Pre-training scan (static, on the dataset).**
- *What it catches:* outliers and class-conditional density anomalies
  that are characteristic of crude label-flipping; gross
  duplicates / near-duplicates that may be poisoning injection.
- *Detectors:* per-class outlier detection in feature space; k-NN
  agreement with class label; near-duplicate detection. A label-noise
  detection routine (e.g. confident-learning-style approaches, such as
  Northcutt et al.) runs here and surfaces a ranked list of suspect
  samples. The research landscape evolves; cite the specific
  label-noise detection method you choose.
- *Blind spots:* small, clean-label, single-class poisoning that
  matches the feature distribution.

**D. Post-training scan (on the trained model).**
- *What it catches:* backdoor triggers and class-targeted misbehavior
  embedded by the training process.
- *Detectors:* activation-clustering on the penultimate layer per
  class (Chen et al., "Detecting Backdoor Attacks on Deep Neural
  Networks by Activation Clustering"), looking for a bimodal cluster
  signature that is the standard fingerprint of trigger-based
  backdoors; spectral-signature scoring of training samples by class
  (Tran, Li, Madry, "Spectral Signatures in Backdoor Attacks",
  NeurIPS 2018); a trigger-reverse-engineering pass (Neural Cleanse
  family — Wang et al., "Neural Cleanse: Identifying and Mitigating
  Backdoor Attacks in Neural Networks") that searches for minimum-norm
  patterns that flip the model to a target class.
- *Blind spots:* backdoors with naturally-shaped triggers that
  defeat reverse-engineering; backdoors that are partition-aware and
  evade clustering.

**E. Inference-time canary.**
- *What it catches:* successful backdoors that the post-training scan
  missed; drift in model behavior on a known canary set; spike
  patterns that match a trigger search.
- *Detectors:* a canary suite of fixed inputs whose expected
  predictions are pinned in the registry — divergence pages oncall.
  Behavior-monitoring rule: flag inputs that contain known suspicious
  patches (if any have been disclosed); flag inputs that produce
  unusually high confidence on a minority class.
- *Blind spots:* fully novel backdoors with no prior disclosure and a
  trigger pattern not in the canary suite.

### 2.3 Response playbook

Every detector has a defined response. A detector with no response is
a vanity metric.

| Detector fires | Severity | Action |
|---|---|---|
| Ingest signature failure | High | Drop the artifact; page data-platform oncall; do *not* manually accept |
| Schema drift on ingest | Medium | Hold artifact in quarantine bucket; require human approver |
| Pre-processing diff with > N rows changed | Medium | Hold release; require dataset-owner sign-off + a second reviewer |
| Pre-training scan: suspect sample ratio above threshold | Medium | Hold; surface ranked list to dataset owner; sample manual review of top-K |
| Post-training scan: activation clustering signature | High | Block model promotion; open incident; re-train with the suspect subset removed and re-scan |
| Inference-time canary divergence | High | Roll back to last known-good model version; open incident |

Two policies that are easy to forget:

- **Quarantine, do not delete.** Suspected poison samples and rejected
  models are retained so that forensic analysis is possible.
- **A poisoning incident invalidates downstream models too.** If a
  dataset version turns out to be poisoned after the fact, every
  model trained against it is suspect, not just the most recent one.

### 2.4 Coverage matrix (proof of defense in depth)

Each row is a poisoning sub-threat; each column is an inspection
point; cell marks which sub-threats each point can catch.

| Sub-threat | A. Ingest | B. Diff | C. Pre-train scan | D. Post-train scan | E. Canary |
|---|---|---|---|---|---|
| Unsigned / unauthenticated source | ✓ |  |  |  |  |
| Label flipping (crude) | (signature only) | ✓ | ✓ | ✓ | partial |
| Clean-label, in-distribution |  | partial | partial | ✓ | partial |
| Trigger backdoor (visible) |  |  | partial | ✓ | ✓ |
| Trigger backdoor (subtle / partition-aware) |  |  |  | partial | ✓ |
| Pretrained-model supply-chain poison | (if model artifact) |  |  | ✓ | ✓ |

Two things this matrix is meant to surface:

- *No row should be empty.* If a sub-threat has no ✓ at any
  inspection point, the design has a gap.
- *No row should rely on a single ✓.* Defense in depth means each
  sub-threat is covered by at least two independent inspection
  points.

## 3. Validation steps

A solution is valid if a reviewer can answer "yes" to each:

1. Are inspection points named, ordered, and tied to a stage in the
   pipeline (not floating in the abstract)?
2. Does each inspection point have at least one named detector and
   at least one named blind spot?
3. Does each detector have a defined response with severity, owner,
   and action?
4. Is there a coverage matrix that crosses sub-threats against
   inspection points?
5. Does the design distinguish dataset poisoning from pretrained-model
   poisoning? (They are different attack surfaces.)
6. Is the quarantine policy stated explicitly (no silent deletion)?

## 4. Rubric

Total points: 30. Suggested cut: ≥24 pass, ≥27 production-ready.

| Section | Criterion | Points |
|---|---|---|
| Pipeline map | Inspection points are explicit and stage-bound | 3 |
| Detectors | Each point has at least one detector | 4 |
| Detectors | Each point has at least one stated blind spot | 3 |
| Detectors | At least one detector covers each of: data, model, runtime | 3 |
| Response | Every detector has a severity + action | 4 |
| Response | Quarantine (not delete) policy stated | 2 |
| Coverage | Matrix present and no sub-threat is uncovered | 3 |
| Coverage | No sub-threat depends on a single detector | 3 |
| Coverage | Pretrained-model supply-chain path called out | 2 |
| Cross-ref | Tied back to OWASP ML02/ML10 and ATLAS Poison / Backdoor techniques | 3 |

## 5. Common mistakes

- **One detector to rule them all.** Activation clustering is a
  popular pick because it works on many published backdoor benchmarks,
  but it is one detector; a design that leans only on it will miss
  the clean-label and subtle-trigger sub-threats.
- **Conflating prevention and detection.** Signed manifests *prevent*
  certain ingest-time attacks; they don't *detect* clean-label
  poisoning. Be specific.
- **No response for pre-training scan alerts.** Detector outputs that
  no one is paged on are noise. Each detector needs an owner.
- **Forgetting the pretrained-model supply chain.** Many learners
  scope only the dataset. Pretrained weights are an equally real
  poisoning surface and have to be in the design.
- **Deleting suspected poison.** Without quarantine, you cannot do
  forensics after the fact, and you cannot regression-test future
  detectors against past poison.
- **"Detect at inference" with no canary suite.** "Monitor for
  weird behavior" is not detection; a pinned canary set is.

## 6. References

- OWASP Machine Learning Security Top 10 — categories ML02 (Data
  Poisoning) and ML10 (Model Poisoning) —
  https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS — techniques "Poison Training Data" and "Backdoor ML
  Model" under the Resource Development and ML Attack Staging
  tactics — https://atlas.mitre.org/
- NIST AI Risk Management Framework — the Measure and Manage
  functions are the relevant home for poisoning detection /
  response — https://www.nist.gov/itl/ai-risk-management-framework
- Sibling exercise: `exercise-01-robustness-assessment/SOLUTION.md`
  for the threat enumeration (T5, T6 in that file).
- Sibling exercise: `exercise-02-defense-plan/SOLUTION.md` for the
  upstream prevention controls that complement detection.
- Sibling project: `projects/project-4-secure-cicd/SOLUTION.md` for
  the signing / supply-chain infrastructure referenced in
  inspection point A.
