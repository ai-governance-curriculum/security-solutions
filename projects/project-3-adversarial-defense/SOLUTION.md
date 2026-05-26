# SOLUTION — Adversarial Defense

> Read this *after* attempting the learning-side project. This file
> explains the design decisions, what the included attacks are actually
> testing, and what is deliberately out of scope.

## What problem this solves

A deployed ML model is exposed to three structurally different attack
classes that require structurally different defenses:

1. **Evasion** — crafted inputs at inference time that change the model's
   output (PGD, FGSM, transfer attacks).
2. **Extraction** — query-based reconstruction of the model's decision
   boundary (model stealing) or training data (membership inference).
3. **Poisoning** — corrupting training data to install backdoors or
   degrade accuracy.

This project addresses evasion and extraction directly. Poisoning is
addressed by upstream controls (data classification, signed datasets,
diff-on-merge for training data — see project-2-compliance and project-4
secure-cicd).

## Architecture decisions and *why*

### Why PGD-based adversarial training (not FGSM)

FGSM is a single-step attack; training on FGSM-perturbed inputs
produces models that look robust to FGSM but fall over to multi-step
attacks like PGD. PGD is the modern standard for adversarial training
because it more closely approximates the worst-case attacker within the
ε-ball. Madry et al. 2018 established this; the curriculum follows that
convention.

### Why input validation in addition to adversarial training

Adversarial training trades clean accuracy for robust accuracy at a
known cost (typically 3–10 percentage points on the clean test set). It
is not a complete defense — adversarial examples outside the training
ε-ball still slip through. Input validation (anomaly detection on the
feature distribution) is a cheaper second layer that catches
out-of-distribution inputs the trained model has no business handling.

### Why differential privacy at training (DP-SGD), not at inference

Inference-time DP (output perturbation) destroys utility quickly for
realistic privacy budgets. DP-SGD bakes privacy into the gradients
during training, so the released model itself is private — and inference
remains deterministic. The trade-off is a measurable utility hit; the
benchmark folder is structured so you can see this trade-off curve.

### Why per-tenant rate limits for extraction defense

A single attacker with unlimited queries can reconstruct decision
boundaries regardless of model defenses. Rate limits aren't a
mathematical defense — they're an economic one. The implementation in
`rate_limit.py` is keyed on tenant identity so a single noisy tenant
can't degrade service for others.

## How to read the code

Execution-order reading path:

1. `attacks/pgd.py` — understand what we are defending against.
2. `defenses/adversarial_training.py` — see the defense that makes
   `pgd.py` harder.
3. `defenses/input_validation.py` — second-layer OOD detector.
4. `defenses/dp_sgd.py` — privacy-preserving training loop.
5. `attacks/membership_inference.py` — the attack DP-SGD is designed to
   defeat.
6. `defenses/rate_limit.py` — economic defense against `model_extraction.py`.
7. `benchmark/robustness.py` — clean accuracy vs. accuracy under attack,
   plotted for each defense combination.

The benchmark is the most useful artifact — it lets you reason about
*how much* robustness each defense buys versus the clean-accuracy cost.

## What's deliberately simplified

- **Single-modality (vision-like) benchmarks.** Adversarial defense for
  LLMs (prompt injection, jailbreaks) is a different research area with
  much weaker formal defenses; it is treated separately in the
  security-learning track and is out of scope here.
- **No certified robustness.** Randomized smoothing / interval-bound
  propagation are mentioned but not implemented. They are the
  state-of-the-art for *provable* robustness within an ε-ball.
- **No watermarking.** Model watermarks for extraction detection are
  intentionally not included; the curriculum uses rate limiting and
  query auditing instead.
- **No federated adversarial training.** All training is centralized.

## Cross-references for deeper coverage

| Topic | Where the deeper implementation lives |
|---|---|
| Per-tenant request budgets (general purpose) | `engineer-solutions/mod-107 exercise-05-rate-limiting` |
| Input feature anomaly detection patterns | `mlops-solutions/03-model-monitoring/exercise-02` |
| Query auditing surface | `mlops-learning/projects/project-4-governance/src/audit/log.py` |
| Data poisoning controls (signed datasets) | `project-4-secure-cicd` + `engineer-solutions/mod-103 ex-10` |

## Production gap checklist

- [ ] Certified robustness (randomized smoothing) for high-stakes models
- [ ] LLM-specific defenses (prompt-injection detection, content moderation)
- [ ] Differential privacy budget accounting across training runs
- [ ] Model watermarking with extraction-detection workflow
- [ ] Adversarial example logging + retraining loop
- [ ] Per-tenant model isolation if any tenant could compromise others
- [ ] Membership-inference monitoring on inference traffic in production
- [ ] Defense-in-depth: combine rate limits with query similarity detection

## Validation

The `benchmark/robustness.py` script reports:

- Clean accuracy (no defenses)
- Clean accuracy (with adversarial training)
- Robust accuracy at ε = {2/255, 4/255, 8/255}
- Membership inference attack AUC (DP-SGD on vs. off)

Acceptance criteria: robust accuracy at ε = 8/255 should be > 30% on the
benchmark task with adversarial training enabled, and membership-inference
AUC should drop measurably with DP-SGD on. If you can't reproduce that
trade-off curve, the defenses are not actually engaged.

## Time budget for studying this solution

- **Skim**: 1 hour — read this file, scan each defense, run the benchmark.
- **Deep**: 1–2 weeks — re-implement PGD adversarial training and DP-SGD
  from scratch on a new dataset. Adversarial robustness research is the
  kind of domain where building it once is the only way to internalize
  the trade-offs.
