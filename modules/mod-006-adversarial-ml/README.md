# mod-006-adversarial-ml — Solutions

Reference solutions for the adversarial-ML module. Each exercise has its
own directory with a `SOLUTION.md`. Exercises in this module are a mix
of **design** (worked example + grading rubric) and **implementation**
(runnable or statically valid artifacts).

| Exercise | Type | Focus |
|---|---|---|
| [exercise-01-robustness-assessment](exercise-01-robustness-assessment/SOLUTION.md) | Design | Threat-model a deployed classifier against evasion, extraction, and inversion. |
| [exercise-02-defense-plan](exercise-02-defense-plan/SOLUTION.md) | Design | Pick defenses per threat and quantify the trade-offs they impose. |
| [exercise-03-poisoning-detection](exercise-03-poisoning-detection/SOLUTION.md) | Design | Design detection for data and model poisoning across the training pipeline. |
| [exercise-04-dp-sgd-configuration](exercise-04-dp-sgd-configuration/SOLUTION.md) | Implementation | Configure DP-SGD (Opacus) and reason about the (ε, δ) budget. |
| [exercise-05-llm-safety-pipeline](exercise-05-llm-safety-pipeline/SOLUTION.md) | Implementation | Wire input/output guardrails around an LLM endpoint. |

## How to use these

Attempt the exercise on the learning side first. Then read the solution
for design rationale and rubric — not as a cut-and-paste answer.

## Anchor sources

These are the three external sources every solution in this module is
allowed to lean on directly:

- OWASP Machine Learning Security Top 10 — https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS — https://atlas.mitre.org/
- NIST AI Risk Management Framework — https://www.nist.gov/itl/ai-risk-management-framework
