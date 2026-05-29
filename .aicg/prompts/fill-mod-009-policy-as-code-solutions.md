# AICG Work Packet: fill-mod-009-policy-as-code-solutions

## Goal

Create module-level reference solutions for `ai-infra-security-solutions` module `mod-009-policy-as-code`.

## Scope

- Modify only the target solutions repository.
- Create one directory per learning exercise under the module solution directory.
- Each exercise directory must contain `SOLUTION.md`.
- Design exercises need a worked example, decision rationale, and grading rubric.
- Implementation exercises need runnable or statically valid artifacts where feasible.

## Source Policy

- Use official standards and project documentation first.
- VeriSwarm references may only be used as practitioner implementation examples.
- Do not invent facts, metrics, incidents, or case studies.
- If a factual claim cannot be verified, write `<!-- needs-research: ... -->`; this blocks auto-merge.

- `owasp-ml-top-10` (official_project): OWASP Machine Learning Security Top 10 - https://owasp.org/www-project-machine-learning-security-top-10/
- `mitre-atlas` (official_project): MITRE ATLAS - https://atlas.mitre.org/
- `nist-ai-rmf` (official_standard): NIST AI Risk Management Framework - https://www.nist.gov/itl/ai-risk-management-framework

## Exercises

### exercise-01 - Exercise 01 — Gatekeeper vs. Kyverno Choice
- Learning file: `lessons/mod-009-policy-as-code/exercises/exercise-01-gatekeeper-vs-kyverno.md`
- Output directory: `modules/mod-009-policy-as-code/exercise-01-gatekeeper-vs-kyverno`
- Required artifact: `SOLUTION.md`

### exercise-02 - Exercise 02 — Rego Policy Library
- Learning file: `lessons/mod-009-policy-as-code/exercises/exercise-02-rego-policy-library.md`
- Output directory: `modules/mod-009-policy-as-code/exercise-02-rego-policy-library`
- Required artifact: `SOLUTION.md`

### exercise-03 - Exercise 03 — Conftest CI Gate
- Learning file: `lessons/mod-009-policy-as-code/exercises/exercise-03-conftest-ci-gate.md`
- Output directory: `modules/mod-009-policy-as-code/exercise-03-conftest-ci-gate`
- Required artifact: `SOLUTION.md`

### exercise-04 - Exercise 04 — ML-Specific Policy Catalog
- Learning file: `lessons/mod-009-policy-as-code/exercises/exercise-04-ml-policy-catalog.md`
- Output directory: `modules/mod-009-policy-as-code/exercise-04-ml-policy-catalog`
- Required artifact: `SOLUTION.md`

### exercise-05 - Exercise 05 — Policy Testing + Distribution Plan
- Learning file: `lessons/mod-009-policy-as-code/exercises/exercise-05-policy-testing-distribution.md`
- Output directory: `modules/mod-009-policy-as-code/exercise-05-policy-testing-distribution`
- Required artifact: `SOLUTION.md`

## Output Contract

For every exercise, write a `SOLUTION.md` with these sections:

1. Solution overview
2. Worked answer or implementation
3. Validation steps
4. Rubric or review checklist
5. Common mistakes
6. References

Keep claims tied to the listed official sources or to clearly labeled local exercise context.
