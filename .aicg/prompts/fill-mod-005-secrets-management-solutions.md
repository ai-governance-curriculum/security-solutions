# AICG Work Packet: fill-mod-005-secrets-management-solutions

## Goal

Create module-level reference solutions for `ai-infra-security-solutions` module `mod-005-secrets-management`.

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

### exercise-01 - Exercise 01 — Secrets Inventory
- Learning file: `lessons/mod-005-secrets-management/exercises/exercise-01-secrets-inventory.md`
- Output directory: `modules/mod-005-secrets-management/exercise-01-secrets-inventory`
- Required artifact: `SOLUTION.md`

### exercise-02 - Exercise 02 — Vault Deployment Plan
- Learning file: `lessons/mod-005-secrets-management/exercises/exercise-02-vault-deployment-plan.md`
- Output directory: `modules/mod-005-secrets-management/exercise-02-vault-deployment-plan`
- Required artifact: `SOLUTION.md`

### exercise-03 - Exercise 03 — Secret Rotation Playbook
- Learning file: `lessons/mod-005-secrets-management/exercises/exercise-03-secret-rotation-playbook.md`
- Output directory: `modules/mod-005-secrets-management/exercise-03-secret-rotation-playbook`
- Required artifact: `SOLUTION.md`

### exercise-04 - Exercise 04 — Keyless CI Design
- Learning file: `lessons/mod-005-secrets-management/exercises/exercise-04-keyless-ci-design.md`
- Output directory: `modules/mod-005-secrets-management/exercise-04-keyless-ci-design`
- Required artifact: `SOLUTION.md`

### exercise-05 - Exercise 05 — Secret-Leak Incident Runbook
- Learning file: `lessons/mod-005-secrets-management/exercises/exercise-05-secret-leak-runbook.md`
- Output directory: `modules/mod-005-secrets-management/exercise-05-secret-leak-runbook`
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
