# AICG Work Packet: fill-mod-008-runtime-security-solutions

## Goal

Create module-level reference solutions for `ai-infra-security-solutions` module `mod-008-runtime-security`.

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

### exercise-01 - Exercise 01 — Pod Security Standards Baseline
- Learning file: `lessons/mod-008-runtime-security/exercises/exercise-01-pss-baseline.md`
- Output directory: `modules/mod-008-runtime-security/exercise-01-pss-baseline`
- Required artifact: `SOLUTION.md`

### exercise-02 - Exercise 02 — Seccomp + AppArmor Profiles
- Learning file: `lessons/mod-008-runtime-security/exercises/exercise-02-seccomp-apparmor-profiles.md`
- Output directory: `modules/mod-008-runtime-security/exercise-02-seccomp-apparmor-profiles`
- Required artifact: `SOLUTION.md`

### exercise-03 - Exercise 03 — Falco Ruleset
- Learning file: `lessons/mod-008-runtime-security/exercises/exercise-03-falco-ruleset.md`
- Output directory: `modules/mod-008-runtime-security/exercise-03-falco-ruleset`
- Required artifact: `SOLUTION.md`

### exercise-04 - Exercise 04 — Behavioral Baseline Design
- Learning file: `lessons/mod-008-runtime-security/exercises/exercise-04-behavioral-baseline-design.md`
- Output directory: `modules/mod-008-runtime-security/exercise-04-behavioral-baseline-design`
- Required artifact: `SOLUTION.md`

### exercise-05 - Exercise 05 — Container-Escape Response Runbook
- Learning file: `lessons/mod-008-runtime-security/exercises/exercise-05-container-escape-runbook.md`
- Output directory: `modules/mod-008-runtime-security/exercise-05-container-escape-runbook`
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
