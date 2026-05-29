# AICG Work Packet: fill-mod-011-security-operations-solutions

## Goal

Create module-level reference solutions for `ai-infra-security-solutions` module `mod-011-security-operations`.

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

### exercise-01 - Exercise 01 — SIEM Evaluation
- Learning file: `lessons/mod-011-security-operations/exercises/exercise-01-siem-evaluation.md`
- Output directory: `modules/mod-011-security-operations/exercise-01-siem-evaluation`
- Required artifact: `SOLUTION.md`

### exercise-02 - Exercise 02 — ML-Specific Detection Ruleset
- Learning file: `lessons/mod-011-security-operations/exercises/exercise-02-ml-detection-ruleset.md`
- Output directory: `modules/mod-011-security-operations/exercise-02-ml-detection-ruleset`
- Required artifact: `SOLUTION.md`

### exercise-03 - Exercise 03 — IR Procedure for ML Threats
- Learning file: `lessons/mod-011-security-operations/exercises/exercise-03-ml-ir-procedure.md`
- Output directory: `modules/mod-011-security-operations/exercise-03-ml-ir-procedure`
- Required artifact: `SOLUTION.md`

### exercise-04 - Exercise 04 — Tabletop Scenario Library
- Learning file: `lessons/mod-011-security-operations/exercises/exercise-04-tabletop-library.md`
- Output directory: `modules/mod-011-security-operations/exercise-04-tabletop-library`
- Required artifact: `SOLUTION.md`

### exercise-05 - Exercise 05 — Postmortem Template + Worked Example
- Learning file: `lessons/mod-011-security-operations/exercises/exercise-05-postmortem-template.md`
- Output directory: `modules/mod-011-security-operations/exercise-05-postmortem-template`
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
