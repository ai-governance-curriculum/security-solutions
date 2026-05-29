# AICG Work Packet: fill-mod-010-supply-chain-security-solutions

## Goal

Create module-level reference solutions for `ai-infra-security-solutions` module `mod-010-supply-chain-security`.

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
- `slsa` (official_project): Supply-chain Levels for Software Artifacts - https://slsa.dev/
- `sigstore-docs` (official_project): Sigstore Documentation - https://docs.sigstore.dev/
- `openssf-scorecard` (official_project): OpenSSF Scorecard - https://openssf.org/scorecard/

## Exercises

### exercise-01 - Exercise 01 — SLSA Self-Assessment
- Learning file: `lessons/mod-010-supply-chain-security/exercises/exercise-01-slsa-self-assessment.md`
- Output directory: `modules/mod-010-supply-chain-security/exercise-01-slsa-self-assessment`
- Required artifact: `SOLUTION.md`

### exercise-02 - Exercise 02 — Signed-Pipeline Design
- Learning file: `lessons/mod-010-supply-chain-security/exercises/exercise-02-signed-pipeline-design.md`
- Output directory: `modules/mod-010-supply-chain-security/exercise-02-signed-pipeline-design`
- Required artifact: `SOLUTION.md`

### exercise-03 - Exercise 03 — Admission Verification Configuration
- Learning file: `lessons/mod-010-supply-chain-security/exercises/exercise-03-admission-verification.md`
- Output directory: `modules/mod-010-supply-chain-security/exercise-03-admission-verification`
- Required artifact: `SOLUTION.md`

### exercise-04 - Exercise 04 — Hugging Face Model Vetting
- Learning file: `lessons/mod-010-supply-chain-security/exercises/exercise-04-hugging-face-vetting.md`
- Output directory: `modules/mod-010-supply-chain-security/exercise-04-hugging-face-vetting`
- Required artifact: `SOLUTION.md`

### exercise-05 - Exercise 05 — Supply-Chain Incident Runbook
- Learning file: `lessons/mod-010-supply-chain-security/exercises/exercise-05-supply-chain-incident-runbook.md`
- Output directory: `modules/mod-010-supply-chain-security/exercise-05-supply-chain-incident-runbook`
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
