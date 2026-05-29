# AICG Work Packet: fill-mod-002-zero-trust-architecture-solutions

## Goal

Create module-level reference solutions for `ai-infra-security-solutions` module `mod-002-zero-trust-architecture`.

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
- `nist-sp-800-207` (official_standard): NIST SP 800-207: Zero Trust Architecture - https://csrc.nist.gov/publications/detail/sp/800-207/final
- `kubernetes-docs` (official_project): Kubernetes Documentation - https://kubernetes.io/docs/

## Exercises

### exercise-01 - Exercise 01 — Zero-Trust Gap Analysis
- Learning file: `lessons/mod-002-zero-trust-architecture/exercises/exercise-01-zero-trust-gap-analysis.md`
- Output directory: `modules/mod-002-zero-trust-architecture/exercise-01-zero-trust-gap-analysis`
- Required artifact: `SOLUTION.md`

### exercise-02 - Exercise 02 — Workload Identity Design
- Learning file: `lessons/mod-002-zero-trust-architecture/exercises/exercise-02-workload-identity-design.md`
- Output directory: `modules/mod-002-zero-trust-architecture/exercise-02-workload-identity-design`
- Required artifact: `SOLUTION.md`

### exercise-03 - Exercise 03 — Microsegmentation Plan (3 layers)
- Learning file: `lessons/mod-002-zero-trust-architecture/exercises/exercise-03-microsegmentation-plan.md`
- Output directory: `modules/mod-002-zero-trust-architecture/exercise-03-microsegmentation-plan`
- Required artifact: `SOLUTION.md`

### exercise-04 - Exercise 04 — Service-Mesh Authorization Policy
- Learning file: `lessons/mod-002-zero-trust-architecture/exercises/exercise-04-service-mesh-authz.md`
- Output directory: `modules/mod-002-zero-trust-architecture/exercise-04-service-mesh-authz`
- Required artifact: `SOLUTION.md`

### exercise-05 - Exercise 05 — Zero-Trust Roadmap
- Learning file: `lessons/mod-002-zero-trust-architecture/exercises/exercise-05-zero-trust-roadmap.md`
- Output directory: `modules/mod-002-zero-trust-architecture/exercise-05-zero-trust-roadmap`
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
