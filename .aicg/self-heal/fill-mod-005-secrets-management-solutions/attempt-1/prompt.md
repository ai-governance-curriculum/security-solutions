# Self-heal: address verify findings for fill-mod-005-secrets-management-solutions

## Goal

The previous attempt at this work item produced content that
failed contract verification. Fix the specific findings listed
below by editing only the affected files. Do NOT regenerate
from scratch and do NOT broaden the scope.

## Findings

### 1. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-005-secrets-management/exercise-01-secrets-inventory/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 inventory schema (the columns that matter)', '2.2 classification tiers (decision rules)', '2.3 worked inventory (representative ml platform)', '2.4 decision rationale (what reviewers should look for)', '2.5 what goes outside the inventory', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — exercise 01: secrets inventory']

### 2. `needs_research_marker` (error)

- Target: `?`
- Message: modules/mod-005-secrets-management/exercise-01-secrets-inventory/SOLUTION.md still contains a `needs-research` marker.

### 3. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-005-secrets-management/exercise-02-vault-deployment-plan/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 target topology', '2.2 auth methods (mapped to actual consumers)', '2.3 secret engines (mapped to inventory tiers)', '2.4 policy model', '2.5 audit', '2.6 backup, recovery, and key custody', '2.7 migration plan from existing stores', '2.8 design decisions and *why*', '2.9 what is deliberately deferred', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — exercise 02: vault deployment plan']

### 4. `needs_research_marker` (error)

- Target: `?`
- Message: modules/mod-005-secrets-management/exercise-02-vault-deployment-plan/SOLUTION.md still contains a `needs-research` marker.

### 5. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-005-secrets-management/exercise-03-secret-rotation-playbook/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 rotation policy by class', '2.2 rotation order (the part that breaks production if wrong)', '2.3 worked example — rotating the model-registry write token (sec-003)', '2.4 calendar and scheduling', '2.5 failure handling', '2.6 detection and audit', '2.7 design rationale', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — exercise 03: secret rotation playbook']

### 6. `needs_research_marker` (error)

- Target: `?`
- Message: modules/mod-005-secrets-management/exercise-03-secret-rotation-playbook/SOLUTION.md still contains a `needs-research` marker.

### 7. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-005-secrets-management/exercise-04-keyless-ci-design/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 reference architecture', '2.2 cloud federation (push path)', '2.3 artefact signing (keyless) and attestation', '2.4 secrets the ci still needs (and how to fetch them keyless-ly)', '2.5 threats this design addresses (and how)', '2.6 design decisions', '2.7 what this solution deliberately omits', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — exercise 04: keyless ci design']

### 8. `needs_research_marker` (error)

- Target: `?`
- Message: modules/mod-005-secrets-management/exercise-04-keyless-ci-design/SOLUTION.md still contains a `needs-research` marker.

### 9. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-005-secrets-management/exercise-05-secret-leak-runbook/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 detection sources', '2.10 worked scenario — model-registry write token leaked', '2.11 design rationale', '2.2 roles', '2.3 severity matrix', '2.4 first 15 minutes (detection → containment start)', '2.5 containment', '2.6 eradication — find every copy', '2.7 forensics — what did the attacker do', '2.8 recovery', '2.9 post-incident', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — exercise 05: secret-leak incident runbook']

### 10. `needs_research_marker` (error)

- Target: `?`
- Message: modules/mod-005-secrets-management/exercise-05-secret-leak-runbook/SOLUTION.md still contains a `needs-research` marker.

### 11. `missing_required_sections` (error)

- Target: `modules/mod-005-secrets-management/exercise-01-secrets-inventory/SOLUTION.md`
- Message: modules/mod-005-secrets-management/exercise-01-secrets-inventory/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 inventory schema (the columns that matter)', '2.2 classification tiers (decision rules)', '2.3 worked inventory (representative ml platform)', '2.4 decision rationale (what reviewers should look for)', '2.5 what goes outside the inventory', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — exercise 01: secrets inventory']

### 12. `needs_research_marker` (error)

- Target: `modules/mod-005-secrets-management/exercise-01-secrets-inventory/SOLUTION.md`
- Message: modules/mod-005-secrets-management/exercise-01-secrets-inventory/SOLUTION.md still contains a `needs-research` marker.

### 13. `missing_required_sections` (error)

- Target: `modules/mod-005-secrets-management/exercise-02-vault-deployment-plan/SOLUTION.md`
- Message: modules/mod-005-secrets-management/exercise-02-vault-deployment-plan/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 target topology', '2.2 auth methods (mapped to actual consumers)', '2.3 secret engines (mapped to inventory tiers)', '2.4 policy model', '2.5 audit', '2.6 backup, recovery, and key custody', '2.7 migration plan from existing stores', '2.8 design decisions and *why*', '2.9 what is deliberately deferred', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — exercise 02: vault deployment plan']

### 14. `needs_research_marker` (error)

- Target: `modules/mod-005-secrets-management/exercise-02-vault-deployment-plan/SOLUTION.md`
- Message: modules/mod-005-secrets-management/exercise-02-vault-deployment-plan/SOLUTION.md still contains a `needs-research` marker.

### 15. `missing_required_sections` (error)

- Target: `modules/mod-005-secrets-management/exercise-03-secret-rotation-playbook/SOLUTION.md`
- Message: modules/mod-005-secrets-management/exercise-03-secret-rotation-playbook/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 rotation policy by class', '2.2 rotation order (the part that breaks production if wrong)', '2.3 worked example — rotating the model-registry write token (sec-003)', '2.4 calendar and scheduling', '2.5 failure handling', '2.6 detection and audit', '2.7 design rationale', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — exercise 03: secret rotation playbook']

### 16. `needs_research_marker` (error)

- Target: `modules/mod-005-secrets-management/exercise-03-secret-rotation-playbook/SOLUTION.md`
- Message: modules/mod-005-secrets-management/exercise-03-secret-rotation-playbook/SOLUTION.md still contains a `needs-research` marker.

### 17. `missing_required_sections` (error)

- Target: `modules/mod-005-secrets-management/exercise-04-keyless-ci-design/SOLUTION.md`
- Message: modules/mod-005-secrets-management/exercise-04-keyless-ci-design/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 reference architecture', '2.2 cloud federation (push path)', '2.3 artefact signing (keyless) and attestation', '2.4 secrets the ci still needs (and how to fetch them keyless-ly)', '2.5 threats this design addresses (and how)', '2.6 design decisions', '2.7 what this solution deliberately omits', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — exercise 04: keyless ci design']

### 18. `needs_research_marker` (error)

- Target: `modules/mod-005-secrets-management/exercise-04-keyless-ci-design/SOLUTION.md`
- Message: modules/mod-005-secrets-management/exercise-04-keyless-ci-design/SOLUTION.md still contains a `needs-research` marker.

### 19. `missing_required_sections` (error)

- Target: `modules/mod-005-secrets-management/exercise-05-secret-leak-runbook/SOLUTION.md`
- Message: modules/mod-005-secrets-management/exercise-05-secret-leak-runbook/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 detection sources', '2.10 worked scenario — model-registry write token leaked', '2.11 design rationale', '2.2 roles', '2.3 severity matrix', '2.4 first 15 minutes (detection → containment start)', '2.5 containment', '2.6 eradication — find every copy', '2.7 forensics — what did the attacker do', '2.8 recovery', '2.9 post-incident', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — exercise 05: secret-leak incident runbook']

### 20. `needs_research_marker` (error)

- Target: `modules/mod-005-secrets-management/exercise-05-secret-leak-runbook/SOLUTION.md`
- Message: modules/mod-005-secrets-management/exercise-05-secret-leak-runbook/SOLUTION.md still contains a `needs-research` marker.

## Output contract

- Edit ONLY the files listed in the findings.
- Preserve the existing content; add or rename headings
  rather than rewriting whole sections.
- Do NOT touch CURRICULUM.md, VERSIONS.md, or anything
  outside the affected files.
