# Self-heal: address verify findings for fill-mod-010-supply-chain-security-solutions

## Goal

The previous attempt at this work item produced content that
failed contract verification. Fix the specific findings listed
below by editing only the affected files. Do NOT regenerate
from scratch and do NOT broaden the scope.

## Findings

### 1. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-010-supply-chain-security/exercise-01-slsa-self-assessment/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '3. validation steps', '4. rubric', '5. common mistakes', '6. references', 'anti-pattern caught during the worked example', 'inventory of the build', 'self-assigned level and remediation', 'solution — exercise 01: slsa self-assessment', 'walk through each build track requirement']

### 2. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-010-supply-chain-security/exercise-02-signed-pipeline-design/SOLUTION.md is missing required heading(s): implementation, rubric.
- missing: ['implementation', 'rubric']
- seen: ['1. solution overview', '2. worked design', '3. validation steps', '4. review checklist', '5. common mistakes', '6. references', 'design rationale', 'reference workflow (github actions, annotated)', 'solution — exercise 02: signed-pipeline design', 'stage list (build → verify)']

### 3. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-010-supply-chain-security/exercise-03-admission-verification/SOLUTION.md is missing required heading(s): rubric.
- missing: ['rubric']
- seen: ['1. solution overview', '2. worked implementation', '3. validation steps', '4. review checklist', '5. common mistakes', '6. references', 'break-glass', 'option a — sigstore policy-controller', 'option b — kyverno', 'rollout strategy', 'solution — exercise 03: admission verification configuration']

### 4. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-010-supply-chain-security/exercise-04-hugging-face-vetting/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked vetting record', '3. validation steps', '4. rubric', '5. common mistakes', '6. references', 'checklist (executed in order)', 'solution — exercise 04: hugging face model vetting', 'worked decision']

### 5. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-010-supply-chain-security/exercise-05-supply-chain-incident-runbook/SOLUTION.md is missing required heading(s): implementation, rubric.
- missing: ['implementation', 'rubric']
- seen: ['1. solution overview', '2. worked runbook', '3. validation steps', '4. tabletop questions', '5. common mistakes', '6. references', 'communications plan', 'decision points (yes/no for on-call)', 'phase 0 — declare and assemble (target: 15 minutes)', 'phase 1 — scope (target: 30 minutes)', 'phase 2 — contain (target: 1 hour)', 'phase 3 — eradicate (target: 4 hours)', 'phase 4 — recover (same day to next day)', 'phase 5 — postmortem (within 5 business days)', 'scope', 'solution — exercise 05: supply-chain incident runbook', 'trigger list']

### 6. `missing_required_sections` (error)

- Target: `modules/mod-010-supply-chain-security/exercise-01-slsa-self-assessment/SOLUTION.md`
- Message: modules/mod-010-supply-chain-security/exercise-01-slsa-self-assessment/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '3. validation steps', '4. rubric', '5. common mistakes', '6. references', 'anti-pattern caught during the worked example', 'inventory of the build', 'self-assigned level and remediation', 'solution — exercise 01: slsa self-assessment', 'walk through each build track requirement']

### 7. `missing_required_sections` (error)

- Target: `modules/mod-010-supply-chain-security/exercise-02-signed-pipeline-design/SOLUTION.md`
- Message: modules/mod-010-supply-chain-security/exercise-02-signed-pipeline-design/SOLUTION.md is missing required heading(s): implementation, rubric.
- missing: ['implementation', 'rubric']
- seen: ['1. solution overview', '2. worked design', '3. validation steps', '4. review checklist', '5. common mistakes', '6. references', 'design rationale', 'reference workflow (github actions, annotated)', 'solution — exercise 02: signed-pipeline design', 'stage list (build → verify)']

### 8. `missing_required_sections` (error)

- Target: `modules/mod-010-supply-chain-security/exercise-03-admission-verification/SOLUTION.md`
- Message: modules/mod-010-supply-chain-security/exercise-03-admission-verification/SOLUTION.md is missing required heading(s): rubric.
- missing: ['rubric']
- seen: ['1. solution overview', '2. worked implementation', '3. validation steps', '4. review checklist', '5. common mistakes', '6. references', 'break-glass', 'option a — sigstore policy-controller', 'option b — kyverno', 'rollout strategy', 'solution — exercise 03: admission verification configuration']

### 9. `missing_required_sections` (error)

- Target: `modules/mod-010-supply-chain-security/exercise-04-hugging-face-vetting/SOLUTION.md`
- Message: modules/mod-010-supply-chain-security/exercise-04-hugging-face-vetting/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked vetting record', '3. validation steps', '4. rubric', '5. common mistakes', '6. references', 'checklist (executed in order)', 'solution — exercise 04: hugging face model vetting', 'worked decision']

### 10. `missing_required_sections` (error)

- Target: `modules/mod-010-supply-chain-security/exercise-05-supply-chain-incident-runbook/SOLUTION.md`
- Message: modules/mod-010-supply-chain-security/exercise-05-supply-chain-incident-runbook/SOLUTION.md is missing required heading(s): implementation, rubric.
- missing: ['implementation', 'rubric']
- seen: ['1. solution overview', '2. worked runbook', '3. validation steps', '4. tabletop questions', '5. common mistakes', '6. references', 'communications plan', 'decision points (yes/no for on-call)', 'phase 0 — declare and assemble (target: 15 minutes)', 'phase 1 — scope (target: 30 minutes)', 'phase 2 — contain (target: 1 hour)', 'phase 3 — eradicate (target: 4 hours)', 'phase 4 — recover (same day to next day)', 'phase 5 — postmortem (within 5 business days)', 'scope', 'solution — exercise 05: supply-chain incident runbook', 'trigger list']

## Output contract

- Edit ONLY the files listed in the findings.
- Preserve the existing content; add or rename headings
  rather than rewriting whole sections.
- Do NOT touch CURRICULUM.md, VERSIONS.md, or anything
  outside the affected files.
