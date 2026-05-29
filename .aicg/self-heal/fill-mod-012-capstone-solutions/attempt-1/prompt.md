# Self-heal: address verify findings for fill-mod-012-capstone-solutions

## Goal

The previous attempt at this work item produced content that
failed contract verification. Fix the specific findings listed
below by editing only the affected files. Do NOT regenerate
from scratch and do NOT broaden the scope.

## Findings

### 1. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-012-capstone/exercise-01-threat-model-and-risk-register/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 scope statement (example)', '2.2 data-flow diagram (trust boundaries called out)', '2.3 stride threat enumeration (excerpt)', '2.4 atlas-aligned ml-specific threats (excerpt)', '2.5 risk register (excerpt)', '2.6 decision rationale (what a reviewer wants to read)', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — capstone exercise 01: threat model + risk register']

### 2. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-012-capstone/exercise-02-security-architecture/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 architectural principles, in priority order', '2.2 architecture diagram (controls overlaid)', '2.3 controls mapped to lifecycle stage and to risks', '2.4 trade-offs and architecture decision records (excerpts)', '2.5 what the architecture does *not* do', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — capstone exercise 02: security architecture']

### 3. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-012-capstone/exercise-03-ml-specific-controls/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 owasp ml top 10 → controls cross-walk', '2.2 control specifications (preventive — detail)', '2.3 control specifications (detective — detail)', '2.4 trade-off and decision notes', '2.5 what is out of scope at this tier (with reason)', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'ctrl-d-01: model-extraction detection', 'ctrl-d-02: training-time poisoning detection', 'ctrl-d-03: promotion-event drift', 'ctrl-p-01: signed-and-attested model promotion', 'ctrl-p-02: tenant-scoped feature-store access', 'ctrl-p-03: schema-validated, signed event ingestion', 'ctrl-p-04: per-tenant inference rate-limit + output rate', 'ctrl-p-05: differentially-private training (selectively applied)', 'solution — capstone exercise 03: ml-specific controls']

### 4. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-012-capstone/exercise-04-compliance-and-policy/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 framework choice and rationale', '2.2 program structure (nist ai rmf 1.0 four-function spine)', '2.3 policies (the rules)', '2.4 policy-as-code: a worked rego example', '2.5 audit and evidence model', '2.6 operating model', '2.7 decision rationale (what a reviewer wants to read)', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — capstone exercise 04: compliance and policy program']

### 5. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-012-capstone/exercise-05-secops-program/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 detection function', '2.2 response function — incident classes and playbooks', '2.3 practice function — tabletop and game day', '2.4 learning function — postmortems', '2.5 operating model', '2.6 decision rationale (what a reviewer wants to read)', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'pb-01: lateral movement (compromised workload)', 'pb-02: model extraction', 'pb-03: data exfiltration from training namespace', 'pb-04: suspicious model promotion', 'pb-05: poisoning suspicion', 'solution — capstone exercise 05: secops program']

### 6. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-012-capstone/exercise-06-stakeholder-portfolio/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 audience map', '2.2 artifact 1 — executive memo (board / sponsor)', '2.3 artifact 2 — engineering leadership briefing (slide outline)', '2.4 artifact 3 — operating-engineer runbook (excerpt)', '2.5 artifact 4 — customer / auditor trust page (outline)', '2.6 artifact 5 — affected-user faq (internal)', '2.7 editorial choices (what was emphasised, what was left out, why)', '2.8 consistency check', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — capstone exercise 06: stakeholder communication portfolio']

### 7. `missing_required_sections` (error)

- Target: `modules/mod-012-capstone/exercise-01-threat-model-and-risk-register/SOLUTION.md`
- Message: modules/mod-012-capstone/exercise-01-threat-model-and-risk-register/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 scope statement (example)', '2.2 data-flow diagram (trust boundaries called out)', '2.3 stride threat enumeration (excerpt)', '2.4 atlas-aligned ml-specific threats (excerpt)', '2.5 risk register (excerpt)', '2.6 decision rationale (what a reviewer wants to read)', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — capstone exercise 01: threat model + risk register']

### 8. `missing_required_sections` (error)

- Target: `modules/mod-012-capstone/exercise-02-security-architecture/SOLUTION.md`
- Message: modules/mod-012-capstone/exercise-02-security-architecture/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 architectural principles, in priority order', '2.2 architecture diagram (controls overlaid)', '2.3 controls mapped to lifecycle stage and to risks', '2.4 trade-offs and architecture decision records (excerpts)', '2.5 what the architecture does *not* do', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — capstone exercise 02: security architecture']

### 9. `missing_required_sections` (error)

- Target: `modules/mod-012-capstone/exercise-03-ml-specific-controls/SOLUTION.md`
- Message: modules/mod-012-capstone/exercise-03-ml-specific-controls/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 owasp ml top 10 → controls cross-walk', '2.2 control specifications (preventive — detail)', '2.3 control specifications (detective — detail)', '2.4 trade-off and decision notes', '2.5 what is out of scope at this tier (with reason)', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'ctrl-d-01: model-extraction detection', 'ctrl-d-02: training-time poisoning detection', 'ctrl-d-03: promotion-event drift', 'ctrl-p-01: signed-and-attested model promotion', 'ctrl-p-02: tenant-scoped feature-store access', 'ctrl-p-03: schema-validated, signed event ingestion', 'ctrl-p-04: per-tenant inference rate-limit + output rate', 'ctrl-p-05: differentially-private training (selectively applied)', 'solution — capstone exercise 03: ml-specific controls']

### 10. `missing_required_sections` (error)

- Target: `modules/mod-012-capstone/exercise-04-compliance-and-policy/SOLUTION.md`
- Message: modules/mod-012-capstone/exercise-04-compliance-and-policy/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 framework choice and rationale', '2.2 program structure (nist ai rmf 1.0 four-function spine)', '2.3 policies (the rules)', '2.4 policy-as-code: a worked rego example', '2.5 audit and evidence model', '2.6 operating model', '2.7 decision rationale (what a reviewer wants to read)', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — capstone exercise 04: compliance and policy program']

### 11. `missing_required_sections` (error)

- Target: `modules/mod-012-capstone/exercise-05-secops-program/SOLUTION.md`
- Message: modules/mod-012-capstone/exercise-05-secops-program/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 detection function', '2.2 response function — incident classes and playbooks', '2.3 practice function — tabletop and game day', '2.4 learning function — postmortems', '2.5 operating model', '2.6 decision rationale (what a reviewer wants to read)', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'pb-01: lateral movement (compromised workload)', 'pb-02: model extraction', 'pb-03: data exfiltration from training namespace', 'pb-04: suspicious model promotion', 'pb-05: poisoning suspicion', 'solution — capstone exercise 05: secops program']

### 12. `missing_required_sections` (error)

- Target: `modules/mod-012-capstone/exercise-06-stakeholder-portfolio/SOLUTION.md`
- Message: modules/mod-012-capstone/exercise-06-stakeholder-portfolio/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '2.1 audience map', '2.2 artifact 1 — executive memo (board / sponsor)', '2.3 artifact 2 — engineering leadership briefing (slide outline)', '2.4 artifact 3 — operating-engineer runbook (excerpt)', '2.5 artifact 4 — customer / auditor trust page (outline)', '2.6 artifact 5 — affected-user faq (internal)', '2.7 editorial choices (what was emphasised, what was left out, why)', '2.8 consistency check', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — capstone exercise 06: stakeholder communication portfolio']

## Output contract

- Edit ONLY the files listed in the findings.
- Preserve the existing content; add or rename headings
  rather than rewriting whole sections.
- Do NOT touch CURRICULUM.md, VERSIONS.md, or anything
  outside the affected files.
