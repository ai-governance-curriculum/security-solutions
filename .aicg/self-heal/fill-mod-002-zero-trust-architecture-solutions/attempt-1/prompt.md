# Self-heal: address verify findings for fill-mod-002-zero-trust-architecture-solutions

## Goal

The previous attempt at this work item produced content that
failed contract verification. Fix the specific findings listed
below by editing only the affected files. Do NOT regenerate
from scratch and do NOT broaden the scope.

## Findings

### 1. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-002-zero-trust-architecture/exercise-01-zero-trust-gap-analysis/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — exercise 01: zero-trust gap analysis', 'summary table', 'tenet 1 — every resource access is authenticated, authorized, and encrypted, regardless of origin', 'tenet 2 — access decisions are made per-request, not per-session', 'tenet 3 — resource access follows least privilege, scoped to the specific operation', 'tenet 4 — all assets are inventoried, identifiable, and protected', 'tenet 5 — posture informs access; failing assets lose privileges, not just generate alerts', 'top 3 gaps to address first', "what zero-trust doesn't help with at smartrecs", 'zero-trust gap analysis: smartrecs']

### 2. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-002-zero-trust-architecture/exercise-02-workload-identity-design/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'cross-workload identity flows', 'design rationale', 'smartrecs workload identity design', 'solution — exercise 02: workload identity design', 'trade-offs accepted', 'trust domain', 'what changes if smartrecs adds a second team', 'why these attestation selectors', 'why these least-privilege boundaries', 'why these ttls', 'workload identity table']

### 3. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-002-zero-trust-architecture/exercise-03-microsegmentation-plan/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'acknowledged gaps', 'cross-layer coverage table', 'decision 1 — per-tenant feature access', 'decision 2 — per-version model-artifact access', 'decision 3 — audit-log append-only enforcement', 'layer 1 — l3/l4 networkpolicy', 'layer 2 — mesh authorization', 'layer 3 — application-layer authorization', 'policy 1.1 — default-deny in `recs`', 'policy 1.2 — gateway → serving allow', 'policy 1.3 — serving → feature-store allow', 'policy 1.4 — training-job egress allow (warehouse)', 'policy 2.1 — gateway-only access to serving `/v1/predict`', 'policy 2.2 — read-only feature-api access from `recs/model-serving`', 'smartrecs microsegmentation plan', 'solution — exercise 03: microsegmentation plan (3 layers)', "why these can't be made at the mesh"]

### 4. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-002-zero-trust-architecture/exercise-04-service-mesh-authz/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'attack scenarios', 'background — the principal format', 'belt-and-braces — explicit deny for write methods on feature-api', 'coverage table', 'mesh authorization plan', 'policies 3–6 — feature-api access', 'policy 1 — `gateway` → `serving-recs` (`post /v1/predict`)', 'policy 2 — `gateway` → `serving-fraud` (`post /v1/score`)', 'policy 7 — `governance` → all serving (`get /v1/healthz`, `get /v1/model-card`)', 'solution — exercise 04: service-mesh authorization policy', 'what this still does not catch']

### 5. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-002-zero-trust-architecture/exercise-05-zero-trust-roadmap/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['"done" definition', '1. solution overview', '2. worked answer', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'cfo-friendly summary', 'executive summary', 'phase 1 — foundations (low-commitment, reversible) — ~4 months', 'phase 2 — microsegmentation (medium-commitment) — ~6 months', 'phase 3 — identity-first at scale (heavy-commitment) — ~5 months', 'risks and mitigations', 'smartrecs zero-trust adoption roadmap', 'solution — exercise 05: zero-trust roadmap', "what this roadmap doesn't include"]

### 6. `missing_required_sections` (error)

- Target: `modules/mod-002-zero-trust-architecture/exercise-01-zero-trust-gap-analysis/SOLUTION.md`
- Message: modules/mod-002-zero-trust-architecture/exercise-01-zero-trust-gap-analysis/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — exercise 01: zero-trust gap analysis', 'summary table', 'tenet 1 — every resource access is authenticated, authorized, and encrypted, regardless of origin', 'tenet 2 — access decisions are made per-request, not per-session', 'tenet 3 — resource access follows least privilege, scoped to the specific operation', 'tenet 4 — all assets are inventoried, identifiable, and protected', 'tenet 5 — posture informs access; failing assets lose privileges, not just generate alerts', 'top 3 gaps to address first', "what zero-trust doesn't help with at smartrecs", 'zero-trust gap analysis: smartrecs']

### 7. `missing_required_sections` (error)

- Target: `modules/mod-002-zero-trust-architecture/exercise-02-workload-identity-design/SOLUTION.md`
- Message: modules/mod-002-zero-trust-architecture/exercise-02-workload-identity-design/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'cross-workload identity flows', 'design rationale', 'smartrecs workload identity design', 'solution — exercise 02: workload identity design', 'trade-offs accepted', 'trust domain', 'what changes if smartrecs adds a second team', 'why these attestation selectors', 'why these least-privilege boundaries', 'why these ttls', 'workload identity table']

### 8. `missing_required_sections` (error)

- Target: `modules/mod-002-zero-trust-architecture/exercise-03-microsegmentation-plan/SOLUTION.md`
- Message: modules/mod-002-zero-trust-architecture/exercise-03-microsegmentation-plan/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'acknowledged gaps', 'cross-layer coverage table', 'decision 1 — per-tenant feature access', 'decision 2 — per-version model-artifact access', 'decision 3 — audit-log append-only enforcement', 'layer 1 — l3/l4 networkpolicy', 'layer 2 — mesh authorization', 'layer 3 — application-layer authorization', 'policy 1.1 — default-deny in `recs`', 'policy 1.2 — gateway → serving allow', 'policy 1.3 — serving → feature-store allow', 'policy 1.4 — training-job egress allow (warehouse)', 'policy 2.1 — gateway-only access to serving `/v1/predict`', 'policy 2.2 — read-only feature-api access from `recs/model-serving`', 'smartrecs microsegmentation plan', 'solution — exercise 03: microsegmentation plan (3 layers)', "why these can't be made at the mesh"]

### 9. `missing_required_sections` (error)

- Target: `modules/mod-002-zero-trust-architecture/exercise-04-service-mesh-authz/SOLUTION.md`
- Message: modules/mod-002-zero-trust-architecture/exercise-04-service-mesh-authz/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'attack scenarios', 'background — the principal format', 'belt-and-braces — explicit deny for write methods on feature-api', 'coverage table', 'mesh authorization plan', 'policies 3–6 — feature-api access', 'policy 1 — `gateway` → `serving-recs` (`post /v1/predict`)', 'policy 2 — `gateway` → `serving-fraud` (`post /v1/score`)', 'policy 7 — `governance` → all serving (`get /v1/healthz`, `get /v1/model-card`)', 'solution — exercise 04: service-mesh authorization policy', 'what this still does not catch']

### 10. `missing_required_sections` (error)

- Target: `modules/mod-002-zero-trust-architecture/exercise-05-zero-trust-roadmap/SOLUTION.md`
- Message: modules/mod-002-zero-trust-architecture/exercise-05-zero-trust-roadmap/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['"done" definition', '1. solution overview', '2. worked answer', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'cfo-friendly summary', 'executive summary', 'phase 1 — foundations (low-commitment, reversible) — ~4 months', 'phase 2 — microsegmentation (medium-commitment) — ~6 months', 'phase 3 — identity-first at scale (heavy-commitment) — ~5 months', 'risks and mitigations', 'smartrecs zero-trust adoption roadmap', 'solution — exercise 05: zero-trust roadmap', "what this roadmap doesn't include"]

## Output contract

- Edit ONLY the files listed in the findings.
- Preserve the existing content; add or rename headings
  rather than rewriting whole sections.
- Do NOT touch CURRICULUM.md, VERSIONS.md, or anything
  outside the affected files.
