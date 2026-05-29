# Self-heal: address verify findings for fill-mod-003-cryptography-for-ml-solutions

## Goal

The previous attempt at this work item produced content that
failed contract verification. Fix the specific findings listed
below by editing only the affected files. Do NOT regenerate
from scratch and do NOT broaden the scope.

## Findings

### 1. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-003-cryptography-for-ml/exercise-01-key-management-plan/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer — the kmp itself', '2.1 document metadata', '2.2 roles (raci for cryptographic operations)', '2.3 key inventory (worked example)', '2.4 lifecycle procedures', '2.5 algorithm transition plan', '2.6 incident response (key compromise)', '2.7 ml-specific considerations', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — exercise 01: key management plan (ml platform)']

### 2. `needs_research_marker` (error)

- Target: `?`
- Message: modules/mod-003-cryptography-for-ml/exercise-01-key-management-plan/SOLUTION.md still contains a `needs-research` marker.

### 3. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-003-cryptography-for-ml/exercise-02-tls-mtls-audit/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked audit', '2.1 scope and target inventory', '2.2 audit checklist', '2.3 reproducible scan', '2.3.1 active tls probe (testssl.sh)', '2.3.2 active tls probe (nmap fallback)', '2.3.3 mtls probe', '2.3.4 static config audit', '2.4 findings template', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'certificate', 'cipher suites (tls 1.2 — if enabled)', 'cipher suites (tls 1.3 — the suite is implicit; verify these are offered)', 'http layer (for https only)', 'key exchange / groups', 'mtls-specific', 'protocol and version', 'server settings', 'signature algorithms', 'solution — exercise 02: tls / mtls configuration audit']

### 4. `needs_research_marker` (error)

- Target: `?`
- Message: modules/mod-003-cryptography-for-ml/exercise-02-tls-mtls-audit/SOLUTION.md still contains a `needs-research` marker.

### 5. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-003-cryptography-for-ml/exercise-03-signed-artifact-rollout/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer — the rollout', '2.1 inventory of artifacts that must be signed', '2.2 trust topology', '2.3 signing flow (per artifact class)', '2.4 verification policy', '2.5 rollout phases', '2.6 break-glass procedure', '2.7 key-compromise drill', '2.8 monitoring', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'container image', 'model artifact (registered as an oci artifact)', 'solution — exercise 03: signed-artifact rollout plan']

### 6. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-003-cryptography-for-ml/exercise-04-certificate-runbook/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer — the runbook', '2.1 certificate inventory (one row per cert family)', '2.2 issuance procedure', '2.3 renewal / rotation', '2.4 monitoring', '2.5 revocation', '2.6 incident response', '2.7 on-call quick reference', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'cf-01 / cf-05 (cert-manager + acme or vault pki)', 'cf-03 (spiffe svid)', 'cf-07 / cf-08 (intermediate / root)', 'incident a: cert expired in prod', 'incident b: ca outage (acme down)', 'incident c: private key compromise', 'incident d: trust bundle drift', 'solution — exercise 04: certificate management runbook']

### 7. `missing_required_sections` (error)

- Target: `?`
- Message: modules/mod-003-cryptography-for-ml/exercise-05-encryption-in-use-decision/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer — the decision document', '2.1 document metadata', '2.2 what "in use" must protect', '2.3 comparison matrix', '2.4 decision and rationale', '2.5 operational requirements (whichever family is chosen)', '2.6 acceptance criteria', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — exercise 05: encryption-in-use decision document']

### 8. `needs_research_marker` (error)

- Target: `?`
- Message: modules/mod-003-cryptography-for-ml/exercise-05-encryption-in-use-decision/SOLUTION.md still contains a `needs-research` marker.

### 9. `missing_required_sections` (error)

- Target: `modules/mod-003-cryptography-for-ml/exercise-01-key-management-plan/SOLUTION.md`
- Message: modules/mod-003-cryptography-for-ml/exercise-01-key-management-plan/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer — the kmp itself', '2.1 document metadata', '2.2 roles (raci for cryptographic operations)', '2.3 key inventory (worked example)', '2.4 lifecycle procedures', '2.5 algorithm transition plan', '2.6 incident response (key compromise)', '2.7 ml-specific considerations', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — exercise 01: key management plan (ml platform)']

### 10. `needs_research_marker` (error)

- Target: `modules/mod-003-cryptography-for-ml/exercise-01-key-management-plan/SOLUTION.md`
- Message: modules/mod-003-cryptography-for-ml/exercise-01-key-management-plan/SOLUTION.md still contains a `needs-research` marker.

### 11. `missing_required_sections` (error)

- Target: `modules/mod-003-cryptography-for-ml/exercise-02-tls-mtls-audit/SOLUTION.md`
- Message: modules/mod-003-cryptography-for-ml/exercise-02-tls-mtls-audit/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked audit', '2.1 scope and target inventory', '2.2 audit checklist', '2.3 reproducible scan', '2.3.1 active tls probe (testssl.sh)', '2.3.2 active tls probe (nmap fallback)', '2.3.3 mtls probe', '2.3.4 static config audit', '2.4 findings template', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'certificate', 'cipher suites (tls 1.2 — if enabled)', 'cipher suites (tls 1.3 — the suite is implicit; verify these are offered)', 'http layer (for https only)', 'key exchange / groups', 'mtls-specific', 'protocol and version', 'server settings', 'signature algorithms', 'solution — exercise 02: tls / mtls configuration audit']

### 12. `needs_research_marker` (error)

- Target: `modules/mod-003-cryptography-for-ml/exercise-02-tls-mtls-audit/SOLUTION.md`
- Message: modules/mod-003-cryptography-for-ml/exercise-02-tls-mtls-audit/SOLUTION.md still contains a `needs-research` marker.

### 13. `missing_required_sections` (error)

- Target: `modules/mod-003-cryptography-for-ml/exercise-03-signed-artifact-rollout/SOLUTION.md`
- Message: modules/mod-003-cryptography-for-ml/exercise-03-signed-artifact-rollout/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer — the rollout', '2.1 inventory of artifacts that must be signed', '2.2 trust topology', '2.3 signing flow (per artifact class)', '2.4 verification policy', '2.5 rollout phases', '2.6 break-glass procedure', '2.7 key-compromise drill', '2.8 monitoring', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'container image', 'model artifact (registered as an oci artifact)', 'solution — exercise 03: signed-artifact rollout plan']

### 14. `missing_required_sections` (error)

- Target: `modules/mod-003-cryptography-for-ml/exercise-04-certificate-runbook/SOLUTION.md`
- Message: modules/mod-003-cryptography-for-ml/exercise-04-certificate-runbook/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer — the runbook', '2.1 certificate inventory (one row per cert family)', '2.2 issuance procedure', '2.3 renewal / rotation', '2.4 monitoring', '2.5 revocation', '2.6 incident response', '2.7 on-call quick reference', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'cf-01 / cf-05 (cert-manager + acme or vault pki)', 'cf-03 (spiffe svid)', 'cf-07 / cf-08 (intermediate / root)', 'incident a: cert expired in prod', 'incident b: ca outage (acme down)', 'incident c: private key compromise', 'incident d: trust bundle drift', 'solution — exercise 04: certificate management runbook']

### 15. `missing_required_sections` (error)

- Target: `modules/mod-003-cryptography-for-ml/exercise-05-encryption-in-use-decision/SOLUTION.md`
- Message: modules/mod-003-cryptography-for-ml/exercise-05-encryption-in-use-decision/SOLUTION.md is missing required heading(s): implementation.
- missing: ['implementation']
- seen: ['1. solution overview', '2. worked answer — the decision document', '2.1 document metadata', '2.2 what "in use" must protect', '2.3 comparison matrix', '2.4 decision and rationale', '2.5 operational requirements (whichever family is chosen)', '2.6 acceptance criteria', '3. validation steps', '4. rubric / review checklist', '5. common mistakes', '6. references', 'solution — exercise 05: encryption-in-use decision document']

### 16. `needs_research_marker` (error)

- Target: `modules/mod-003-cryptography-for-ml/exercise-05-encryption-in-use-decision/SOLUTION.md`
- Message: modules/mod-003-cryptography-for-ml/exercise-05-encryption-in-use-decision/SOLUTION.md still contains a `needs-research` marker.

## Output contract

- Edit ONLY the files listed in the findings.
- Preserve the existing content; add or rename headings
  rather than rewriting whole sections.
- Do NOT touch CURRICULUM.md, VERSIONS.md, or anything
  outside the affected files.
