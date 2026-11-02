# Solutions Index — security-solutions

This repository provides reference implementations for the paired [`security-learning`](../security-learning/) track — the **AI/ML Security & Governance Engineer** curriculum (level 35, AI Governance family).

- Paired learning repo: [`security-learning`](../security-learning/)
- Plan of record: [`security-learning/.aicg/curriculum-plan.json`](../security-learning/.aicg/curriculum-plan.json)
- Requirements catalog: [`security-learning/.aicg/job-requirements.json`](../security-learning/.aicg/job-requirements.json)

## Repository layout

- `modules/` — module-level exercise solutions (mirrors `security-learning/lessons/`)
- `projects/` — project-grade solutions (mirrors `security-learning/projects/`)
- `guides/` — troubleshooting and implementation notes
- `resources/` — supporting references and shared assets

## Synchronization rules

- Module slugs must match `security-learning/lessons/`.
- Every learner-facing exercise or project should eventually have a corresponding solution path here.
- Operational reports belong in the workspace `_meta/housekeeping/`, not the repo root.
- When the paired `.aicg/curriculum-plan.json` migrates legacy `mod-001..mod-012` content to `mod-101..mod-112`, mirror the same migration here — see the `ownership_links[]` map in the plan.

## Module solutions

| Planned module | Legacy solution path (if applicable) | Status |
|---|---|---|
| mod-101-ml-security-governance-position | [`modules/mod-001-ml-security-foundations`](modules/mod-001-ml-security-foundations) (legacy source) | planned — migrate |
| mod-102-threat-modelling-for-ai-ml-systems | (net-new) | planned |
| mod-103-secure-ml-platform-architecture | [`modules/mod-002-zero-trust-architecture`](modules/mod-002-zero-trust-architecture) + [`modules/mod-004-network-security`](modules/mod-004-network-security) (legacy sources) | planned — merge |
| mod-104-data-and-model-lineage-security | (net-new) | planned |
| mod-105-secrets-and-key-management | [`modules/mod-003-cryptography-for-ml`](modules/mod-003-cryptography-for-ml) + [`modules/mod-005-secrets-management`](modules/mod-005-secrets-management) (legacy sources) | planned — merge |
| mod-106-adversarial-ml-defense | [`modules/mod-006-adversarial-ml`](modules/mod-006-adversarial-ml) (legacy source) | planned — repurpose |
| mod-107-llm-agent-security | (net-new) | planned |
| mod-108-privacy-engineering-for-ml | (net-new) | planned |
| mod-109-ai-governance-and-compliance-engineering | [`modules/mod-007-compliance-and-governance`](modules/mod-007-compliance-and-governance) + [`modules/mod-009-policy-as-code`](modules/mod-009-policy-as-code) (legacy sources) | planned — merge |
| mod-110-supply-chain-security-for-ai | [`modules/mod-010-supply-chain-security`](modules/mod-010-supply-chain-security) (legacy source) | planned — repurpose |
| mod-111-security-operations-and-incident-response-for-ml | [`modules/mod-008-runtime-security`](modules/mod-008-runtime-security) + [`modules/mod-011-security-operations`](modules/mod-011-security-operations) (legacy sources) | planned — merge |
| mod-112-program-leadership-for-ml-security-governance | (net-new) | planned |

## Project solutions

| Planned project | Hours | Status |
|---|---|---|
| project-101-secure-mlops-gate-for-one-model | 35 | planned |
| project-102-adversarial-defense-and-privacy-bundle | 40 | planned |
| project-103-ai-governance-control-library-slice | 50 | planned |

The legacy `projects/project-1-zero-trust`, `projects/project-2-compliance`, `projects/project-3-adversarial-defense`, `projects/project-4-secure-cicd`, and `projects/project-5-security-operations` skeletons are preserved for content re-use. Their content will fold into `project-101` (secure-cicd + zero-trust slices), `project-102` (adversarial-defense), and `project-103` (compliance + security-operations slices) during the migration.
