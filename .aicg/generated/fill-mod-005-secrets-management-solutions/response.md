All 5 reference solutions are written to `modules/mod-005-secrets-management/`. Each `SOLUTION.md` follows the required 6-section contract (Overview → Worked answer → Validation → Rubric → Common mistakes → References), with claims grounded in the listed official sources (OWASP ML Top 10, MITRE ATLAS, NIST AI RMF) plus the directly relevant standards for this topic (NIST SP 800-57 / 800-53 / 800-61 / 800-204D, OWASP Secrets Management Cheat Sheet, Sigstore, Vault, GitHub/AWS/GCP/Azure OIDC).

Summary of what each delivers:

- **exercise-01 — Secrets Inventory**: schema with required columns, T0–T4 classification rules, worked inventory for an ML platform, validation via discovery cross-check, rubric.
- **exercise-02 — Vault Deployment Plan**: 5-node HA Raft topology, KMS auto-unseal, auth methods mapped to real consumers, secret engines, policy templating, audit, backup, 3-phase strangler migration.
- **exercise-03 — Secret Rotation Playbook**: per-class cadence table, the five rotation patterns with the "add-propagate-verify-revoke" rule, worked SEC-003 rotation, failure handling, success-criterion based on audit.
- **exercise-04 — Keyless CI Design**: GitHub Actions → AWS STS via OIDC with subject-pinned trust, Cosign keyless image + model signing, in-toto SLSA attestations, ClusterImagePolicy verification, Vault OIDC for build-time secrets, threat coverage table.
- **exercise-05 — Secret-Leak Incident Runbook**: NIST 800-61-aligned phases, detection sources, severity matrix tied to inventory tiers, 15-minute timed playbook, revoke-first containment with named exceptions, eradication checklist, forensics including ML-specific items, worked SEV-1 scenario for SEC-003.

Because the learning-side exercise files in the sibling `ai-infra-security-learning` repo were not accessible during authoring, each file ends with a `<!-- needs-research: ... -->` marker noting the assumption about scenario scope; per the source policy this blocks auto-merge for a human to reconcile against the actual lesson prompt.
