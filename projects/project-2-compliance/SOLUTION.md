# SOLUTION — Compliance Framework

> Read this *after* attempting the learning-side project. This file
> explains the design decisions behind the reference implementation, what
> is deliberately simplified, and what would need hardening for
> production.

## What problem this solves

ML systems collect, derive from, and act on regulated data: PII for
prediction inputs, training datasets that mix consented and non-consented
records, and outputs that can themselves be regulated (e.g., creditworthiness
decisions under FCRA / Equal Credit Opportunity Act). Three concrete needs:

1. **Subject rights** — delete, export, and explain on request, with proof.
2. **Auditability** — every model decision that touches regulated data
   must be reconstructable from logs that can survive an adversarial
   insider.
3. **Reporting** — quarterly evidence packs for GDPR, HIPAA, SOC 2.

## Why this directory is intentionally small

The bulk of the compliance implementation lives in the
**mlops-learning** repo at
`projects/project-4-governance/`. That repo has the FastAPI service,
hash-chain audit log, model card generator, and fairness metrics —
because compliance is fundamentally a *platform-engineering*
implementation problem, not a security-only one.

This security-side folder adds the security-specific additions on top of
that base:

- `data_inventory/` — classification scanners that walk feature stores
  and label fields by sensitivity.
- `quarterly_report/` — automated evidence packs that pull from the
  governance hash chain and produce a signed PDF.
- `retention/` — automated enforcement of retention windows derived
  from data class.

## Design decisions and *why*

### Why a hash chain (not blockchain) for audit

A blockchain solves trust between mutually-untrusted parties — a real
overspend for an internal audit log. A simple Merkle hash chain (each
entry's hash includes the previous entry's hash, periodic anchors signed
by an external timestamp authority) gives you tamper-evidence at a
fraction of the operational cost. The base implementation in the
governance project follows this approach.

### Why data classification at the *feature* level, not the *table* level

Sensitivity travels with the column, not the table. A feature derived from
a sensitive field stays sensitive even when joined into a new dataset.
The `data_inventory/` scanner therefore tags features, propagates
sensitivity through lineage, and surfaces "an `unrestricted` feature is
fed by a `restricted` upstream" as a hard violation.

### Why pre-generated quarterly reports (vs. on-demand auditor access)

Auditors will see what you choose to surface anyway. Pre-generating the
evidence pack on a fixed schedule (a) makes the evidence harder to
selectively shape, (b) gives engineering early warning of failing
controls, (c) lets you sign the pack at generation time so any
post-hoc edit is detectable.

### Why retention is *enforced* in code, not just *documented* in policy

A retention policy that exists only in Confluence is not a retention
policy. The enforcement loop in `retention/` reads the data-class
catalog, walks storage, and *actually deletes* records past their TTL —
emitting a signed deletion certificate per record into the hash chain
so you can prove the deletion happened.

## How to read the code

Execution-order reading path:

1. **Start in mlops-learning** — `projects/project-4-governance/src/audit/log.py`
   to see the hash-chain implementation that everything else builds on.
2. `data_inventory/` — how features get tagged.
3. `retention/` — how the tagged-data lifecycle gets enforced.
4. `quarterly_report/` — how the evidence pack gets generated and signed.

## What's deliberately simplified

- **Single hash-chain anchor.** A real deployment would publish anchors
  to multiple independent timestamp authorities (RFC 3161, OpenTimestamps).
- **No formal regulatory mapping.** The quarterly pack template includes
  GDPR/HIPAA/SOC 2 sections but does not encode the full control catalog —
  it covers the controls this curriculum touches.
- **No formal explainability surface.** "Explain" requests in the
  governance project use a stub explainer; replacing with SHAP / Anchor /
  Integrated Gradients is left as an extension.
- **No retention-hold workflow.** Legal holds (suspending automated
  retention for an active dispute) are not implemented.

## Cross-references for deeper coverage

| Topic | Where the deeper implementation lives |
|---|---|
| Audit hash chain | `mlops-learning/projects/project-4-governance/src/audit/log.py` |
| Subject request API (delete/export/explain) | `mlops-learning/projects/project-4-governance/src/compliance/gdpr.py` |
| Model cards | `mlops-learning/projects/project-4-governance/src/model_cards/` |
| Fairness metrics (disparate impact, four-fifths rule) | `mlops-learning/projects/project-4-governance/src/fairness/metrics.py` |
| Backup encryption + access controls | `engineer-solutions/mod-109 exercise-07-secret-management` |

## Production gap checklist

- [ ] Multi-authority hash-chain anchoring (RFC 3161)
- [ ] Full GDPR/HIPAA/SOC 2 control mapping with traceability matrix
- [ ] Real explainability surface (SHAP or similar) wired into the explain endpoint
- [ ] Retention hold (legal hold) workflow
- [ ] Independent attestation of deletion (third-party verifier)
- [ ] Differential privacy budget accounting per subject (for analytics on PII)
- [ ] Cross-region replication of the hash chain with quorum reads
- [ ] Automated PII detection in *output* logs (not just input features)

## Validation

The acceptance test is reproducibility of a *subject erasure*:
1. Submit data with a known subject ID.
2. Train a model on the data, log all activity.
3. Issue a delete request.
4. Verify the data is gone from feature stores, model artifacts, and logs.
5. Verify the deletion certificate exists in the hash chain and validates.

If any of step 4's checks fail, the framework is incomplete — not a bug
in the test.

## Time budget for studying this solution

- **Skim**: 45 min including reading the upstream governance code.
- **Deep**: 6–8 hours to re-implement the hash chain and trace a full
  erasure scenario end-to-end.
