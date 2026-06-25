# Project 2 Solution — Compliance Framework

Reference for [learning project 2](https://github.com/ai-governance-curriculum/security-learning/tree/main/projects/project-2-compliance).

The full FastAPI implementation lives in [mlops-learning/projects/project-4-governance](https://github.com/ai-infra-curriculum/ai-infra-mlops-learning/tree/main/projects/project-4-governance):
- `src/audit/log.py` — tamper-evident hash chain
- `src/compliance/gdpr.py` — subject request handler (delete/export/explain)
- `src/model_cards/template.py` — Jinja model card generator
- `src/fairness/metrics.py` — disparate impact, four-fifths rule

This solution-side directory adds the security-specific additions on top of
the governance base.

## Layout

```
project-2-compliance/
├── README.md
├── quarterly_report/        # auto-generated GDPR/HIPAA/SOC 2 reports
├── data_inventory/          # classification + scan tooling
└── retention/               # automated retention enforcement
```
