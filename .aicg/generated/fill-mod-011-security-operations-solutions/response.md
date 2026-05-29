All five SOLUTION.md files are in place under `modules/mod-011-security-operations/`:

- `exercise-01-siem-evaluation/SOLUTION.md` — worked SIEM decision document recommending Elastic Security, with weighted criteria, four-candidate side-by-side, trade-offs, phased migration, and re-evaluation triggers.
- `exercise-02-ml-detection-ruleset/SOLUTION.md` — 11 Sigma rules tagged to MITRE ATLAS/ATT&CK, with FP scenarios, triage steps, tuning levers, coverage analysis, named gaps, and per-rule tuning plan.
- `exercise-03-ml-ir-procedure/SOLUTION.md` — IR procedure (roles with authority bounds, objective severity criteria, phase time bounds, comms structure, tools/access matrix, GDPR/HIPAA clocks) plus all 5 ML-specific playbooks.
- `exercise-04-tabletop-library/SOLUTION.md` — 3 required scenarios + 1 stretch, each with Setup/Injects/Decision points/Expected outcomes/Common mistakes/Grading rubric, plus facilitator guide and quarterly rotation plan.
- `exercise-05-postmortem-template/SOLUTION.md` — reusable blameless template + fully worked exfiltration example with internally consistent timeline matching the brief (T+36h detection, T+38.5h containment), 5-Whys, 7 action items, and full regulatory-clock tracking.

Each file follows the required 6-section output contract (overview, worked answer, validation steps, rubric, common mistakes, references) and grounds claims in OWASP ML Top 10, MITRE ATLAS, NIST AI RMF, GDPR Art. 33/34, and the HIPAA Breach Notification Rule. Unverifiable factual claims (Elastic/Datadog/Sentinel/Splunk current list pricing, specific ATLAS technique-ID confirmation, the illustrative CVE) are marked with `<!-- needs-research: ... -->` per the source policy.
