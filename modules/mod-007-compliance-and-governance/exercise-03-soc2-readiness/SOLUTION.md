# SOLUTION — Exercise 03: SOC 2 Readiness Assessment

> Read this *after* attempting the learning-side exercise. The worked
> assessment below shows the format auditors will recognize and the
> reasoning that converts a pile of evidence into a defensible
> readiness conclusion.

## 1. Solution overview

SOC 2 is an attestation, not a certification. A licensed CPA firm
expresses an opinion on whether the system's controls were
suitably designed (Type 1) or operated effectively over a period
(Type 2) against the AICPA Trust Services Criteria (TSC). The
*readiness assessment* is the internal exercise — usually run before
engaging an auditor — that identifies gaps you would otherwise pay
the auditor to discover.

The deliverable is a memo that:

1. States the report type and TSC categories targeted (the *scope*).
2. Maps in-scope controls to TSC points of focus.
3. Tests each control sample, captures the result, and rates the gap.
4. Concludes whether the entity is ready to engage an auditor, and if
   not, what remediation must complete before the observation window
   starts (Type 2) or before the as-of date (Type 1).

A good readiness assessment is honest. An assessment that finds zero
gaps is almost always a poor assessment.

## 2. Implementation

### 2.1 Scope decision

| Question | Answer |
|---|---|
| Report type | SOC 2 Type 2 |
| Observation window | 6 months for the first Type 2 (3 months acceptable but reduces customer value) |
| TSC categories | Security (mandatory), Confidentiality, Availability. Privacy and Processing Integrity deferred to v2 of the program |
| Subservice organizations | Cloud provider (carve-out method): customer-responsibility controls noted in the management description |
| Systems in scope | The production ML inference plane, model training pipeline, customer admin console, audit log subsystem |
| Systems out of scope | Marketing site, employee productivity SaaS, R&D notebooks not connected to production data |
| Period | Trailing window ending at the audit start date |

Justification for the scope:

- **Security is mandatory under SOC 2.** Other TSCs are elected.
- **Confidentiality** is included because customer ML data is contracted
  as confidential.
- **Availability** is included because customers contract on uptime SLAs.
- **Privacy** is deferred because the company's privacy program (GDPR
  plan from exercise-02) is younger than 12 months; adding it would
  risk a qualified opinion.
- **Processing Integrity** is deferred because ML output correctness
  controls (covered in mod-006-adversarial-ml) are still maturing.
- **Carve-out** for the cloud provider matches industry norm and uses
  the provider's own SOC 2 report.

### 2.2 Control-to-criteria mapping (excerpt)

Mapping format: TSC → company control → owner → evidence type → test.
SOC 2 TSC is organized as Common Criteria (CC1–CC9) plus
category-specific criteria. The excerpt below shows representative
mappings; the production assessment covers every TSC point of focus
in scope.

| TSC area | Company control | Owner | Evidence | Test |
|---|---|---|---|---|
| CC1 Control Environment | Code of conduct, security policy, role definitions reviewed annually | People + CISO | Signed policies, annual attestation record | Sample 25 hires; confirm policy acknowledgment within onboarding window |
| CC2 Communication & Information | Internal & external commitments communicated via published security page | Marketing + CISO | Live page snapshot, change log | Confirm material changes within last period were re-communicated |
| CC3 Risk Assessment | Annual risk assessment with ML-specific threat catalog (OWASP ML Top 10, MITRE ATLAS mapping) | CISO | Risk register, mitigation owners | Sample 5 risks; verify mitigation status and re-rating |
| CC4 Monitoring Activities | Continuous control monitoring (see exercise-04) with named control owners and findings tickets | SecOps | Monitoring dashboard, ticket history | Walk a finding from detection to closure |
| CC5 Control Activities | Documented engineering controls (SDLC, change management) | Eng leadership | Change tickets, peer reviews | Sample 25 changes; confirm review, approval, rollback evidence |
| CC6 Logical & Physical Access | IAM with MFA, least privilege, quarterly access reviews, JIT to production | Infra + SecOps | IAM exports, review records | Sample 25 access changes; verify least privilege, MFA, JIT logs |
| CC7 System Operations | Vuln management, incident response, logging, anomaly detection | SecOps | Scan results, IR tickets, SIEM | Sample 5 vulns; verify SLA adherence. Walk an incident end-to-end |
| CC8 Change Management | Production change ticket required, CI gates required, segregation of duties for deploys | Eng leadership | CI logs, deployment audit | Sample 25 deploys; confirm gate evidence |
| CC9 Risk Mitigation | Vendor risk reviews (see exercise-05), business continuity | Procurement + CISO | Vendor register, BCP test | Sample 5 vendors; verify reassessment |
| A1 Availability | Capacity planning, backups, restore tests, DR runbooks | SRE | Restore-test report, post-incident reviews | Confirm restore test completed in period |
| C1 Confidentiality | Data classification, encryption, retention, secure disposal | Data platform | Classification catalog, KMS logs, disposal certs | Sample 10 records; verify retention enforcement |
| ML-specific (mapped under CC3/CC7) | Model release gate covering eval, security scan, eval-set integrity | ML platform | Release record per model | Sample 5 releases; verify gate completeness |
| ML-specific (under CC7) | Adversarial-input detection telemetry (cross-reference mod-006) | SecOps + ML | SIEM dashboards | Walk a detection-to-triage event |

### 2.3 Sample readiness findings

| ID | Severity | Finding | Affected criterion | Remediation |
|---|---|---|---|---|
| R-01 | High | Policy review attestation is annual on paper but last completed 14 months ago | CC1 | Re-run attestation; tighten reminder; pre-audit |
| R-02 | High | Quarterly access reviews evidenced for engineering org only; ML platform org missing 2 quarters | CC6 | Backfill reviews; add ML platform to review tooling |
| R-03 | Medium | Vendor risk register has 3 vendors with reassessment overdue >180 days | CC9 | Reassess; remediate before observation window |
| R-04 | Medium | Restore-test runs but does not validate that erased subjects remain erased after restore | A1 + C1 | Extend restore-test scope (cross-reference exercise-02 control C-7) |
| R-05 | Medium | Model release gate evidence is captured in chat threads, not a system of record | CC8 + ML | Move gate to ticketed workflow with structured fields |
| R-06 | Low | DLP coverage on outbound model responses is alert-only, not blocking | CC7 + C1 | Document compensating control or escalate to blocking |
| R-07 | Low | Customer-facing breach-notification clock not codified internally as a control | CC2 + CC7 | Encode as SLA in IR playbook |

### 2.4 Readiness conclusion

**Not yet ready for Type 2 with start-of-window today.** High-severity
findings R-01 and R-02 would each generate a probable exception, with
R-02 likely a control-failure issue rather than a one-off, raising the
risk of a *qualified* opinion on CC6. Recommend:

1. Close R-01 and R-02 before the observation window starts.
2. Close R-03 and R-04 within the first 30 days of the window so the
   sample of period evidence is clean.
3. Address R-05 through R-07 during the window with documented
   timelines so the auditor sees an active remediation track even if
   they sample early.
4. Re-baseline this readiness in 60 days.

## 3. Validation steps

1. **Tie scope decisions to facts.** A reviewer should be able to ask
   "why is privacy out of scope?" and find a documented reason.
2. **Sample a control end-to-end.** Pick a row from the mapping table
   and trace it: policy → procedure → control activity → evidence →
   test. Anywhere this breaks is a finding.
3. **Sanity-check the severity ratings.** A "low" finding that an
   auditor will mark as a control failure is mis-rated; assume
   auditor-conservative.
4. **Cross-reference exercise-02 (GDPR) and exercise-05 (vendor risk).**
   The TOMs and vendor register that satisfy GDPR controls map to
   SOC 2 controls; readiness should not duplicate work or
   double-report.
5. **Mock the Management's Description of the System.** SOC 2 reports
   open with a management description; if the company cannot describe
   the system in one document, the assessment is incomplete.

## 4. Rubric / review checklist

| Criterion | Weight | Pass condition |
|---|---|---|
| Report type and observation window stated and justified | 10% | Type 1 vs. Type 2 reasoned, not assumed |
| TSC categories in/out of scope each carry a justification | 10% | Every inclusion/exclusion has a reason |
| Subservice treatment declared (inclusive vs. carve-out) | 5% | Stated explicitly |
| Common Criteria CC1–CC9 each have at least one company control mapped | 15% | No CC area is blank |
| ML-specific controls mapped to relevant CC items | 10% | Release gate, eval-set integrity, adversarial telemetry appear |
| Sample findings include high, medium, and low | 10% | A finding-set with only lows is not credible |
| Each finding has a remediation owner and date | 10% | Owners are roles or people, dates are concrete |
| Conclusion is explicit and defensible | 10% | "Ready / not ready" stated with reasoning |
| Cross-reference to GDPR plan and vendor-risk review | 5% | Reuses controls instead of duplicating |
| Honest about gaps | 10% | Includes at least one finding the company would prefer to hide |
| No invented audit citations or AICPA quotes | 5% | Cites AICPA TSC at the source, not paraphrased blogs |

Pass ≥ 70%. An assessment with zero high findings on a six-month-old
program is rarely honest; flag for redo if the reviewer believes a
real auditor would generate more.

## 5. Common mistakes

- **Picking Type 1 to avoid the observation window.** Type 1 is
  legitimate for a first report but offers customers far less
  assurance; not stating the trade-off is the mistake.
- **Including Privacy because it sounds good.** Privacy is a heavy
  TSC; including it without a mature privacy program courts a
  qualified opinion.
- **Treating the cloud provider's SOC 2 as a free pass.** A
  carve-out report still requires the customer to operate
  controls on its side of the responsibility split.
- **Treating policies as controls.** A policy without a procedure
  and an evidence trail is not a control.
- **Designing "evidence" as PDFs.** Auditors will want system
  evidence (logs, tickets, configuration exports), not
  hand-curated PDFs.
- **Skipping ML-specific controls.** SOC 2 doesn't have an "ML
  section"; the assessor must map ML controls into Common
  Criteria, especially CC3 (risk), CC7 (operations), and CC8
  (change management).
- **Confusing readiness with the audit.** Readiness is the dress
  rehearsal; the audit is the show. The output is a remediation
  plan, not a clean opinion.

## 6. References

- AICPA — Trust Services Criteria (TSP Section 100). Cite the
  current TSC publication directly when running the real
  assessment; this document references the criteria at the
  category level only to avoid drift.
- NIST AI Risk Management Framework — governance scaffolding that
  maps cleanly onto SOC 2 Common Criteria CC3 and CC4.
  https://www.nist.gov/itl/ai-risk-management-framework
- NIST AI 600-1: Generative AI Profile — risk actions used to
  populate ML-specific entries in the risk register.
  https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- OWASP Machine Learning Security Top 10 — input to the risk
  catalog for CC3.
  https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS — adversary tactics referenced in the
  ML-specific control rows.
  https://atlas.mitre.org/
- VeriSwarm Trust Center — practitioner example of a customer-
  facing trust posture, including SOC 2 status presentation.
  https://veriswarm.ai/trust
