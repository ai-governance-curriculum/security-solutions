# SOLUTION — Exercise 04: Continuous Compliance Design

> Read this *after* attempting the learning-side exercise. The design
> below shows what "continuous compliance" should *do*, what it should
> *produce*, and what it should *not* try to be.

## 1. Solution overview

Continuous compliance is the practice of running compliance controls as
code: automated, observable, and tied to a system of record so that
evidence is generated as a byproduct of operation rather than collected
in a fire drill before each audit.

The learner is asked to design — not necessarily fully implement — a
continuous-compliance pipeline for an ML platform that satisfies
multiple regimes (GDPR from exercise-02, SOC 2 from exercise-03,
vendor risk from exercise-05, NIST AI RMF as scaffolding). The design
deliverable has four components:

1. **Control library** — declarative definitions of each control.
2. **Telemetry plane** — collectors that produce evidence per control.
3. **Decision plane** — evaluators that emit pass/fail/findings and
   feed dashboards, tickets, and gates.
4. **Evidence plane** — append-only store of control outcomes and
   underlying artifacts, suitable for audit handover.

The design also addresses what *not* to automate: judgment-heavy
controls (lawful basis, DPIA, risk-acceptance decisions) should stay
human-driven, with the automation handling reminders and evidence
capture rather than the decision itself.

## 2. Implementation

### 2.1 Reference architecture

```
+----------------------------------------------------------+
| Control library (YAML/code)                              |
|  - control_id, framework_refs, owner, severity           |
|  - inputs: telemetry signals + system state              |
|  - check: declarative rule or function                   |
|  - cadence, SLA, action_on_fail                          |
+------------------------+---------------------------------+
                         |
                         v
+----------------------------------------------------------+
| Telemetry collectors                                     |
|  - cloud config (IAM, KMS, network, storage)             |
|  - SaaS state (HRIS, ticketing, MDM, code host, CI)      |
|  - app/runtime (audit logs, model-release records)       |
|  - human-in-loop attestations (training, DPIA sign-off)  |
+------------------------+---------------------------------+
                         |
                         v
+----------------------------------------------------------+
| Decision plane (control evaluators)                      |
|  - run controls on signals + state                       |
|  - emit pass / fail / partial + finding payload          |
|  - de-dup findings; route to owners; SLA timers          |
+------------------------+---------------------------------+
            |                 |                  |
            v                 v                  v
   +----------------+  +---------------+  +------------------+
   | Dashboards     |  | Ticketing /   |  | Evidence store   |
   | (program view) |  | runbook       |  | (append-only,    |
   |                |  | triggers      |  |  integrity-      |
   |                |  |               |  |  protected)      |
   +----------------+  +---------------+  +------------------+
                                                   |
                                                   v
                                          +------------------+
                                          | Audit handover   |
                                          | bundles (PDF +   |
                                          | signed JSON)     |
                                          +------------------+
```

### 2.2 Control library shape

A control entry is declarative so reviewers can read it without reading
code. Example (illustrative YAML, not a particular vendor's schema):

```yaml
- id: CC6-iam-mfa-prod-write
  framework_refs:
    - soc2: CC6.1
    - gdpr: art32-toms
    - aicg-mod-007: exercise-03 control mapping
  description: >
    All production write-capable IAM principals must require MFA at
    sign-in and must have at least one active enforcement signal in
    the IdP log within the last 30 days.
  owner: secops-iam
  severity: high
  inputs:
    - idp.sign_in_events
    - idp.user_directory
    - iam.role_assignments
  check:
    kind: rule
    expression: |
      forall principal in iam.role_assignments
        where principal.scope == "prod" and principal.has_write
        require principal.mfa_enforced == true
        require idp.sign_in_events[principal].recent_mfa_within_30d
  cadence:
    schedule: hourly
    sla_to_remediate: 24h
  on_fail:
    - open_ticket: { project: SECOPS, severity: P1 }
    - notify: secops-iam-oncall
    - evidence_capture: principals_list + last_mfa_event
```

The shape encodes:

- A **stable ID** so auditors can re-find the same control across years.
- **Framework references** so one control can satisfy multiple regimes
  without duplicate work.
- An **owner** (a team / on-call rotation, not "everyone").
- An **inputs** list that ties the control to specific telemetry
  signals — useful for impact analysis when a signal goes down.
- A **check** expression that a reviewer can read.
- A **cadence + SLA** that turn the control from a snapshot into an
  always-on test.
- **on_fail** actions that make failures consequential.

### 2.3 What to automate vs. leave to humans

| Control type | Automate the decision? | Automate the evidence? |
|---|---|---|
| Encryption-at-rest enabled on a bucket | Yes | Yes |
| MFA enforced for prod-write principals | Yes | Yes |
| Quarterly access reviews completed | Decision is a sign-off; automate the *reminder*, *capture*, and *audit trail* | Yes |
| DPIA required for new high-risk processing | No (judgment); automate trigger detection + reminder | Yes (DPIA documents stored, hashed) |
| Lawful-basis determination | No (legal call) | Yes (lawful-basis register stored, versioned) |
| Vendor reassessment due | Trigger automated; decision is human | Yes |
| Model release gate (eval + security scan + provenance) | Yes for the *gate*; human sign-off on the *release decision* | Yes |
| Subject erasure executed successfully | Yes (a runbook with verifiable post-conditions) | Yes |
| Risk-acceptance for an open finding | No | Yes (acceptance record with owner, scope, expiry) |

This split matters because over-automating compliance reduces it to
the lowest common denominator of what a script can express, which
quietly drops the most important controls (the judgment ones) from
the program.

### 2.4 Evidence plane requirements

The evidence store is the heart of the design, because the auditor
asks for evidence, not for dashboards. Requirements:

1. **Append-only with integrity protection.** Every control outcome
   and every linked artifact is written once. The pattern from
   `projects/project-2-compliance/SOLUTION.md` (hash-chain over
   audit records, periodic external timestamp anchors) is the
   reference; the design here adopts it.
2. **Versioned schemas.** A control's check changes over time; the
   evidence record captures the version of the control definition
   used at evaluation time.
3. **Stable identifiers** for principals, resources, models, and
   artifacts so a finding can be re-pulled years later.
4. **Audit bundle generator.** A reproducible job that, given a
   period and a TSC scope, materializes the evidence pack as a
   signed bundle (JSON + PDF + supporting artifacts). The bundle
   is itself recorded in the evidence store.
5. **Retention separate from operational logs.** Audit evidence
   has its own retention window (commonly 7 years; verify per
   regime). Tying it to operational log retention is a
   common mistake.
6. **Read access controlled and audited.** Auditors get a
   time-boxed, read-only view; engineers do not freely browse.

### 2.5 Drift detection and remediation flow

A control's lifecycle:

1. **Drift event** — a check transitions pass → fail.
2. **De-dup** — same drift on the same scope within a debounce
   window collapses to one finding, not N.
3. **Routing** — finding is opened against the control's owner with
   severity-driven SLA.
4. **Triage** — owner accepts, requests context, or escalates to
   risk-acceptance.
5. **Remediation** — fix or accepted-risk record.
6. **Verification** — next scheduled run confirms remediation or
   re-opens.
7. **Closure** — closure event recorded in evidence store; original
   finding is not deleted.

The design must address *flap-friendly* controls (e.g., short-lived
infra in CI) separately from *steady-state* controls; otherwise the
program drowns in noise and stops being trusted.

### 2.6 NIST AI RMF and AI-specific extension

Continuous compliance for an ML platform also needs to encode the
AI-specific controls. Map the NIST AI RMF functions to the design:

- **GOVERN** → controls covering policy, roles, accountability,
  vendor responsibility. Evidence: signed policy versions,
  governance forum minutes, vendor register.
- **MAP** → controls covering use-case inventory, impact
  assessment trigger, and stakeholder identification. Evidence:
  use-case register, DPIA / model card per qualifying use case.
- **MEASURE** → controls covering evaluation, monitoring,
  red-teaming, adversarial robustness (cross-reference
  mod-006). Evidence: eval reports, red-team results,
  monitoring dashboards.
- **MANAGE** → controls covering response, recovery, and
  decommissioning. Evidence: incident records, retraining
  decisions, model retirement records.

For generative systems, NIST AI 600-1 risk actions become specific
controls (provenance / watermarking signals for generated content,
training-data documentation, abuse monitoring), each with its own
telemetry signal and check.

## 3. Validation steps

1. **Walk one control end-to-end.** Pick CC6-iam-mfa-prod-write
   from §2.2. Trace input collectors, evaluator, ticket,
   evidence record, and bundle inclusion. If any hop is unowned,
   the design has a gap.
2. **Force a drift.** Demote an MFA-enforced principal in a test
   account; expect a ticket, an evidence record, and a follow-up
   verification. If the demotion does not generate a finding
   within the SLA, the telemetry path is broken.
3. **Force a flap.** Stand up a short-lived prod-like resource
   that intentionally violates a control for less than the
   debounce window. Expect one finding, not many; expect closure
   on its own.
4. **Reproduce an audit bundle.** Re-run the bundle generator
   for the previous quarter and confirm output is bit-for-bit
   stable (modulo signatures over volatile fields).
5. **Confirm the human-in-loop controls.** Pick a DPIA-trigger
   control; verify it captures the *judgment artifact* and the
   *reminder cadence*, not a synthetic pass/fail.
6. **Verify integrity of the evidence store.** Run the
   tamper-detection check (hash-chain verifier) on a sample
   period.

## 4. Rubric / review checklist

| Criterion | Weight | Pass condition |
|---|---|---|
| Control library is declarative with stable IDs and framework cross-refs | 10% | Example matches §2.2 in spirit |
| Telemetry plane covers cloud, SaaS, app, and human-in-loop inputs | 10% | All four categories addressed |
| Decision plane includes cadence, SLA, and on_fail actions | 10% | Each control row has all three |
| Evidence plane is append-only and integrity-protected | 10% | Hash chain or equivalent specified |
| Audit-bundle generator is reproducible | 5% | Stated as a goal with a verification step |
| Human-in-loop controls are not over-automated | 10% | DPIA, lawful basis, vendor reassessment kept human-decided |
| Drift / remediation lifecycle defined incl. de-dup and flap handling | 10% | All seven lifecycle steps from §2.5 present |
| NIST AI RMF functions mapped to controls | 10% | GOVERN / MAP / MEASURE / MANAGE each covered |
| GenAI-specific extension from NIST AI 600-1 addressed | 5% | At least provenance + training-data documentation |
| Cross-references to GDPR plan, SOC 2 readiness, vendor risk | 5% | Reuses controls instead of duplicating |
| Avoids inventing tools or features that don't exist | 5% | Vendor-neutral or accurately scoped |

Pass ≥ 70%. Designs that ace the telemetry and evaluator sections
but fail the human-in-loop section are typical "automate everything"
attempts; flag for redo.

## 5. Common mistakes

- **Replacing controls with dashboards.** A dashboard that lights
  up red is not a control. A control has an owner, an SLA, and a
  closure path.
- **Automating the judgment, not the workflow.** Trying to teach a
  rule engine to decide lawful basis or to risk-accept a finding
  produces wrong answers and creates a false sense of coverage.
- **Storing evidence in the same system that operates the
  controls.** If an attacker (or a buggy migration) can rewrite
  operational state, they can rewrite the evidence too. Evidence
  needs separation and integrity protection.
- **Using `latest` everywhere.** Without versioned control
  definitions, an auditor cannot tell what was being checked when
  a finding was generated.
- **Treating a vendor's "compliance product" as the program.**
  A SaaS that promises "SOC 2 in a box" is a useful tool but
  cannot replace the controls themselves.
- **Failing to address flapping.** Without de-dup and debounce,
  noisy controls poison the ticket queue and engineers stop
  trusting findings.
- **Ignoring decommissioning.** Continuous compliance includes
  retiring controls when systems they target are gone.

## 6. References

- NIST AI Risk Management Framework — the GOVERN/MAP/MEASURE/MANAGE
  scaffolding used in §2.6.
  https://www.nist.gov/itl/ai-risk-management-framework
- NIST AI 600-1: Generative AI Profile — risk-action set used to
  derive GenAI-specific controls.
  https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- OWASP Machine Learning Security Top 10 — input to the
  ML-specific control library entries (e.g., model serialization,
  evaluation-set integrity).
  https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS — adversary techniques translated into monitoring
  signals fed into the telemetry plane.
  https://atlas.mitre.org/
- VeriSwarm Trust Center — practitioner example of how a vendor
  surfaces continuous control status to customers; useful as a
  reference for the *external* face of the evidence plane.
  https://veriswarm.ai/trust
- Internal cross-reference: `projects/project-2-compliance/SOLUTION.md`
  for the hash-chain audit log pattern adopted by the evidence
  plane.
