# Exercise 05 — Postmortem Template + Worked Example (Reference Solution)

> Read after attempting [`exercise-05-postmortem-template.md`](../../../../ai-infra-security-learning/lessons/mod-011-security-operations/exercises/exercise-05-postmortem-template.md).
> This reference ships the reusable template and the fully
> worked example for the exfiltration incident described in the
> exercise.

## 1. Solution overview

A postmortem template's job is to be *boring* to fill in and
*useful* to read later. The reference here keeps two principles
front of mind:

- **Blameless by construction.** Every field that names a human
  is omitted or replaced with a team/role. The 5-Whys terminates
  at a systemic cause, not at a person.
- **Regulatory clocks first-class.** The template treats the
  GDPR 72-hour clock and HIPAA Breach Notification Rule as
  required fields, not as something to remember to mention.
  Recording the start condition forces an explicit
  determination instead of an implicit assumption.[^gdpr][^hipaa]

The worked example uses the exact incident in the exercise (RCE
in serving pod via a Python dependency, 36-hour detection,
38.5-hour containment, 3 customers' feature data exposed). It
fabricates plausible details consistent with the brief — and
labels them as such where helpful.

The shape of the template aligns with the structure suggested in
the module's §10.2 lecture notes and is consistent with NIST AI
RMF MANAGE-4 ("identify and respond to risks", which in practice
turns into the postmortem loop).[^nist-ai-rmf]

## 2. Implementation (worked answer)

---

### Part A — Reusable template

```
# Postmortem: <Title> (<YYYY-MM-DD>)

## Header

| Field | Value |
|---|---|
| Incident title | <short, action-noun title — what happened, not who did it> |
| Severity | SEV1 / SEV2 / SEV3 |
| Detection time (UTC) | <YYYY-MM-DDThh:mm> |
| Containment time (UTC) | <YYYY-MM-DDThh:mm> |
| Resolution time (UTC) | <YYYY-MM-DDThh:mm> |
| Author | <team> |
| IC | <role + team, not name> |
| Postmortem reviewers | <teams> |

## Summary

<3–5 sentences. A reader unfamiliar with the incident should be
able to understand what happened, what the impact was, and what
the root cause was in under 30 seconds. No jargon-only sentences.>

## Impact

### Customer impact
- Affected customers: <count + tier breakdown>.
- Affected data: <data classes, e.g. customer feature vectors,
  account metadata, conversation content>.
- Duration of impact: <hh:mm>.

### Data impact
- Records exposed: <count or estimate>.
- Data classification: <PII / PHI / commercial / internal>.

### Business impact
- Revenue at risk: <range or "TBD">.
- Trust impact: <commitments touched: MSA, SOC 2 report, etc.>.
- Operational impact: <engineering hours; opportunity cost>.

## Timeline (UTC)

All timestamps in UTC. Events attributed to systems or roles,
not to individuals.

| Time | Event | Source |
|---|---|---|
| <ts> | <event description> | <log / alert / report> |
| … | … | … |

## Root cause analysis (5-Whys)

1. Why did X happen? — Because Y.
2. Why did Y happen? — Because Z.
3. Why did Z happen? — …
4. Why … — …
5. Why … — <systemic cause; do not stop at "human error">.

## What went well (≥3)

- …
- …
- …

## What went poorly (≥3)

- …
- …
- …

## Action items (≥5)

| ID | Action | Owning team | Due | Success criterion |
|---|---|---|---|---|
| AI-1 | <action> | <team> | <YYYY-MM-DD> | <measurable> |
| AI-2 | … | … | … | … |
| AI-3 | … | … | … | … |
| AI-4 | … | … | … | … |
| AI-5 | … | … | … | … |

## Lessons learned

<Generalize beyond this incident. What does this teach us about
the system, not just the immediate fix? What pattern recurs and
deserves a systemic response?>

## Regulatory tracking

| Regulation | Clock duration | Started at (UTC) | Owner (team) | Notification deadline (UTC) | Status |
|---|---|---|---|---|---|
| GDPR Art. 33 | 72 hours from controller awareness of personal-data breach | <ts or "N/A — recorded determination below"> | Privacy lead | <ts + 72h> | <pending / sent / not triggered> |
| GDPR Art. 34 | "Without undue delay" if high-risk | <ts> | Privacy lead + comms lead | <decision pending / sent / not triggered> | <status> |
| HIPAA Breach Notification Rule | 60 days from discovery (treat as ASAP internally) | <ts> | Privacy lead + customer BA contact | <ts + 60d> | <pending / sent / not triggered> |
| Customer commitments (MSA) | Per-customer | <varies> | Comms lead | <varies> | <varies> |

For each regulation with status `not triggered`, record the
determination in the next subsection.

### Regulatory determination record

<For each regulation marked "not triggered", a one-paragraph
explanation of why. This is the audit trail.>

## References

- Audit-chain entries: <links / IDs>
- Slack threads: <war-room channel ID>
- Detection rules involved: <Sigma rule IDs>
- Runbooks consulted: <links>
- External vendor advisories: <links>
- Related prior incidents: <links>
```

---

### Part B — Worked example

```
# Postmortem: Customer-Data Exfiltration via Serving Pod (2026-05-29)

## Header

| Field | Value |
|---|---|
| Incident title | Customer-data exfiltration via serving pod RCE |
| Severity | SEV1 |
| Detection time (UTC) | 2026-05-26T14:00 |
| Containment time (UTC) | 2026-05-26T18:30 |
| Resolution time (UTC) | 2026-05-28T22:00 |
| Author | Security |
| IC | Senior security engineer (on-call) |
| Postmortem reviewers | Security, Platform, ML Platform, Privacy, Legal |

## Summary

A serving pod in the recommendation-model namespace was compromised
via a known vulnerability in a Python dependency, then used as the
egress vector for customer feature-store data over 36 hours before
detection. Hubble flow logging detected sustained outbound to an
unrecognized destination and the on-call confirmed exfiltration
and contained the workload 4.5 hours later. Three customers'
feature data was exposed. Containment was complete at T+38.5
hours; the regression in the vulnerability-scan workflow that
allowed the dependency to ship is the systemic root cause.

## Impact

### Customer impact
- Affected customers: 3 (1 Enterprise, 2 Pro tier).
- Affected data: customer feature vectors (recommendation
  inputs); no model weights exfiltrated; no conversation
  content involved.
- Duration of impact: 36 hours of exfiltration, 4.5 hours of
  containment delay after detection.

### Data impact
- Records exposed: ~2.1M feature rows across 3 tenants
  (estimate based on Hubble byte volume / row size assumption;
  confirm exact row count from the feature-store audit log
  before any external disclosure).
- Data classification: feature vectors include behavioral
  attributes derived from customer data; one tenant uses
  SmartRecs in a healthcare workflow so the data is treated
  as PHI under their BAA with SmartRecs.

### Business impact
- Revenue at risk: 1 Enterprise renewal under review (~$180k
  ARR) plus reputational risk to 2 Pro accounts.
- Trust impact: customer commitments under MSA breach
  notification clauses triggered for all 3 customers; SOC 2
  Type 2 audit will note this incident in the next reporting
  period.
- Operational impact: ~210 engineer-hours over 3 days
  (incident response, forensics, postmortem, customer comms).

## Timeline (UTC)

| Time | Event | Source |
|---|---|---|
| 2026-05-15T00:00 | CVE-2026-XXXX disclosed for `feature-utils` Python package, CVSS 9.8 (RCE) | NVD feed |
| 2026-05-15T01:00 | Daily dependency scan workflow runs; no alert produced | CI logs (job ID 7421) |
| 2026-05-15T02:30 | Same workflow ran the prior day and 11 prior days; same misconfiguration | CI logs |
| 2026-05-24T03:00 | Serving-pod image rebuild includes `feature-utils` at vulnerable version | Image build logs |
| 2026-05-26T02:00 | Initial RCE exploitation against serving pod; reverse shell to unrecognized destination 198.51.100.42:443 | Pod memory snapshot (post-containment) |
| 2026-05-26T02:00–14:00 | Sustained low-rate exfiltration; ~50 KB/min outbound | Hubble flow logs |
| 2026-05-26T14:00 | Hubble anomaly detector triggers; ML-DET-010 fires | SIEM alert |
| 2026-05-26T14:05 | On-call paged | PagerDuty |
| 2026-05-26T14:15 | Severity declared SEV1; war room opened | War-room transcript |
| 2026-05-26T14:30 | Audit-chain query confirms feature-store reads from the serving pod's service account at anomalous rate | Audit chain |
| 2026-05-26T15:30 | CEO informed; legal engaged | Slack DM record |
| 2026-05-26T16:00 | NetworkPolicy default-deny applied to serving namespace | Cluster audit log |
| 2026-05-26T16:30 | Pod forensic snapshot completed to `ir-evidence` bucket | S3 object-lock log |
| 2026-05-26T18:30 | Containment confirmed: no outbound to 198.51.100.42 observed for 30 consecutive minutes; affected service account credentials revoked | Hubble + IAM audit |
| 2026-05-27T04:00 | Initial vector confirmed: vulnerable `feature-utils` package | Forensic analysis |
| 2026-05-27T08:00 | Vuln-scan workflow misconfiguration root-caused: a `continue-on-error: true` override added 4 months ago for a flaky test step had been left in place and was suppressing the dependency-scanner step's exit code | CI workflow git history |
| 2026-05-27T12:00 | New image built without the vulnerable package; cosign signature + Rekor entry verified | Build pipeline log |
| 2026-05-27T16:00 | Customer-success initiated outreach to the 3 affected tenants | CRM record |
| 2026-05-27T18:00 | Privacy lead confirmed: 1 tenant's data is PHI under BAA; HIPAA Breach Notification clock starts from controller awareness time 2026-05-26T14:30 | Privacy review note |
| 2026-05-27T20:00 | Privacy lead confirmed: 2 tenants' data includes EU residents' personal data; GDPR Article 33 clock starts from controller awareness time 2026-05-26T14:30 | Privacy review note |
| 2026-05-28T10:00 | Supervisory authority (Irish DPC) notified per GDPR Article 33 within 72-hour window | Notification record |
| 2026-05-28T22:00 | New serving deployment fully rolled out; incident resolved | Deployment record |
| 2026-05-29T09:00 | Postmortem drafted | This document |

## Root cause analysis (5-Whys)

1. **Why was customer feature data exfiltrated?** — A serving pod
   was compromised by RCE in a Python dependency and used as the
   egress vector for feature-store reads.
2. **Why did the serving pod run a vulnerable dependency?** —
   The dependency was added to the image 2 days after a public
   CVE was disclosed for it; the dependency-scanner workflow
   should have flagged the build and did not.
3. **Why did the dependency-scanner workflow not flag the
   build?** — The dependency-scanner step's exit code was
   masked by a `continue-on-error: true` override that had been
   added at the workflow level (not step level) 4 months prior
   to work around an unrelated flaky test, and then left in.
4. **Why was a workflow-level `continue-on-error` override
   added and left in place?** — There is no required review
   for changes to CI workflow files distinct from application
   code; the change passed a normal application-code review
   that did not focus on CI hardening.
5. **Why does the team not require dedicated review for CI
   workflow changes?** — The team does not maintain a CODEOWNERS
   entry for the workflow path nor a static-check linter that
   flags `continue-on-error: true` at workflow scope. The
   broader systemic cause is a missing control for the
   *control plane* (CI workflows are the control plane for
   release safety; treating them like application code
   under-weights their criticality).

## What went well

- The Hubble flow anomaly detector caught a low-rate
  exfiltration pattern (50 KB/min) — the kind of slow drip an
  egress-bytes threshold alone would not have flagged.
- The war room ran smoothly: scribe, IC, comms lead, and
  technical responder roles were filled within 20 minutes of
  declaration.
- Audit-chain queries gave the team a complete picture of
  which feature-store keys were touched within an hour, which
  enabled accurate customer-impact scoping.
- The cosign + Rekor signing pipeline produced a clean rebuild
  path with verifiable provenance.
- GDPR 72-hour notification was filed within window despite
  the incident starting on a weekend.

## What went poorly

- 36-hour detection delay is the most significant gap; the
  vulnerability was disclosed 11 days before exploitation and
  should have prevented the bad build entirely.
- The vuln-scan workflow had been silently failing for 4
  months. No metric or canary detected the silent failure.
- Customer-success outreach happened more than 24 hours after
  containment; the original procedure assumed business-hours
  outreach, which did not match the impact severity.
- The "noise floor" baseline used by the Hubble anomaly
  detector was not tight enough to catch the slow-rate phase;
  it only fired once the volume crossed an absolute threshold.
  We were lucky.
- The initial pod forensic snapshot omitted the pod's network
  namespace state — a gap in the evidence-preservation runbook.

## Action items

| ID | Action | Owning team | Due | Success criterion |
|---|---|---|---|---|
| AI-1 | Add a CODEOWNERS entry for `.github/workflows/**` requiring CI-platform team review on changes | Platform | 2026-06-12 | CODEOWNERS merged; one workflow PR routed through the new review path |
| AI-2 | Add a workflow static-check linter that fails any PR introducing workflow-scope `continue-on-error: true`, with documented exception process | Platform | 2026-06-19 | Linter live in CI; test PR with the override is blocked |
| AI-3 | Add a "vuln-scan workflow canary": a known-vulnerable test dependency that should always trigger the scanner; alert on absence | Security | 2026-06-26 | Canary running; intentional removal in staging confirms alert path |
| AI-4 | Tighten Hubble flow anomaly detector baseline to flag sustained low-rate egress (specifically: per-pod outbound bytes/min above 10 KB to non-allowlisted destinations for >15 min) | Security + Platform | 2026-07-03 | Tuned detector deployed; replay of this incident's flows triggers within 30 min |
| AI-5 | Update IR evidence-preservation runbook to capture pod network namespace state (conntrack, listening sockets) in the forensic snapshot | Security | 2026-06-19 | Runbook updated; verified during the next Q2 tabletop |
| AI-6 | Change customer-success on-call procedure to enforce same-business-hour outreach for SEV1 incidents regardless of weekend/weekday | Customer Success | 2026-06-12 | Procedure published; on-call rotation acknowledges |
| AI-7 | Audit the prior 4 months of CI workflow runs for other silently failing steps; document any found and remediate | Security + Platform | 2026-07-10 | Audit report shared; any silent failures triaged |

## Lessons learned

- **CI workflows are control-plane code.** Treating them like
  application code under-weights their criticality. Future
  control-plane changes (build, sign, admit, deploy) get a
  dedicated review path and dedicated linting.
- **"Continue on error" is a control-failure flag.** Wherever
  used, it must be scoped to the smallest possible unit and
  paired with a positive signal that the suppressed failure
  was anticipated. Workflow-level uses are anti-patterns.
- **Detectors silently regress.** Canary inputs are the
  counterpart to canary outputs. Every detection rule should
  have a paired canary that intentionally exercises it; the
  absence of an expected alert is a higher-severity signal
  than the presence of a real one.
- **Slow-rate exfiltration is the common case.** Anomaly
  detection on rate-of-change beats absolute thresholds for
  low-and-slow attacks. The threshold-only detector here was
  lucky to fire at all.
- **Weekend incidents need explicit policy.** The default
  customer-success procedure assumed business-hours response;
  for SEV1, that's wrong.

## Regulatory tracking

| Regulation | Clock duration | Started at (UTC) | Owner | Notification deadline (UTC) | Status |
|---|---|---|---|---|---|
| GDPR Art. 33 | 72 hours from controller awareness | 2026-05-26T14:30 | Privacy lead | 2026-05-29T14:30 | Sent 2026-05-28T10:00 (within window) |
| GDPR Art. 34 | "Without undue delay" if high-risk | 2026-05-26T14:30 | Privacy + comms lead | Determination by 2026-05-28T14:30 | Determined: notification to data subjects via the controller customer; not required directly by SmartRecs as processor. Decision recorded 2026-05-28T08:00. |
| HIPAA Breach Notification Rule | 60 days from discovery | 2026-05-26T14:30 | Privacy lead + customer's HIPAA officer | 2026-07-25T14:30 | Customer's HIPAA officer notified 2026-05-27T18:30; SmartRecs is BA and supports customer's notification timeline. |
| Customer MSA notification | Per MSA: 48 hours from confirmation of breach affecting customer data | 2026-05-26T18:30 (containment confirmed; treated as MSA "confirmation") | Comms lead | 2026-05-28T18:30 | Sent to all 3 customers 2026-05-27T16:00–22:00. |

### Regulatory determination record

The GDPR Article 33 clock started at 2026-05-26T14:30 — the
moment the IC confirmed exfiltration of feature-store reads,
which include personal data of EU residents. The supervisory
authority was notified within 67 hours and 30 minutes, well
inside the 72-hour window.[^gdpr]

The HIPAA Breach Notification Rule applies because one tenant
uses SmartRecs in a healthcare workflow under a BAA. The
customer's HIPAA officer was notified within 28 hours of
SmartRecs' controller-awareness time, well inside the 60-day
HHS window.[^hipaa] SmartRecs operates as Business Associate;
the customer remains responsible for any individual
notifications to affected patients.

The GDPR Article 34 (notification to data subjects)
determination is that the breach poses high risk to the
rights and freedoms of data subjects, but SmartRecs is the
processor; notification to data subjects is the controller
customers' obligation. SmartRecs supports the customers with
the technical detail required.

## References

- War-room channel: `#inc-20260526-serving-exfil` (Slack archive).
- Audit-chain entries: range `[2026-05-26T14:00, 2026-05-26T18:30]`
  for service account `serving-pod-recommender`.
- Detection rules involved: ML-DET-010 (notebook egress —
  triggered for serving-namespace flow), ML-DET-009 (cross-
  tenant access pattern, did not fire).
- Runbooks consulted: `runbooks/playbook-4-data-exfil.md`
  (Exercise 03), `runbooks/evidence-preservation.md`.
- Vendor advisory: CVE-2026-XXXX (NVD; CVE ID and publication
  date are illustrative for the `feature-utils` package
  vulnerability — replace with the live identifier when using
  this template against a real incident).
- Related prior incidents: none on this vector;
  `INC-20260301-cosign-rotation` covered signing pipeline
  hygiene.
```

---

## 3. Validation steps

To check a learner's submission:

1. The template contains all 11 required sections in the
   prescribed order (header, summary, impact, timeline, RCA,
   what went well, what went poorly, action items, lessons
   learned, regulatory tracking, references).
2. No field in the template invites individual blame: no "who
   did this", no "responsible party", no person-level
   attribution.
3. The 5-Whys terminates at a systemic cause, not at "human
   error".
4. Action items: at least 5; each has owner *team*, due date,
   and measurable success criterion. "Be more careful" or "do
   better next time" are failing entries.
5. Regulatory tracking: every applicable regime has start
   condition, owner, deadline, and status. Anything marked "not
   triggered" has an accompanying determination record.
6. The worked example has internally consistent timestamps:
   detection at T=0 = 2026-05-26T14:00, containment at +4.5h =
   18:30, resolution within the brief's 38.5h window.
7. Customer-impact counts (3 customers per the brief) match
   throughout.

## 4. Rubric or review checklist

| Aspect | Strong (3) | Adequate (2) | Weak (1) |
|---|---|---|---|
| Template reusability | Other teams can fill in without facilitation | Reusable with explanation | One-off |
| Blamelessness | No human-blame fields anywhere | Mostly blameless | Names individuals or invites blame |
| 5-Whys depth | Terminates at systemic cause | Terminates at process gap | Stops at "human error" |
| Action item quality | ≥5, team-owned, dated, measurable criterion | ≥5, some vague criteria | <5 or generic ("be careful") |
| Regulatory tracking | Each regime tracked with start condition + owner + status | Regimes named, partial detail | Missing |
| Worked-example realism | Timestamps internally consistent; details match brief | Mostly consistent | Inconsistent / unrealistic |
| References section | Specific log/runbook/audit-chain pointers | Mentions sources | None |

Passing threshold: ≥15/21; no axis scored 1 on blamelessness or
regulatory tracking.

## 5. Common mistakes

- **Loose, generic fields.** "Describe what happened" is not a
  field; "Customer impact: count + tier breakdown + data
  classes" is.
- **Action items like "be more careful".** Behavioral exhortation
  is not a control. Each action item needs an owner team, a
  date, and a falsifiable success criterion.
- **No regulatory tracking.** GDPR Article 33's 72-hour clock
  and HIPAA's 60-day breach notification clock both start at
  discovery; record the start time or justify why a regime
  doesn't apply.
- **Example reads as fiction.** Inconsistent timestamps or
  impossibly tidy details (e.g., resolution exactly 4 hours
  after detection regardless of complexity) signal the author
  did not check the math.
- **5-Whys that stops at "human error".** Almost always wrong.
  Push at least two layers deeper — what made the error
  possible, what made the error invisible, what made the
  invisibility persist.
- **Action items the author owns alone.** A postmortem whose
  action items all map to the security team is one that hasn't
  been read by the rest of engineering.
- **Skipping the references.** References are how future
  responders pivot from the postmortem back to the evidence;
  without them, the postmortem is unverifiable narrative.

## 6. References

- NIST AI Risk Management Framework (AI RMF 1.0), MANAGE-4 —
  continuous improvement loop that postmortems
  implement.[^nist-ai-rmf]
- MITRE ATLAS — context for the threat scenarios postmortems
  cover.[^atlas]
- OWASP Machine Learning Security Top 10 — ML-specific
  attacker patterns that frame ML postmortem
  expectations.[^owasp-ml]
- GDPR Article 33 (controller notification) and Article 34
  (data subject notification).[^gdpr]
- HIPAA Breach Notification Rule (45 CFR §§164.400–414).[^hipaa]

[^nist-ai-rmf]: NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>
[^atlas]: MITRE ATLAS — <https://atlas.mitre.org/>
[^owasp-ml]: OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>
[^gdpr]: GDPR Article 33 (and 34) — <https://eur-lex.europa.eu/eli/reg/2016/679/oj>
[^hipaa]: HIPAA Breach Notification Rule — <https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html>
