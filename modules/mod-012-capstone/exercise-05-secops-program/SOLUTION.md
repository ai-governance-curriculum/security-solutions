# SOLUTION — Capstone Exercise 05: SecOps Program

> Read this *after* attempting the exercise. The aim is an operable
> SecOps program — detection, response, practice, and learning — for
> the ML system scoped in Exercises 01 and 02.

## 1. Solution overview

The exercise asks for a SecOps program with four named functions
(detection, response, practice, learning), each implemented with
concrete artifacts. A passing answer must:

- Define ML-aware detections (not just generic infra detections) tied
  to the risks in Exercise 01 and the controls in Exercise 03.
- Provide response playbooks for the ML-specific incident classes
  (model extraction, training-data poisoning, adversarial DoS,
  malicious model promotion).
- Plan recurring practice (tabletop / game day) so the playbooks are
  exercised before they are needed.
- Standardise postmortems so each incident improves the program.
- Define the operating model: roles, escalation, on-call,
  communication, and metrics.

A weak submission writes "we have a SOC" without naming what the SOC
is *looking at*, what it does in the first 30 minutes of an incident,
or how the program learns.

## 2. Implementation

### 2.1 Detection function

Detections are written in **Sigma** for portability (per Module 11 —
the Sigma format converts to most SIEM dialects). Each detection
names: signal, severity, source, false-positive sources, and the
playbook it triggers.

| Detection ID | Threat (Ex-01) | Signal | Severity | False-positive sources | Playbook |
|--------------|----------------|--------|----------|------------------------|----------|
| DET-01 lateral-movement.yml | T-02, T-03 | Pod with tenant-A SPIFFE identity attempts call to tenant-B feature store or to the model registry it has no role in. | High | Misconfigured allow-list during onboarding. | PB-01 Lateral movement |
| DET-02 model-extraction.yml | M-01, M-02 | Queries-per-key/minute > p99 baseline AND input entropy above per-day baseline against a single served model. | Medium | Legitimate batch evaluator without rate-limit exception. | PB-02 Model extraction |
| DET-03 data-exfiltration.yml | T-07, data-class breach | Egress volume from training namespace > 3× rolling baseline AND destination outside known whitelist. | High | Large dataset checkpoint to known storage — whitelisted. | PB-03 Data exfiltration |
| DET-04 unsigned-promotion.yml | T-04, M-04, ML10 | Registry admission denies a promotion for missing or invalid signature — counted; multiple failures from same identity in 24h. | Medium | New signer mis-rotated key. | PB-04 Suspicious promotion |
| DET-05 schema-drift-burst.yml | M-03, T-01 | Schema validation failures from a single Kafka producer cross threshold within 5 minutes. | Medium | Producer deploy with unannounced schema change. | PB-05 Poisoning suspicion |
| DET-06 promotion-evaluation-regression.yml | M-05, ML10 | Promotion candidate's slice error rate exceeds champion by > X% on protected slices. | High | Real model regression — but still requires investigation. | PB-04 Suspicious promotion |
| DET-07 spire-anomaly.yml | T-02 | Sustained SPIFFE identity issuance failures or unusual identity request bursts. | Medium | SPIRE upgrade. | PB-01 Lateral movement |

Each detection's Sigma file lives in `projects/project-5-security-operations/sigma-rules/` (per Module 11). Tuning notes (baseline derivation, threshold history) live next to the rule.

### 2.2 Response function — incident classes and playbooks

Each playbook follows the same shape: triggers, first-30-minutes
actions, containment, investigation, recovery, communication, and
postmortem.

#### PB-01: Lateral movement (compromised workload)

- **Trigger:** DET-01 fires.
- **First 30 min:**
  1. Page on-call SecOps; on-call confirms not a known onboarding
     event.
  2. Cordon the suspect pod's node; preserve the pod for forensics.
  3. Revoke the SPIFFE identity used by the workload; rotate any
     downstream credentials Vault issued to it.
  4. Page the workload's owning team.
- **Containment:** scope check — does any other workload share the
  identity? Disable promotion of any artifact built from the same
  pipeline run.
- **Investigation:** image hash, SBOM diff vs. last known good,
  audit-log review for what the workload touched.
- **Recovery:** redeploy from last known good image with new identity.
- **Communication:** internal — engineering Slack + governance group.
  External — only if customer data was reached.
- **Postmortem:** within 10 business days.

#### PB-02: Model extraction

- **Trigger:** DET-02 fires.
- **First 30 min:**
  1. Identify the caller key and the model.
  2. Rate-limit the key to 0 (temporary block) pending review.
  3. Capture a sample of the queries for offline analysis.
  4. Notify the model's owning team.
- **Containment:** if the model exposes confidence vectors, switch to
  label-only output.
- **Investigation:** classify the queries (legitimate batch vs.
  systematic boundary probing); examine queries for crafted
  similarity patterns; check if the model is watermarked.
- **Recovery:** if abusive, leave block in place; engage legal if a
  signed customer contract was breached.
- **Communication:** internal first; customer (if external key) only
  after legal review.
- **Postmortem:** within 10 business days.

#### PB-03: Data exfiltration from training namespace

- **Trigger:** DET-03 fires.
- **First 30 min:**
  1. Cordon the training namespace; pause all jobs.
  2. Snapshot pod state and egress logs.
  3. Page Data + SecOps.
- **Containment:** verify whether the egress destination is allowed;
  if not, block at the egress proxy.
- **Investigation:** identify what data left, by hash; check feature
  classification.
- **Recovery:** rotate any credentials the namespace held; redeploy.
- **Communication:** governance + legal if `restricted` data may
  have left.
- **Postmortem:** within 10 business days.

#### PB-04: Suspicious model promotion

- **Trigger:** DET-04 or DET-06.
- **First 30 min:**
  1. Freeze promotions to production for the affected model.
  2. Page the model's owning team and SecOps.
  3. Pull the promotion audit record: who signed, what was the
     attestation, what did the holdout evaluation show.
- **Containment:** if production already serves the suspect version,
  roll back to the prior champion.
- **Investigation:** reproduce the holdout evaluation independently;
  diff the model artifact vs. the previous champion (size, training
  data hash).
- **Recovery:** require additional review before promotion of any
  version of this model for N days.
- **Communication:** internal; governance if ML10 (insider) is
  suspected.
- **Postmortem:** within 10 business days.

#### PB-05: Poisoning suspicion

- **Trigger:** DET-05 fires repeatedly *or* a training-time drift
  alert.
- **First 30 min:**
  1. Quarantine the affected producer's recent topic offsets.
  2. Hold the next training run from those offsets.
  3. Page Data + ML platform.
- **Containment:** verify schema-registry state; if the producer is
  external, block at the broker.
- **Investigation:** statistical comparison of recent vs. baseline
  feature distributions; identify which records would be excluded.
- **Recovery:** retrain from cleaned data; verify the candidate on
  the holdout set.
- **Communication:** product owner of the model; governance if a
  protected-class slice was affected.
- **Postmortem:** within 10 business days.

### 2.3 Practice function — tabletop and game day

The program runs at least one tabletop per quarter and at least one
game day (technical exercise on a staging environment) per six
months.

**Tabletop format (90 minutes):**

1. Facilitator introduces a scenario (e.g., "DET-02 has been firing
   against the fraud-scoring model for 20 minutes; the caller is a
   long-standing partner").
2. Each role (SecOps, ML platform, ML product owner, governance,
   legal, comms) describes what they would do in the next 30 minutes.
3. Facilitator injects complications (e.g., "the partner contract
   gives them unlimited queries").
4. Group decisions are recorded.
5. After-action review identifies gaps (process, tooling,
   playbook).

**Game day format (3 hours):**

- A safe simulated incident is injected into the staging environment
  (synthetic extraction traffic, a planted "malicious" promotion,
  etc.).
- Real detections fire; real playbooks are followed; real timing is
  recorded.
- After-action review compares observed timing to the program's
  stated SLAs.

Scenarios are drawn from the threat model and rotated so each
playbook is exercised at least annually.

### 2.4 Learning function — postmortems

Every High-severity incident produces a written postmortem within 10
business days. The template captures:

- Timeline (detection → containment → recovery), with timestamps.
- Detection delta: was the detection in place? Did it fire? How
  much earlier could it have fired with the right rule?
- Contributing factors (not "root cause" — incidents have multiple
  causes).
- Decisions made under uncertainty, and what information would have
  changed them.
- Specific, owned, dated action items (tooling, process, detection,
  policy).
- Customer impact summary (drafted for the comms team).

Postmortems are blame-aware (people are named only when necessary to
describe a decision) and the action items are tracked in the same
backlog as feature work, with the same SLAs.

### 2.5 Operating model

- **Roles:** Incident Commander (on-call, rotates); SecOps on-call
  (rotates); ML platform on-call (rotates); ML product owner per
  model; Comms lead; Legal partner.
- **Escalation:** Sev1 (customer impact / regulated data) pages
  Incident Commander + executive sponsor; Sev2 (internal impact)
  pages Incident Commander; Sev3 (no immediate impact) tracked in
  the normal queue.
- **Communication channels:** dedicated Slack channel per incident;
  status page for customer-visible Sev1.
- **Metrics:** mean time to detect (MTTD), mean time to contain
  (MTTC), mean time to recover (MTTR), per-detection
  false-positive rate, postmortem-action-item closure SLA.
- **Reporting:** monthly to the AI governance group; quarterly to
  leadership.

### 2.6 Decision rationale (what a reviewer wants to read)

- **Why ML-aware detections, not just infra detections.** Generic
  detections catch generic threats; the threats in Ex-01 that
  motivated this capstone — extraction, poisoning, malicious
  promotion — are invisible to a SOC that does not know what the
  workloads do.
- **Why playbooks are written *before* incidents.** A playbook
  written under incident pressure inherits the bias of the moment;
  one written in advance can be debated and reviewed.
- **Why tabletop *and* game day.** Tabletop catches process gaps
  cheaply; game day catches tooling and detection gaps that only
  surface against real traffic.
- **Why postmortems must be timed.** Incidents whose lessons are not
  captured within 10 business days are routinely never captured —
  the on-call rolls over and context fades.

## 3. Validation steps

1. **Risk coverage.** For every High risk in Ex-01, confirm at
   least one detection and one playbook reference it.
2. **Playbook rehearsal.** Confirm each playbook has been used in a
   tabletop within the last quarter or a game day within the last
   six months.
3. **Detection health.** Confirm each detection has a documented
   baseline and a quarterly tuning review.
4. **SLA dashboards exist.** MTTD, MTTC, MTTR are reported monthly.
5. **Postmortem closure rate.** Action items from the last quarter's
   incidents have a closure rate > 80% within their stated SLA.

## 4. Rubric / review checklist

| Criterion | Weight | Pass condition |
|-----------|--------|----------------|
| ML-aware detections present | 15 | At least 5 detections target ML-specific threats (extraction, poisoning, malicious promotion, adversarial inputs, exfil). |
| Detection ↔ risk traceability | 10 | Every detection cites a risk ID from Ex-01. |
| Playbooks cover all High-risk classes | 15 | Each High risk has at least one playbook that names it. |
| Playbooks have first-30-minute actions | 10 | First-30-minute checklist is specific and actionable. |
| Tabletop + game-day cadence stated | 10 | Quarterly tabletop and semi-annual game day are named, with scenario rotation. |
| Postmortem template specified | 10 | Template covers timeline, detection delta, contributing factors, action items. |
| Operating model defined | 10 | Roles, escalation, channels, metrics are stated. |
| Detection tuning cadence stated | 5 | Each detection has a tuning review cadence. |
| Cross-reference to architecture | 5 | Detections and responses point at chokepoints from Ex-02. |
| Metrics named and measurable | 5 | MTTD/MTTC/MTTR + per-rule FP rate defined. |
| References cited | 5 | Official sources linked. |

## 5. Common mistakes

- **Generic SOC, no ML awareness.** A SOC that only watches Linux
  syscalls cannot see model extraction.
- **Detections without baselines.** Threshold values without
  derivation are unsupported and will be tuned away.
- **Playbooks that are "investigate".** The first 30 minutes need
  decisions and actions, not goals.
- **No practice cadence.** Playbooks written and never used are
  rumours, not procedures.
- **Postmortems with "root cause".** Mature programs use
  contributing factors; "root cause" hides the multi-causal nature
  of incidents.
- **No action-item SLA.** Lessons not closed are lessons not
  learned.
- **No customer comms branch in playbooks.** When Sev1 hits, the
  question "do we have to tell the customer" is the most
  time-consuming one in the room — pre-decide what triggers it.

## 6. References

- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>
- MITRE ATLAS — <https://atlas.mitre.org/>
- NIST AI Risk Management Framework (AI RMF 1.0) — <https://www.nist.gov/itl/ai-risk-management-framework>
