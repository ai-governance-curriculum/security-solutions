# Exercise 03 — IR Procedure for ML Threats (Reference Solution)

> Read after attempting [`exercise-03-ml-ir-procedure.md`](../../../../ai-infra-security-learning/lessons/mod-011-security-operations/exercises/exercise-03-ml-ir-procedure.md).
> This solution presents the IR procedure plus all five required
> playbooks, sized for SmartRecs' 6-person team.

## 1. Solution overview

The exercise asks for an end-to-end IR procedure for a small team
plus five ML-specific playbooks. A passing answer keeps two ideas
in mind:

1. **Procedures decide; playbooks act.** The procedure tells the
   responder *who decides what and when* (severity, comms,
   regulatory clocks). The playbooks tell the responder *what to
   type* (queries, kubectl commands, IAM revocations).
2. **Time pressure exposes ambiguity.** Anything written in the
   procedure that requires interpretation under pressure will be
   interpreted differently each time, which is how procedures
   fail. The reference below uses objective criteria for
   severity, named authority bounds for roles, and explicit
   regulatory-clock start conditions.

The reference draws on NIST AI RMF MANAGE-4 (incident response,
governance, and continuous improvement) for procedure shape and
on MITRE ATLAS for the threat scenarios the playbooks must
cover.[^nist-ai-rmf][^atlas] Where regulatory specifics are
named (GDPR Article 33's 72-hour clock; HIPAA Breach
Notification Rule's 60-day clock), the source is the regulation
itself, not commentary.[^gdpr][^hipaa]

## 2. Implementation (worked answer)

---

```
# SmartRecs IR Procedure

## Overview

Scope: security incidents affecting SmartRecs production
systems, customer data, ML models, or the build/deploy chain.
Applies to all engineers; the on-call security engineer is the
default first responder.

Out of scope: privacy or product incidents without a security
dimension; those are handled by the product on-call.

## Roles

| Role | Responsibilities | Authority bounds |
|---|---|---|
| Incident Commander (IC) | Owns the response from declaration to closure. Chooses severity and phase transitions. Owns the war-room channel. | May invoke any other role; may take customer-visible containment action up to and including pausing a tenant's traffic. May not commit to customer notification timing without the comms lead. |
| Communications Lead | Drafts internal updates, customer notifications, regulator disclosures. Coordinates with legal/privacy. | Speaks externally only after IC and CEO (for SEV1) or IC alone (for SEV2/3) have signed off. |
| Technical Responder(s) | Executes containment, investigation, eradication, recovery actions under the playbooks. | May take any reversible technical action; irreversible actions (e.g., model rollback, key rotation, customer-traffic suspension) require IC approval. |
| Stakeholder Liaison | Coordinates with customer-success for any customer-impacting incident. Pulls in the privacy lead when EU customers are involved. | Speaks to customers only with comms-lead-approved messaging. |
| Scribe | Logs every decision and action to the incident timeline. Owns the post-incident timeline artifact. | Read-only authority; appends to the audit chain. |

For SEV1 incidents the IC is the senior on-call security engineer.
For SEV2/3 the IC may be the on-call who declared the incident.
At a 6-person company the same person frequently wears multiple
hats; the procedure assumes that the IC explicitly names who holds
each role at declaration.

## Severity classification

| Severity | Objective criteria (any one) | Response time | Communications |
|---|---|---|---|
| **SEV1** | Confirmed customer-data exfiltration; confirmed unauthorized access to a production model; LLM took an external action causing customer financial harm; SmartRecs build/deploy chain compromise with production reach. | IC engaged within 15 min, 24/7. War room open within 30 min. | CEO + legal informed within 1 hour. Customers notified per the comms plan within 24h or as required by regulation. |
| **SEV2** | Strong evidence of model theft in progress; poisoning indicators in a model that is in production; LLM prompt injection with action chain compromise but no confirmed customer harm; CI compromise without production reach. | IC engaged within 1 hour during business hours; within 4 hours overnight. | Engineering leadership notified within 4 hours. Customer comms deferred to incident review unless impact is confirmed. |
| **SEV3** | Detection fired and the signal is real but contained (e.g., tenant rate-limit cap engaged, alert is investigatable without active mitigation). Anomaly worth investigating but no active compromise. | Triage within the next business day. | Internal only. |

Severity is set at declaration and may only be *raised* by anyone
on the response team without ceremony. Lowering severity requires
the IC's explicit decision recorded in the timeline.

## Phases and time bounds

| Phase | Goal | Target time bound (SEV1) |
|---|---|---|
| Detection | Alert acknowledged, IC identified | <15 min from page |
| Triage | Severity declared, war room open, scribe online | <30 min from page |
| Containment | Active harm stopped or rate-limited | <2 hours from declaration |
| Investigation | Scope, blast radius, evidence preserved | <8 hours from containment |
| Eradication | Root vector closed (vuln patched, credential rotated, malicious artifact removed) | <24 hours from investigation |
| Recovery | Production restored to known-good state | <24 hours from eradication |
| Post-incident | Postmortem (Exercise 05) published | <7 calendar days from resolution |

SEV2 multiplies the bounds by 2x; SEV3 is best-effort within the
next business day.

## Communication structure

- **War room channel**: dedicated Slack channel created at
  declaration (`#inc-YYYYMMDD-<short-name>`). IC is channel owner.
  All decisions and actions land here.
- **Internal status updates**: every 60 min for SEV1; every 4
  hours for SEV2; once daily for SEV3.
- **Stakeholder updates**: customer-success and CEO via DM at
  declaration; status update at 4-hour mark for SEV1.
- **External (customer / regulator) communication**: drafted by
  the comms lead, reviewed by legal/privacy, sent by the IC.
  Templates for customer breach notification, GDPR Article 33
  notification, and HIPAA Breach Notification Rule notification
  are stored in `runbooks/comm-templates/`.

## Tools and access

| Function | Tool | Where access lives |
|---|---|---|
| SIEM queries | Elastic Security | `siem-responder` SSO role |
| Audit-chain queries | Internal audit-chain CLI | `audit-reader` SSO role |
| K8s containment | `kubectl cordon`, NetworkPolicy `default-deny`, `kubectl delete pod` | `cluster-ir-responder` ClusterRole |
| IAM containment | AWS IAM Access Analyzer; `aws iam put-user-policy`; AWS SSO session revoke | `iam-ir-responder` role |
| Model rollback | Internal model-registry CLI (`mr promote --rollback`) | `model-registry-admin` |
| Tenant traffic suspension | LLM/inference gateway feature flag | `gateway-ir-responder` |
| Evidence preservation | S3 object-lock bucket `smartrecs-ir-evidence` | `ir-evidence-writer` |
| Communication | Slack war room; PagerDuty for paging; Statuspage for external | Standard team access |

Access to IR roles is just-in-time via the access broker; the
broker logs to the audit chain. Pre-incident drills (Exercise 04)
verify each responder can assume their IR role within the time
bound.

## Regulatory clocks

| Regulation | Clock duration | Clock starts when… | Owner |
|---|---|---|---|
| GDPR Article 33 (controller breach notification to supervisory authority) | 72 hours | The controller becomes "aware" of a personal-data breach — for SmartRecs, that is when the IC confirms a breach involving personal data; "awareness" is recorded in the incident timeline. | Comms lead + privacy lead, IC approval. See GDPR Art. 33.[^gdpr] |
| GDPR Article 34 (notification to data subjects) | "Without undue delay" if breach is high-risk to rights and freedoms | Same trigger as Article 33 plus a risk-classification decision recorded in the timeline. | Same as above. |
| HIPAA Breach Notification Rule (45 CFR §164.404–410) | 60 days from discovery, but treated internally as "as soon as possible" | A HIPAA covered entity or business associate discovers a breach of unsecured PHI. SmartRecs treats discovery as the point the IC confirms PHI was implicated. | Comms lead, privacy lead, customer's HIPAA officer if SmartRecs is BA. See HHS HIPAA Breach Notification Rule.[^hipaa] |
| SOC 2 (customer commitment-based notification) | Per the SmartRecs Master Subscription Agreement | At IC's confirmation of customer-impacting security incident. | IC, comms lead. |

The IC explicitly records the clock start time in the timeline at
declaration. Any disagreement about whether the clock has started
escalates to legal/privacy immediately, not at the next sync.

---

## Playbook 1: Suspected model extraction

### Detection sources
- ML-DET-001 (Exercise 02) — per-tenant query rate spike.
- ML-DET-006 — membership-inference probe pattern.
- Customer-success report of unusual behavior from a customer's
  account.

### Triage steps
1. Acknowledge the alert in PagerDuty. Identify the tenant.
2. Run the inference-gateway query:
   `event.kind:inference_request AND tenant.id:"<TID>" AND @timestamp:[now-24h TO now]`
   and chart count + unique-feature-ratio over time.
3. Pull the tenant's account metadata (creation date, tier,
   contract).
4. Confirm whether `tenant.tag` includes `planned_batch` or
   `load_test`.

### Containment
- If unexplained: apply per-tenant rate cap at 1.5x the
  baseline through the inference-gateway feature flag.
- If extraction is confirmed: drop to baseline cap and enable
  query logging to S3 (`ir-evidence` bucket with object-lock).

### Investigation
1. Export 7 days of the tenant's queries with prompt content
   redacted to PII-safe representations.
2. Compute query diversity, redundancy, and target coverage on
   the model's feature space.
3. Identify the model variants accessed.
4. Audit-chain query: `actor.tenant=<TID> AND
   action=inference.request` for the same window.

### Eradication
- Revoke the tenant's API key set; require re-onboarding.
- If sufficient queries succeeded to reconstruct the model's
  decision boundary on critical regions, plan a model rotation
  per `runbooks/model-rotation.md`.

### Recovery
- Restore standard rate cap if the tenant relationship is
  preserved (false positive or commercial resolution).
- Promote rotated model variant via the model-registry CLI.
- Verify the new model's accuracy on the canary tenant set.

### Communication
- Customer-success owner contacted at containment.
- If extraction is confirmed and the tenant is acting in bad
  faith: comms lead drafts a termination-notice cooperative
  with legal.
- No regulator clock unless personal data was implicated, which
  is unusual for an extraction attack but must be checked.

### Post-incident
- File a postmortem within 7 days using the Exercise 05
  template.
- Tune ML-DET-001 thresholds based on what fired and what did
  not.

---

## Playbook 2: Suspected data poisoning

### Detection sources
- ML-DET-007 — training-data distribution shift on retraining.
- ML-DET-008 — per-model accuracy regression in production.

### Triage steps
1. Identify the affected training job (job ID, dataset version,
   model digest).
2. Compare PSI per feature against the registered "expected
   drift" log.
3. Pull the data-source change log for the affected pipeline.
4. Sample 100 rows from the new batch; manual inspection for
   poisoning markers (label-flipping, target injection,
   adversarially crafted records).

### Containment
- Pause the affected training pipeline.
- If a poisoned model has already been promoted: roll back to
  the prior known-good digest via `mr promote --rollback`.
- Freeze the suspect dataset version in S3 with object-lock.

### Investigation
1. Identify the data ingestion path. Was a new source added or
   an existing source compromised?
2. Audit-chain pivot: who modified the dataset, when, from
   what identity.
3. Cross-reference with CI/CD logs and IAM session logs for
   any unauthorized data writes.
4. Inspect upstream sources (vendor feeds, customer-supplied
   training data) for compromise indicators.

### Eradication
- Revoke any compromised credentials.
- Remove the poisoned dataset version from the training-data
  registry.
- If a vendor source was compromised, suspend the feed pending
  vendor confirmation.

### Recovery
- Retrain from the last known-good dataset snapshot.
- Validate the retrained model against the holdout set and
  baseline metrics.
- Promote the retrained model via standard promotion path;
  verify cosign signature and Rekor entry.

### Communication
- Customer-success informed if any customer-impacting model
  was implicated.
- GDPR/HIPAA notification only if personal data was *exposed*
  during the poisoning attempt; poisoning of model behavior is
  not, by itself, a personal-data breach under GDPR Article 33
  and so does not start the 72-hour clock — but the IC must
  record this determination in the timeline rather than skip
  the question.[^gdpr]
- Internal lessons-learned shared with the ML platform team.

### Post-incident
- Postmortem within 7 days.
- Strengthen the training-data ingestion controls; possibly
  introduce signed dataset commits.

---

## Playbook 3: Confirmed LLM prompt-injection harm

### Detection sources
- Customer report (most common entry point).
- ML-DET-003 (direct prompt injection) or ML-DET-004 (indirect).
- Output filtering caught a clear harmful action chain.

### Triage steps
1. Acknowledge and identify the affected customer + conversation.
2. Pull the conversation transcript from the LLM gateway logs:
   `event.kind:llm_conversation AND conversation.id:"<CID>"`.
3. Identify the action chain executed by the LLM and any
   external-facing effect (email sent, subscription cancelled,
   ticket created).
4. Determine whether the injection was direct (user input) or
   indirect (retrieved document, plugin output).

### Containment
- Disable the affected tool/plugin via gateway feature flag.
- If the action chain is reversible (subscription cancellation,
  ticket creation): execute the rollback action with the
  customer's consent recorded.
- If indirect injection from a corpus document: quarantine the
  document.

### Investigation
1. Reproduce the conversation in a sandbox to confirm the
   exploit path.
2. Identify any other conversations that touched the same
   document or used the same tool in the prior 24 hours.
3. Quantify customer impact (financial harm, data exposure).
4. Audit-chain pivot to identify any actions the LLM took
   outside the conversation context.

### Eradication
- Patch the prompt-template or tool-use gating logic that
  permitted the harmful action.
- Remove or sanitize the injected content from the source
  document or input pipeline.
- Strengthen ML-DET-003 / ML-DET-004 patterns based on the
  injection vector.

### Recovery
- Restore the affected customer's account state; document the
  remediation.
- Re-enable the tool/plugin under stricter gating.
- Add a regression test for the specific injection pattern.

### Communication
- Customer notification within 24 hours; comms lead drafts.
- If financial harm: legal and finance involved within 4 hours.
- GDPR Article 34 clock starts if the injection exposed
  personal data to unauthorized parties; record the start time.

### Post-incident
- Postmortem within 7 days.
- Treat as input to the LLM safety review cycle.

---

## Playbook 4: Customer-data exfiltration from ML pipeline

### Detection sources
- ML-DET-010 — notebook egress to non-allowlisted destination.
- ML-DET-009 — cross-tenant feature-access anomaly.
- Cilium Hubble flow anomaly + audit-chain anomaly.

### Triage steps
1. Identify the originating pod, namespace, and service account.
2. Pull the Hubble flow log for the destination + connection
   pattern.
3. Audit-chain query: every action taken by the implicated
   identity in the prior 24 hours.
4. Estimate data-volume exfiltrated: bytes_sent in the flow log,
   feature-store keys touched.
5. Identify which customers' data is implicated by mapping
   touched feature-store keys to tenants.

### Containment
- Apply Kubernetes NetworkPolicy default-deny to the affected
  namespace.
- Revoke the implicated service account's credentials and
  rotate any related API keys.
- If the destination is identifiable: blackhole at the egress
  proxy.

### Investigation
1. Forensic snapshot of the pod (memory + filesystem) to the
   `ir-evidence` bucket under object-lock.
2. Identify the initial compromise vector: dependency vuln,
   credential theft, supply-chain artifact, etc.
3. Map the full set of affected customers and feature keys.
4. Determine whether the data is encrypted at rest in the
   feature store and whether the encryption boundary held.

### Eradication
- Patch the initial vector (dependency update, credential
  rotation, image rebuild + cosign sign + Rekor entry).
- Remove any persistence mechanisms (init containers, sidecars,
  cron-like behaviors).
- Verify no other workloads are running the same image digest.

### Recovery
- Redeploy the workload from a known-good signed image.
- Confirm egress to the suspect destination is blackholed.
- Restore normal NetworkPolicy posture once verification holds.

### Communication
- GDPR Article 33 clock starts at IC confirmation of personal-
  data exposure; comms lead and privacy lead own the
  supervisory-authority notification. 72-hour clock is binding.[^gdpr]
- HIPAA Breach Notification Rule clock starts at discovery if
  PHI was implicated.[^hipaa]
- SOC 2 customer commitments may impose tighter timelines than
  the regulator's; comms lead checks the MSA for each affected
  customer.
- CEO informed within 1 hour; legal within 1 hour.

### Post-incident
- Postmortem within 7 days using the Exercise 05 template (the
  worked example in Exercise 05 is exactly this scenario).
- Action items target both the vulnerability scanner workflow
  *and* the supply-chain controls.

---

## Playbook 5: Container escape from training pod

### Detection sources
- Falco container-escape alerts (e.g., `Terminal shell in
  container`, `Mount Launched in Privileged Container`,
  `Symlinks Created Over Sensitive Files`).
- Hubble flow log showing the training pod reaching the node
  IP or another pod's namespace.

### Triage steps
1. Identify the pod, node, and the specific Falco rule that
   fired.
2. Pull the Falco event detail: process name, parent process,
   syscall arguments.
3. Identify the workload: training job ID, dataset, model
   target, owning team.
4. Determine whether the escape attempt succeeded (did the
   process actually reach node resources?).

### Containment
- Cordon the affected node (`kubectl cordon`).
- Delete the training pod (`kubectl delete pod -n training
  <pod>` with `--grace-period=0` if necessary).
- Apply NetworkPolicy default-deny to the training namespace.
- Preserve the pod's filesystem before deletion if forensic
  capacity allows: `kubectl debug` + tarball to `ir-evidence`.

### Investigation
1. Determine whether the escape was an attack or a
   misconfiguration (legitimate container that needed elevated
   permissions and got them through the wrong path).
2. If attack: identify the initial vector — was the training
   image compromised? Did a dependency execute hostile code?
3. Check whether the node was compromised: SSH access, kernel
   module loads, suspicious processes.
4. Inspect adjacent pods on the same node for IoC's.

### Eradication
- Patch the image and any compromised dependency.
- Verify the pod's SecurityContext was correctly enforced; fix
  the gap if not.
- Roll the node if compromise on the node itself is confirmed
  (terminate the node, replace from the AMI).

### Recovery
- Recreate the training job from a clean image; monitor for
  re-occurrence.
- Re-enable workloads to the namespace.
- Verify Falco continues to fire on test cases (don't trust
  silence after an incident).

### Communication
- Internal: engineering leadership and platform team within
  4 hours.
- Customer: only if customer-impacting (training pod's
  artifacts have been promoted to production); else internal-
  only.
- Regulatory: unlikely to trigger GDPR / HIPAA clocks unless
  personal data was reachable from the escaped process.

### Post-incident
- Postmortem within 7 days.
- Action items: tighten SecurityContext defaults; add a Falco
  test for the specific escape vector.
```

---

## 3. Validation steps

To check a learner's submission:

1. Confirm the procedure has objective severity criteria — no
   "the on-call decides" without bounded conditions.
2. Each role has a named **authority bound** (what it may and
   may not do unilaterally).
3. Phase time bounds are present and differentiated by severity.
4. Regulatory clocks are addressed for at least GDPR and HIPAA;
   each clock has a named *start condition* and *owner*.
5. Tools section names *which command or tool* and *where access
   lives*. "Use kubectl" is not sufficient; "kubectl cordon via
   the cluster-ir-responder ClusterRole" is.
6. Each playbook covers all seven phases (detection, triage,
   containment, investigation, eradication, recovery,
   communication, post-incident) and uses *commands*, not
   "investigate".
7. Spot-check at least two playbooks against the matching Sigma
   rule from Exercise 02 — the detection-source field must
   correspond to a real rule.

## 4. Rubric or review checklist

| Aspect | Strong (3) | Adequate (2) | Weak (1) |
|---|---|---|---|
| Roles with authority | Bounds named, conflict paths clear | Roles listed, vague authority | "Whoever's around" |
| Severity criteria | Objective, falsifiable | Mostly objective, some judgment | "Critical means really bad" |
| Phase time bounds | Per-severity, defended | Single set of bounds | None |
| Communication structure | Named channels + cadence | Mentions Slack | Implicit |
| Tools & access | Commands + role names | Tools listed | Generic |
| Regulatory clocks | Each clock has start condition + owner | Clocks named | Missing |
| Playbook specificity | Commands, queries, runbook refs | Phases covered | "Investigate, fix, communicate" |
| Detection-source linkage | Each playbook references real detection | Mentions detections | Disconnected |
| Post-incident loop | Postmortem cadence + tuning loop | Mentions postmortem | None |

Passing threshold: ≥18/27; no axis scored 1 on severity criteria,
regulatory clocks, or playbook specificity.

## 5. Common mistakes

- **"The on-call decides."** Severity criteria must be
  falsifiable. "Customer financial harm > $0" is a criterion;
  "if it's bad" is not.
- **No regulatory clocks.** GDPR's 72-hour Article 33 clock and
  HIPAA's Breach Notification Rule both have specific start
  conditions; the procedure must name them and assign owners.
- **Playbooks of the form "investigate, fix, communicate."**
  Real playbooks have commands. The reference above shows the
  level of specificity required.
- **No tools/access section.** "We'll use kubectl" is not a
  control. Name the role, the command, and where access lives.
- **Single IC with no comms separation.** At a 6-person company
  the IC may *also* be the comms lead, but those are different
  jobs and the procedure must name them separately.
- **Playbooks not linked to detections.** A model-extraction
  playbook should reference the model-extraction detection rule
  from Exercise 02; otherwise the IR layer is divorced from the
  detection layer.
- **Skipping post-incident.** A playbook that doesn't end with
  postmortem + tuning + action items is a one-off, not a
  procedure.

## 6. References

- NIST AI Risk Management Framework (AI RMF 1.0) — MANAGE-4
  (incident response, continuous improvement).[^nist-ai-rmf]
- MITRE ATLAS — threat tactics that ground each playbook in a
  real attack pattern.[^atlas]
- OWASP Machine Learning Security Top 10 — categories that
  shape the playbook coverage.[^owasp-ml]
- GDPR Article 33 + Article 34 — the 72-hour notification
  obligation and data-subject notification, respectively.[^gdpr]
- HIPAA Breach Notification Rule (45 CFR §§164.400–414).[^hipaa]

[^nist-ai-rmf]: NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>
[^atlas]: MITRE ATLAS — <https://atlas.mitre.org/>
[^owasp-ml]: OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>
[^gdpr]: Regulation (EU) 2016/679 — General Data Protection Regulation, Articles 33–34. Official consolidated text: <https://eur-lex.europa.eu/eli/reg/2016/679/oj>
[^hipaa]: HHS HIPAA Breach Notification Rule (45 CFR §§164.400–414). Reference: <https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html>
