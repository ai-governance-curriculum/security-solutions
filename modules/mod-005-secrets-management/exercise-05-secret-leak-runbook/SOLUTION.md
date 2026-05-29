# SOLUTION — Exercise 05: Secret-Leak Incident Runbook

## 1. Solution overview

The deliverable is the operational runbook the team executes when a
secret is suspected (or confirmed) leaked. The runbook covers:

1. Detection sources that trigger an incident.
2. Triage decisions in the first 15 minutes.
3. Containment (revoke / rotate / contain blast radius).
4. Eradication (find every copy of the leaked value).
5. Recovery (restore service on the rotated credential).
6. Lessons-learned and the post-incident updates that feed back into
   exercise-01 (inventory), exercise-03 (rotation), and exercise-04
   (keyless CI).

The runbook structure follows NIST SP 800-61 Rev. 2's incident-handling
phases (Preparation → Detection & Analysis → Containment, Eradication
& Recovery → Post-Incident Activity); the contents are tailored to
secrets specifically.

The exercise is operational; the artifact is the runbook itself.
Tabletop exercises against the inventory's worst cases (T0 KMS root
leaked, T1 model-registry token leaked, T1 OIDC trust misconfigured)
are the validation.

## 2. Implementation (worked answer)

### 2.1 Detection sources

The runbook is invoked from any of:

- **Secret scanner alert** — GitHub secret-scanning push protection,
  Gitleaks/TruffleHog in CI or against published artefacts, scheduled
  repo or registry scans.
- **External notice** — provider notification ("this token has been
  shared publicly"), abuse report, third-party breach disclosure
  including the platform's credentials.
- **Audit/SIEM** — unexpected use of a credential from an unexpected
  source IP/identity/region; use of a credential after its rotation
  cut-off; first use of a credential outside its declared consumer
  set (from exercise-01).
- **Internal report** — engineer noticed a secret in a log, a
  screenshot, a support ticket, a Slack message, a public repo, a
  laptop they no longer have, etc.
- **Build- or runtime-failure** that surfaces a secret unexpectedly
  in a logged stack trace.

Each detection source has a documented intake path (GitHub alerts
channel, SIEM oncall queue, security@ inbox). The runbook is the
*same* once invoked; the source determines only how it was triggered.

### 2.2 Roles

| Role | Responsibility |
|---|---|
| **Incident commander (IC)** | Calls the shots, owns the timeline, runs the bridge, declares severity. |
| **Secrets owner** (from exercise-01) | Executes rotation per exercise-03; the IC does not. |
| **Communications** | Internal updates, customer notifications if required, regulator notifications if required. |
| **Scribe** | Captures timeline (events, decisions, who acted) into the incident document; the IC does not. |
| **Forensics** | Reads audit logs, builds timeline of credential use during the exposure window. |

The IC is a different person from the secrets owner. The most common
runbook failure mode is one person trying to coordinate *and* execute
the rotation, missing one or the other.

### 2.3 Severity matrix

| Severity | Definition | Examples |
|---|---|---|
| **SEV-1** | T0 or T1 credential confirmed exposed, with evidence (or strong probability) of adversarial use. | KMS root key shares disclosed; model-registry write token used from an unknown IP; OIDC trust policy with `repo:*` discovered being abused. |
| **SEV-2** | T1 credential confirmed exposed but no evidence of adversarial use. | Production read token in a public gist; webhook secret in a screenshot. |
| **SEV-3** | T2/T3 credential exposed or T1 *suspected* (e.g. unverified provider notice). | Dev DB password in a Slack message; vendor warning we cannot yet corroborate. |
| **SEV-4** | T4 non-secret reported as a leak; misclassification. | Public OAuth client ID flagged by a scanner. |

Severity *only* governs the response cadence and notification
breadth; the technical steps are the same for SEV-1 through SEV-3.

### 2.4 First 15 minutes (detection → containment start)

```
T+0   Detection event reaches the secrets-incident channel.
T+1   On-call security engineer becomes IC. Opens an incident doc.
T+2   IC pages the secrets owner for the suspected secret(s).
      - Lookup uses the exercise-01 inventory: scanner hit / audit
        event → inventory ID → owner.
T+5   IC confirms whether the value is in fact a secret (against
      inventory T4 row to avoid false positives).
T+7   Severity declared (§2.3). Comms paged if SEV-1 or SEV-2.
T+10  Forensics begins building the exposure-window timeline:
      - When was the secret first issued?
      - When was it last rotated (inventory row)?
      - What is the earliest plausible exposure time?
      - What audit events touched it in that window?
T+15  Containment plan agreed (§2.5). Secrets owner begins
      execution. IC continues to coordinate.
```

If the secret cannot be identified from the inventory, the runbook
escalates immediately — an unknown secret is one whose blast radius
the team cannot bound, and unbounded blast radius is SEV-1 by
default.

### 2.5 Containment

Containment uses the rotation patterns from exercise-03 §2.2, but
biases toward **revoke first, restore second**, with two exceptions
noted below.

**Default (T1 single-secret leak with known blast radius):**

```
1. Revoke the leaked credential N.
2. Issue replacement N+1.
3. Push N+1 to all consumers (consumer list from inventory).
4. Restart / redeploy consumers.
5. Confirm consumers using N+1 (audit log).
6. Confirm zero further uses of N (audit log shows revocation
   blocking attempts).
```

In an incident, "revoke first" is correct because the cost of a brief
outage on the affected workload is smaller than the cost of
attacker-controlled use during a graceful rotation window.

**Exceptions (Pattern A overlap retained):**

- **T0 root key** (KMS root, signing CA): cannot be revoked
  instantly without taking everything beneath it offline. Execute
  Pattern C (verifier overlap) under SEV-1, with the additional
  constraint that the new root is provisioned in an out-of-band
  channel.
- **Cryptographic material protecting data at rest** (transit keys,
  storage-encryption keys): old version is *retained for decryption*
  (`min_decryption_version`) while new version takes over encryption;
  see exercise-03 Pattern E. Revoking immediately would break access
  to existing data and could cause data loss.

**Trust-config leaks** (e.g. an IAM role trust policy unintentionally
permits `repo:*`): the leaked artefact is the *configuration*, not a
credential. Containment is to tighten the trust policy first, then
audit any STS calls that occurred under the looser policy.

### 2.6 Eradication — find every copy

A leaked secret is rarely in just one place. The runbook prescribes
a search across:

- **Source repos** — the leaking commit and every fork, including
  archived repositories. `git log -S<token-prefix>` plus a fresh
  scanner run.
- **CI logs** — every pipeline that printed the secret to stdout.
  Many CI systems retain logs for weeks; the value must be invalidated
  before this matters, but the logs are then redacted.
- **Container images** — search any image layer for the value;
  rebuild and re-publish affected images under N+1 even if N is
  already revoked, because the leaked image is still evidence of the
  pattern.
- **Backups and snapshots** — Vault snapshots, database dumps, log
  archives. The leaked value may continue to exist there until
  retention expires; tag the affected backups so they are not
  restored without a rotation step.
- **Chat / docs / tickets** — Slack, Confluence, Jira, Notion. The
  most common locations for human-pasted secrets.
- **External services** — paste sites, Stack Overflow answers, GitHub
  Gists, search indexes; submit takedown requests where applicable.
- **Endpoints** — engineer laptops if the secret was a personal
  token; covered by IT.

Each location's check is logged in the incident doc; "we don't think
it's there" without a check is not eradication.

### 2.7 Forensics — what did the attacker do

Forensics builds a usage timeline of the leaked credential in its
exposure window:

- **Authentication events**: every successful and failed use, with
  source identity / IP / user-agent / region.
- **Authorisation events**: every API call made under the
  credential's identity.
- **Downstream artefacts**: anything created, modified, or deleted
  under the credential's identity (objects, IAM changes, model
  registry entries, container pushes, etc.).
- **Anomaly markers**: uses outside business hours, from unfamiliar
  ASNs, in patterns inconsistent with the workload (e.g. an
  inference token making `iam:ListUsers` calls).

For ML-specific credentials:

- **Model-registry write token**: every model version created,
  including its name, tag, and signature. Verify each against the
  expected CI build (signed attestation per exercise-04). Unsigned or
  mis-attested versions are treated as adversarial until proven
  otherwise.
- **Training-data read token**: any unusual data egress patterns
  (large bulk reads, full-table scans).
- **OIDC subject misconfiguration**: every STS call under the looser
  policy in CloudTrail; each is reviewed individually for whether the
  caller was legitimate.

### 2.8 Recovery

- Consumers running on N+1; N revoked or expired.
- All copies of N inventoried and either removed or marked
  non-restorable.
- The forensic timeline has no entries after the revocation cutoff;
  if it does, that is a new incident, not recovery.
- For SEV-1 with confirmed adversarial use, the secrets owner reviews
  every artefact created under N during the exposure window for
  rollback or re-creation under a clean identity.

Recovery is declared by the IC, not by the secrets owner — the same
person who declared the incident closes it.

### 2.9 Post-incident

Within five business days the IC writes a post-incident report
covering:

- Timeline (from the scribe's notes).
- Detection latency (exposure → detection → containment → recovery).
- Root cause.
- Contributing factors (process, tooling, training).
- Inventory updates (exercise-01) — was the secret in the
  inventory? Was the consumer list correct? Was the blast radius
  correctly tiered?
- Rotation playbook updates (exercise-03) — did the playbook
  cover this rotation pattern?
- Keyless-CI updates (exercise-04) — could this leak have been
  prevented by a short-lived credential?
- Detection updates — what audit/SIEM rule, if it had existed,
  would have caught this sooner?

Action items have owners and due dates. The runbook is read again in
quarterly tabletops; if an action item appears for a second time, it
is escalated.

### 2.10 Worked scenario — model-registry write token leaked

A SEV-1 walkthrough for SEC-003 (from exercise-01).

```
T+0  Gitleaks finds the MLflow token value in a Markdown changelog
     committed to a public mirror of the platform repo.
T+1  IC paged; secrets owner = ML platform oncall.
T+5  IC confirms value matches SEC-003. Severity SEV-1: T1, public
     exposure, evidence-of-use TBD.
T+10 Forensics: token last rotated 47d ago. Exposure window =
     since first appearance of the leaked commit (28d).
T+12 Containment plan: revoke N immediately; issue N+1; push N+1
     to GitHub Actions org secret; trigger one canary workflow to
     validate.
T+18 N revoked at MLflow. CI workflows now failing — expected.
T+22 N+1 stored; canary workflow succeeds.
T+25 All scheduled workflows rerun on next trigger using N+1
     successfully.
T+30 Forensics: MLflow audit log for the exposure window. Every
     model version created under N is enumerated; each is compared
     to the expected commit (signed attestation per exercise-04).
T+90 Three model versions created under N have no matching signed
     attestation. They are quarantined and not used; the
     adversarial-defense team (project-3) examines them.
T+24h IC declares recovery: consumers stable on N+1, no further
      use of N in audit, suspect model versions quarantined.
T+5d Post-incident report:
     - Action item: SEC-003 retirement (migration to OIDC-derived
       short-lived MLflow token per exercise-04). Owner: ML Platform.
       Due: next sprint.
     - Action item: add SIEM rule for MLflow writes from IPs outside
       the GitHub Actions runner ranges.
     - Action item: extend Gitleaks to scan the public mirror.
     - Inventory: SEC-003 rotation cadence tightened to 30d until
       retirement.
```

### 2.11 Design rationale

- **Same runbook for all severities** keeps the incident response
  drilled and predictable; severity affects who is paged, not what
  is done.
- **Revoke first, restore second** trades a brief workload outage
  for bounded attacker time. The exceptions (T0 keys, encryption
  keys) are deliberate.
- **Inventory is the source of truth** for owner, consumer list,
  blast radius. A runbook with no inventory cannot answer "who do we
  page?" at T+1.
- **Eradication is a checklist, not a vibe.** Every location either
  has a "checked, clean" entry or it isn't eradicated.
- **Forensics output drives the post-incident.** A timeline of
  attacker actions is the only basis for deciding what artefacts to
  trust afterwards.
- **The runbook feeds back into the other exercises.** Post-incident
  improvements that don't change the inventory, the rotation
  playbook, or the keyless-CI design are weak improvements.

## 3. Validation steps

1. **Tabletop the worked scenario** quarterly with the named roles.
   Measure detection→containment time. Any role that cannot identify
   the next action from the runbook alone is a gap.
2. **Inject a known-secret canary** into a non-production location
   (private gist, dev container layer). Scanner alerts must reach
   the on-call within the SLO; the runbook must be triggered without
   intervention from the planter.
3. **Negative test the inventory linkage.** Hand the IC a fabricated
   alert containing a secret ID that does *not* exist in the
   inventory. The runbook must escalate, not stall.
4. **Audit-pipeline test.** Confirm that the audit signals needed
   for forensics (per-secret access events, source IP, identity
   claim) are reaching the SIEM. A runbook step that depends on a
   log nobody collects is a fiction.
5. **Cross-exercise consistency.** Walk the worked scenario; every
   step references either an exercise-01 row, an exercise-03 pattern,
   or an exercise-04 component. Steps referencing nothing are signs
   the runbook is detached from the rest of the program.

## 4. Rubric / review checklist

| Criterion | Pass | Partial | Fail |
|---|---|---|---|
| **Detection sources** | Multiple sources named, each with intake path. | Sources named, intake path missing. | "We will be alerted somehow". |
| **Roles** | IC and secrets owner are different people; comms, forensics, scribe distinct. | Roles defined; some shared. | One person does everything. |
| **Severity** | Matrix grounded in T0-T3 from exercise-01. | Matrix exists; not linked to inventory. | One severity for everything. |
| **First 15 minutes** | Timed playbook; each step has an owner and an output. | Steps listed without timing. | Free-form prose. |
| **Containment** | Revoke-first default + named exceptions (T0, encryption keys, trust config). | Revoke-first default only. | Graceful rotation in all cases. |
| **Eradication** | Search across repos, CI logs, images, backups, chat/docs, external services. | Subset of locations. | "Remove from the original commit". |
| **Forensics** | Authentication / authorisation / artefacts / anomaly timelines, with ML-specific items. | Timeline exists; ML specifics absent. | Forensics step is "look at logs". |
| **Recovery** | Closed by IC against named criteria. | Recovery undefined. | "Wait until it's quiet". |
| **Post-incident** | Feedback loop into exercise-01/-03/-04 explicit. | Lessons captured; no follow-through. | None. |
| **Tabletop history** | Drills scheduled and dated. | Drill planned. | Never drilled. |

## 5. Common mistakes

- **No inventory linkage.** The first thing the IC needs at T+1 is
  the owner; without an inventory the IC starts by *finding* the
  owner.
- **IC also rotating.** The person running the bridge cannot also
  execute. Splitting the roles is non-negotiable.
- **Revoking the T0 root key on instinct.** Take everything beneath
  it offline; rehearse the recovery path first.
- **Skipping eradication because "revoked is enough".** The leaked
  copy of the secret is now a pattern in repos and logs; future
  inventory work depends on knowing about it.
- **No forensic timeline for ML artefacts.** Quarantining suspect
  model versions only works if you know which were created under the
  exposed credential.
- **Post-incident with no action items.** Or with action items that
  never close. Tabletop will surface the repeat offenders.
- **Tabletop using only the runbook author.** The drill should pass
  with someone who has never seen the runbook before; otherwise the
  runbook is in the author's head, not on the page.
- **No detection of the runbook's own breakdown.** A SIEM rule that
  watches for use of a credential *after* its revoke event is the
  best safety net; without it, eradication failures go silent.

## 6. References

- NIST SP 800-61 Rev. 2, *Computer Security Incident Handling Guide*:
  <https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final>
- NIST SP 800-53 Rev. 5, control families `IR-4` (incident handling),
  `IR-8` (incident response plan), `IA-5` (authenticator management):
  <https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final>
- NIST SP 800-57 Part 1 Rev. 5, *Recommendation for Key Management* —
  compromise recovery for cryptographic material:
  <https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final>
- NIST AI Risk Management Framework — Manage function (incident
  response for AI systems):
  <https://www.nist.gov/itl/ai-risk-management-framework>
- OWASP Secrets Management Cheat Sheet (compromise response):
  <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>
- OWASP Machine Learning Security Top 10 — model-supply-chain
  threats motivating the post-incident quarantine of model
  artefacts:
  <https://owasp.org/www-project-machine-learning-security-top-10/>
- MITRE ATLAS — adversarial techniques against ML systems including
  credential-driven model-supply-chain compromise:
  <https://atlas.mitre.org/>
- GitHub — *About secret scanning* and *Push protection*:
  <https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning>
- HashiCorp Vault audit devices (basis for forensics steps):
  <https://developer.hashicorp.com/vault/docs/audit>

