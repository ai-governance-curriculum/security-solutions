# SOLUTION — Security Operations Center

> Read this *after* attempting the learning-side project. This file
> explains the design decisions, what the detections are actually
> watching for, and how the operational components fit together.

## What problem this solves

The first four projects in this track focus on *preventive* security —
controls that stop bad outcomes. Project 5 is about what happens *after*
an incident starts, and how you find out in the first place:

1. **Detection** — Sigma-format rules that fire on the events ML
   platforms actually generate.
2. **Response** — playbooks for the realistic threat scenarios you'll
   face (model theft, data poisoning, adversarial DoS).
3. **Practice** — game-day / tabletop exercises so the playbooks don't
   first get tested mid-incident.
4. **Learning** — a structured postmortem template so each incident
   improves the system.

## Architecture decisions and *why*

### Why Sigma rules (not vendor-specific SIEM rules)

Sigma is a generic, YAML-based detection format that converts to most
SIEM query languages (Splunk SPL, Elasticsearch DSL, Sentinel KQL,
Chronicle YARA-L). Writing detections in Sigma keeps the curriculum
vendor-neutral and gives readers a portable artifact they can take to
any SOC.

### Which detections are in scope and why

- `lateral-movement.yml` — captures the *very common* pattern of a
  compromised training pod attempting to reach feature stores or
  model registries it has no business touching. Keys off the SPIFFE
  identity from project-1.
- `model-extraction.yml` — high-volume / high-similarity query bursts
  against a single served model from a single tenant identity. Catches
  the attack `project-3-adversarial-defense` is trying to prevent.
- `data-exfiltration.yml` — anomalous egress, *with ML-aware noise
  reduction* (training jobs naturally have heavy egress to dataset
  storage; the rule whitelists known patterns to reduce false positives).

Generic detections (Linux user enumeration, kernel-module loads, etc.)
are explicitly out of scope here — they belong in a general security
program, not the ML-specific one this project demonstrates.

### Why ML-specific playbooks (not generic IR plays)

Generic IR playbooks ("isolate the host, preserve the disk, call the
forensics team") apply but are insufficient. ML incidents have
additional questions:

- **Model theft**: does the attacker have a usable copy, or just a
  partial decision boundary? What is the *commercial impact*? Should we
  rotate the deployed model to invalidate the stolen copy?
- **Data poisoning**: which downstream models were trained on the
  affected dataset? Do we need to retrain from a known-good snapshot?
  What is the model rollback impact?
- **Adversarial DoS**: is the load attack-driven or organic? Per-tenant
  rate limits + adversarial-example logging together answer this.

Each playbook in `playbooks/` walks through the ML-specific decision
points alongside the standard IR checklist.

### Why tabletop / game-day before automation

Detections and playbooks both decay. Tabletops surface the decay
before an attacker does. The exercise scripts in `tabletop/` inject
realistic-looking events into the test environment and let the on-call
practice the playbook end-to-end. Fault-injection scripts (cross-ref
to `engineer-solutions/mod-108 ex-09 gameday`) drive the simulated
attacker side.

## How to read the code

Execution-order reading path:

1. `sigma-rules/lateral-movement.yml` — read with project-1's
   SPIFFE-keyed audit log in mind.
2. `sigma-rules/model-extraction.yml` — read alongside project-3's
   rate-limit logic.
3. `sigma-rules/data-exfiltration.yml` — note the whitelist patterns.
4. `playbooks/` — pick one and walk through it with the matching
   detection in tab beside you.
5. `tabletop/q1-tabletop.md` — run this with your team.
6. `tabletop/injection-scripts.sh` — what makes the tabletop feel real.
7. `postmortem-template.md` — what the team produces afterward.

## What's deliberately simplified

- **No SIEM-specific implementation.** The Sigma rules are deliberately
  abstract; a real deployment converts them to your stack (uncoder.io,
  sigmac, sigma-cli).
- **No threat intelligence integration.** No IOC ingestion, no STIX/TAXII
  feed, no third-party threat intel feed correlation.
- **No automated response (SOAR).** Each playbook ends with a manual
  decision step. Automating containment is risky and out of scope for
  curriculum material.
- **No legal-hold integration.** Real incidents trigger legal-hold
  workflows — pointers only here.
- **No insider-threat detections.** UEBA is a specialized domain; this
  project sticks to external-threat patterns.

## Cross-references for deeper coverage

| Topic | Where the deeper implementation lives |
|---|---|
| Alert routing + escalation | `engineer-solutions/mod-108 exercise-07-alertmanager-routing` |
| Fault-injection / game day | `engineer-solutions/mod-108 exercise-09-incident-response-gameday` |
| Tamper-evident audit log (incident evidence) | `mlops-learning/projects/project-4-governance/src/audit/log.py` |
| Per-tenant rate limits | `project-3-adversarial-defense/defenses/rate_limit.py` |
| SPIFFE-keyed identity for lateral-movement detection | `project-1-zero-trust/spire/` |

## Production gap checklist

- [ ] SIEM-specific rule conversions for your stack + tested in staging
- [ ] Threat-intel feed ingestion (IOC correlation)
- [ ] SOAR runbooks for the contained-blast-radius response steps
- [ ] On-call rotation with documented escalation paths and SLAs
- [ ] Quarterly tabletop cadence with rotating scenarios
- [ ] Insider-threat detections (UEBA)
- [ ] Forensic data retention policy aligned with regulatory requirements
- [ ] Coordinated disclosure / customer notification workflow for incidents
      that affect models served to external users

## Validation

The tabletop *is* the acceptance test. A team that can execute
`q1-tabletop.md` end-to-end without referring to the playbook mid-flow
is operationally ready. A team that gets stuck mid-tabletop has
identified the part of the system that would have failed in a real
incident — fix that gap before running the next quarter's tabletop.

## Time budget for studying this solution

- **Skim**: 45 min — read this file, walk through one playbook.
- **Deep**: 2–3 days — run the full Q1 tabletop with a team, produce a
  postmortem, identify the gaps the tabletop surfaced.

The tabletop is the highest-leverage artifact in the entire security
track. If you only do one thing from this project, run it.
