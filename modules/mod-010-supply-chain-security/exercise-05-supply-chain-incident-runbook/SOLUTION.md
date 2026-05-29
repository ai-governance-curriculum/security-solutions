# SOLUTION — Exercise 05: Supply-Chain Incident Runbook

Reference solution for authoring an incident-response runbook for a
supply-chain compromise affecting an ML system.

## 1. Solution overview

The exercise asks for a runbook that an on-call engineer can execute
mid-incident, not a post-hoc essay. The deliverable is:

- A scope statement (what counts as "supply-chain" for this runbook).
- A trigger list (concrete signals that open the runbook).
- Ordered phases with explicit owners and exit conditions per phase.
- Decision points written so they can be answered yes/no under time
  pressure.
- A communications plan.
- Tabletop questions for the team to rehearse against.

Framing references:

- **NIST AI RMF — MANAGE** function covers incident response for AI
  systems; the runbook is the operational instrument of MANAGE 4.x.
- **MITRE ATLAS** provides the attacker-side framing — *ML Supply
  Chain Compromise* (model, dataset, libraries).
- **OWASP Machine Learning Security Top 10** provides the
  defender-side framing.
- **SLSA** and **Sigstore** describe the artifact-level controls the
  runbook must check during containment and recovery.

## 2. Implementation — worked runbook

### Scope

This runbook applies when an artifact in the build-or-serve path is
suspected compromised. Concretely, any of:

- A model file, container image, base image, or library version that
  the prod inference path consumes.
- A signing identity, OIDC issuer, or transparency-log entry that
  underpins verification of those artifacts.
- A training dataset whose hash no longer matches the recorded
  provenance.

Out of scope (handled by other runbooks): account compromise without
artifact impact; data-only breaches; runtime-only attacks (prompt
injection, model evasion) that do not touch the supply chain.

### Trigger list

The runbook opens on any of the following:

1. Admission controller logs show signature or attestation
   verification failing for a previously-passing artifact (could be
   key compromise *or* attacker tampering).
2. Sigstore advisory or upstream advisory (e.g. CISA, vendor) names
   a dependency this system uses.
3. Hugging Face takedown, Hub revision rewrite, or model-card change
   on an internally re-hosted model.
4. SBOM diff shows an unexpected dependency added or version pinned
   downward.
5. CI runner logs show a workflow step modifying files outside its
   declared output paths.
6. Internal scanner flags a new CVE on a deployed image with
   `severity >= configured threshold`.

### Phase 0 — Declare and assemble (target: 15 minutes)

| Action | Owner |
|---|---|
| Page the on-call security engineer | Triggering system |
| Open an incident channel (named: `inc-<date>-<short-tag>`) | On-call |
| Page the ML platform on-call | On-call |
| Page the affected service's tech lead | On-call |
| Stand up an incident document with the trigger evidence linked | On-call |
| Assign roles: incident commander, scribe, comms lead, technical lead | On-call |

Exit condition: roles assigned, evidence pasted into the doc.

### Phase 1 — Scope (target: 30 minutes)

Goal: answer "what is affected" before any containment action.

1. Identify the suspect artifact by digest.
2. From the registry / model store, list every other artifact derived
   from it (children of the digest).
3. From the admission controller logs (Kyverno policy reports or
   policy-controller events), list every workload that has admitted
   this digest.
4. From the GitOps repo, list every environment pinned to it.
5. From the SBOMs (CycloneDX or SPDX, attached as Sigstore attestations
   per exercise-02), list every image whose SBOM includes the suspect
   component.

Exit condition: a written list of (artifact digest, environments,
workloads) on the incident doc.

### Phase 2 — Contain (target: 1 hour)

Containment is *deny-list at the policy boundary, not surgery on
running pods*. Pods on a compromised digest may still be doing
useful work; you may need to drain rather than kill, depending on
the service.

1. Add a Kyverno / policy-controller rule that explicitly denies the
   suspect digest. Apply to all namespaces in scope; commit via
   GitOps for audit.
2. Block the digest in the registry (read-only tag or explicit deny)
   so a re-pull cannot succeed.
3. Pause auto-scaling on the affected deployments so the controller
   does not try to admit fresh copies of the denied digest.
4. If the suspect is a signing identity (not an artifact), revoke the
   identity at the OIDC issuer side. *Existing* Rekor entries cannot
   be revoked — that is a property of an append-only transparency
   log per the Sigstore documentation. The verifier must additionally
   refuse the compromised identity going forward.
5. Decide rollback vs. patch:
   - **Rollback** if the last-known-good artifact's digest is still
     present in the registry, signed, and attested.
   - **Patch** if the last-known-good is not available, with the
     understanding that a patched artifact must run through the full
     signing pipeline before deploy.

Exit condition: the suspect digest cannot be deployed via any path
(GitOps, manual kubectl, third-party operator). The deny rule is
committed.

### Phase 3 — Eradicate (target: 4 hours)

1. Identify the entry point. Common possibilities:
   - Compromised dependency or base image (SBOM diff).
   - Compromised model from external source (re-vet evidence missing
     or pre-vetting evidence inadequate).
   - CI runner compromise (workflow run logs and OIDC token
     issuance).
   - Signing identity compromise (Rekor search by certificate
     identity).
2. Rebuild from a known-good source revision in a clean build
   environment (fresh runner, no cached layers).
3. Re-sign and re-attest per exercise-02.
4. Re-deploy with the deny rule still in place for the bad digest.
   The deny rule stays even after rotation; the bad digest is
   permanently quarantined.

Exit condition: a freshly built, signed, attested artifact is
running in prod and the old digest is denied.

### Phase 4 — Recover (same day to next day)

1. Restore auto-scaling.
2. Remove temporary mitigations (rate limits, fallback model
   downgrades) one by one with monitoring.
3. Confirm SLOs are back inside their targets.

Exit condition: SLOs green for one full monitoring window, ack from
the affected service tech lead.

### Phase 5 — Postmortem (within 5 business days)

1. Timeline reconstruction.
2. Detection-lag analysis: how long between attacker action and the
   trigger that opened the runbook? Each gap is a backlog item.
3. Control-effectiveness analysis: which controls fired? Which were
   absent or silent?
4. Update the SLSA self-assessment (exercise-01) for the affected
   artifact. A compromise often invalidates a previously-defensible
   level claim.
5. File backlog items with owners and dates. The runbook is not
   "closed" until the backlog has owners.

### Communications plan

| Audience | Channel | Cadence | Owner |
|---|---|---|---|
| Incident channel | Chat | Continuous | Scribe |
| Affected service owners | Direct ping into their channel | At trigger, at phase transitions | Comms lead |
| Leadership | Status email or doc | Hourly until contained, then on phase change | Incident commander |
| External (if user data implicated) | Per legal/privacy team's process | Per legal team's clock | Comms lead with legal |
| Regulators (if applicable) | Per the legal team's process | Per regulator's clock | Legal |

Do not externally name vendors or upstream projects until the eradication
phase confirms attribution.

### Decision points (yes/no for on-call)

- Is a *running* prod workload on the suspect digest? → If yes,
  drain before deny so users do not see errors mid-request.
- Has the signing identity itself been compromised? → If yes, all
  artifacts signed by that identity in the relevant time window are
  suspect, not just the triggering one.
- Did the suspect artifact pass through the standard pipeline? → If
  no, there is an out-of-band ingestion path that needs to be closed
  as part of eradication.
- Is the dataset implicated? → If yes, model retraining is in scope;
  re-signing the existing model is insufficient.

## 3. Validation steps

A runbook that has never been exercised is a wish list. Validation:

1. Run a tabletop with the team using the questions in §4.
2. Run a game-day at least quarterly: stage a controlled deny event
   (e.g. publish a deliberately mis-signed image into a test
   registry) and run the runbook through to Phase 2.
3. Time each phase. If Phase 1 ("Scope") takes more than the target,
   the inventory tooling is the gap, not the runbook prose. Backlog
   it.
4. After every real incident, walk the runbook against the actual
   timeline. Lines that nobody read in the heat of the moment are
   either redundant or in the wrong place — fix them.

## 4. Rubric — tabletop questions

Use these to exercise the runbook with the team:

1. The Kyverno admission controller starts rejecting images from
   `ghcr.io/example/inference-svc` with "identity mismatch." Last
   night's build passed. What is the first thing you do?
2. A maintainer of a transitive Python dependency posts on GitHub
   that their PyPI account was compromised yesterday. Two of your
   production images include that library. Which runbook phase are
   you in, and what is the deny scope?
3. The model team announces that the Hugging Face source for the
   model you re-host had its `main` branch rewritten three weeks
   ago. Your internal copy still works. Are you in incident?
4. CI logs for the daily training job show an extra
   `curl -X POST` step that was not in the workflow file. The
   resulting model has been deployed. Walk Phase 2 step by step.
5. The Cosign signing identity used for production builds was a
   self-hosted runner that was just discovered to be running a
   miner. The signing certificates are short-lived but the Rekor
   entries are not. What is your eradication step?

## 5. Common mistakes

- **Containing before scoping.** A snap "kubectl delete deploy"
  removes one symptom and erases evidence of the others. Scope
  first.
- **Trying to revoke Rekor entries.** Append-only by design
  (Sigstore docs). The compensating control is the verifier — refuse
  the compromised identity at the boundary going forward.
- **Treating a signature failure as the root cause.** A signature
  failure is a *symptom*. The cause is upstream: compromised
  identity, registry tampering, or attestation mismatch.
- **Removing the deny rule after the patch.** The bad digest stays
  denied permanently. Re-allowing it removes the only guardrail
  against an attacker re-pushing it.
- **Skipping the SLSA self-assessment update.** A compromise often
  invalidates the prior claim; leaving the assessment unchanged
  misleads future reviewers.
- **No tabletop.** A runbook that has only ever been read in
  isolation is not the runbook the team will execute under stress.
- **Comms-by-rumor.** Without a named comms lead and named cadence,
  the incident channel fills with speculation. Pre-assign roles in
  Phase 0.

## 6. References

- NIST AI Risk Management Framework — MANAGE function —
  <https://www.nist.gov/itl/ai-risk-management-framework>
- MITRE ATLAS, *ML Supply Chain Compromise* — <https://atlas.mitre.org/>
- OWASP Machine Learning Security Top 10 —
  <https://owasp.org/www-project-machine-learning-security-top-10/>
- SLSA v1.0 specification — <https://slsa.dev/spec/v1.0/>
- Sigstore documentation (Rekor transparency log, identity
  revocation) — <https://docs.sigstore.dev/>
- OpenSSF Scorecard — <https://openssf.org/scorecard/>
- Local cross-references:
  [exercise-01 SLSA self-assessment](../exercise-01-slsa-self-assessment)
  (update after incident),
  [exercise-03 admission verification](../exercise-03-admission-verification)
  (where the deny rule lives),
  [project-5-security-operations](../../../projects/project-5-security-operations)
  (where the wider SOC patterns live).
