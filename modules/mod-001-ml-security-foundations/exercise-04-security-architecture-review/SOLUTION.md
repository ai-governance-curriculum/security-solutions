# SOLUTION — Exercise 04: Security Architecture Review of GlobalRecs

> Read this *after* writing your own review. The reference is *one*
> defensible review. Reasonable reviews will rank findings differently
> within severity bands; what matters is calibration (not everything
> Critical), concreteness (specific fixes), and a clear recommendation
> the GlobalRecs team can act on.

## 1. Solution overview

GlobalRecs proposes a recommender that fine-tunes a pretrained public
base model (`bert-large-uncased`) nightly, loads from `s3://.../latest/`
on pod startup with no signing or registry, authenticates tenants with
shared API keys, runs default-allow network policy, mounts AWS keys as
env vars, has no per-request logging, and treats SOC 2 as the compliance
answer.

**Recommendation: Block until critical fixes are in place.** The
proposal has three architectural choices that compound — mutable
`latest/` artifact, default-allow network policy, and the pretrained-
base + nightly retraining loop — such that a single early compromise
becomes a persistent serving compromise that monitoring cannot detect.
A "fix after launch" plan does not work here because the riskiest
vectors are activated *at* launch.

The review identifies eight findings across four severities. Three are
Critical (block); two are High (first sprint); two are Medium (next
quarter); one is Low (backlog). Two genuinely-correct choices are
acknowledged.

## 2. Worked answer — the review

### Reviewer

Module-001 security review — reference reviewer. Reviewed against the
proposal as written, OWASP ML Top 10, MITRE ATLAS tactic mappings, and
the prompt's lecture-notes references.

### Scope

**In scope.** The architecture proposal text as submitted.

**Out of scope.** Implementation-level code review, network topology,
data residency, the upstream Hugging Face Hub's own security posture
beyond the supply-chain risk it implies for GlobalRecs.

### Summary recommendation

**Block until Critical findings are addressed.** The riskiest choices
are activated at launch: the `s3://globalrecs/models/latest/` pointer
becomes the serving control plane on day one, and a default-allow
NetworkPolicy means any compromised pod can reach any other. Approving
"with conditions to be fixed after launch" makes those exposures
permanent if the post-launch work is deprioritized — which it usually
is.

### What's right

To calibrate the review and avoid reading as adversarial:

- **Choosing a versioned object store (S3) for artifacts** is right,
  even though the `latest/` path is wrong. Object-store + IAM is the
  correct primitive; the problem is the mutable alias and the missing
  signature.
- **Streaming click events back through the warehouse** is a defensible
  architectural pattern. The closed loop itself is normal; the lack of
  outlier detection on it is the issue (also flagged at SmartRecs).
- **Per-pod resource metrics in Prometheus** is the right starting
  point operationally. The gap is the missing per-request logging, not
  the choice of Prometheus.

### Findings

Ordered by severity, then by effort within severity.

#### Critical (must fix before launch)

**C1. Mutable `s3://.../latest/` artifact path with no signature
verification at pod startup.**

- **Threat.** Any principal with write to the bucket (training role,
  any other workload that may share the role, or a compromised CI)
  can change what every serving pod will load next time it restarts.
  No signature means no integrity check. This is OWASP **ML10 Model
  Poisoning** and ATLAS *ML Supply Chain Compromise*.
- **Reference.** OWASP ML10; MITRE ATLAS Resource Development +
  ML Supply Chain.
- **Fix.** Move from `latest/` to immutable `models/v{N}/` paths;
  introduce a model registry (or at minimum a Git-tracked promotion
  manifest that names a specific version). Sign artifacts (cosign or
  AWS Signer). Verify signature at pod startup; fail closed.
- **Effort.** Medium (2–3 sprints).

**C2. Default-allow Kubernetes NetworkPolicy with no plan to restrict
until "after launch."**

- **Threat.** Default-allow means a compromised pod in the cluster
  (which includes the nightly training pod that pulls from the public
  internet) can reach the model serving pods, the warehouse pods, and
  any sidecar that holds credentials. "After launch" is the time at
  which compromises become persistent — fixing later means
  retrofitting policy onto a workload graph already in use.
- **Reference.** Lecture notes §5.4 on default-deny; CIS Kubernetes
  Benchmark.
- **Fix.** Default-deny NetworkPolicy at namespace creation. Explicit
  allow rules per (source, destination, port). Add as part of the
  namespace bootstrap, not as a follow-up.
- **Effort.** Small (1 sprint).

**C3. AWS access keys mounted as environment variables to the training
pod.**

- **Threat.** Environment variables leak into crash dumps, child
  processes, logs, debugger output, and any library that prints the
  environment for diagnostics. The training pod also pulls a public
  model on each run, so any malicious code in the base model has
  process-level read of the env. The proposed ServiceAccount per pod
  is good but is wasted when the secret is mounted directly. Use
  short-lived, workload-bound credentials instead.
- **Reference.** Lecture notes §5.3 on workload identity; AWS IAM
  Roles for Service Accounts (IRSA) or equivalent.
- **Fix.** Replace static AWS keys with IRSA / Pod Identity (or, off
  AWS, a SPIFFE/SPIRE identity). Grant least-privilege IAM. Rotate
  any existing key as part of the migration.
- **Effort.** Small (1 sprint).

#### High (fix in first sprint after launch)

**H1. No per-request audit logging.**

- **Threat.** Without per-request logging, every other detection (model
  theft, abuse, poisoning of the feedback channel) loses its primary
  evidence source. "Too much volume" is solved by sampling, async
  shipment, and a short hot retention with longer cold retention.
- **Reference.** OWASP ML05 Model Theft; lecture notes §5.6.
- **Fix.** Per-request structured log to a cold store (S3 + Athena
  pattern), sampled at 100% for the first 90 days then re-evaluated.
  Include tenant_id, model_version, response_hash, latency.
- **Effort.** Small (1 sprint).

**H2. Tenant API keys are shared inside the tenant's organization
(data team, analytics team).**

- **Threat.** A leaked key is indistinguishable from legitimate use.
  Rotation costs are high because the key is shared. No path to
  per-user revocation. The proposal explicitly named "OIDC was more
  complex" as the reason — that's the very justification flagged in
  the prompt as a failing-mode signal.
- **Reference.** Lecture notes §5.3; OWASP ML05 in combination with
  ML02.
- **Fix.** Move to OIDC for the data/analytics human users; reserve
  long-lived API keys for service-to-service. Provide a per-user
  short-lived token exchange flow. Rotate the per-tenant key as part
  of cutover.
- **Effort.** Medium (2 sprints).

#### Medium (planned next quarter)

**M1. Nightly retraining from a public pretrained base model with no
provenance pinning.**

- **Threat.** OWASP **ML06 AI Supply Chain Attacks** + **ML07 Transfer
  Learning Attack**. The nightly job re-downloads the "latest public
  version" — there is no pin, no hash, no provenance check. A
  compromised or tampered upstream artifact silently becomes the base
  of GlobalRecs' production model. Note: this is exactly the threat
  ML07 names; SmartRecs (Exercise 02) did not have it because
  SmartRecs does not use a pretrained base. GlobalRecs does, so the
  same Top-10 item rates differently.
- **Reference.** OWASP ML06 + ML07; SLSA provenance v1.0.
- **Fix.** Pin the base model by hash (digest of the model artifact +
  tokenizer + config). Re-pin deliberately during scheduled refresh
  windows. Record the pinned hash in the training job manifest.
  Consider mirroring the upstream artifact into an internal registry
  before consumption.
- **Effort.** Small (1 sprint), but recurring policy work.

**M2. No outlier detection on the click-event feedback stream.**

- **Threat.** OWASP **ML02 Data Poisoning**. The same closed-loop
  pattern as SmartRecs. Any authenticated tenant — and shared API
  keys broaden the surface (see H2) — can submit feedback that
  drives the next retrain.
- **Reference.** OWASP ML02.
- **Fix.** Per-tenant outlier detection on feedback rate and event-
  type distribution. Reject or quarantine events that exceed a
  per-tenant baseline.
- **Effort.** Medium (2–3 sprints).

#### Low (note for the backlog)

**L1. "We have SOC 2" stated as the compliance answer.**

- **Threat.** SOC 2 is process attestation; it does not by itself
  address any ML-specific threat. Naming it as the security answer
  in an architecture review is the failing-mode signal the prompt
  explicitly calls out (lecture notes §5.6).
- **Reference.** Lecture notes §5.6.
- **Fix.** Document the *scope* of the SOC 2 (what is in and out of
  scope of the audit). Treat SOC 2 as evidence for a subset of
  controls; do not treat it as a substitute for ML-specific controls.
- **Effort.** Small (documentation update + scoping conversation).

### Open questions

The review cannot conclude on the following without more information:

- Whether `bert-large-uncased` is actually appropriate as the base —
  the architectural reasoning is not in the proposal.
- Whether the shared warehouse used for click-event streaming is
  multi-tenant; if so, the cross-tenant isolation question applies
  there too.
- Whether the training pod has egress to the public internet only for
  the model download, or for arbitrary endpoints; the proposal does
  not say.

### Next steps

1. GlobalRecs addresses C1–C3 before any production cutover.
2. Joint design session with security on the H1/H2 plan within two
   weeks of beginning C1–C3.
3. Re-review the revised proposal once C1–C3 are committed in code
   (manifests + Terraform/Pulumi).
4. M1 and M2 are scheduled into the next-quarter planning cycle, not
   carried as informal action items.

## Implementation

The review document is the deliverable; turning the summary
recommendation into action looks like this:

1. **Send the review back to GlobalRecs with the summary
   recommendation as the headline** (conditional go / block / hold)
   so the decision is unambiguous before anyone reads the findings.
2. **Open one ticket per Critical and High finding** (`C1`, `C2`,
   `C3`, `H1`, `H2`, …) on the GlobalRecs team's board, linked back
   to this document. Medium and Low live in the backlog with the same
   finding IDs.
3. **Block the production cutover gate** on C1–C3 being closed and
   re-reviewed; do not let "we'll fix it after launch" reopen the
   conversation.
4. **Schedule the re-review** as a calendar item, not a verbal
   commitment, so the loop actually closes.

## 3. Validation steps

To validate your own review:

1. **Coverage check.** Did you find at least 6 distinct findings? The
   exercise prompt names 6+ as the bar.
2. **Severity calibration.** Mix of severities. If you marked
   everything Critical, recalibrate — Critical is "production cannot
   start." If you marked nothing High, recalibrate the other way.
3. **Fix concreteness.** Each fix names a tool, a configuration
   change, or a specific control. "Improve security posture" is not
   a fix.
4. **"What's right" present.** The exercise prompt calls out
   calibrated reviews including positives; reviews that are all-
   negative get dismissed.
5. **SOC 2 finding present.** The prompt explicitly names missing
   the SOC 2-as-shield issue as a failing mode.
6. **LLM-specific risks present.** The proposal uses a pretrained
   LM as the base. ML06 + ML07 should appear. The prompt calls
   out missing this as a failing mode.
7. **Clear recommendation.** Approve / Approve with conditions /
   Block — pick one, defend it.

## 4. Rubric / review checklist

Pass at ≥ 8 of 10.

- [ ] Recommendation is explicit (Approve / With conditions / Block)
      and defended
- [ ] At least 6 distinct findings across multiple severities
- [ ] No more than 4 Critical findings (calibration)
- [ ] Every finding has Title, Severity, Threat, Reference, Fix, Effort
- [ ] References cite OWASP ML Top 10, MITRE ATLAS, or named lecture
      sections (not invented sources)
- [ ] At least one finding explicitly addresses the pretrained-base
      supply chain risk (ML06 / ML07)
- [ ] At least one finding explicitly addresses the SOC 2 framing
- [ ] "What's right" section present with at least two items
- [ ] Open questions section names what could not be concluded
- [ ] Total length 2–3 pages; not padded

## 5. Common mistakes

- **All-Critical reviews.** If the env-var secrets, the `latest/`
  alias, the missing audit logging, and the shared API key are all
  Critical, the review gives the team no signal about where to start.
  Calibrate: launch-blockers are Critical; first-sprint-after-launch
  is High.
- **Missing the SOC 2 finding.** The prompt explicitly names this as
  a failing-mode signal.
- **Missing the LLM-specific supply chain risk.** GlobalRecs starts
  from a pretrained public model and re-downloads nightly. ML06 and
  ML07 are the canonical mappings; missing them is the failing-mode
  signal called out in the prompt.
- **Treating "after launch" mitigations as acceptable for default-
  allow network policy.** Default-allow at launch becomes
  default-allow permanently. The fix has to land before traffic.
- **No "what's right" section.** Reviews without acknowledgement
  read as adversarial and are dismissed.
- **"Implement security best practices."** The prompt names this as
  a failing-mode phrase. Always name the control.
- **Hand-waving on effort.** "1 day" for IAM rework or "small" for
  IDP migration to OIDC. Calibrate against the size of GlobalRecs
  and the cross-team coordination required.

## 6. References

- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>
  (categories ML02, ML05, ML06, ML07, ML10 referenced in findings)
- MITRE ATLAS — <https://atlas.mitre.org/>
  (ML Supply Chain Compromise referenced in C1)
- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>
  (MANAGE function frames the "block until fixes" decision and the
  follow-up scheduling)
- Local exercise context: GlobalRecs proposal in
  `lessons/mod-001-ml-security-foundations/exercises/exercise-04-security-architecture-review.md`
