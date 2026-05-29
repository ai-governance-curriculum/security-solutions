# SOLUTION — Exercise 05: Defense-in-Depth Design for SmartRecs

> Read this *after* writing your own control map. The reference design is
> *one* defensible answer for SmartRecs at its current scale (five
> engineers, no dedicated security role). Alternative designs that trade
> more detective controls for fewer preventive ones — or that defer more
> aggressively into "accepted at this stage" — are also defensible.

## 1. Solution overview

A defensible defense-in-depth design for SmartRecs satisfies three
constraints from the exercise prompt:

- **Concrete.** Each control names a tool, a signal, or a contract,
  not a category.
- **Operable by a five-person team.** Preventive controls dominate
  early lifecycle stages where they are cheap; detective controls
  dominate later stages where prevention is impossible or expensive.
- **Honest about accepted risk.** Several stages defer risk to cross-
  cutting controls or accept residual risk explicitly.

The design treats the ML lifecycle stages as a *control flow*: identity
and audit are bootstrapped first; data and artifact integrity follow;
prediction-time controls and post-deployment monitoring land last.
Sequencing is justified in §2.10. The design references the
prioritized backlog from Exercise 01 and the matrix from Exercise 02.

## 2. Worked answer — control map

### 2.1 Stage 1 — Data ingest

**Threats.** OWASP ML02 (data poisoning via the feedback channel);
ML06 (supply chain — the warehouse extracts as an internal trust
boundary). ATLAS *Collection* and *ML Supply Chain Compromise*.

- **Preventive.** Schema validation at the gateway ingest endpoint
  for click/purchase events. Reject events whose `(event_type,
  item_id, store_id)` tuple is implausible (item_id not in the
  tenant's catalog, store_id mismatch with API key). Pin warehouse
  data extracts by hash recorded in the training job manifest.
- **Detective.** Per-tenant feedback-event rate vs. a 30-day baseline
  (Prometheus gauge `feedback_event_rate_per_tenant`); alert when
  rate exceeds 3 σ for ≥ 30 min, paged to ml-platform on-call.
  Outlier detection on event-type ratio per tenant.
- **Responsive.** Per-tenant quarantine: when an alert fires, route
  that tenant's feedback to a quarantine table that does not feed
  training. Quarantine is a one-line config flag, not a code change.
- **Accepted at this stage.** Sub-quarantine-threshold drift goes
  uncaught here; relies on Stage 4 (Evaluation) and Stage 8
  (Monitoring) to catch slow accumulation.

### 2.2 Stage 2 — Feature engineering

**Threats.** ML08 (model skewing — dominant-tenant bias creeps into
features); silent feature-pipeline regressions.

- **Preventive.** Feature definitions live in version control with
  required review. Feature pipeline runs against a held-out
  reference dataset; refuses to publish features whose statistics
  shift > defined bounds vs. the previous run.
- **Detective.** Per-feature statistics surfaced as a Prometheus
  metric (`feature_statistic{feature="user_recency_days", stat="mean"}`)
  with alerts on KL-divergence > 0.1 from the prior week.
- **Responsive.** Block the downstream training run when statistics
  alert; require human approval to proceed.
- **Accepted at this stage.** Per-tenant fairness is not addressed
  here — deferred to Stage 4 / Stage 8 where per-tenant model
  quality is measured directly.

### 2.3 Stage 3 — Training

**Threats.** ML06 (supply chain — base data extracts, training
container images, library dependencies). ML10 (model poisoning at
artifact write). ATLAS *Resource Development / ML Supply Chain
Compromise*.

- **Preventive.** Training runs in a workload-identity-bound pod
  with least-privilege IAM (cf. cross-cutting control X1). Training
  image is pinned by digest; image signature verified at admission
  (Sigstore cosign). Dependencies pinned and audited via a lockfile
  produced from a known-good resolver.
- **Detective.** Training-job audit log records: input data hash,
  image digest, code commit SHA, output artifact hash. The signed
  build provenance attests these. Difference from the previous run
  is reviewed on the promotion ticket.
- **Responsive.** A failed signature check at deploy-time fails
  closed (cf. Stage 6). A poisoned artifact never reaches serving
  because Stage 6 verifies signatures.
- **Accepted at this stage.** A compromise of the training role
  itself (writing a legitimately-signed but malicious artifact)
  is not prevented here — it is detected by Stage 4 (Evaluation)
  and bounded by Stage 6 (Deployment) admission criteria.

### 2.4 Stage 4 — Evaluation

**Threats.** ML02 / ML10 detection by quality regression; ML08
detection by per-tenant performance.

- **Preventive.** Promotion ticket requires evaluation evidence:
  NDCG@10 on a held-out reference set, per-tenant NDCG@10 deltas,
  drift score vs. `recs-prod`. Promotion ticket template encodes
  these as required fields, not free text.
- **Detective.** Evaluation job emits structured metrics
  (`recs_eval{tenant_id, metric="ndcg_at_10", model_version}`). Per-
  tenant regression > 1 σ from `recs-prod` blocks promotion
  automatically.
- **Responsive.** Promotion ticket cannot be marked "approved" by
  the workflow if the structured evaluation has a blocking signal.
  Human approver can override with documented justification — the
  override is itself logged.
- **Accepted at this stage.** Evaluation against a *reference* set
  cannot detect targeted backdoors that activate only on adversary-
  chosen inputs; that is deferred to Stage 7 (Inference) input
  monitoring and Stage 8 (Monitoring).

### 2.5 Stage 5 — Registration

**Threats.** ML10 (artifact substitution at registration time);
audit-log tampering.

- **Preventive.** Artifact path is immutable per version
  (`recs-v{N}` is write-once). Promotion changes a separate
  pointer; the artifact itself is not overwritten. Two IAM roles:
  *trainer* (writes `recs-vN`), *promoter* (updates the
  `recs-prod` pointer). No single role does both.
- **Detective.** Object-store inventory diff: alert on any
  modification of a `recs-vN` path after its initial write. Alert
  on any change to the `recs-prod` pointer outside the promotion
  window or by a principal that is not the promotion workflow.
- **Responsive.** Auto-revert the `recs-prod` pointer to the prior
  value if a change occurs outside the workflow.
- **Accepted at this stage.** A compromise of the promoter role
  itself can still flip the pointer. The signature-verification
  control at Stage 6 is the backstop.

### 2.6 Stage 6 — Deployment

**Threats.** ML10 (deploying a poisoned artifact); ML09 (output
integrity via gateway/sidecar tampering).

- **Preventive.** Pod startup performs cosign verification of the
  artifact against a known set of training-pipeline signers; fails
  closed on signature mismatch. mTLS between gateway and pods
  (workload identity via SPIFFE or equivalent).
- **Detective.** Pod logs include the signature-verification outcome
  and the artifact digest actually loaded. Alert on any pod that
  loaded an artifact whose digest is not in the approved set.
- **Responsive.** A canary rollout pattern — first pod, then 25%,
  then 100% — with rollback on first-pod failure or per-tenant
  NDCG@10 regression > defined bound during the 25% window.
- **Accepted at this stage.** A signing-key compromise defeats this
  control; bounded by Stage 5 promoter-role separation and Stage 8
  monitoring.

### 2.7 Stage 7 — Inference

**Threats.** ML01 (input manipulation); ML05 (model theft / extraction);
ML03 / ML04 (inversion / membership inference); ML09 (output integrity).

- **Preventive.** Input validation at the gateway: payload schema,
  reasonable bounds on numeric features, rejection of obviously
  malformed requests. Per-tenant rate limit (already present).
  Suppress confidence scores in the response (ML03 / ML04
  mitigation).
- **Detective.** Per-tenant query-diversity metric
  (`tenant_query_unique_item_ratio`) — see Exercise 03's first
  detection point. Per-tenant feature-distribution drift detector.
  Per-pod tail-latency anomaly (an indirect ML01 signal).
- **Responsive.** Per-tenant throttling when detectors fire. A
  manual ToS-enforcement path documented for the customer success
  team.
- **Accepted at this stage.** Sophisticated low-and-slow extraction
  that stays under the diversity threshold is not detected here;
  bounded by aggregate Stage 8 monitoring (similarity audits) and
  contractual ToS.

### 2.8 Stage 8 — Monitoring

**Threats.** Cross-cutting catch-all: ML01 / ML02 / ML05 / ML08
incidents that slipped earlier controls; data drift; per-tenant
quality regressions; behavioral changes from competitors.

- **Preventive.** N/A — monitoring is detection by construction.
- **Detective.** A small fixed dashboard surface:
  - `model_ndcg_per_tenant` (alerts on per-tenant regression)
  - `feature_drift_score` (alerts > 0.3 on any monitored feature)
  - `tenant_query_diversity` (alerts on Exercise-03 thresholds)
  - `feedback_event_rate_per_tenant` (alerts on 3 σ excursions)
  - Audit-log ingest pipeline lag (a meta-detection)
  All routed to a single on-call rotation; runbook per alert.
- **Responsive.** Each alert points to a documented response: who
  pages, what they touch first, what the rollback / quarantine
  step is. SmartRecs' five-person team cannot operate dozens of
  alerts; the design intentionally keeps the active set small.
- **Accepted at this stage.** Long-tail attack patterns the team
  cannot observe (e.g., off-platform staging — cf. Exercise 03's
  detection gap) are deferred to ToS enforcement and to post-hoc
  similarity audits.

### 2.9 Stage 9 — Decommission

**Threats.** Data and model residue exfiltration after a model is
retired; lingering credentials.

- **Preventive.** Retirement runbook: revoke the deployment
  pointer, rotate signing keys if the retiring model was the
  signature anchor for any tenant integration, delete the
  artifact after retention window, revoke any per-model
  credentials.
- **Detective.** Audit query: any read of a `recs-vN` after its
  retirement timestamp. Alert.
- **Responsive.** Investigate any post-retirement access. Rotate
  credentials that the principal had.
- **Accepted at this stage.** Retention windows themselves (how
  long the artifact lives after retirement) are a business
  decision; the security design enforces *that* the decision is
  made and *that* the runbook executes consistently.

### 2.10 Cross-cutting controls

These span every stage. Implementing them is the prerequisite for the
per-stage controls.

- **X1. Workload identity.** Every pipeline pod and serving pod has
  a per-workload identity (IRSA on AWS; SPIFFE/SPIRE in cluster;
  GKE Workload Identity on GCP). No static AWS keys in pods. IAM
  policies key off the workload identity. *Foundation for Stage 3,
  Stage 5, Stage 6.*
- **X2. Append-only, tamper-evident audit log.** Per-request and
  per-pipeline-step structured logs to object storage with
  object-lock and a hash chain (or an append-only managed log
  service). Retention extended from 30 days to 1 year. *Foundation
  for every detective control.*
- **X3. Secrets management.** Move static secrets to a managed
  secret store with short-lived credentials and rotation.
  Application code does not see long-lived material.
- **X4. Code and config review with required approval on any
  change that touches identity, IAM, or admission policy.** Two-
  reviewer requirement on these directories; security review
  triggered automatically.
- **X5. Quarterly access review.** Who has *promoter* role, who
  has trainer role, who has tenant-key rotation rights. Review
  produces a written record.

### 2.11 Sequencing — the order to implement

Defended against the obvious alternative of starting with per-stage
controls.

- **Phase A (weeks 0–6). Foundation.** X1 workload identity, X2
  audit infrastructure, X3 secrets management. *Why first:* every
  detective control depends on credible identity and on log
  integrity. Building detection on top of static keys means the
  attacker can produce events that look authentic.
- **Phase B (weeks 6–14). Artifact integrity.** Stage 5 immutable
  versions + role separation, Stage 6 signature verification at
  pod startup, Stage 3 signed build provenance. *Why second:*
  closes the highest-leverage vector (one write to `recs-prod`
  becomes one deployment).
- **Phase C (weeks 14–22). Promotion and evaluation.** Stage 4
  structured evaluation criteria, codified promotion ticket. *Why
  third:* now that identity + integrity are in place, the human
  approval gate has *evidence* to act on.
- **Phase D (weeks 22–30). Closed-loop and runtime.** Stage 1
  feedback outlier detection and quarantine; Stage 7 per-tenant
  diversity detector. *Why fourth:* these detections produce
  pages — the on-call needs a runbook and capacity, which is
  built during the earlier phases.
- **Phase E (weeks 30+). Monitoring consolidation.** Stage 8
  dashboard with the five-metric surface; runbook authoring;
  Stage 9 decommission runbook. *Why last:* there is no value in
  a dashboard until the underlying signals exist.

The alternative — starting per-stage from Stage 1 forward — looks
appealing because it matches the lifecycle order, but every per-stage
detective control fails or becomes spoofable without the X1/X2
foundation.

### 2.12 Open questions

- Whether the warehouse the feedback events land in is shared with
  other internal teams. If so, X4 (review on identity/IAM changes)
  needs to cover those teams' bindings too.
- Whether the team can support a runbook-on-call rotation
  immediately, or if Phase D detections need to land as logs-only
  initially.
- Whether tenants have an integration contract that mandates
  signed responses; if so, X1 + Stage 6 mTLS arrive earlier in
  Phase A.

## Implementation

The control map is the artifact; the implementation work is taking
the Phase A → Phase D sequence (§2.11) and executing it.

1. **Phase A first, no exceptions.** Identity, audit, signed
   artifacts, and the kill switch are the cheap, high-leverage
   controls that every later phase assumes. Do not let teams pull
   later-phase work forward to skip Phase A.
2. **One ticket per (stage, control) cell** with the control kind
   (Preventive / Detective / Responsive) in the label so reporting
   can tell whether the program is over-indexed on detection without
   the response capacity to use it.
3. **Wire detective controls to runbooks** before they go to alert
   state. A new detective control without a runbook is logs-only
   until the runbook exists — see the open question on Phase D
   detections.
4. **Review the cross-cutting controls (§2.10) at every architecture
   change.** They are the controls that quietly stop working when
   identity, IAM, or secret-management changes underneath them.

## 3. Validation steps

1. **Concreteness check.** For every detective control, you named
   the signal, the surface, and the threshold. Re-read every
   "Detective" line; "monitor X" without a metric and threshold is
   a fail.
2. **No-duplication check.** A control that appears at every stage
   is usually wrong. Identity, audit, and secrets belong in cross-
   cutting; per-stage entries should be specific to that stage.
3. **Sequencing defense.** You can defend why foundations come first
   against the "match the lifecycle order" alternative.
4. **Accepted-risk check.** At least two stages have an explicit
   "Accepted at this stage" entry. A design with no accepted risk is
   usually over-claiming.
5. **Team-fit check.** Re-read the control list and ask: can five
   engineers operate this? If your design has 25 alerts, none of
   them will be answered well. The reference keeps the active
   alert set to about five.
6. **Cross-reference check.** Every High-priority gap from your
   Exercise 01 backlog should map to a preventive or detective
   control at a specific stage here.

## 4. Rubric / review checklist

Pass at ≥ 8 of 10.

- [ ] All nine lifecycle stages are present
- [ ] Each stage has a non-trivial entry (no "same as previous")
- [ ] Detective controls name a signal + surface + threshold
- [ ] At least two stages have an explicit "Accepted at this stage"
- [ ] Cross-cutting controls section names workload identity, audit,
      and secrets at minimum
- [ ] Sequencing section defends the order
- [ ] Sequencing puts identity / audit before per-stage controls
- [ ] The active monitoring surface is small enough for a 5-person
      team
- [ ] At least one control deliberately *removes* a feature (e.g.,
      suppress confidence scores) rather than adding one
- [ ] Total length 2–4 pages; not padded

## 5. Common mistakes

- **One control per stage, all preventive.** The exercise asks for
  preventive + detective + responsive. Detection is where slow
  attacks (poisoning, extraction) are actually caught.
- **Every stage has a `feature_drift` control.** Drift detection
  belongs at one stage (Monitoring) with a hook at Feature
  Engineering. Putting it everywhere is duplication, not depth.
- **No accepted risks.** A design that claims to mitigate every
  threat at every stage is over-claiming.
- **Treating Decommission as decorative.** Retired models leak
  through residual artifacts and credentials more often than
  through active attack. The runbook matters.
- **A 25-alert monitoring surface.** SmartRecs has five engineers.
  Alerts that nobody answers are worse than no alerts because they
  produce a false sense of detection.
- **Starting from Stage 1.** The lifecycle order looks like
  implementation order, but detective controls without identity
  and audit are deceptive — they fire on spoofable signals.
- **"Implement Sigstore" at three stages.** Pick a control's home
  stage; reference it cross-stage. Repetition is not depth.

## 6. References

- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>
  (ML01, ML02, ML05, ML06, ML08, ML09, ML10 referenced per stage)
- MITRE ATLAS — <https://atlas.mitre.org/>
  (tactic references in Stages 1, 3, 5, 7)
- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>
  (the MAP / MEASURE / MANAGE structure maps onto Foundation /
  Detective / Responsive in §2.10 sequencing)
- Local exercise context: SmartRecs threat model in
  `modules/mod-001-ml-security-foundations/exercise-01-threat-model-a-small-ml-system/SOLUTION.md`
  and OWASP coverage matrix in
  `modules/mod-001-ml-security-foundations/exercise-02-map-system-to-owasp-ml-top-10/SOLUTION.md`
