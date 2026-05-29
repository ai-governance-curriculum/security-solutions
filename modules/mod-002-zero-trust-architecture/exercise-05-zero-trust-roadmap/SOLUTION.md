# SOLUTION — Exercise 05: Zero-Trust Roadmap

> Read this *after* attempting the exercise.

## 1. Solution overview

The exercise asks for a 3–4 page roadmap document that
sequences SmartRecs' zero-trust adoption **by reversibility,
not by enthusiasm**, with a defined end state, per-phase
deliverables / success criteria / duration / headcount /
rollback, named risks, and a CFO-friendly summary.

The most common failure is over-optimism: "we'll have
zero-trust in 6 weeks." Zero-trust adoption at SmartRecs' size
(5 engineers + 1 security engineer, paying customers in
production) is realistically a **12–24 month effort** running
at part-time intensity. This solution sequences three phases
totalling **~15 months** of calendar time, with phase
boundaries set so each phase is reversible without an outage.

Three properties drive the design:

1. **Identity comes first.** Without workload identity, every
   later control is encrypted traffic between unknown
   parties. Phase 1 lands identity before any mesh / network
   policy work.
2. **Detection precedes enforcement.** Every Phase 2 and
   Phase 3 control is deployed first in **dry-run** /
   **monitor** mode, with metrics, before flipping to
   enforce. This is the Module 09 policy-as-code pattern and
   it is what makes rollback achievable.
3. **The unsexy controls (audit, asset inventory) come
   before the glamorous ones (mesh, per-request authz).**
   Audit is what proves you did the rest correctly; without
   it, every later claim is unverifiable.

This solution sequences the same gaps identified in
Exercise 01 — and intentionally schedules tenet-5 (posture
informs access) into Phase 3, because closing the loop
between detection and authorization is the most operationally
expensive change in the set.

## 2. Implementation (worked answer)

The remainder of this section is the worked artifact.

---

### SmartRecs Zero-Trust Adoption Roadmap

**Author:** _reference solution_
**Date:** 2026-05
**Prior artifacts:** Module 01 threat model; Exercise 01 gap
analysis ([`../exercise-01-zero-trust-gap-analysis/SOLUTION.md`](../exercise-01-zero-trust-gap-analysis/SOLUTION.md));
Exercise 02 workload-identity design ([`../exercise-02-workload-identity-design/SOLUTION.md`](../exercise-02-workload-identity-design/SOLUTION.md)).

#### Executive summary

SmartRecs will adopt zero-trust in three phases over
approximately 15 months at ~30% of the platform team's
engineering capacity, sequenced so each phase is independently
reversible. By the end of Phase 3 (target Q3 2027 given a Q3
2026 start), every workload-to-workload call inside the
platform is authenticated, authorized per-request, and
auditable; failures of any single control fall back to a
denied request, not a silent exposure.

#### "Done" definition

"Adoption complete" means:

1. Every production workload has a workload identity from
   SPIFFE / SPIRE (or the cloud-equivalent IRSA / GKE WI /
   AAD WI).
2. Mesh-wide `PeerAuthentication: STRICT` is in effect; no
   plaintext east-west traffic exists in production.
3. Every mesh-allowed flow has an `AuthorizationPolicy`
   keyed on `principals` and `methods/paths`; default-deny
   is effective.
4. Per-tenant authorization is enforced in the application
   (or via OPA sidecar) on every multi-tenant resource —
   feature store, model registry.
5. The per-request audit log is signed by the calling
   workload's SVID and retained for ≥1 year.
6. Runtime detection (Falco or equivalent) is wired to the
   mesh: a workload that fails runtime posture checks has
   its SVID revoked or downgraded within 5 minutes.

This is an auditable end state. A reviewer can answer each
of the six statements with "yes / no / partial" by reading
configuration and audit records.

It is **not** "we have Istio installed." Istio is a means;
the six statements above are the end.

#### Phase 1 — Foundations (low-commitment, reversible) — ~4 months

- **Goal.** Establish identity, audit, and asset inventory.
  These are the prerequisites for any meaningful enforcement
  in Phases 2 and 3.
- **Deliverables (3–7 items).**
  1. SPIRE Server + SPIRE Agent running in the cluster (or
     IRSA / GKE WI / AAD WI fully wired if managed
     Kubernetes is in use). Identities issued to gateway,
     serving, training, governance, and notebook workloads
     per the Exercise 02 identity table.
  2. Per-request audit log centralized in S3 with the
     workload's SVID URI in every entry. Retention
     extended from 30 days to 1 year.
  3. Asset and credential inventory in Vault KV; manual
     enumeration of every static credential in current use
     and an owner per credential.
  4. Pod Security Standards `restricted` profile enforced
     in `notebooks` and `gov`; `baseline` in production
     namespaces with a tracked plan to migrate to
     `restricted`.
  5. Image-digest pinning by Kyverno admission policy in
     all production namespaces (rejects deployments that
     reference tags only).
- **Success criterion to advance.** All five deliverables
  shipped; identity issuance success rate ≥99% across one
  week of normal operations; no incident attributable to
  Phase 1 changes.
- **Duration.** 4 calendar months (16 weeks). Estimate
  rationale: SPIRE bootstrap is the largest single task
  (~4 weeks); audit-log rework is ~3 weeks; PSS rollout per
  namespace is ~1 week each plus the unavoidable cycle of
  finding workloads that misbehave under `restricted`.
- **Headcount.** Security engineer at 80% allocation; one
  platform engineer at 30%. ML engineers consulted, not
  staffed.
- **Rollback plan.** Each deliverable is independently
  reversible.
  - SPIRE: workloads continue to function on ServiceAccount
    tokens if SPIRE is removed; identity-keyed audit drops
    back to namespace-keyed.
  - Audit log changes: append-only, so reverting the schema
    only affects new entries; old entries retain the
    extended fields.
  - PSS: profile downgrade is a single annotation per
    namespace.
  - Kyverno admission: removing the policy returns admission
    to default-allow for image references.

#### Phase 2 — Microsegmentation (medium-commitment) — ~6 months

- **Goal.** Default-deny the east-west fabric at L3/L4
  and at the mesh layer; explicit allows keyed on identity
  from Phase 1.
- **Deliverables.**
  1. NetworkPolicy default-deny in every production
     namespace, with the explicit allow set from Exercise
     03 in place and admitted.
  2. Istio installed in production with sidecar injection
     enabled in serving namespaces;
     `PeerAuthentication: STRICT` mesh-wide. Sidecar
     injection migrated namespace-by-namespace, not all at
     once.
  3. `AuthorizationPolicy` set from Exercise 04 deployed
     in `dry-run` (audit-only) mode for 4 weeks before
     flipping to enforce. Metrics show predicted-deny
     count vs actual-deny count after flip.
  4. Application-layer tenant authorization in the
     feature store (the highest-risk app-layer decision
     in Exercise 03 Layer 3). Implemented as an OPA
     sidecar to avoid embedding policy in the feature-api
     code (Module 09 cross-reference).
  5. Per-version model-artifact IAM: each serving
     identity reads only the model version it is bound
     to; verified by an automated check on each
     deployment.
- **Success criterion to advance.** Mesh authorization in
  enforce mode for 8 weeks with no production incident
  attributable to over-denial; OPA tenant-authz on
  feature-api enforced; cross-tenant access denied in audit
  log under synthetic load test.
- **Duration.** 6 calendar months. Estimate rationale:
  sidecar rollout per namespace + the dry-run-to-enforce
  cycle per policy + the human time to triage unexpected
  denials. The single most underestimated item is the
  cycle of "we enabled enforce, prod broke, we rolled
  back, we fixed the policy, we tried again." Budget for
  it.
- **Headcount.** Security engineer at 60% (other 40% is
  Phase 1 maintenance and incident response). Platform
  engineer at 50% during sidecar rollout. ML engineers
  pulled in for the application-layer authz design.
- **Rollback plan.**
  - NetworkPolicy: deletable; cluster reverts to
    default-allow on the deleted policies.
  - Istio sidecars: per-namespace label flip disables
    injection; existing pods keep their sidecars until
    next deploy, at which point they come up without.
  - `AuthorizationPolicy`: per-namespace removable. The
    dry-run-first pattern means an unexpected deny can be
    diagnosed against audit logs without an outage.
  - OPA sidecar on feature-api: per-deployment removable;
    feature-api falls back to its prior authorization
    (which is "allow if mesh-allowed", i.e. Phase 2 minus
    OPA). This is a regression in security posture but
    not an outage.

#### Phase 3 — Identity-first at scale (heavy-commitment) — ~5 months

- **Goal.** Close the posture-informs-access loop (tenet
  5) and federate identity across boundaries SmartRecs is
  likely to grow into.
- **Deliverables.**
  1. Runtime detection (Falco) wired to the
     `AuthorizationPolicy` control plane: a failed
     runtime posture check produces a temporary deny rule
     for the affected workload's principal. Latency
     target: ≤5 minutes from detection to mesh-level deny.
  2. Tamper-evident audit chain (Module 07 pattern) —
     append-only hash chain over per-request audit entries
     signed by workload SVIDs.
  3. Per-run training credentials via Vault dynamic
     secrets — replaces the team-shared warehouse
     credential.
  4. Customer-facing API moves from per-store API key to
     short-lived OIDC token (1h TTL with refresh). Old
     API key path retained for 6 months for migration.
  5. Trust-domain federation set up *only if* SmartRecs
     has acquired a second cluster or partner integration
     in this period. Otherwise this item is descoped and
     replaced with a documented federation playbook for
     when the trigger arrives.
- **Success criterion to advance to "done."** Six "done"
  statements all answer "yes" in a written review;
  Falco-to-mesh feedback loop demonstrated in a quarterly
  game day; CFO-friendly summary updated with actuals vs
  estimates.
- **Duration.** 5 calendar months. The Falco-to-mesh
  feedback loop is the single largest item (~2 months) and
  the only one of these whose underestimation is
  catastrophic — under-budgeting it tends to land it as
  "Falco emits alerts" rather than "Falco revokes
  access."
- **Headcount.** Security engineer at 50%; platform engineer
  at 40%; ML engineers at 10% for the OIDC migration on the
  customer-API path.
- **Rollback plan.**
  - Falco-to-mesh wiring: a feature flag on the
    integration disables the deny-emission and falls back
    to alert-only. The detection still runs; the
    enforcement stops.
  - Audit chain: append-only; rolling back means new
    entries stop being signed but existing chain remains
    valid.
  - Vault dynamic secrets for training: training jobs
    fall back to the long-lived warehouse credential if
    Vault is unreachable (with audit log of the fallback).
  - OIDC for customer API: dual-stack with the legacy
    API key for the 6-month migration window; rollback
    means routing all customers back to API key for the
    duration of an incident.

#### Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Mesh enforcement over-denies in production after dry-run flip | High | Outage of a customer-facing path | Dry-run for ≥4 weeks per policy; per-namespace flip; documented per-policy rollback |
| SPIRE bootstrap failure after cluster restart | Medium | Cluster comes up without workload identities; sidecars fail TLS | Trust bundle baked into node AMIs; documented manual bootstrap procedure with tested DR runbook |
| ML engineering team perceives roadmap as friction | High | Roadmap stalls or workarounds undermine it | CFO-friendly summary + monthly review with ML lead; visible "value per phase" examples (e.g., "Phase 1 lets us see who accessed model X last week") |
| OIDC migration breaks a long-tail customer integration | Medium | Customer churn or escalation | 6-month dual-stack window; per-customer migration support; reversion path documented |
| Tenet-5 wiring lands as alert-only, not enforcement | Medium | Phase 3 looks complete but isn't | Phase-3 success criterion specifically requires the demonstrated mesh-deny path |
| Security engineer leaves mid-roadmap | Low | Loss of institutional knowledge | Roadmap is the document the replacement reads on Day 1; per-deliverable design docs live in the platform repo |
| Compliance / customer audit forces re-prioritization | Medium | Phase 2 deliverables get reshuffled | The "done" definition is the negotiating artifact; trade off scope, not the reversibility ordering |

#### What this roadmap doesn't include

Zero-trust adoption does not solve the following threats from
the Module 01 SmartRecs threat model. Each is addressed in a
different module of the track:

- **Model extraction by paying customers** — Modules 06
  (adversarial ML) and 11 (security operations).
- **Adversarial input attacks (OWASP ML01)** — Module 06.
- **Training-data poisoning via the feedback loop** —
  Modules 07 (governance) and 10 (supply chain).
- **Compliance evidence** — Module 07. Zero-trust controls
  feed compliance audits; they do not produce SOC 2 / GDPR
  evidence on their own.
- **Insider abuse** — least-privilege caps blast radius
  (Exercise 02 NOT columns) but does not stop an
  authenticated insider with legitimate access.

The CFO and CTO should understand this list, so it appears
in the executive summary as "what we are still exposed to."

#### CFO-friendly summary

> SmartRecs will adopt the zero-trust security architecture
> (NIST SP 800-207) over approximately 15 months at roughly
> one-third of platform engineering capacity, split across
> three phases that are each independently reversible.
> Phase 1 (4 months) installs the identity, audit, and
> inventory foundations. Phase 2 (6 months) deploys
> default-deny networking and mesh authorization, with a
> 4-week dry-run before each enforcement flip. Phase 3
> (5 months) ties runtime detection into authorization and
> moves customer authentication to short-lived tokens. The
> roadmap explicitly excludes anti-evasion, anti-poisoning,
> and compliance-evidence work, which belong to later
> tracks. The success criteria are six measurable
> statements; the audit log will let any future reviewer
> confirm each independently. Risk to the customer-facing
> experience is held to the dry-run window of any single
> phase; no phase requires a maintenance window or planned
> outage.

This paragraph is the version the CTO can paste into a
finance conversation. Everything above it is the version
the engineering team executes against.

---

## 3. Validation steps

The artifact is a written roadmap; validation is the
author's self-check before submission.

1. **"Done" definition test.** A reviewer reading only the
   six statements should be able to say "yes, no, or partial"
   for each, given access to the cluster. If any statement
   reads "improve X" or "harden Y," it fails — the team
   cannot tell when it is done.
2. **Phase-sequence test.** Reading Phase 2 deliverables,
   confirm each one depends on a Phase 1 deliverable. If a
   Phase 2 item has no Phase 1 prerequisite, it could
   reasonably move earlier.
3. **Rollback test.** For each phase, point at the rollback
   plan and confirm at least one production-safe path
   exists. "Roll it forward" is not a rollback.
4. **Duration sanity check.** Total calendar duration ≥12
   months for SmartRecs' scale. Less than that is fiction.
5. **Headcount sanity check.** Security engineer allocation
   never >80% (they need slack for incident response and
   meetings). Platform allocation never >50% during peak
   migration weeks.
6. **Risks table count.** ≥5 risks, each with likelihood,
   impact, and a mitigation that names a deliverable. A
   risk with no mitigation is a known unmitigated risk —
   put it in "what this doesn't include."
7. **CFO summary length.** One paragraph, ≤200 words,
   readable in 20 seconds, accurate enough that the
   engineering team would not push back if it appeared in
   a board deck verbatim.

## 4. Rubric / review checklist

| # | Criterion | Pass condition |
|---|---|---|
| 1 | "Done" defined concretely | Six (or similar) auditable statements; not "we'll be more secure" |
| 2 | Sequenced by reversibility | Phase 1 = cheap/reversible; Phase 2 = medium; Phase 3 = heavy/quarters-to-undo |
| 3 | Per-phase deliverables | 3–7 named items per phase, each a concrete artifact |
| 4 | Success criterion per phase | Measurable; not "team feels good about progress" |
| 5 | Calendar duration realistic | ≥12 months overall for SmartRecs-scale team |
| 6 | Headcount realistic | Security engineer ≤80%; explicit fractional allocations |
| 7 | Rollback plan per phase | Production-safe path called out per deliverable |
| 8 | Risk table ≥5 risks | Each row: risk + likelihood + impact + mitigation |
| 9 | What zero-trust doesn't solve | Cross-reference to ≥3 Module 01 threats + the modules that address them |
| 10 | CFO-friendly summary | One paragraph, ≤200 words, defensible in a board deck |
| 11 | Identity before mesh | Phase 1 lands identity; Phase 2 lands mesh. Reverse order is failing. |
| 12 | Detection precedes enforcement | Dry-run / monitor mode for ≥4 weeks per policy class |

A common borderline case: the roadmap looks ambitious but
misses the rollback section. Push back — a roadmap without
rollback is a roadmap to an outage.

## 5. Common mistakes

- **"Phase 1: install Istio."** Over-tooling early. The
  foundation is identity and audit; mesh comes once there
  is something to authenticate.
- **6-week timeline.** The work does not fit. The lecture
  notes §7 ("Operational realities") and the exercise's
  own constraints rule this out.
- **No rollback story.** A roadmap is not a one-way door.
  Every change in production needs a path back.
- **No CFO-friendly summary.** The CTO cannot take a
  rolled-up technical doc into a finance review without
  one. The engineering team produces it, not finance.
- **Tenet 5 in Phase 1.** Wiring detection-to-mesh is the
  most operationally expensive control in zero-trust;
  putting it before identity and mesh exist is a
  sequencing error.
- **Headcount of "1.0 FTE security engineer for 18
  months."** The security engineer is also doing incident
  response, vendor reviews, customer security questions,
  and on-call. Allocating them >80% to the roadmap is
  optimistic; >100% is fantasy.
- **Risks without mitigations, or mitigations without
  owners.** A risks table that doesn't name the
  deliverable that mitigates each risk is incomplete.
- **Defining "done" as "we are zero-trust."** Zero-trust
  is an architectural posture, not a binary state. The
  exercise asks for measurable end-state criteria.
- **Omitting "what this doesn't solve."** Overclaim. The
  CTO will rely on the roadmap; they need to know what
  *remains* a concern after Phase 3.
- **Skipping the dry-run window.** The single biggest
  cause of zero-trust adoption outages is flipping
  enforcement on without observing the predicted-deny
  set first. Module 09's policy-as-code pattern
  exists for this reason.

## 6. References

- **NIST SP 800-207 — Zero Trust Architecture.**
  https://csrc.nist.gov/pubs/sp/800/207/final
  §4 (Deployment Scenarios / Use Cases) and §5
  (Threats Associated with Zero Trust Architecture) are
  directly relevant to the roadmap and the residual-risk
  section.
- **NIST SP 800-204A — Building Secure Microservices-based
  Applications Using Service-Mesh Architecture.**
  https://csrc.nist.gov/pubs/sp/800/204/a/final
  Phase 2 mesh deployment guidance.
- **CISA Zero Trust Maturity Model.**
  https://www.cisa.gov/zero-trust-maturity-model
  Useful as a scoring framework for the "done" definition
  if SmartRecs wants to track maturity in addition to the
  six binary statements.
- **NIST AI Risk Management Framework.**
  https://www.nist.gov/itl/ai-risk-management-framework
  Referenced for the "what this doesn't solve" section —
  AI-RMF GOVERN and MAP functions cover concerns
  zero-trust does not.
- **Kubernetes Pod Security Standards.**
  https://kubernetes.io/docs/concepts/security/pod-security-standards/
  Phase 1 PSS deliverable.
- **Module 02 lecture notes §7 (Operational realities), §9
  (What zero-trust deliberately doesn't solve).**
- **Cross-references:**
  - Exercise 01 ([`../exercise-01-zero-trust-gap-analysis/SOLUTION.md`](../exercise-01-zero-trust-gap-analysis/SOLUTION.md))
    — the gap list that drives the deliverables.
  - Exercise 02 ([`../exercise-02-workload-identity-design/SOLUTION.md`](../exercise-02-workload-identity-design/SOLUTION.md))
    — Phase 1 identity targets.
  - Exercise 03 ([`../exercise-03-microsegmentation-plan/SOLUTION.md`](../exercise-03-microsegmentation-plan/SOLUTION.md))
    — Phase 2 NetworkPolicy and application-layer authz.
  - Exercise 04 ([`../exercise-04-service-mesh-authz/SOLUTION.md`](../exercise-04-service-mesh-authz/SOLUTION.md))
    — Phase 2 mesh authorization model.
  - [`projects/project-1-zero-trust/SOLUTION.md`](../../../projects/project-1-zero-trust/SOLUTION.md)
    — production-gap checklist for what a *post-roadmap*
    SmartRecs would still need to harden.
