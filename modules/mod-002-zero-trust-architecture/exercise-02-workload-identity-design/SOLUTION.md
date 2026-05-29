# SOLUTION — Exercise 02: Workload Identity Design

> Read this *after* attempting the exercise.

## 1. Solution overview

This exercise asks for a SPIFFE-style workload-identity design for
the SmartRecs system, with attestation selectors, scoped
authorizations, SVID TTLs, and explicit "not authorized" entries
per workload.

The single most important property of a passing design is that
**identity attestation is bound to enforceable artifacts**, not to
opt-in labels. A pod label `app=trainer` is not, on its own, an
attestation — anyone who can create a pod in that namespace can
add the label. Attestation that ties an SVID issuance to a
ServiceAccount, a container image digest, *and* a node selector is
defensible; attestation by label alone is not.

The reference design covers five workload classes the exercise
requires (training, serving, gateway, governance, notebook) plus
one additional class — a per-run training **child** identity — to
demonstrate the "per-operation, not per-team" pattern from
lecture-notes §3.5.

SVID TTLs in this solution sit between 30 minutes (notebook,
serving) and 2 hours (governance), with the per-run training SVID
expiring with the job. These values follow SPIFFE / SPIRE
guidance (short-lived; 1h is a common default) — values longer
than 24h indicate a static credential dressed in cert clothing.

## 2. Implementation (worked answer)

The remainder of this section is the worked artifact a learner
should produce.

---

### SmartRecs Workload Identity Design

**Author:** _reference solution_
**Date:** 2026-05
**Trust domain:** `spiffe://smartrecs.internal`
**Reference:** Exercise 02 of module 02
([learning file](https://github.com/ai-infra-curriculum/ai-infra-security-learning/blob/main/lessons/mod-002-zero-trust-architecture/exercises/exercise-02-workload-identity-design.md)).

#### Trust domain

A single SPIFFE trust domain `spiffe://smartrecs.internal` covers
the entire SmartRecs production environment. Multi-cluster
federation is **not** part of this design; SmartRecs runs a single
production cluster and the lecture-notes §6.2 guidance is to
avoid premature federation complexity.

Workload paths follow the canonical `ns/<ns>/sa/<sa>[/...]`
pattern recommended by the SPIFFE specification
(https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md),
with a `/version/<v>` or `/run/<id>` suffix where the workload's
identity is genuinely versioned (model serving) or per-execution
(training).

#### Workload identity table

| Workload | SPIFFE ID | Attestation selectors | Read access | Write access | Network egress | SVID TTL | Explicitly NOT |
|---|---|---|---|---|---|---|---|
| Training (controller) | `spiffe://smartrecs.internal/ns/recs-train/sa/training-controller` | `k8s:ns:recs-train`, `k8s:sa:training-controller`, `k8s:pod-image:registry.smartrecs/training-controller@sha256:<digest>`, `k8s:node-label:workload=batch` | None of the production data directly; reads the training-run definition only | Creates per-run child SVIDs via SPIRE delegated-identity API; writes the run manifest to `s3://models/runs/<id>/manifest.json` | SPIRE server, S3 manifest path only | 1 h | Cannot read the warehouse, cannot write model artifacts directly, cannot read `recs-prod` |
| Training (per-run) | `spiffe://smartrecs.internal/ns/recs-train/sa/training-job/run/<run-id>` | All controller selectors **plus** `k8s:pod-label:run-id=<run-id>`, `k8s:pod-image:registry.smartrecs/trainer@sha256:<digest>` | `s3://training-data/recs/slice/<window>/` (read), `warehouse://events?range=<window>` via Vault-issued JDBC credential | `s3://models/runs/<run-id>/` only | Warehouse host + S3 only; DNS to internal resolver only | Duration of run + 5 min grace, capped at 12 h | Cannot read other runs' artifacts, cannot read `recs-prod`, cannot read other tenants' slices, cannot egress to public internet |
| Serving | `spiffe://smartrecs.internal/ns/recs/sa/model-serving/version/<vN>` | `k8s:ns:recs`, `k8s:sa:model-serving`, `k8s:pod-image:registry.smartrecs/serving@sha256:<digest>`, `k8s:pod-label:model-version=<vN>` (set by deployment controller, not author-mutable) | `s3://models/recs-v<N>/` (read-only), feature-store `GET /features/v1/*` for permitted tenants | Metrics endpoint to Prometheus only | Feature-store API host, S3 (read), Prometheus push | 30 min | Cannot read any other `recs-v*` artifact, cannot write the feature store, cannot read training-data warehouse, cannot read governance namespace |
| Gateway | `spiffe://smartrecs.internal/ns/edge/sa/gateway` | `k8s:ns:edge`, `k8s:sa:gateway`, `k8s:pod-image:registry.smartrecs/gateway@sha256:<digest>` | Customer OIDC issuer (JWKS), tenant config in Vault KV (read-only) | Audit log for `request-id` and `tenant` propagation | Serving (`recs`) and Serving (`fraud`-if-exists) only; OIDC issuer | 1 h | Cannot call the feature store directly, cannot call governance, cannot call training |
| Governance | `spiffe://smartrecs.internal/ns/gov/sa/governance` | `k8s:ns:gov`, `k8s:sa:governance`, `k8s:pod-image:registry.smartrecs/governance@sha256:<digest>` | Model registry (`GET /model-card`, `GET /healthz`), feature-store `GET /features/v1/metadata/*` | Append-only writes to the tamper-evident audit log only (Module 07) | Audit log writer, registry API | 2 h | Cannot call `/v1/predict` on any serving pod (no inference), cannot read `s3://training-data/...`, cannot read or write model artifacts |
| Notebook | `spiffe://smartrecs.internal/ns/notebooks/sa/researcher-<oidc-sub>` | `k8s:ns:notebooks`, `k8s:sa:researcher-<sub>`, `k8s:pod-label:owner=<sub>`, OIDC-bound user identity from Module 03 issuer | Sampled / anonymized data slice `s3://research/<sub>/`, no production warehouse | Researcher's own scratch path `s3://research/<sub>/scratch/` | Internal package mirror, sampled-data S3, OIDC issuer; **no** public-internet egress | End of working day, max 12 h | Cannot read production warehouse, cannot read `s3://models/...`, cannot call any production API, cannot reach the public internet |

#### Design rationale

##### Why these attestation selectors

The SPIFFE specification lets SPIRE require *all* selectors in a
registration entry to match before issuing an SVID
(https://spiffe.io/docs/latest/spire/using/registering/). The
defensive pattern is `ns + sa + image-digest + node-label`
(four-factor attestation). Any single selector can be spoofed by
a sufficiently privileged actor:

- `ns` alone — anyone with `create pods` in the namespace.
- `sa` alone — anyone who can bind that SA to a pod.
- `image-tag` alone — image tags are mutable; `image-digest` is
  not. The exercise quality criteria explicitly call out
  attestation by label alone as a failing pattern.
- `node-label` alone — a pod can be scheduled on any matching
  node.

Combining four selectors means a successful identity spoof
requires compromising four independent control surfaces, which
is the level of defense the exercise asks for.

Cloud-equivalent attestation: in IRSA / GKE Workload Identity /
AAD Workload Identity, the attestation is `ServiceAccount` +
OIDC-issuer-binding from the cluster + image-policy admission.
The principle (multi-factor attestation) is the same; the
mechanism is the platform's.

##### Why these TTLs

- **Per-run training (≤12 h, expires with run).** A training job
  has a known finite lifetime. The SVID should not outlive the
  job; SPIRE supports tying the lifetime to the workload's
  presence. Long-running training (hours, not days) is the upper
  end of credible job durations; anything longer should be split
  into checkpointed runs.
- **Serving (30 min).** Latency-critical and high replica count,
  but the rotation cost is low because SPIRE workload-API
  refreshes are non-disruptive. Short TTL means a compromised
  SVID is useful for at most 30 minutes after the pod is killed.
- **Gateway (1 h).** Receives external traffic; mTLS to many
  serving deployments. 1 h matches the OIDC token TTL it issues
  to customers, simplifying reasoning about session boundaries.
- **Governance (2 h).** Lower call volume; the audit-log
  workload is more sensitive to rotation churn because each
  rotation produces a new signing key in the audit chain.
- **Notebook (end-of-day, ≤12 h).** Time-bounded user sessions
  per lecture-notes §8.4. The notebook is the highest-risk
  identity in the system; the TTL is the second line of defense
  after the data-scope restriction.

Values >24 h would not be workload identity — they would be
long-lived API keys with a cert wrapper. Values <5 min would
cause rotation thrash without meaningful security gain on
SmartRecs' threat model.

##### Why these least-privilege boundaries

The "Explicitly NOT" column is the operational checklist a
security review reads first. Each entry catches a documented
real-world failure mode:

- **Serving cannot read other model versions.** Catches the
  case where a buggy or compromised serving pod swaps to a
  different model version mid-flight (lecture-notes §8.1).
- **Per-run training cannot read other runs' artifacts.**
  Catches the "training job poisons another team's model"
  failure mode.
- **Governance cannot call `/v1/predict`.** Catches the case
  where governance is mis-scoped into the inference path and
  becomes a confused deputy.
- **Notebook cannot reach the public internet.** Catches
  exfiltration via `pip install` and analogous package-
  manager channels (lecture-notes §8.4).
- **Gateway cannot call the feature store.** Catches "the
  gateway calls everything because it's the entry point" —
  the feature store should be called only by an inference
  pod that the gateway has authorized into the path.

Each entry is small in itself; together they are the system's
blast-radius cap.

##### What changes if SmartRecs adds a second team

Two changes:

1. **Trust domain stays the same; the path namespacing
   grows.** A second team `fraud` adds workloads under
   `spiffe://smartrecs.internal/ns/fraud/...` and
   `spiffe://smartrecs.internal/ns/fraud-train/...`. No
   second SPIRE server, no federation — the same SPIRE
   server issues SVIDs for both teams' workloads.
2. **Cross-team authorizations are explicitly denied.** The
   feature store's `AuthorizationPolicy` (see Exercises 03
   and 04) keys each path on the calling SPIFFE principal;
   `serving-recs` cannot read `serving-fraud`'s feature
   slices. The "Explicitly NOT" column for each workload
   gains a row naming the other team's resources.

A team-count threshold for revisiting this: when SmartRecs
grows past ~5 teams or starts integrating with a partner
organization, federate trust domains rather than keeping a
single shared one. Until then, federation is premature
complexity (lecture-notes §6.2).

#### Cross-workload identity flows

```
[ customer ]
     |  external mTLS + OIDC token (customer-side IdP or SmartRecs IdP)
     v
[ gateway (spiffe://.../sa/gateway) ]
     |  mesh mTLS; gateway propagates the customer OIDC token as a JWT in
     |  the `x-on-behalf-of` header; the request also carries `tenant`,
     |  `request-id`, and `model-version` set by the gateway
     v
[ serving (spiffe://.../sa/model-serving/version/vN) ]
     |  mesh mTLS; serving propagates the same `x-on-behalf-of` JWT
     |  unchanged so the feature store can verify the original user
     v
[ feature-api (in features namespace) ]
     application-layer authorization: validates the JWT signature,
     extracts the customer `tenant`, and checks that the calling
     workload identity (serving) is allowed to read this tenant's
     features (Module 09 OPA policy)
```

The customer's identity rides as a JWT (on-behalf-of). Each hop's
workload identity is the *mesh* authorization principal; the
customer identity is the *application* authorization principal.
This split is the lecture-notes §7.2 propagation pattern and the
basis for the Exercise 03 application-layer plan.

#### Trade-offs accepted

- **Notebook identity is per-researcher, not per-job.** A truly
  least-privilege design would issue an SVID per notebook
  *session*. Operationally, researchers run many short-lived
  cells against the same long-lived kernel; per-session
  identities would force kernel restarts every few minutes. The
  EOD TTL plus strict data scope is the negotiated compromise.
- **Gateway identity is not user-scoped.** Per-customer
  identities at the gateway would multiply identity churn for
  little gain (the gateway calls the same internal services
  regardless of the customer; tenant isolation lives one hop
  downstream).
- **Single trust domain.** Federation is deferred until SmartRecs
  has multi-cluster or partner integration. Adding federation
  later is straightforward — the SPIFFE IDs and selectors stay
  the same; only the SPIRE server config and trust-bundle
  endpoint change.
- **Image-digest pinning requires admission policy.** The
  attestation selectors assume an admission policy (Kyverno or
  Gatekeeper, Module 09) prevents tag-only image references in
  Deployments. Without that policy, the digest selector is
  bypassable by editing the Deployment to use a tag. The
  identity design and the admission policy are
  co-load-bearing.

---

## 3. Validation steps

1. **Selector enforceability.** For each workload, list the
   selectors. If any single selector controls issuance (no
   `+` combinator with at least one immutable factor like
   image digest), it fails the spec — see SPIRE registration
   docs at https://spiffe.io/docs/latest/spire/using/registering/.
2. **TTL bounds.** Confirm every TTL is between 5 minutes and
   24 hours. TTL outside this window indicates a misframed
   identity (too short = churn, too long = static credential).
3. **Read = explicit list.** Each workload's read access
   should be a finite, named list (resource URIs or API paths),
   not "data we need."
4. **Explicit NOT count.** Quality criterion requires at least
   one entry per workload; the reference uses two or more for
   each.
5. **On-behalf-of present.** Confirm the design names how the
   customer identity travels (JWT propagation header) and
   where it is verified (application layer / OPA).
6. **Per-tenant test.** For the multi-team thought experiment,
   trace whether `serving-fraud` could read `recs`-tenant
   features under this design. Answer must be "no, blocked by
   AuthorizationPolicy keyed on principal" — and this should
   be verifiable in Exercise 04's mesh policies.

If the design is implemented in a sandbox, validation extends
to:

- `spire-server entry show` lists one registration entry per
  identity row with all selectors.
- `kubectl exec -n recs <serving-pod> -- spire-agent api fetch`
  returns an SVID whose URI matches the table.
- A pod that bypasses one selector (e.g., correct ns/sa but
  unpinned image) receives **no** SVID. This is the
  acceptance test for the attestation policy.

## 4. Rubric / review checklist

| # | Criterion | Pass condition |
|---|---|---|
| 1 | ≥5 distinct workload classes | Training, serving, gateway, governance, notebook all present |
| 2 | Each identity has ≥1 "Explicitly NOT" entry | Reference uses ≥2 each |
| 3 | TTLs credible | All between 5 min and 24 h; per-run training scoped to job duration |
| 4 | Attestation multi-factor | At minimum: `ns + sa + image-digest` (or cloud-equivalent immutable factor) |
| 5 | On-behalf-of addressed | Customer identity propagation named (JWT header, JWKS verify point) |
| 6 | Cross-workload flow drawn | Gateway → serving → feature-store path with both workload identity and user identity called out |
| 7 | Multi-team thought experiment answered | Design names what changes; trust-domain choice justified |
| 8 | Trade-offs acknowledged | At least two trade-offs (e.g., notebook session TTL, federation deferral) called out |
| 9 | References to SPIFFE / NIST | At least one citation to the SPIFFE spec or SP 800-207; no vendor whitepapers in place of standards |
| 10 | Format | Table for the per-workload identities; ≤2 pages of prose |

A common borderline case: the design covers serving and
training thoroughly but slights gateway or governance. Push
back — those two are the system's identity hinges.

## 5. Common mistakes

- **Shared identity for all training jobs.** Every nightly
  training run gets the same SVID. This is per-team identity
  with extra steps; it is not per-workload identity. The
  exercise penalizes this directly.
- **Attestation by label alone.** A pod label
  `app=trainer` is opt-in; any pod can claim it. SPIRE
  selectors must include at least one immutable factor.
- **TTLs of 24 h or more.** Lecture-notes §3.4 explicitly
  flags this as not workload identity.
- **No version suffix on the serving SPIFFE ID.** A serving
  identity that doesn't encode the model version lets one
  identity read every artifact (lecture-notes §8.1).
- **Notebook with public-internet egress.** Lecture-notes
  §8.4 — exfiltration via `pip install` is real. Notebook
  egress should be limited to an internal mirror.
- **No on-behalf-of plan.** The mesh principal (serving)
  authenticates the workload; only the propagated user JWT
  identifies the customer. Designs that conflate the two
  fail the multi-tenant feature-store test in Exercise 03.
- **Federating prematurely.** Single-cluster SmartRecs doesn't
  need trust-domain federation. Adding it now is complexity
  for no current benefit (lecture-notes §6.2).
- **Naming Istio as the identity issuer.** Istio consumes
  identity; SPIRE / cloud workload-identity issues it. The
  two are not interchangeable.

## 6. References

- **SPIFFE specification — SPIFFE IDs.**
  https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md
- **SPIFFE specification — SVIDs and Workload API.**
  https://github.com/spiffe/spiffe (repository root with all
  standards documents).
- **SPIRE concepts and registration.**
  https://spiffe.io/docs/latest/spire-about/ and
  https://spiffe.io/docs/latest/spire/using/registering/
- **NIST SP 800-207, §2 (tenets) and §3.4.1 (identity-driven
  access).** https://csrc.nist.gov/pubs/sp/800/207/final
- **AWS IAM Roles for Service Accounts (IRSA).**
  https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html
- **GKE Workload Identity.**
  https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity
- **Azure AD Workload Identity.**
  https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview
- **Kubernetes ServiceAccount and admission control.**
  https://kubernetes.io/docs/concepts/security/service-accounts/
- **Module 02 lecture notes §3 (identity-first), §6
  (federation), §7.2 (on-behalf-of), §8 (ML-specific).**
- **Cross-reference:**
  [`projects/project-1-zero-trust/SOLUTION.md`](../../../projects/project-1-zero-trust/SOLUTION.md)
  for SPIRE-vs-IRSA rationale in a deployed reference.
