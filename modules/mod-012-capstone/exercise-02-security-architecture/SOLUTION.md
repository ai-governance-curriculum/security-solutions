# SOLUTION — Capstone Exercise 02: Security Architecture

> Read this *after* attempting the exercise. The capstone integrates
> every prior module — your architecture should justify which controls
> apply where, not list every control once.

## 1. Solution overview

The exercise asks for a defensible security architecture for the ML
system scoped in Exercise 01. A passing answer must:

- Pick one organising principle and stick with it. The two reasonable
  choices are **zero trust** (identity-centric, "never trust, always
  verify") and **defense in depth** (layered controls so that any one
  failing does not let the threat through). A strong architecture
  uses zero trust as the framing and defense in depth as the
  realization at each layer.
- Map every High and Medium risk from Exercise 01's register to one
  or more concrete architectural controls — by layer, by component,
  and by lifecycle stage (data, training, registry, serving).
- Show the controls on a diagram. A wall of bullet lists is not an
  architecture; reviewers must be able to *see* where the controls
  apply.
- Justify the trade-offs that the architecture makes. Every security
  control has a cost (latency, complexity, operator burden); a
  defensible architecture names the cost and the reason it is
  acceptable.

A submission that simply lists every control from every prior module
without ever saying "no, not here, because …" has not done
architecture; it has done inventory.

## 2. Implementation

### 2.1 Architectural principles, in priority order

1. **Identity over network.** Every workload-to-workload call is
   authenticated by SPIFFE/SPIRE-issued identity. Network reachability
   is a coarse filter, not a trust statement.
2. **Signed artifacts, verified at admission.** Models, container
   images, and Helm charts are signed at build time and verified at
   the registry boundary and at the runtime admission controller.
3. **Least privilege, default-deny.** IAM, Kubernetes RBAC, Istio
   AuthorizationPolicy, and database grants all start at deny and
   are opened only with named justifications.
4. **Observability that is itself a control.** Logs must be
   tamper-evident (append-only with hash chains) because they are
   relied upon to detect the cases the preventive controls miss.
5. **Blast-radius containment.** Tenants and lifecycle stages share
   no privileged credentials. A compromise of one training job does
   not compromise the registry or another tenant.

The priority order matters because controls trade against each other.
When a tension appears — for example, observability vs. data
minimization — the higher-priority principle wins and the conflict is
documented.

### 2.2 Architecture diagram (controls overlaid)

```
                +---------------------+
                |  External caller     |
                +-----------+----------+
                            | mTLS (caller identity → JWT)
                            v
                +-----------+----------+
                |  API gateway         |  [WAF, rate limit, schema validate]
                +-----------+----------+
                            | mTLS, SPIFFE
                            v
                +-----------+-----------+
                |  Service mesh sidecar  |  [AuthorizationPolicy: deny by default]
                +-----------+-----------+
                            v
                +-----------+----------+
                |  Inference service   |  [seccomp, read-only fs, signed image]
                +-----------+----------+
                            | signed pull
                            v
       =====================|====================== Registry boundary
                            v
                +-----------+----------+
                |  Model registry      |  [Cosign verify, SBOM check, attestations]
                +-----------+----------+
                            ^ signed push
                            |
                +-----------+----------+
                |  Training job         |  [tenant namespace, SPIFFE identity,
                +-----------+----------+    no host network, KMS-backed secrets]
                            ^
                            | feature read (signed dataset hash pinned)
                            |
                +-----------+----------+
                |  Feature/object store |  [tenant-scoped IAM, CMK, immutable
                +-----------+----------+    object lock for training snapshots]
                            ^
                            | schema-validated, signed
                            |
                +-----------+----------+
                |  Feature pipeline     |  [Kafka SASL/mTLS, schema registry]
                +-----------------------+
```

Three transverse layers run alongside the data path: **identity**
(SPIFFE/SPIRE, Vault-issued short-lived secrets), **policy** (OPA
admission for K8s and registry promotions), and **telemetry** (audit
log → SIEM with the detections from Module 11).

### 2.3 Controls mapped to lifecycle stage and to risks

| Stage | Control | Treats risks (from ex-01) | Trade-off accepted |
|-------|---------|---------------------------|-------------------|
| Data ingest | Kafka SASL+mTLS; schema registry with version pin; reject on schema drift. | R-02 (poisoning) | Producers must upgrade in lock-step; slows feature evolution. |
| Data at rest | Tenant-prefixed buckets with customer-managed keys; object lock on training snapshots. | R-04 (cross-tenant); R-02 | Higher KMS cost; slightly more complex IAM. |
| Training | Namespace-per-tenant; SPIFFE workload identity; no `hostNetwork`/`hostPID`; seccomp + AppArmor; pinned base images + SBOM. | R-04; R-01 (supply chain) | Training image rebuild required when base CVE drops; latency on first-of-day pull. |
| Registry | Cosign signature required; in-toto attestation for training provenance; OPA gate on promotion. | R-01 | Rejection of unsigned community models — explicit allow-list needed. |
| Serving | mTLS + AuthorizationPolicy; per-tenant rate limit; output confidence suppressed by default. | R-03 (extraction/evasion) | Slight UX hit for benign batch callers; mitigated by per-key allow-list. |
| Cross-cutting: identity | SPIFFE/SPIRE; Vault short-lived DB credentials; no long-lived service-account tokens. | All | Operational complexity of SPIRE — but bounded by the platform team. |
| Cross-cutting: policy | OPA admission for K8s resources, registry promotions, and IaC changes. | R-01; R-04 | False positives in early rollout — mitigated by `dryrun` mode before enforcing. |
| Cross-cutting: telemetry | SIEM ingest of audit events with hash-chained log shipping. | R-05 (repudiation) | Storage cost; tuned by retention class. |

### 2.4 Trade-offs and architecture decision records (excerpts)

**ADR-001: Use service-mesh-issued mTLS identity, not network ACLs,
as the primary inter-service trust signal.**

- Decision: SPIFFE workload identity via Istio sidecars; network
  policies remain as a coarse, redundant control.
- Rationale: NetworkPolicies break when a workload moves namespaces or
  the underlying CNI changes. SPIFFE identities are bound to workload
  selectors, survive reshuffling, and carry into audit events
  unmodified.
- Trade-off: Adds a sidecar to every pod, raising memory footprint
  ~50 MiB/pod and adding ~1ms latency. Accepted because the
  identity-bound audit trail is required for compliance (Module 7) and
  for detection rules (Module 11).

**ADR-002: Verify model signatures at admission, not at pull.**

- Decision: An OPA admission controller verifies the model
  manifest's Cosign signature and in-toto attestation before the
  Pod is admitted; pull-time verification is *additionally* enabled
  in the runtime but is not the primary gate.
- Rationale: Pull-time verification depends on the runtime being
  configured correctly on every node; admission is one chokepoint
  the platform team controls.
- Trade-off: Admission lag — a few hundred ms — but only on first
  deployment of a model version.

**ADR-003: Per-tenant namespaces, not multi-tenant namespaces with
NetworkPolicy isolation.**

- Decision: One Kubernetes namespace per tenant for training and one
  per tenant for serving.
- Rationale: NetworkPolicy isolation within a shared namespace has
  repeatedly been shown to fail open under CNI upgrade; namespace
  isolation also gives RBAC, ResourceQuota, and audit-log boundaries
  for free.
- Trade-off: More namespaces to manage; mitigated by generator
  pipelines.

### 2.5 What the architecture does *not* do

- It does not attempt confidential computing (TEEs / Nitro Enclaves)
  for training data — out of scope for the capstone tier's threat
  model.
- It does not introduce homomorphic encryption or secure aggregation
  — risk register entries do not justify the cost.
- It does not federate identity to every downstream consumer; the API
  gateway terminates external auth and re-issues internal identity.

Saying *what an architecture does not do* is as important as saying
what it does — it shows the author reasoned about boundaries.

## 3. Validation steps

1. **Risk traceability.** For every High/Medium risk in Exercise 01,
   confirm that at least one control row in this document names it by
   ID.
2. **Diagram-vs-table consistency.** Every control in the table must
   be visible on the diagram (or in a transverse layer); every
   diagram element must appear in the table.
3. **Trade-off completeness.** Every control row has a non-empty
   "trade-off accepted" cell. A control with zero cost is suspicious
   and should be re-examined.
4. **ADR sanity check.** Each ADR follows the standard "Decision /
   Rationale / Trade-off" structure; reversing the decision must be
   feasible from the rationale.
5. **Reviewer dry run.** Hand the diagram and one ADR to a peer; ask
   "If you had to defend this in a design review, where would you be
   uncomfortable?" Any uncovered area is a missing control or a
   missing trade-off.

## 4. Rubric / review checklist

| Criterion | Weight | Pass condition |
|-----------|--------|----------------|
| Organising principle stated and applied | 10 | Zero trust (or named alternative) is declared and the rest of the doc is consistent with it. |
| Every High risk has a named control | 15 | Each High-rated risk from Ex-01 is treated by at least one control here. |
| Defense in depth shown at ≥3 layers | 10 | A single threat (e.g. supply-chain) is shown reaching at least three controls before getting through. |
| Diagram + table are consistent | 10 | No control appears in only one of the two. |
| Trade-offs are named, not waved away | 15 | Every control row has a specific cost (latency, complexity, operator effort). |
| At least three ADRs | 10 | ADRs follow Decision / Rationale / Trade-off; each ADR's decision is reversible from its rationale. |
| Identity is workload-bound, not network-bound | 5 | SPIFFE or equivalent is the primary identity story. |
| Registry / admission gate present | 5 | Signed artifacts are verified at an enforced chokepoint. |
| Out-of-scope controls listed | 5 | The doc says explicitly what it does *not* do and why. |
| References cited | 5 | The official sources for this module are linked. |
| Diagram is legible | 10 | A reviewer can answer "where would a poisoned dataset be stopped?" by pointing at the diagram. |

## 5. Common mistakes

- **Listing every control once at the top of the doc.** An
  architecture says *where each control applies*. Inventory is not
  architecture.
- **No trade-offs.** Every control has a cost. If none is named, the
  reviewer cannot tell whether the author understood the cost.
- **"Zero trust" as a label, not a property.** Saying "zero trust" in
  the intro and then issuing long-lived service-account tokens
  elsewhere shows the principle was not actually applied.
- **No admission gate.** Verifying signatures at pull only — without
  an admission controller — leaves runtime as the sole enforcer; one
  misconfigured node bypasses the policy.
- **Confusing controls with goals.** "Reduce supply-chain risk" is a
  goal; "OPA admission rejects unsigned model manifests" is a
  control. Goals do not belong in the control table.
- **No reference to threat model.** An architecture that does not
  cite risks from Ex-01 by ID has no traceability — it could
  arbitrarily diverge from the threats it claims to treat.

## 6. References

- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>
- MITRE ATLAS — <https://atlas.mitre.org/>
- NIST AI Risk Management Framework (AI RMF 1.0) — <https://www.nist.gov/itl/ai-risk-management-framework>
