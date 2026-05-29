# SOLUTION — Exercise 01: CNI Evaluation

> Reference solution for `mod-004-network-security` exercise 01. Read this
> *after* attempting the learner-side exercise. The intent is to model
> how a security-minded platform team selects a CNI for an AI/ML
> Kubernetes cluster, not to declare a single winner.

## 1. Solution overview

A CNI evaluation for an AI infrastructure cluster must score plugins on
the **same** properties that the cluster's workloads actually exercise:

- **Identity-aware policy** — workloads (training, inference, feature
  store, model registry) must be addressable by identity, not by IP, so
  that lateral movement controls survive pod rescheduling and node
  churn.
- **Egress control** — ML workloads pull weights, datasets, base
  images, and telemetry from heterogeneous external endpoints; egress
  becomes the primary exfiltration path that policy needs to constrain.
- **Encryption in transit at L3/L4** — the cluster crosses node and
  AZ boundaries; in-cluster traffic should not depend on every
  application correctly terminating TLS.
- **Observability** — flow logs and policy decision logs are the
  primary input for detection-engineering rules and incident triage.
- **GPU/RDMA compatibility** — high-throughput training traffic
  (NCCL, RDMA, multi-NIC) interacts non-trivially with CNI dataplanes.
- **Operational fit** — kernel version requirements, upgrade story,
  blast radius of an agent crash, and skills already present in the team.

The deliverable for the learner is a **scored matrix** plus a
**written recommendation** that names the workloads the recommendation
is optimized for. A CNI choice that is correct for batch training is
not automatically correct for low-latency online inference.

This exercise is design-based; the artifact is a decision document,
not running code.

## 2. Worked implementation

### 2.1 Candidate set

Three production-grade candidates that meaningfully differ on the
properties above:

| Candidate | Dataplane | Position |
|---|---|---|
| Calico (iptables or eBPF) | iptables/IPVS by default; eBPF dataplane available | Mature, broad K8s deployment surface |
| Cilium | eBPF | Identity-aware policy, L7 policy, transparent encryption |
| Antrea | OVS (Open vSwitch) | OVS-based dataplane with NetworkPolicy + tracing |

Other plugins exist (Flannel, Weave, etc.); they are intentionally not
candidates here because they do not implement the full
`networking.k8s.io/v1` NetworkPolicy surface required by exercise 02,
or because their security-relevant featureset is a subset of the three
above.

### 2.2 Scoring rubric (1–5 per criterion)

The matrix below is a *template*. The learner fills in scores based on
the deployment target and cites the source for each non-trivial claim.
Anything sourced only to a vendor blog or marketing page must be
labelled as such.

| Criterion | Weight | Calico | Cilium | Antrea | Notes |
|---|---|---|---|---|---|
| Implements full Kubernetes NetworkPolicy v1 | 3 | | | | All three implement the upstream API. See [Kubernetes NetworkPolicy reference](https://kubernetes.io/docs/concepts/services-networking/network-policies/). |
| Identity-aware (workload identity, not IP) | 3 | | | | Cilium offers identity-based policy via labels; Calico GlobalNetworkPolicy uses selectors; Antrea ClusterNetworkPolicy uses selectors. |
| L7 (HTTP/gRPC/DNS) policy at the CNI layer | 2 | | | | Cilium supports L7 policy natively; Calico via WAF/integration; Antrea via L7 NetworkPolicy. Confirm current feature flags and stability tiers in each project's release notes before scoring. |
| Egress policy (FQDN/CIDR) | 3 | | | | Egress to external model/dataset hosts is the primary exfiltration path. |
| In-cluster encryption (WireGuard/IPsec) | 2 | | | | Required if mesh-level mTLS is not adopted. |
| eBPF observability (flow logs, drops) | 2 | | | | Cilium Hubble, Calico eBPF flow logs, Antrea Flow Exporter — feed `mod-004 exercise-05`. |
| GPU/RDMA + multi-NIC compatibility | 2 | | | | Multi-NIC and RDMA paths often bypass the CNI; check sidecar/host-network exceptions explicitly. Cite each plugin's RDMA/Multus integration page when scoring. |
| Operational maturity in target cloud | 2 | | | | Managed-K8s distributions ship one or more of these as the supported CNI; map this score to your cloud. |
| Upgrade & blast radius | 1 | | | | Agent crash, node-restart behavior, version-skew with kube-proxy. |

**Recommendation rule:** the chosen CNI must score ≥3 on every
weighted-3 criterion. A weighted-2 criterion may score 2 only if a
documented compensating control exists (e.g. a service mesh provides
the missing capability and the team will operate it).

### 2.3 Worked recommendation example

> The following is one valid worked answer for a multi-tenant AI
> platform that does both training and online inference and has *no*
> service mesh in scope for this quarter.

**Choice:** Cilium, eBPF dataplane, with Hubble enabled for flow
telemetry and WireGuard transparent encryption between nodes.

**Why this choice for this workload mix:**

1. **Identity-aware policy without a mesh.** Cilium policies key on
   pod identity (label set), and identities survive IP reuse. Training
   pods churn frequently; an IP-based policy would have to be
   regenerated on every pod restart.
2. **FQDN-based egress.** Training workloads pull weights and datasets
   from S3-compatible endpoints, registries, and an internal feature
   store. A CIDR-only policy cannot represent these stably; FQDN
   policy can.
3. **In-cluster encryption without sidecars.** WireGuard at the CNI
   layer covers node-to-node traffic without per-pod CPU overhead from
   sidecar TLS termination, which matters for GPU pods where the
   spare CPU is small.
4. **Hubble flow telemetry.** Feeds the detection rules in
   `mod-004 exercise-05` directly. The alternative (mirroring traffic
   and reconstructing flows in a SIEM) is more expensive and less
   timely.

**Trade-offs explicitly accepted:**

- Cilium pins a minimum kernel version. The team commits to upgrading
  worker-node OS images on the cadence Cilium requires (pin the exact
  kernel-version floor for the Cilium minor you adopt from the upstream
  release notes).
- Cilium L7 policy is enforced in the eBPF proxy; teams with a
  full-mesh L7 deployment may prefer to let the mesh do that.
- WireGuard between nodes does not encrypt host-network pods or
  hostPort traffic. Those classes must be banned by admission policy.

### 2.4 What changes the recommendation

| If the deployment looks like… | Reasonable alternative recommendation |
|---|---|
| Already on Calico cluster-wide with a working policy library | Stay on Calico (eBPF dataplane), add WireGuard, add FQDN egress via GlobalNetworkPolicy — switching CNI for parity wins is rarely worth the migration cost. |
| Managed-K8s distribution ships Antrea | Stay on Antrea; close the L7 gap with a mesh or a dedicated gateway. |
| Heavy NCCL / RDMA fabric | Treat the AI fabric as out-of-CNI and use Multus + a separate, policed fabric; CNI choice is decided by the control-plane / north-south path. |
| Mesh-managed L7 already in production | The CNI's L7 capability stops mattering; lower its weight and re-score. |

## 3. Validation steps

The deliverable is a written decision; "validation" is reviewing the
artifact, not running code. The artifact passes review when:

1. **Each candidate is scored against every criterion** with a one-line
   justification per cell.
2. **Each non-obvious factual claim is cited.** Citations must be
   upstream project documentation, Kubernetes documentation, or the
   sources listed in §6. Vendor blog posts are allowed only if the
   claim is also reproducible from the upstream docs.
3. **The chosen plugin scores ≥3 on every weight-3 criterion**, or a
   compensating control is documented for any below-threshold score.
4. **The recommendation names the workload mix it is optimized for**
   (training-only / training+inference / multi-tenant / single-tenant).
5. **At least one alternative is documented** with the condition that
   would flip the choice.
6. **Trade-offs and limits are explicit**, including kernel-version
   floor and any host-network/hostPort exceptions.
7. **MITRE ATLAS / OWASP ML Top 10 mapping** — the recommendation
   identifies which network-layer adversary techniques the CNI
   directly mitigates and which are out of scope.

## 4. Rubric / review checklist

| # | Criterion | 0 — missing | 1 — partial | 2 — meets bar |
|---|---|---|---|---|
| 1 | Scored matrix covering all listed criteria for all candidates | No matrix | Matrix incomplete for ≥1 candidate or criterion | Complete |
| 2 | Citations for non-trivial claims | None | Some, vendor-only | Upstream project docs or standards |
| 3 | Workload-mix scope stated | Not stated | Implied | Explicit, with examples |
| 4 | Recommendation meets weighted threshold | Not justified | Threshold ignored | Threshold satisfied or compensating control documented |
| 5 | Alternative documented with flip condition | None | Listed without condition | Listed with condition |
| 6 | Trade-offs / limits explicit | Hidden | Generic | Specific to chosen CNI + workload |
| 7 | ATLAS/OWASP ML mapping | Missing | Mentioned | Mapped per technique |
| 8 | Operational fit (skills, upgrade story) addressed | Ignored | Hand-waved | Plan named |

Pass = ≥12 / 16 with no zero scores.

## 5. Common mistakes

- **Scoring on features that aren't enabled by default.** A capability
  behind an alpha/beta feature gate is not the same as an enforced
  control. State the feature gate and stability tier.
- **Conflating mesh-level mTLS with CNI encryption.** mTLS at the mesh
  encrypts L7 between sidecars; WireGuard/IPsec at the CNI encrypts
  L3 between nodes. They are not substitutes for each other in all
  threat models.
- **Ignoring host-network pods.** Daemonsets that run with
  `hostNetwork: true` (CSI drivers, GPU operators, node-exporters)
  bypass most CNI policy. The recommendation must say how those are
  governed.
- **Forgetting the AI fabric.** NCCL and RDMA paths often bypass the
  primary CNI via Multus or SR-IOV. Don't claim CNI policy covers
  GPU-to-GPU training traffic unless it actually does.
- **Vendor-only citations.** A vendor blog claiming a benchmark or
  feature is not a substitute for upstream documentation. Mark such
  claims as unverified in the matrix and open a follow-up to confirm
  against the project's own docs before relying on them.
- **Picking eBPF for status.** eBPF is a dataplane, not a security
  control by itself. The control is the policy + identity + logging
  story; eBPF is one valid implementation.

## 6. References

Official standards and project documentation only (per the source
policy). Practitioner references (VeriSwarm etc.) may be used as
implementation examples in the learner-side write-up but are not
load-bearing here.

- Kubernetes — NetworkPolicy reference:
  https://kubernetes.io/docs/concepts/services-networking/network-policies/
- Kubernetes — CNI plugins:
  https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/
- CNI project specification:
  https://github.com/containernetworking/cni/blob/main/SPEC.md
- Calico documentation:
  https://docs.tigera.io/calico/latest/about/
- Cilium documentation:
  https://docs.cilium.io/
- Antrea documentation:
  https://antrea.io/docs/
- MITRE ATLAS — adversary techniques (network-layer mappings):
  https://atlas.mitre.org/
- OWASP Machine Learning Security Top 10:
  https://owasp.org/www-project-machine-learning-security-top-10/
- NIST AI Risk Management Framework (AI RMF 1.0):
  https://www.nist.gov/itl/ai-risk-management-framework
