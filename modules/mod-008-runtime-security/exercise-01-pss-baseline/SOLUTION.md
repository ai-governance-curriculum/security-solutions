# SOLUTION — Exercise 01: Pod Security Standards Baseline

> Read this *after* attempting the exercise. The rollout below is one reasonable
> answer for the SmartRecs platform context — alternate splits (e.g., Baseline
> everywhere then Restricted only for `recs`/`fraud`) are also defensible if the
> rationale tracks the workload constraints.

---

## 1. Solution overview

Three forces shape the per-namespace decision:

1. **What the workload genuinely needs** (host paths, capabilities, GPU drivers,
   privileged init containers, hostNetwork for log shippers, etc.).
2. **Blast radius if compromised** (production serving + governance/audit log
   are high-impact, notebooks are medium-impact, training is high-impact for
   model integrity).
3. **How disruptive a failed enforce step would be** (cert-manager outage
   blocks renewals → mesh starts failing in hours; `kube-system` outage is
   immediate).

Pod Security Standards (PSS) lets us pick **one of three profiles per
namespace** — Privileged, Baseline, Restricted — and apply it in **three
modes** — `warn`, `audit`, `enforce`. The rollout pattern below stages
`warn → audit → enforce` over three weeks per cohort, so we see violations in
events and audit logs *before* admission starts rejecting pods.

The transition from PodSecurityPolicy to the built-in Pod Security Admission
controller is the model we follow; PSP was removed in Kubernetes 1.25.

## 2. Worked answer / implementation

### 2.1 Target profile per namespace

| Namespace | Target | Rationale |
|---|---|---|
| `edge` | Restricted | Stateless gateway. No GPU, no host paths, no privileged init. The most-exposed namespace — Restricted is mandatory. |
| `recs` | Restricted | Model-serving (CPU/light-GPU inference). Workload is a Python+Uvicorn HTTP server with read-only mounts; nothing here legitimately needs Baseline-tier privileges. |
| `fraud` | Restricted | Same shape as `recs`. Compromise touches scoring decisions that flow into customer-visible holds, so we hold this to the same bar. |
| `recs-train` | Baseline | NVIDIA device plugin DaemonSet and training pods need `add: ["IPC_LOCK"]` plus device mounts; this fails Restricted's `allowedCapabilities` and `volumes` rules. Baseline is the realistic target. |
| `fraud-train` | Baseline | Same justification as `recs-train`. |
| `features` | Restricted | Feature store API; behaves like a serving pod. No reason to weaken. |
| `gov` | Restricted | Governance + audit-chain workloads. High-trust namespace; if anything, the bar should be *higher* than the average, not lower. |
| `obs` | Baseline | Prometheus needs to expose `hostNetwork` for some node-exporter setups, and some sidecars need `RunAsNonRoot=false` to read host metrics. Baseline plus a Kyverno deny rule for `privileged: true` is the practical compromise. |
| `cert-manager` | Restricted | The controller itself does not need elevated privileges; this is a common misconception. |
| `notebooks` | Baseline (+ tenant isolation) | Many notebook images run as root; forcing Restricted breaks the user-installable kernel workflow. See §2.4 for the rationale on isolating the namespace rather than relaxing safer ones. |
| `kube-system` | Privileged | System components: kubelet plugins, CNI, kube-proxy, CSI drivers. Forcing Baseline here breaks the cluster. |

### 2.2 Namespace label YAML

The pattern is the same per namespace; only the profile and the namespace name change. Apply each as a namespace metadata update:

```yaml
# recs (Restricted)
apiVersion: v1
kind: Namespace
metadata:
  name: recs
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: latest
```

```yaml
# recs-train (Baseline)
apiVersion: v1
kind: Namespace
metadata:
  name: recs-train
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: latest
```

Note: even for Baseline-enforced namespaces we set `audit` and `warn` to
`restricted` so we keep seeing the gap between current state and the stricter
profile. That is what tells us if the namespace could be tightened in a future
hardening pass.

```yaml
# kube-system (Privileged enforce, Baseline warn)
apiVersion: v1
kind: Namespace
metadata:
  name: kube-system
  labels:
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: baseline
    pod-security.kubernetes.io/warn-version: latest
    pod-security.kubernetes.io/audit: baseline
    pod-security.kubernetes.io/audit-version: latest
```

The other namespaces follow the same shape — replace the name and the profile.

### 2.3 Rollout schedule

We cohort namespaces by risk-of-disruption. Low-disruption namespaces ride
the change first so we shake out tooling (label automation, alerting, rollback
muscle memory) before touching production serving.

| Week | Cohort | Phase | Notes |
|---|---|---|---|
| 1 | `edge`, `features`, `gov` | `warn` + `audit` | Read the events; treat each violation as a ticket. |
| 2 | `edge`, `features`, `gov` | `enforce` | Switch once the audit-log violations have stabilized at zero for 48 h. |
| 2 | `recs`, `fraud` | `warn` + `audit` | In parallel with cohort-1 enforce. |
| 3 | `recs`, `fraud` | `enforce` | Production serving — same 48-h-clean rule. |
| 3 | `recs-train`, `fraud-train`, `obs` | `warn` + `audit` (Baseline target) | GPU + observability stack. |
| 4 | `recs-train`, `fraud-train`, `obs` | `enforce` (Baseline) | Confirm device plugin + Prometheus survive enforce step. |
| 4 | `notebooks` | `warn` + `audit` (Baseline) | Expect noisy violations from user-supplied images. |
| 5 | `notebooks` | `enforce` (Baseline) | After remediating top violators or moving them to a sandboxed sub-namespace. |
| — | `kube-system` | `enforce: privileged` from day 1 | Never changes; only `warn`/`audit` upgrades over time. |
| — | `cert-manager` | follows cohort 1 | Small, easy to swap out if a controller upgrade re-introduces a violation. |

The same warn → audit → enforce sequence is what the Kubernetes project itself
documents for the PSP-to-PSS migration; this is not a SmartRecs invention.

### 2.4 Expected failures and remediation

| Namespace | Expected failure | Remediation | Risk class |
|---|---|---|---|
| `recs-train` | NVIDIA device-plugin DaemonSet sets `securityContext.privileged: true` and mounts `/dev`. Restricted rejects both. | Target = Baseline. Add Kyverno policy that only allows `privileged: true` for the `nvidia-device-plugin` ServiceAccount in this namespace. | Documented exemption (GPU drivers). |
| `fraud-train` | Same as above. | Same as above. | Same. |
| `notebooks` | Default Jupyter images run as UID 0; pull `pip` packages that require `--user`-writable site-packages; sometimes need `add: ["NET_RAW"]` for student networking labs. | Two-track: (a) ship a vetted base image that runs as UID 1000 with non-root packages; (b) for users who insist on root, give them a `notebooks-sandbox` sub-namespace on a *separate* node pool with stricter NetworkPolicy and no shared storage. | Risk concentrated, not spread. |
| `obs` | `node-exporter` mounts `/proc`, `/sys`, `/`; needs `hostNetwork: true`, `hostPID: true`. Restricted blocks all of these. | Target = Baseline. Lock `node-exporter`'s ServiceAccount to the exact `hostPath` mounts it needs via a Kyverno mutate rule. | Documented exemption. |
| `kube-system` | Kubelet plugins, CSI node DaemonSets, CNI agents. All require privileged. | Target = Privileged. Compensating controls: (1) image allow-list (Kyverno) restricting which images can run here; (2) admission webhook that disallows new Deployments in `kube-system` outside the platform-team OIDC group. | Accepted. |
| `cert-manager` | None expected for the controllers themselves. ACME HTTP-01 solver pods may run as root in older charts. | Pin chart version that ships UID-1000 solvers, or set `securityContext.runAsNonRoot: true` in chart values. | Low. |
| `edge`/`recs`/`fraud`/`gov`/`features` | Custom service charts that default `allowPrivilegeEscalation` to unset (Restricted requires explicit `false`) or skip `seccompProfile`. | Update Helm chart values: `allowPrivilegeEscalation: false`, `seccompProfile.type: RuntimeDefault`, `capabilities.drop: [ALL]`, `runAsNonRoot: true`. | Low; one-line fixes. |

### 2.5 Rollback plan

A failed `enforce` step manifests as: new pods stuck in `FailedCreate` with
admission-rejection events. Existing pods continue running (PSA is admission-
time, not runtime). The window to act is "until the next deployment rollout
of the affected workload."

Rollback per namespace, in order:

1. **Revert the enforce label** to the previously-known-good profile (most
   often: from `restricted` to `baseline`, or from `baseline` to `privileged`).
   Keep `warn` and `audit` at the stricter level so we still see the gap.

   ```bash
   kubectl label --overwrite namespace recs \
     pod-security.kubernetes.io/enforce=baseline
   ```

2. **Trigger a rollout** of the affected Deployments/StatefulSets so the
   blocked replicas come back up:

   ```bash
   kubectl -n recs rollout restart deployment recs-serving
   ```

3. **Confirm pods reach Ready** before touching the next namespace.
4. **File an incident ticket** with: which namespace, which workload, which
   PSS rule, what change is needed to re-attempt enforce.
5. **Keep `warn` + `audit` at `restricted`** so the violation keeps appearing
   in audit logs; that is the backlog for the next attempt.

What we do *not* do on rollback: delete the namespace label entirely. An
unlabeled namespace falls back to the cluster default, which on most clusters
is "no enforcement" — a silent regression.

### 2.6 Acceptance criteria

A namespace's rollout is "done" when, for 48 consecutive hours after enforce
is flipped:

- Zero admission rejections caused by PSS for that namespace's normal
  deployment pipeline.
- All Deployments / StatefulSets at desired replica count.
- Audit log produces zero new `Violation` events for the enforced profile.
- A re-run of `kubectl auth can-i create pod --as=system:anonymous -n <ns>` is
  still denied (sanity check that we didn't loosen RBAC by accident).

## 3. Validation steps

1. **Lint the manifests** — every namespace YAML passes `kubectl apply
   --dry-run=server`. The API server validates the label values.
2. **Test in a non-production cluster first.** Apply the full label set and
   try to deploy each tier's representative workload (one serving pod, one
   training pod, one notebook pod, the node-exporter). Capture the
   admission-rejection events with `kubectl get events --field-selector
   reason=FailedCreate`.
3. **Run a Restricted-target audit before any enforce.** With `audit:
   restricted` set, `kubectl get events -n <ns> -o json | jq
   '.items[] | select(.reason=="Violation")'` should enumerate every
   workload that would break under Restricted. This list *is* the remediation
   backlog.
4. **Run the validating admission policy in a dry mode.** Kyverno's `audit`
   policy mode (separate from PSA `audit`) gives the same coverage for any
   compensating rules added to handle exemptions.
5. **Replay rollback once on the staging cluster** end-to-end (force a
   violation by adding a `privileged: true` pod, watch the rejection,
   step through the §2.5 commands, confirm recovery). Don't run the live
   rollout until that drill is timed.

## 4. Rubric / review checklist

Mark each as `pass | partial | fail`:

- [ ] **Profile selection diverges per namespace** based on observed workload
      need, not "Restricted everywhere."
- [ ] **GPU / training namespaces** are Baseline (not Restricted) with the
      reason recorded.
- [ ] **`kube-system`** is left at Privileged with compensating controls
      named (image allow-list, RBAC scope).
- [ ] **`notebooks`** has a strategy that isolates the looser profile rather
      than relaxing the rest of the cluster to its level.
- [ ] **Label YAML** uses both `enforce` *and* `warn`/`audit`. Setting only
      `enforce` loses the early-warning signal.
- [ ] **Rollout** uses `warn → audit → enforce` over distinct windows.
      Immediate enforce loses points.
- [ ] **Expected-failure table** names concrete workloads and the concrete
      field that fails (e.g., "`securityContext.privileged: true` in
      `nvidia-device-plugin`"). Generic "device plugin fails" loses points.
- [ ] **Rollback plan** specifies the exact label-revert command and an
      explicit "do not delete the label" instruction.
- [ ] **Acceptance criteria** are observable in events/metrics, not a
      subjective "looks good."

A pass-grade plan answers all of the above with specifics; partial-grade
answers some; a fail-grade plan is "Restricted on everything Monday morning."

## 5. Common mistakes

- **"Restricted everywhere immediately."** Breaks the device plugin, the
  node-exporter, and any helper container someone added to `kube-system`
  without telling you. Restricted is a target, not a default-on switch.
- **Skipping the `warn`/`audit` phase.** Without it, the first you hear about
  a violation is when a deployment fails at 02:00 because the on-call team
  rolled a normal patch.
- **Removing the label to "fix" a rollout.** Unlabeled namespaces fall back
  to the cluster-default profile, which is often unenforced. Silent regression.
- **Treating PSA as runtime enforcement.** PSA validates at admission time
  only. Running pods are not killed when you raise the bar; they continue until
  re-scheduled. Plan a rolling restart if you need the new profile to take
  effect immediately.
- **Lowering the profile of an entire namespace** to accommodate one
  privileged workload. The fix is a Kyverno exception for that one workload's
  ServiceAccount, not loosening the namespace.
- **Confusing PSS profiles with NetworkPolicy.** PSS doesn't constrain
  network behavior. Pair every PSS rollout with a default-deny NetworkPolicy
  in the same namespace; otherwise a Restricted pod can still reach the cloud
  metadata endpoint.
- **Forgetting the `-version` labels.** Without `enforce-version`, a future
  Kubernetes upgrade may quietly tighten the Restricted definition and break a
  previously-passing workload. Pin to `latest` *or* pin to the version you
  tested against — pick one consciously.

## 6. References

- Kubernetes Pod Security Standards — definitions of Privileged / Baseline /
  Restricted profiles.
  <https://kubernetes.io/docs/concepts/security/pod-security-standards/>
- Kubernetes Pod Security Admission — label syntax, enforce / audit / warn
  modes, namespace exemption mechanism.
  <https://kubernetes.io/docs/concepts/security/pod-security-admission/>
- Pod Security Admission moves to stable (PSP → PSS migration guidance).
  <https://kubernetes.io/blog/2022/08/25/pod-security-admission-stable/>
- NIST SP 800-190 — *Application Container Security Guide* (the container-
  isolation threat model that motivates Restricted-tier defaults).
  <https://csrc.nist.gov/pubs/sp/800/190/final>
- NSA / CISA Kubernetes Hardening Guide v1.2 — pod-level hardening
  recommendations consistent with Restricted profile.
  <https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF>
- CIS Kubernetes Benchmark — pod-security control catalogue used to
  cross-check the per-namespace exemption decisions.
  <https://www.cisecurity.org/benchmark/kubernetes>
- Module 08 lecture notes §2 (Pod Security Standards) for the SmartRecs-
  specific framing.
