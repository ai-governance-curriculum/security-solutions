# SOLUTION — Exercise 03: Falco Ruleset for SmartRecs ML Platform

> Read this *after* attempting the exercise. The rules below are a worked
> reference; expected false-positive volumes are calibrated for the SmartRecs
> exercise context, not measured from a specific deployment. Re-tune against
> your own baseline before promoting to PagerDuty severity.

---

## 1. Solution overview

Falco gives you a syscall-level (or eBPF, in newer drivers) view of every
container on a node, plus the Kubernetes audit-event feed. Default rules
catch generic Linux compromise patterns. The point of this ruleset is the
**ML-specific layer on top**: model file tampering, training-job egress
anomalies, GPU misuse, notebook outbound surprises — patterns Falco's
upstream ruleset doesn't have because they're domain-specific.

Three design choices shape the ruleset:

1. **Conditions are specific.** Each rule names the SmartRecs workload it
   targets (label selector, namespace, image, process). Generic conditions
   ("any shell anywhere") drown the on-call in noise within a day.
2. **Priority maps to response cost, not feeling.** CRITICAL = page out of
   hours. HIGH = page during business hours. WARNING/NOTICE = SIEM only.
   If every rule is CRITICAL, none of them are.
3. **Each rule names its tuning levers.** The first week after promotion is
   when the false-positive list shows up; the rule must tell future-you
   how to silence the expected ones without disabling detection.

Each rule is also tagged with the relevant MITRE ATT&CK for Containers or
MITRE ATLAS technique so an alert in the SIEM links to the threat model.
Use MITRE ATLAS for ML-specific tactics like model poisoning, and ATT&CK
for Containers for general escape / persistence / lateral-movement
tactics — both are referenced in the lecture notes.

## 2. Worked answer / implementation

### Rule index

| ID | Rule | Priority | Tags |
|---|---|---|---|
| R001 | Model file tampering | CRITICAL | `ml`, `model_integrity`, `atlas_aml.t0018` |
| R002 | Training-job egress anomaly | HIGH | `ml`, `training`, `exfiltration`, `attack_t1567` |
| R003 | Reverse shell in production serving | CRITICAL | `ml`, `serving`, `execution`, `attack_t1059` |
| R004 | Privileged container in production namespace | CRITICAL | `policy`, `privesc`, `attack_t1611` |
| R005 | Cloud metadata access from non-system pod | CRITICAL | `cloud`, `credential_access`, `attack_t1552_005` |
| R006 | `kubectl exec` into production serving pod | HIGH | `audit`, `lateral_movement`, `attack_t1609` |
| R007 | GPU misuse outside training window | HIGH | `ml`, `gpu`, `cryptomining`, `attack_t1496` |
| R008 | Notebook outbound to non-allow-listed destination | HIGH | `ml`, `notebook`, `exfiltration`, `attack_t1567` |
| R009 *(optional)* | Container-escape primitive (`setns`/`unshare`/`nsenter`) | CRITICAL | `escape`, `attack_t1611` |
| R010 *(optional)* | Sensitive file access (`/etc/shadow`, `/proc/*/environ`) | HIGH | `credential_access`, `attack_t1552_001` |

### Lists and macros (shared by multiple rules)

```yaml
- list: smartrecs_prod_serving_ns
  items: [recs, fraud, edge, features, gov]

- list: smartrecs_training_ns
  items: [recs-train, fraud-train]

- list: model_loader_allowlist
  items: [model-loader, init-loader, weight-downloader]

- list: training_allowed_egress
  items:
    - registry.smartrecs.internal
    - artifacts.smartrecs.internal
    - feature-store.features.svc.cluster.local
    - mlflow.gov.svc.cluster.local

- list: notebook_allowed_egress
  items:
    - pip-mirror.notebooks.svc.cluster.local
    - dataset-bucket.notebooks.svc.cluster.local
    - feature-store.features.svc.cluster.local

- macro: in_prod_serving
  condition: k8s.ns.name in (smartrecs_prod_serving_ns)

- macro: in_training
  condition: k8s.ns.name in (smartrecs_training_ns)

- macro: shell_proc
  condition: >
    proc.name in (sh, bash, zsh, ash, dash, ksh) or
    (proc.name = python and proc.args contains "-i") or
    (proc.name = python3 and proc.args contains "-i")
```

### Rules

#### R001 — Model file tampering

```yaml
- rule: smartrecs_model_file_tampering
  desc: >
    A file under /models is being written by a process that is not in the
    declared model-loader allow-list. Model files should be immutable after
    container start; writes indicate either a deployment-channel bypass or
    an active poisoning attempt.
  condition: >
    open_write and container and
    fd.directory startswith "/models" and
    not proc.name in (model_loader_allowlist) and
    not k8s.ns.name in (smartrecs_training_ns)
  output: >
    Model file write outside loader allow-list
    (user=%user.name pod=%k8s.pod.name ns=%k8s.ns.name
     image=%container.image.repository proc=%proc.cmdline file=%fd.name)
  priority: CRITICAL
  tags: [ml, model_integrity, atlas_aml.t0018]
```

- **Expected FPR:** Low. Most likely sources: (a) emergency hotfix where a
  human SREs in to overwrite a corrupted weights file (this *should* page —
  the runbook is "page even when expected, validate out-of-band"); (b) a
  framework that writes a `.lock` file next to the model.
- **Triage:**
  1. Confirm pod/ns from alert. If `gov`/`recs`/`fraud`, treat as P1.
  2. Pull `kubectl get events` for the pod and the audit log for the same
     window to see who is on the node and what triggered it.
  3. Compare the file hash to the deployment-time hash in the model registry
     (MLflow / governance store). Hash mismatch → containment per Exercise 05.
- **Tuning levers:** if a framework writes lock files into `/models`, mount
  `/models` read-only via Pod Security Context and isolate the lock dir
  elsewhere — *don't* loosen the rule.

#### R002 — Training-job egress anomaly

```yaml
- rule: smartrecs_training_egress_anomaly
  desc: >
    Outbound connection from a training pod to a destination not in the
    training egress allow-list. Training pods should only reach the model
    registry, the artifact store, the feature store, and the MLflow API.
  condition: >
    outbound and container and in_training and
    not fd.sip in (cluster_ipv4_cidr_list) and
    not fd.name in (training_allowed_egress) and
    not fd.sport in (53, 80, 443) and
    not (fd.sip = "169.254.169.254")
  output: >
    Training pod outbound to disallowed destination
    (pod=%k8s.pod.name ns=%k8s.ns.name dest=%fd.name proto=%fd.l4proto
     image=%container.image.repository)
  priority: HIGH
  tags: [ml, training, exfiltration, attack_t1567]
```

- **Expected FPR:** Moderate during the first 1–2 weeks (data scientists
  add a new pip mirror, a new HuggingFace cache, etc.). Drops to near-zero
  once the egress allow-list reflects real workflow.
- **Triage:**
  1. Is the destination a known data source? Add to `training_allowed_egress`
     after a ticket recording why.
  2. If unknown: snapshot pod's network connections (`crictl inspect`),
     check for matches in threat-intel sources, then proceed per Exercise 05
     if the destination is hostile.
- **Tuning levers:** the `training_allowed_egress` list is the only knob —
  resist the temptation to widen the CIDR exception.
- **Note on cloud metadata:** the `169.254.169.254` exclusion here is
  intentional — it would *also* fire R005, which is the rule we want to
  page on. Don't double-alert.

#### R003 — Reverse shell in production serving

```yaml
- rule: smartrecs_reverse_shell_in_serving
  desc: >
    A shell process spawned inside a production serving container. The
    serving images don't ship a shell in their normal execution path; a
    shell is either an attacker's interactive session or a misconfigured
    operator pulse.
  condition: >
    spawned_process and container and in_prod_serving and
    shell_proc and
    not proc.pname in (model_loader_allowlist) and
    not proc.aname[2] = "containerd-shim"
  output: >
    Shell spawned in production serving pod
    (user=%user.name pod=%k8s.pod.name ns=%k8s.ns.name
     proc=%proc.cmdline parent=%proc.pname image=%container.image.repository)
  priority: CRITICAL
  tags: [ml, serving, execution, attack_t1059]
```

- **Expected FPR:** Very low if the serving image is distroless (no shell to
  spawn). Slightly higher with a debian-slim base because a misconfigured
  liveness probe may exec `sh -c`. Pin probes to direct binary calls.
- **Triage:**
  1. Identify the parent process. If it's the application binary, this is a
     real RCE — treat as Exercise 05 §detection-source-1.
  2. If it's `kubelet` running a liveness/readiness probe, the probe
     definition is wrong; file a ticket and tune the rule with a probe
     allow-list.
- **Tuning levers:** add specific probe scripts to a `serving_probe_allowlist`
  list; never add `kubectl` itself.

#### R004 — Privileged container in production namespace

```yaml
- rule: smartrecs_privileged_in_production
  desc: >
    A container started with privileged=true in a production serving
    namespace. This should never happen — admission controllers (PSS,
    Kyverno) should have blocked it. If it fires, an admission path was
    bypassed.
  condition: >
    container_started and container and
    container.privileged = true and
    k8s.ns.name in (smartrecs_prod_serving_ns)
  output: >
    Privileged container started in production
    (pod=%k8s.pod.name ns=%k8s.ns.name image=%container.image.repository
     user=%user.name)
  priority: CRITICAL
  tags: [policy, privesc, attack_t1611]
```

- **Expected FPR:** Effectively zero. Each firing is a real admission-policy
  bypass.
- **Triage:**
  1. Capture the pod spec (`kubectl get pod -o yaml`).
  2. Audit which admission controllers were running at the time
     (`kubectl get validatingwebhookconfigurations`).
  3. Treat as a policy-bypass incident; escalate to the platform team and
     restore the missing controller before the next deployment.
- **Tuning levers:** none. If this fires for a "legitimate" reason, the
  legitimacy is the bug.

#### R005 — Cloud metadata access from non-system pod

```yaml
- rule: smartrecs_imds_access
  desc: >
    Outbound connection to the cloud metadata service (169.254.169.254 /
    fd00:ec2::254) from a workload not on the system allow-list. Common
    pre-stage of credential theft via instance-profile abuse.
  condition: >
    outbound and container and
    (fd.sip = "169.254.169.254" or fd.sip = "fd00:ec2::254") and
    not k8s.ns.name in (kube-system) and
    not container.image.repository in (system_metadata_clients)
  output: >
    Cloud metadata service accessed from workload pod
    (pod=%k8s.pod.name ns=%k8s.ns.name proc=%proc.cmdline
     image=%container.image.repository)
  priority: CRITICAL
  tags: [cloud, credential_access, attack_t1552_005]
```

- **Expected FPR:** Near zero on EKS clusters using IRSA (Pods don't talk
  to IMDS directly when IRSA is wired correctly). Slightly higher if a
  legacy chart still uses node-role credentials — these are themselves a
  finding that should be remediated.
- **Triage:**
  1. Look at the pod's ServiceAccount. If it should be using IRSA but
     isn't, file a ticket *and* page on-call for the credential theft
     window.
  2. If on GKE/Workload Identity, same logic.
- **Tuning levers:** `system_metadata_clients` should be a tightly-managed
  list (cluster-autoscaler, cloud-controller-manager) reviewed quarterly.

#### R006 — `kubectl exec` into production serving pod

```yaml
- rule: smartrecs_exec_into_prod_serving
  desc: >
    Kubernetes API audit event: an exec or attach request against a pod in
    a production serving namespace. Operator access to production should
    be break-glass and pre-announced.
  condition: >
    ka.verb in (create) and
    ka.target.resource = "pods" and
    ka.target.subresource in (exec, attach) and
    ka.target.namespace in (smartrecs_prod_serving_ns) and
    not ka.user.name in (system:serviceaccount:gov:break-glass-controller)
  output: >
    Operator exec into production serving pod
    (user=%ka.user.name pod=%ka.target.name ns=%ka.target.namespace
     verb=%ka.verb sub=%ka.target.subresource)
  priority: HIGH
  source: k8s_audit
  tags: [audit, lateral_movement, attack_t1609]
```

- **Expected FPR:** Predictable spikes during incident response (which is
  exactly when we want the audit log to confirm "yes, the SRE on-shift
  did this"). Routine background rate should be 0.
- **Triage:**
  1. Cross-reference the user against the on-call schedule.
  2. If unscheduled, treat as a credential-compromise incident.
- **Tuning levers:** keep the allow-list tiny (the break-glass controller
  ServiceAccount); never allow individual humans.

#### R007 — GPU misuse outside training window

```yaml
- rule: smartrecs_gpu_misuse_off_window
  desc: >
    GPU utilization sustained >95% on a pod that is either not in a
    training namespace or is in a training namespace outside the scheduled
    training window (defined elsewhere — this rule emits whenever the
    annotation is missing or expired).
  condition: >
    spawned_process and container and
    (proc.name in (nvidia-smi, python, python3, torchrun)) and
    k8s.pod.annotations["smartrecs.io/gpu-window-active"] != "true" and
    proc.cmdline contains "cuda"
  output: >
    GPU compute outside declared training window
    (pod=%k8s.pod.name ns=%k8s.ns.name proc=%proc.cmdline
     image=%container.image.repository)
  priority: HIGH
  tags: [ml, gpu, cryptomining, attack_t1496]
```

- **Note:** Falco doesn't natively read GPU utilization; this rule depends
  on a sidecar (or DCGM exporter) that writes the annotation
  `smartrecs.io/gpu-window-active=true` during scheduled training windows
  and removes it outside. Falco then alerts on CUDA-using processes outside
  the window. Without that sidecar, this rule's intent is implemented as a
  Prometheus alert (`DCGM_FI_DEV_GPU_UTIL > 95`) joined against the
  training-schedule label.
- **Expected FPR:** Modest. Drift in the annotation TTL produces alerts when
  a training run overruns its window — this is information you want
  anyway, so treat as a feature.
- **Triage:** check the training schedule. If the pod has a legitimate
  reason to be running, extend the window (and capture the overrun in the
  weekly review).
- **Tuning levers:** the window definition lives outside Falco; tune
  there, not in the rule.

#### R008 — Notebook outbound to non-allow-listed destination

```yaml
- rule: smartrecs_notebook_egress_anomaly
  desc: >
    Outbound connection from the notebooks namespace to a destination not
    in the notebook egress allow-list. Notebook users have a habit of
    pulling from public package mirrors; the allow-list captures the
    sanctioned internal mirrors.
  condition: >
    outbound and container and k8s.ns.name = "notebooks" and
    not fd.sip in (cluster_ipv4_cidr_list) and
    not fd.name in (notebook_allowed_egress) and
    not fd.sport in (53)
  output: >
    Notebook pod outbound to disallowed destination
    (pod=%k8s.pod.name dest=%fd.name proto=%fd.l4proto user=%k8s.pod.label.user)
  priority: HIGH
  tags: [ml, notebook, exfiltration, attack_t1567]
```

- **Expected FPR:** High in week 1 (data scientists test the limits of the
  mirror), then drops sharply once the allow-list reflects real workflow.
  This is the rule most at risk of becoming alert fatigue; pair with a
  Slack-only routing for `notebooks`, never PagerDuty.
- **Triage:**
  1. Identify the destination. New legitimate mirror → ticket to add it.
  2. Public destination not in the mirror → user-coaching ticket;
     repeat-offender pattern → conversation with the data-science manager.
- **Tuning levers:** the allow-list. Time-box exceptions ("48-h trial of
  destination X") with auto-removal.

#### R009 (optional) — Container-escape primitive

```yaml
- rule: smartrecs_escape_primitive
  desc: >
    A process invoked setns / unshare / nsenter, or attempted a mount-
    namespace manipulation. These are container-escape primitives and have
    no legitimate use inside a SmartRecs workload pod.
  condition: >
    spawned_process and container and
    (proc.name in (nsenter, unshare) or
     evt.type in (setns, unshare, mount, pivot_root))
  output: >
    Container-escape primitive observed
    (pod=%k8s.pod.name ns=%k8s.ns.name proc=%proc.cmdline syscall=%evt.type)
  priority: CRITICAL
  tags: [escape, attack_t1611]
```

- **Expected FPR:** Effectively zero in a SmartRecs workload. Falco's own
  driver and the CNI may invoke these, so add them to the system allow-list
  if needed.
- **Triage:** treat as Exercise 05 escape runbook, source 1.

#### R010 (optional) — Sensitive file access

```yaml
- rule: smartrecs_sensitive_file_read
  desc: >
    Read of a sensitive file: /etc/shadow, another process's /proc
    environment, the kernel ring buffer.
  condition: >
    open_read and container and
    (fd.name = "/etc/shadow" or
     fd.name pmatch (/proc/[0-9]+/environ) or
     fd.name in ("/proc/kallsyms", "/proc/kcore"))
  output: >
    Sensitive file read inside container
    (pod=%k8s.pod.name ns=%k8s.ns.name proc=%proc.cmdline file=%fd.name)
  priority: HIGH
  tags: [credential_access, attack_t1552_001]
```

- **Expected FPR:** Low. Some monitoring agents read `/proc/.../environ`;
  scope the rule to non-system namespaces or maintain an allow-list.
- **Triage:** depends on caller; environment-variable reads are a known
  credential-theft pattern.

### Cross-references with the audit chain

Every CRITICAL or HIGH event passes through Falcosidekick and lands in the
governance audit-chain store with the following normalized fields:

- `event.id` (Falco-assigned UUID)
- `event.priority`
- `event.rule` (one of R001-R010)
- `event.tags` (used to bucket by MITRE technique)
- `k8s.pod`, `k8s.ns`, `k8s.image`
- `proc.cmdline` / `fd.name` / `fd.sip` (the discriminating field for that
  rule)
- `audit.chain.prev_hash` (computed downstream by the governance signer)

The audit-chain entry is what compliance produces during an external
review; Falco is the upstream signal.

### Integration with Falcosidekick

| Priority | Destination | Why |
|---|---|---|
| CRITICAL | PagerDuty (P1) + SIEM + audit chain + Slack `#sec-incidents` | Page out of hours; written record across all systems. |
| HIGH | PagerDuty (P3, business hours only) + SIEM + audit chain + Slack `#sec-alerts` | Triage within the day. |
| WARNING / NOTICE | SIEM + audit chain (no paging) | Weekly review backlog. |
| INFO / DEBUG | Dev cluster only | Off in production. |

Falcosidekick YAML sketch:

```yaml
slack:
  webhookurl: https://hooks.slack.com/services/T.../B.../...
  minimumpriority: warning
pagerduty:
  routingkey: ${PD_ROUTING_KEY}
  minimumpriority: high
elasticsearch:
  hostport: https://siem.gov.svc.cluster.local:9200
  minimumpriority: notice
```

### Quarterly review process

Every quarter the platform-security on-call does:

1. **Volume report.** Per-rule alert counts for the quarter, with the FPR
   estimate vs. observed. Rules with FPR > 30% get a tuning sprint.
2. **Retirement candidates.** Rules with zero alerts AND zero replayed
   true-positive scenarios in the quarter get downgraded to NOTICE or
   removed. Detection that never fires is a false sense of coverage.
3. **Coverage gap review.** New MITRE ATLAS / ATT&CK techniques added since
   last quarter. Add new rules for techniques that map to SmartRecs assets.
4. **Replay drill.** Run synthetic attacks for the top-5 highest-priority
   rules to confirm they still fire (driver upgrades have broken rule
   semantics in the past).

## 3. Validation steps

1. **`falco --validate` on each rule file.** Catches YAML and condition
   syntax errors before deploy.
2. **Rule lint via `falcoctl` rules lint** — checks tag formatting and
   priority spelling.
3. **`falco --list-fields` sanity check** — confirm every field reference
   (e.g., `k8s.pod.annotations`) is supported by the Falco version you ship.
4. **Per-rule synthetic test** in the staging cluster. Each test is a tiny
   Job that does exactly the thing the rule is supposed to catch:

   | Rule | Trigger |
   |---|---|
   | R001 | `kubectl exec -n recs … -- sh -c "echo x > /models/test.bin"` (must be a privileged debug pod that bypasses readOnlyRootFilesystem). |
   | R002 | Job in `recs-train` that curls a random public IP. |
   | R003 | `kubectl debug -n recs … --image=busybox -- sh`. |
   | R004 | Apply a pod with `privileged: true` to `recs` (PSS should reject; if it doesn't, that's R004 firing for a real reason). |
   | R005 | `kubectl exec -n recs … -- curl http://169.254.169.254/`. |
   | R006 | `kubectl exec` from a non-allow-list user. |
   | R007 | Run a CUDA job outside the annotated window. |
   | R008 | From a notebook pod, curl an unknown destination. |
   | R009 | `kubectl exec -n recs … -- nsenter -t 1 -m`. |
   | R010 | `kubectl exec -n recs … -- cat /etc/shadow`. |

   Each trigger must result in an event in the SIEM within 60 s, with the
   expected rule id and priority. This becomes a CI gate on the rules
   repo.
5. **End-to-end routing test.** A CRITICAL synthetic event must reach
   PagerDuty (use the test routing key); a HIGH must reach Slack
   `#sec-alerts`. The on-call confirms receipt.

## 4. Rubric / review checklist

- [ ] **At least 8 ML-specific rules** (R001-R008) with concrete
      conditions, not generic patterns.
- [ ] **Conditions reference SmartRecs context** (namespaces, image names,
      labels), not "any container."
- [ ] **Priorities are calibrated** to response cost: CRITICAL only for
      page-out-of-hours events.
- [ ] **Each rule lists** expected FPR, triage steps, tuning levers.
- [ ] **MITRE tags** present and correct (ATLAS for model-tampering,
      ATT&CK for the rest).
- [ ] **Macros and lists** are factored out (model_loader_allowlist,
      training_allowed_egress, etc.) so a context change is one edit.
- [ ] **Falcosidekick routing matrix** maps priority → destination.
- [ ] **Quarterly review process** is named (who runs it, what they
      produce).
- [ ] **Validation tests** include a per-rule synthetic trigger.
- [ ] **No rule both relies on a non-Falco signal and pretends to be a
      pure Falco rule** (R007 honestly notes the GPU-metric dependency).

## 5. Common mistakes

- **All rules at CRITICAL.** The on-call learns to ignore the queue; real
  CRITICALs get missed. Calibrate priority to response cost.
- **Conditions written as `proc.name = bash`** without context. Fires for
  every `bash` in any container on every node, including jobs that
  legitimately run shells. Always pin to namespace + image + parent
  process or label.
- **No FPR estimate.** When the rule fires 200 times the first day, no one
  knows whether that's normal or a real incident.
- **Hard-coded namespace names** inline instead of in a list. The first
  rename triggers a multi-rule edit; lists make rename a one-line change.
- **Falco rule that depends on a metric (GPU util, request rate) and
  pretends to do it natively.** R007 explicitly says "implement this as a
  Prometheus alert if you don't have the annotation sidecar." Honest
  rule design.
- **Treating Falco as the only detection layer.** Falco sees container
  syscalls; it doesn't see HTTP request bodies, model output drift, or
  the audit log unless k8s_audit is wired. Pair with the audit chain and
  the behavioural baseline from Exercise 04.
- **Skipping the routing test.** The rule fires perfectly but the alert
  never reaches anyone because the Slack webhook rotated. Test
  end-to-end, not just the rule.
- **Disabling a noisy rule instead of tuning.** Every disabled rule is a
  blind spot. Tune the conditions, narrow the scope, or downgrade the
  priority — don't delete coverage.

## 6. References

- Falco documentation — engine, rule conditions, priorities, field
  reference.
  <https://falco.org/docs/>
- Falco rules reference — syntax for `rule`, `macro`, `list`, condition
  predicates, output formats.
  <https://falco.org/docs/reference/rules/>
- Falco default rules repo — upstream baseline these rules layer on top of.
  <https://github.com/falcosecurity/rules>
- Falcosidekick — alert routing to Slack, PagerDuty, Elasticsearch,
  webhooks.
  <https://github.com/falcosecurity/falcosidekick>
- MITRE ATLAS — ML-specific adversary tactics (used for R001 / AML.T0018
  model poisoning).
  <https://atlas.mitre.org/>
- MITRE ATT&CK for Containers — container-relevant technique IDs used in
  the tag column.
  <https://attack.mitre.org/matrices/enterprise/containers/>
- OWASP Machine Learning Security Top 10 — risk taxonomy the ML-specific
  rules map to (model integrity, data leakage, supply chain).
  <https://owasp.org/www-project-machine-learning-security-top-10/>
- NIST AI Risk Management Framework — Measure & Manage functions that
  cite runtime detection as a control.
  <https://www.nist.gov/itl/ai-risk-management-framework>
- Module 08 lecture notes §5 (Falco) and §9 (ML-specific runtime
  threats) for the rule-derivation rationale.
