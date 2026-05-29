# SOLUTION — Exercise 05: Container-Escape Response Runbook

> Read this *after* attempting the exercise. The runbook below is rehearsable
> in a SmartRecs-shaped cluster; before adoption, swap in your real on-call
> roster, escalation paths, and SIEM query syntax.

---

## 1. Solution overview

Container escape is the worst-case runtime-security event: an attacker who
got code execution in a pod has broken out to the host and now has access
to every container on that node, the kubelet, and any host filesystem
mounts. The runbook below is built around four constraints:

1. **Evidence first, containment second.** Most response shortcuts (drain
   the node, restart the pod, `kubectl delete pod`) destroy the evidence
   needed to understand the attack. Sequence matters; the order below is
   deliberate.
2. **Time-bounded steps.** Each phase has a target window: triage in 5 min,
   contain in 15 min, investigate within 4 h, communicate per regulatory
   deadlines. Without a budget, on-call response sprawls.
3. **Specific commands, not "investigate."** Every step names the tool, the
   command, and the expected output. A runbook that says "gather
   evidence" is a runbook that fails under pressure.
4. **Rehearsable.** The tabletop in §3 should run in one hour with the
   on-call rotation; it surfaces the gaps before a real incident does.

The runbook references Falco rules R001–R009 from Exercise 03 as detection
sources, the behavioural-baseline cross-correlations C1–C3 from Exercise
04, and the PSS / seccomp / AppArmor profiles from Exercises 01 and 02 as
controls that should have contained the blast radius before this runbook
fires. If the runbook fires, *one of those layers failed* — the post-
incident review starts there.

The compliance backdrop is GDPR's 72-hour notification deadline (Article
33) as the most common worst-case for customer-data exposure; specific
regulations and contractual obligations vary by jurisdiction and customer
agreement.

## 2. Worked answer / implementation

```
# Container-Escape Response Runbook — SmartRecs

Last updated: 2026-Q2
Owner: Platform Security on-call (rotating; primary in PagerDuty service
       smartrecs-platform-security)
Co-owners: SmartRecs SRE on-call (for node-level actions)

## Severity classification

| Confidence | Severity | Initial response |
|---|---|---|
| Confirmed escape (host-level evidence) | SEV-1 | Page primary + secondary security on-call + SRE on-call + Director of Engineering. |
| Strongly suspected (Falco R009 fired OR R001 + R005 within 60 s) | SEV-2 | Page security on-call + SRE on-call. |
| Possible (single-rule signal without corroboration) | SEV-3 | Security on-call investigates; no broad escalation. |

## Detection sources

### Source 1 — Falco "container escape primitive" (R009)

Specific alert text examples:
- "Container-escape primitive observed (... syscall=setns)"
- "Container-escape primitive observed (... proc=nsenter)"

First 5 minutes — collect BEFORE acting:

1. Capture the full Falco event JSON from the SIEM
   (`event.id` is the primary key for the audit chain).
2. Note pod, namespace, node, image, and the parent-process tree from
   the event output.
3. Pull the pod manifest as it currently exists:
   ```
   kubectl -n <ns> get pod <pod> -o yaml > /tmp/<event.id>-pod.yaml
   ```
4. Pull the node's recent events:
   ```
   kubectl get events --field-selector involvedObject.name=<node> -o yaml \
     > /tmp/<event.id>-node-events.yaml
   ```
5. Snapshot the audit-log entries for the same pod over the previous
   30 min:
   ```
   gov-audit-cli query --pod <pod> --since '-30m' > /tmp/<event.id>-audit.json
   ```

Do NOT exec into the pod yet; that itself fires R006 and creates more
noise in the timeline.

### Source 2 — Tetragon enforcement event

When Tetragon is configured in enforcement mode, an escape primitive is
blocked at the kernel level and emits a `process_kprobe` event.

First 5 minutes:
1. Pull the Tetragon event from the SIEM. Note that this is a blocked
   attempt — investigation still proceeds because the attacker is in the
   pod even if the escape didn't succeed.
2. Confirm enforcement is engaged for this node:
   ```
   kubectl -n kube-system get tracingpolicy escape-prevention -o yaml
   ```
3. Same evidence capture as Source 1, steps 3–5.

### Source 3 — Audit-chain anomaly

Behavioural-baseline correlation C3 (process tree depth + outbound to
new destination) or C1 (egress + CPU spike) firing on a serving
namespace.

First 5 minutes:
1. Pull the cross-dimension alert from the SIEM with all child events.
2. The contributing single-dimension events are themselves evidence; do
   not delete the corresponding metrics.
3. Same evidence capture as Source 1, steps 3–5.

### Source 4 — Host-level alert

Examples: auditd flagging `setns` on PID 1 of a container; node-exporter
metric showing unexpected `/dev` access from a non-system pod;
unexpected SSH session on a worker node.

First 5 minutes:
1. Snapshot `dmesg`, `journalctl -k`, and the auditd log:
   ```
   ssh <node> 'sudo dmesg -T > /tmp/dmesg.txt; \
     sudo journalctl -k --since "30 min ago" > /tmp/jrnl.txt; \
     sudo ausearch --start recent > /tmp/audit.txt'
   ```
2. Snapshot the process list with namespace info:
   ```
   ssh <node> 'sudo ps -eo pid,ppid,uid,cmd,nsuts,nsipc,nsmnt,nsnet,nspid \
     > /tmp/ps.txt'
   ```
3. Network connection list:
   ```
   ssh <node> 'sudo ss -tnp > /tmp/net.txt'
   ```

### Source 5 — External report

Someone tells you. Vendor disclosure, customer report, internal user.

First 5 minutes:
1. Open an incident ticket with the report verbatim — do not paraphrase.
2. Ask the reporter for evidence they have (logs, screenshots,
   timestamps).
3. Begin source-1 evidence capture for the suspected pod once
   identified.

## Immediate containment (target: within 15 min of confirmed alert)

### Step 1 — Identify affected pod and node

```
POD=<from alert>
NS=<from alert>
NODE=$(kubectl -n $NS get pod $POD -o jsonpath='{.spec.nodeName}')
echo "Pod=$POD  Ns=$NS  Node=$NODE"
```

### Step 2 — Preserve forensic evidence (BEFORE network isolation)

The order here is critical. Once we isolate the network, in-memory
attacker artefacts that depend on outbound connections may exit; once we
cordon and drain, the pod is gone with its memory.

a. **Pod memory snapshot via process dump on the node:**
   ```
   ssh $NODE
   sudo crictl ps --name=$POD
   CONTAINER_ID=<from above>
   sudo crictl inspect $CONTAINER_ID | jq '.info.pid' # gets host PID
   HOST_PID=<from above>
   sudo gcore -o /var/forensic/<event.id>.core $HOST_PID
   ```
   `gcore` produces an in-place ELF core dump without killing the
   process. Move the core to off-node storage before any node action.

b. **Container filesystem snapshot:**
   ```
   sudo crictl inspect $CONTAINER_ID | jq '.info.runtimeSpec.root.path'
   ROOT=<from above>
   sudo tar --acls --xattrs -czf /var/forensic/<event.id>-rootfs.tar.gz $ROOT
   ```

c. **Node process list with namespace mapping:**
   ```
   sudo ps -eo pid,ppid,uid,nsutsns,nsmntns,nsnetns,nspidns,cmd \
     > /var/forensic/<event.id>-procs.txt
   ```

d. **Network state on the node:**
   ```
   sudo ss -tnp > /var/forensic/<event.id>-net.txt
   sudo conntrack -L > /var/forensic/<event.id>-conntrack.txt
   ```

e. **Copy forensic artifacts off the node** (to the governance
   namespace's append-only object bucket; configured to require dual
   sign-off to delete):
   ```
   aws s3 cp /var/forensic/ s3://smartrecs-forensic/<event.id>/ --recursive
   ```

### Step 3 — Network isolation (pod and node)

a. **Per-pod NetworkPolicy override** — apply a deny-all policy that
   targets the pod label:
   ```
   kubectl -n $NS apply -f - <<EOF
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: ir-isolate-$POD
     labels: { incident-response: "true", event-id: "<event.id>" }
   spec:
     podSelector:
       matchLabels: { incident-quarantine: "true" }
     policyTypes: [Ingress, Egress]
   EOF

   kubectl -n $NS label pod $POD incident-quarantine=true
   ```
   The egress allow-list collapses to nothing; the pod can no longer
   reach the network. The pod continues to run (we still want its
   process state preserved).

b. **Node-level egress filter** (only if the escape is confirmed at the
   host level — Source 4 or Falco R009 in enforcement mode):
   ```
   ssh $NODE 'sudo iptables -I OUTPUT -j REJECT \
     -m comment --comment ir-quarantine-<event.id>'
   ```
   This is destructive to all workloads on the node. SEV-1 only.

### Step 4 — Cordon the node (NOT drain — drain reschedules pods and destroys
                                    evidence)

```
kubectl cordon $NODE
kubectl annotate node $NODE smartrecs.io/ir-cordoned-at="$(date -Iseconds)" \
  smartrecs.io/ir-event-id="<event.id>"
```

Cordon prevents new pods from scheduling on the node. Drain is
explicitly NOT run because:
- It would move the affected pod to another node (lateral attack
  surface increase).
- It would terminate the affected pod (memory state lost; gcore must
  precede this).
- It rolls all other pods on the node, generating churn that masks
  attacker activity in the audit log.

Drain happens later, after evidence capture and a deliberate decision.

## Investigation (target: within 4 h of containment)

### Process lineage

From the forensic capture (`<event.id>-procs.txt`):

1. Identify the host PID of the original container PID 1 (from
   `crictl inspect`).
2. Walk up the PPID chain. Anything outside the container's PID
   namespace is the escape evidence (or the kubelet legitimately
   running probes — distinguish by parent UID).
3. Walk down: enumerate child processes spawned in the 30 min
   preceding the alert and the 5 min after.

### Filesystem changes since pod started

```
# On the forensic copy, not the live node:
sudo find /forensic-mount -newer /forensic-mount/.dockerenv -type f \
  -printf '%T@ %p\n' | sort -n > /forensic/<event.id>-fs-changes.txt
```

Anything not in `/tmp`, `/var/tmp`, `/proc`, `/sys` deserves a closer
look. Compare against the workload's expected writable paths from the
chart.

### Network connections during the incident window

From the forensic conntrack capture + Cilium Hubble flow log query:

```
hubble observe --pod $NS/$POD --since '-2h' --output json \
  > /tmp/<event.id>-hubble.json
```

Cross-reference with VPC flow logs for traffic that left the cluster.

### Audit-chain queries

```
gov-audit-cli query \
  --since '<event.start - 2h>' \
  --until '<now>' \
  --filter 'pod=$POD OR node=$NODE OR (verb=exec AND target_ns=$NS)' \
  > /tmp/<event.id>-audit-full.json
```

Look for:
- `kubectl exec` events on this pod or any pod on this node.
- ServiceAccount-token issuances (the attacker may have leveraged the
  pod's SA to call the API).
- ConfigMap / Secret reads in the same namespace within the window.

### Correlation with other systems

Same window, query:

- **CI / deploy events** (GitHub Actions, ArgoCD) for unexpected
  deployments to this namespace.
- **Access changes** (IAM, OIDC) for newly-issued tokens to this
  workload's SA.
- **Image registry** for image pulls of unfamiliar tags.
- **Module 11 SIEM** correlated alerts for the same time window across
  unrelated systems.

## Eradication

### Root-cause analysis

Determine the entry point. Most-likely-to-least:

1. **Vulnerable application code** — the serving framework or model
   handler accepted a payload that produced RCE. CVE check on the
   image's pip / OS package list.
2. **Compromised dependency** — a transitive pip package in the model
   wheel contained a malicious payload. SBOM diff against last known-
   good image.
3. **Container-runtime vulnerability** — CVE in containerd, runc,
   kernel. Less common with patched nodes; check the node's `uname -r`
   and `containerd --version` against current CVE feed.
4. **Privileged misconfiguration** — a chart change added a capability
   or weakened a security context. Git blame the chart diff for the
   last release.
5. **Insider** — audit chain shows a human invoked the action. Escalate
   to HR/legal per company policy.

### Patch / mitigation

Per root cause:

- Application code: revert to the prior image, deploy with the patched
  framework once available.
- Dependency: pin the safe version in the chart, rebuild image,
  re-scan SBOM in CI.
- Runtime / kernel: drain the node, replace with a patched AMI (do NOT
  re-use the node).
- Misconfiguration: revert the chart change, re-deploy.

Whatever the cause: **add a Falco / behavioural-baseline detection rule
that would catch the same pattern faster next time.** A post-incident
review without new detection coverage means we will rediscover the
same gap during the next incident.

## Recovery

### Node return-to-service

- For SEV-1: **replace the node entirely.** Terminate the instance from
  the cloud console, let the autoscaler bring up a fresh one. The
  compromised node's disk / memory state cannot be trusted.
- For SEV-2/3 where root cause is application-level: after eradication
  and validation, `kubectl uncordon $NODE`. Do NOT remove the audit
  annotation; that becomes part of the node's audit history.

### Workload re-deployment

- Deploy the patched image to a *fresh* namespace
  (`<ns>-recovery-<timestamp>`).
- Route 1% of traffic for 24 h.
- Promote only after the behavioural baseline (Exercise 04) shows the
  new pods within normal envelope for all dimensions.

### Validation

- Re-run the attack pattern (synthetic, in staging) and confirm the new
  Falco rule fires.
- Confirm the patched dependency / chart change passes the security
  gate in CI (SBOM scan, image scan, policy validation).
- Confirm the audit-chain entry for the incident is sealed and
  immutable.

## Communication

| Audience | When | What | Owner |
|---|---|---|---|
| Engineering leadership (Director, VP) | Within 30 min of SEV-1 | Status: confirmed escape; pod, node, blast radius assessment so far. | Security on-call. |
| Internal #incident-response Slack | Continuous from triage onward | Timeline updates every 30 min. | Incident commander. |
| Wider engineering (#eng-broadcast) | After containment is confirmed | Affected namespaces, expected impact, no action needed. | Incident commander. |
| Customer success | Once data exposure assessment is preliminary (within 4 h) | Whether customer data was potentially accessed; talking points; do not promise definitive numbers yet. | Customer Success on-call + Legal. |
| Customers (affected) | Per the worst applicable obligation in scope — e.g., GDPR Article 33's 72 h for personal data; or earlier per contract | Affected dataset, time window, mitigation, what we ask of them. | Customer Success + Legal. |
| Regulators | Per applicable regulation (verify with Legal per data type and jurisdiction) | Same content as customer notification + regulator-specific schema. | Legal + Compliance lead. |
| Post-mortem | Within 5 business days, blameless | Full timeline, root cause, detection gap, prevention plan. | Incident commander + technical lead; invited: on-call rotation + Engineering leadership + (optionally) Customer Success. |

## Post-incident actions

### Runtime-security rule updates

- Author the new Falco / Tetragon rule that would have caught this
  pattern at least 30 min earlier.
- Update Exercise 03's R001–R010 if a category gap is exposed.
- Update Exercise 04's cross-dimension correlations if the
  cross-signal would have flagged the incident.

### Procedure updates

- Update this runbook based on what worked / didn't in real time.
- Update PSS / seccomp / AppArmor profiles if the escape exploited a
  loophole.
- Update the on-call rotation training material with the new scenario.

### Detection-coverage updates

- Update the SIEM correlation rules for related patterns.
- Add a synthetic-attack replay to the staging cluster's nightly drill.

### Customer-facing post-mortem

- Publish a customer-facing summary (no specific customer names, no
  internal architecture beyond what's necessary).
- Include: what happened, what we changed, what to expect from us
  next.

---

# Tabletop Scenario — "Suspected Escape in `recs`"

## Setup (0 min)

Falco rule R009 fires:

```
Container-escape primitive observed
  pod=recs-serving-7c8d9f-xk2vh  ns=recs  syscall=setns
  proc=/tmp/.tmp_x  parent=python3 (uvicorn worker)
```

A behavioural-baseline correlation C3 fires 30 s later (process tree
depth 5 above mode, new outbound destination 198.51.100.42:8443).

PagerDuty pages the security on-call. SRE on-call is co-paged.

On the table:
- The two alert JSON payloads (Falco + C3).
- The pod manifest.
- The node name (`worker-12.us-east-1a`).
- 30 min of audit-chain entries for `recs`.

## Inject events

### +10 min
The SRE on-call says: "I'm going to `kubectl drain worker-12` to be
safe."

*Decision required:* Does the incident commander allow the drain?
(Expected answer: no — gcore the pod first; drain destroys the
in-memory evidence.)

### +30 min
The forensic copy completes. The core dump shows a Python `exec()`
of a payload fetched from `198.51.100.42`. The payload tried `setns`
to escape into the kubelet's PID namespace; Falco's eBPF driver
captured the syscall.

The serving image is `recs/serving:v4.7.2`, deployed two days ago.
SBOM diff shows a transitive `pyrequest_aux` dependency was added at
that release; the package is unrelated to the team's stated needs.

*Decision required:* Containment scope. Is this a single-pod or a
namespace-wide incident? (Expected answer: namespace-wide. Every
pod running `v4.7.2` is at risk because the dependency was baked
into the image. Quarantine the deployment, fall back to v4.7.1.)

### +60 min
A customer-success rep messages the channel: "Customer X is asking
why model latency is 2× normal."

*Decision required:* How much do you tell the customer? (Expected
answer: route the question through the customer-comms playbook; do
not give specifics on an active incident until Legal has reviewed
the disclosure language. Acknowledge degradation, give a holding
ETA.)

## Decision points

1. **Containment vs. observation.** The temptation is to "watch and
   learn" longer before isolating; the runbook says contain at 15 min
   max. The drill measures whether the team holds the line.
2. **Communication.** When does Customer Success learn? When does
   Legal? When does the customer? Each gate has a different SLA.
3. **Escalation.** At what point is the Director of Engineering paged
   vs. given a status update? The drill confirms the escalation rules
   are unambiguous.

## Expected outcomes

A well-run drill produces:
- Forensic snapshot captured before any destructive action.
- Per-pod quarantine within 15 min; namespace-wide rollback within
  60 min.
- Customer communication held until Legal reviewed; no premature
  speculation.
- A new Falco rule drafted within 24 h that would catch the
  `pyrequest_aux` callback pattern.
- A post-mortem scheduled within 5 business days with the right
  participants.

## Common mistakes

- **Drain the node before snapshot** — loses evidence.
- **`kubectl exec` into the affected pod for "a quick look"** —
  fires R006, adds noise, and may execute attacker-supplied scripts
  that activate on shell entry.
- **Delete the pod and restart it** — loses the in-memory state;
  attacker rotates to a different pod on the same node anyway.
- **Quiet the alerts** to "let everyone focus" — the alert stream
  is the evidence stream; silencing it loses ground truth.
- **Skip the per-pod NetworkPolicy** and go straight to a node-wide
  egress block — kills every other tenant's workload on the node.
- **Send a customer notification before Legal review** — exposes
  the company to additional risk that the legal review is supposed
  to manage.
- **Restart the same node** after eradication — disk + memory state
  cannot be cleansed in place; replace the node.
- **Skip the post-incident detection rule** — the next incident
  rediscovers the same gap.
- **Single-person incident command** — there is no second pair of
  eyes on the decisions made under pressure. Pair the IC with a
  scribe + a second senior on-call from minute zero.
```

## 3. Validation steps

1. **Runbook lint.** Every step has a concrete command or named tool;
   none say "investigate," "look around," or "do appropriate analysis."
   A peer reviewer reads through and flags any step that requires
   improvisation under pressure.
2. **Walk-through drill (45 min).** Two engineers read the runbook
   aloud as a script. Stop at every step that's ambiguous or where
   the expected output isn't named; fix in place.
3. **Tabletop drill (90 min).** Run the §3 scenario with the actual
   on-call rotation. Track:
   - Time-to-evidence-capture (target: ≤ 5 min from alert).
   - Time-to-containment (target: ≤ 15 min).
   - Number of "ad hoc" decisions made (target: ≤ 2 — anything more is
     a runbook gap).
4. **Synthetic-attack drill in staging.** Plant a binary that calls
   `setns` in a staging serving pod; confirm Falco R009 fires, the
   alert reaches the right pager, and the on-call can execute steps
   1–3 of containment within the 15-min window. Run quarterly.
5. **Communication-channel test.** Send a synthetic SEV-1 to PagerDuty
   monthly to verify the routing still works.
6. **Forensic-storage test.** Quarterly, write a test artifact to the
   forensic bucket; verify retention policy still prevents deletion
   without dual sign-off; verify access path from a fresh on-call
   workstation.

## 4. Rubric / review checklist

- [ ] **Detection sources** enumerate at least four (Falco rule,
      Tetragon, behavioural baseline, host audit, external report).
- [ ] **Each detection source** has a "first 5 minutes" section that
      collects evidence BEFORE destructive action.
- [ ] **Containment is time-bounded** (15 min target) with explicit
      commands.
- [ ] **Evidence preservation precedes** any destructive containment
      action (gcore before drain, snapshot before delete).
- [ ] **The runbook explicitly forbids drain** in favour of cordon.
- [ ] **Per-pod NetworkPolicy** is preferred to node-wide egress
      blocks where possible.
- [ ] **Investigation phase** names specific tools (Hubble, auditd,
      conntrack, SBOM diff, gov-audit-cli) and concrete queries.
- [ ] **Root cause** enumerates ≥ 4 plausible categories with how to
      check each.
- [ ] **Recovery** replaces the node entirely for SEV-1; does not
      reuse compromised hardware/AMI state.
- [ ] **Communication matrix** lists audience, timing, content, owner
      for at least internal, customer, regulatory, post-mortem.
- [ ] **Tabletop** has setup, three injects, three decision points,
      expected outcomes, common mistakes — all runnable in one hour.
- [ ] **Post-incident actions** include a new detection rule (not
      just procedure updates).

## 5. Common mistakes

- **"Investigate, then contain."** The runbook reads well; in real
  time, "investigate" expands without bound. The drill measures the
  budget; the runbook enforces it.
- **Drain before snapshot.** Most common destructive shortcut. The
  pod's in-memory state is the highest-fidelity forensic artefact;
  drain reschedules and kills it.
- **No customer-communication plan.** The 72-h GDPR Article 33 clock
  starts at "becoming aware" of a personal-data breach; ambiguity
  about who notifies whom when wastes the limited window. (Verify the
  specific deadline that applies to your jurisdictions and customer
  contracts.)
- **Tabletop that's narrative, not actionable.** "Imagine you see an
  alert" produces lecture-style discussions, not muscle memory. The
  injects must require decisions with the runbook in hand.
- **One-person incident command.** Decisions made under pressure with
  no peer review degrade quickly. Pair IC with a scribe and a second
  senior on-call from minute zero.
- **Restoring the affected node** to service after "patching the
  vulnerability." A compromised node's disk and memory are
  untrustworthy. Replace, don't repair.
- **No new detection coverage post-incident.** The same pattern
  recurs. Every post-mortem must produce at least one new rule (Falco
  or behavioural correlation) that closes the time-to-detect gap.
- **Forensic artefacts deletable by the incident response team.** The
  team that's under pressure to "clean up" is the same team that
  shouldn't have unilateral delete authority. Require dual sign-off.
- **Skipping the per-pod NetworkPolicy step** and going straight to
  node-wide isolation. Wipes out every other tenant on the node;
  produces a customer-impact incident on top of the security
  incident.

## 6. References

- Falco — alert source for escape primitives (rule R009 in Exercise
  03).
  <https://falco.org/docs/>
- Tetragon — kernel-level enforcement of escape primitives via
  TracingPolicy CRs.
  <https://tetragon.io/docs/>
- Cilium Hubble — flow logs for the network-connection investigation
  step.
  <https://docs.cilium.io/en/stable/observability/hubble/>
- NIST SP 800-61r2 — *Computer Security Incident Handling Guide*
  (preparation, detection, containment, eradication, recovery, post-
  incident phases used here).
  <https://csrc.nist.gov/pubs/sp/800/61/r2/final>
- NIST SP 800-190 — runtime threat model for the container-escape
  class.
  <https://csrc.nist.gov/pubs/sp/800/190/final>
- NSA / CISA Kubernetes Hardening Guide v1.2 — escape-class
  controls (PSS, seccomp, AppArmor, runtime detection).
  <https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF>
- MITRE ATT&CK for Containers — T1611 (Escape to Host); T1059
  (Command and Scripting); T1567 (Exfiltration over Web Service).
  <https://attack.mitre.org/matrices/enterprise/containers/>
- MITRE ATLAS — adversary tactics matrix for ML platforms; covers
  the model-integrity and exfiltration tactics that frame this
  runbook's ML-specific framing.
  <https://atlas.mitre.org/>
- NIST AI Risk Management Framework — MANAGE function (incident
  response and recovery for AI systems).
  <https://www.nist.gov/itl/ai-risk-management-framework>
- GDPR Article 33 — 72-hour personal-data breach notification deadline
  (used as the worst-case timing benchmark in §Communication).
  <https://gdpr-info.eu/art-33-gdpr/>
- Module 08 lecture notes §1 (threat model), §9 (container escape),
  §10 (operating runtime security at scale).
- Module 11 (Security Operations) — SIEM integration and broader IR
  playbook this runbook plugs into.
