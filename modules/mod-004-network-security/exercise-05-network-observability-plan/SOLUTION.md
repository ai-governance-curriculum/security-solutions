# SOLUTION — Exercise 05: Network Observability Plan

> Reference solution for `mod-004-network-security` exercise 05. The
> deliverable is a network-observability plan for the AI platform —
> what telemetry, from where, joined how, alerting on what, with the
> security and operational tradeoffs surfaced.

## 1. Solution overview

Network observability is the substrate for every detection and every
incident-response workflow on the platform. The plan must answer five
questions explicitly:

1. **What is the source of truth for "who talked to whom at L4"?**
   (CNI flow logs — Hubble / Calico flowlogs / Antrea flow exporter.)
2. **What is the source of truth for L7 (request, identity, status)?**
   (Gateway access logs + service-mesh logs.)
3. **How are flows joined to identity?**
   (Pod labels, ServiceAccount, JWT subject, SPIFFE ID — *recorded
   at the producing component*, not reconstructed downstream.)
4. **What retention is required, and where?**
   (Hot store for ~14 days for triage, cold/object store for ≥90
   days for incident review and audit. Confirm the organisation-
   specific retention floor under any SOC 2 / HIPAA / GDPR scope that
   applies before finalising the numbers.)
5. **Which detections is this telemetry actually backing, and how is
   each one tested?**

The plan is *design-based*; the artifact is a written plan plus a
small set of representative detection rules with regression tests.

## 2. Worked implementation

### 2.1 Layered telemetry sources

| Layer | Source | Captures | Cardinality concern |
|---|---|---|---|
| L3/L4 in-cluster flows | CNI flow exporter (Hubble / Calico / Antrea) | src/dst pod identity, ports, verdict (forwarded/dropped), policy decision | High under churn — sample + aggregate |
| L7 gateway requests | Edge gateway access log (Envoy/NGINX) | method, path, status, identity, tls, latency, request-id | High — already structured |
| L7 mesh service-to-service | Sidecar access logs (if mesh present) | identity-to-identity per request | High — sample or aggregate |
| DNS | CoreDNS log + node DNS (egress) | QNAME, qtype, response code | Very high — aggregate to top-N + anomalies |
| Egress (cluster→external) | Cloud VPC flow logs + egress gateway | src pod (mapped), dst, bytes | Useful for exfil detection |
| Cloud LB / WAF | Provider access + block logs | Allowed/blocked, rule hits | Pair with §2.4 detections |

### 2.2 Schema (canonical fields)

Every record, regardless of source, must populate the canonical
fields below before it reaches the analytics store. Records that
cannot populate `principal` or `route` are still useful but must be
labelled so dashboards do not silently undercount.

| Field | Type | Notes |
|---|---|---|
| `ts` | RFC 3339 | Ingest timestamp + originating timestamp; keep both. |
| `cluster` | string | Multi-cluster awareness. |
| `namespace` | string | Source pod namespace. |
| `workload` | string | Source workload (Deployment/StatefulSet name). |
| `principal` | string | SPIFFE ID, ServiceAccount, or JWT sub. |
| `dst_namespace` | string | If in-cluster. |
| `dst_workload` | string | If resolvable. |
| `dst_external` | string | FQDN or CIDR if external. |
| `protocol` | enum | tcp/udp/http/grpc/dns. |
| `route` | string | L7 only — gateway path. |
| `status` | string | HTTP/gRPC status, or verdict (forwarded/dropped). |
| `bytes_in` / `bytes_out` | int | Required for exfil detection. |
| `request_id` | string | Same ID across gateway + mesh + access log. |
| `tls_version`, `tls_cipher` | string | Where applicable. |
| `source` | enum | hubble / envoy / mesh / vpc / waf — never confuse sources. |

### 2.3 Pipeline

```
                ┌───────────────────────┐
 in-cluster ───►│ CNI flow exporter     │──┐
                └───────────────────────┘  │
                ┌───────────────────────┐  │
   gateway   ───►│ Envoy access log     │──┤
                └───────────────────────┘  ├──► OTel Collector
                ┌───────────────────────┐  │    (transform → canonical schema)
   mesh      ───►│ sidecar access log   │──┤        │
                └───────────────────────┘  │        ▼
                ┌───────────────────────┐  │   ┌──────────┐   ┌───────────┐
   DNS       ───►│ CoreDNS log          │──┘   │ hot store │──►│ detection │
                └───────────────────────┘      └──────────┘   └───────────┘
                ┌───────────────────────┐            │
   cloud     ───►│ VPC flow / WAF log   │────────────┘
                └───────────────────────┘            ▼
                                              ┌──────────────┐
                                              │ cold store   │
                                              │ (object,     │
                                              │  immutable)  │
                                              └──────────────┘
```

OpenTelemetry Collector handles the transform to canonical schema so
each source's idiosyncrasies do not leak into the analytics store.

### 2.4 Detection set (illustrative)

The five detections below are the minimum bar. Each is paired with a
regression test that **must** pass before the rule is enabled (the
project-5 SOC reference contains the test harness).

**D-1. Default-deny violation.** A flow with verdict `forwarded`
that does not match any known allow-policy identity pair → alert. A
regression test injects an unmatched flow and confirms the rule
fires; a permitted flow does not.

**D-2. Egress to unexpected external destination.** Per workload, an
allow-list of expected external endpoints (registry, object store,
telemetry). A flow to anything else, with bytes_out above N → alert.
Maps to MITRE ATLAS exfiltration-style techniques.

**D-3. Sudden DNS QNAME diversity.** Per workload, a spike in unique
QNAMEs in a 5-minute window above the 30-day p99 baseline. Detects
DGA-style behaviour or generic data exfiltration via DNS.

**D-4. Gateway authn failure burst.** 401s per identity, per route,
above threshold in a window. Maps to credential-stuffing / token
exhaustion attempts.

**D-5. Cross-tenant flow.** A flow whose src workload has tenant
label `T_a` and dst workload tenant label `T_b` → alert. A
regression test stages a legitimate same-tenant flow and a forbidden
cross-tenant flow, asserts only the latter fires.

Each detection has:

- a written **owner** (which team triages),
- a **runbook** (project-5 reference structure),
- a **suppression contract** (named, time-bounded suppression for
  known maintenance windows; suppressions expire automatically),
- a **regression test** in CI.

### 2.5 Dashboards (Grafana / equivalent)

Three dashboards, ranked by frequency of use:

1. **Edge & gateway** — RPS, 4xx/5xx ratios, top routes, top
   identities, top IPs, rate-limit fires. The on-call's first
   landing page.
2. **East-west flows by identity** — heatmap of source identity ×
   destination identity over time. Default-deny violations stand out
   as red cells outside the matrix.
3. **Egress** — per-workload bytes_out by destination, with the
   allow-list overlaid. Anomalies are visible against the baseline.

Dashboards are version-controlled (JSON or Grafana provisioning) and
reviewed alongside detection rules.

### 2.6 Retention and access

| Tier | Where | Retention | Access |
|---|---|---|---|
| Hot, queryable | Search engine / column store | 14 days | Engineering on-call, SOC analyst |
| Cold, immutable | Object store with object lock | ≥90 days (confirm against the regulated workloads in scope) | SOC analyst; legal hold on request |
| Audit trail (who queried) | Append-only log | ≥1 year (align with the SIEM compliance baseline) | Compliance + privacy |

The cold store is **immutable**: object lock (legal hold + retention
period), separate cloud account, distinct IAM. The same engineer
that can read it cannot delete it.

### 2.7 Privacy and least-disclosure

- **Headers like `Authorization` are never logged in clear.** The
  gateway logs the derived `jwt.sub` and `jwt.aud` after validation,
  not the raw token.
- **Request bodies are not captured at the gateway by default.**
  Bodies for inference can contain customer data; capture is opt-in,
  per-route, with a retention floor that is shorter than the default
  hot tier.
- **PII fields detected in URLs (emails, tokens) are scrubbed at
  ingest.** The OTel transform owns this; the scrub list is reviewed
  by privacy and aligned with the organisation's data-classification
  policy before each release.

### 2.8 Health of the observability pipeline itself

The observability pipeline is in the threat model. Required signals:

- "No CNI flow logs for ≥N minutes from cluster X" — paged.
- "OTel collector dropping records" — paged.
- "Cold-store write failure" — paged with a 4-hour SLO, since hot
  tier is still ingesting.
- The detection rules themselves emit a "ran with N inputs" metric.
  A rule that suddenly evaluates zero inputs is silently broken.

## 3. Validation steps

The deliverable is a plan; validation is a tabletop plus a
proof-of-life test that each named data source actually arrives in
the analytics store and each detection fires on a known input.

### 3.1 Telemetry presence

For every data source in §2.1, the plan author runs a check that the
last-N-minutes' record count is non-zero **per cluster, per
namespace**. A zero count on a known-busy namespace is the most
common silent failure mode.

### 3.2 Synthetic detection inputs

For each detection D-1..D-5:

1. Author writes the simulated input as a unit/integration test.
2. The test is run end-to-end through ingest, transform, and rule
   evaluation in a staging environment.
3. The rule fires; the alert reaches the configured channel; the
   runbook URL resolves.
4. A negative case (no fire) is also tested to catch over-firing.

### 3.3 Privacy review checklist

A reviewer opens a sample of records (≥100) and confirms:

- No `Authorization` header value present.
- No request body recorded outside the opt-in routes.
- PII patterns scrubbed (regex against the scrub list).

### 3.4 Tabletop

A tabletop walks two scenarios end to end:

- **Exfil from a compromised training pod.** Does the egress
  telemetry surface it? Are the bytes attributable to a workload?
- **Cross-tenant lateral movement.** Does the east-west dashboard
  show it? Does D-5 fire?

For each scenario the artifact is a short post-tabletop write-up of
what was visible, what was not, and the follow-up backlog.

## 4. Rubric / review checklist

| # | Criterion | 0 | 1 | 2 |
|---|---|---|---|---|
| 1 | All seven canonical schema fields named and sourced | Missing | Some | All |
| 2 | Sources include CNI flow + gateway + DNS + cloud (minimum) | Subset | Most | All |
| 3 | Identity is attached at the producer, not reconstructed | Reconstructed | Mixed | Producer-attached |
| 4 | At least five detections, each with a regression test | <3 | 3–4 with tests | ≥5 with tests |
| 5 | Retention split into hot / cold / audit with rationale | None | Hot only | All three with rationale |
| 6 | Privacy controls explicit (headers, body, PII scrub) | Ignored | Mentioned | Implemented in transform |
| 7 | Observability-of-observability signals listed | Missing | Mentioned | Per-component + paging contract |
| 8 | Dashboards version-controlled | Ad hoc | Some VCS | All in VCS + review process |
| 9 | Tabletop scenarios executed and reported | Not done | One scenario | Two+ with backlog |
| 10 | Mapping to OWASP ML / MITRE ATLAS / NIST AI RMF | Missing | Mentioned | Per-detection mapping |

Pass = ≥16 / 20 with no zero scores.

## 5. Common mistakes

- **Reconstructing identity downstream.** Joining IP→pod in the
  analytics store is racy; the IP may have been recycled by the
  time the join runs. Identity must be stamped at the producer.
- **No producer for east-west flows.** Without a CNI flow exporter,
  lateral movement is invisible.
- **Logging tokens.** `Authorization` headers leak into archives,
  long-lived even after rotation. Never log them.
- **Body capture by default.** Inference bodies contain user data;
  default-on body capture is a privacy and storage problem.
- **No regression test for detections.** Rules silently break when
  schemas change; a rule with no test is effectively decoration.
- **Detection-only, no runbook.** A page that fires with no runbook
  becomes background noise within a quarter.
- **Mutable cold tier.** Object store without object lock = retention
  is whatever the most recent compromised IAM grant says.
- **Pipeline blind to its own failure.** No "this rule evaluated zero
  inputs" check — the most common silent-failure shape.

## 6. References

- Kubernetes — Audit logging:
  https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
- Kubernetes — DNS for Services and Pods (CoreDNS source-of-truth):
  https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/
- Cilium Hubble — flow observability:
  https://docs.cilium.io/en/stable/overview/intro/#hubble
- Calico flow logs:
  https://docs.tigera.io/calico/latest/observability/
- Antrea flow exporter:
  https://antrea.io/docs/main/docs/network-flow-visibility/
- OpenTelemetry Collector:
  https://opentelemetry.io/docs/collector/
- Envoy access logging:
  https://www.envoyproxy.io/docs/envoy/latest/configuration/observability/access_log/usage
- OWASP Machine Learning Security Top 10:
  https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS — case studies and tactics for ML systems:
  https://atlas.mitre.org/
- NIST AI Risk Management Framework (Measure function — monitoring
  is the implementation):
  https://www.nist.gov/itl/ai-risk-management-framework
