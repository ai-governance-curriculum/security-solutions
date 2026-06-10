# SOLUTION — Exercise 04: Rate-Limit and DDoS Design

> Reference solution for `mod-004-network-security` exercise 04. The
> deliverable is a layered rate-limiting and DDoS-protection design
> for an AI inference platform, with budgets, enforcement points, and
> failure modes called out.

## 1. Solution overview

Inference platforms have two properties that make rate limiting
non-trivial:

1. **Cost per request is high and variable.** A single LLM request
   can hold a GPU for seconds; a single tabular prediction takes
   microseconds. A flat per-second cap is wrong in both directions.
2. **Anonymous and authenticated traffic mix.** Public model demos,
   signed-up users, and platform services all share the gateway. The
   same limit on all three is unusable.

A correct design has **three enforcement layers**:

- **L3/L4 at the cloud edge** — volumetric, SYN/UDP floods, AS-block
  reputation, geo-block if applicable. Handled by the cloud LB / WAF
  / DDoS service.
- **L7 at the gateway** — per-route, per-identity, per-IP, per-tenant
  token-bucket limits with body and concurrency caps.
- **Per-workload at the upstream** — concurrency limit, queue depth,
  and admission control specific to that model's capacity (especially
  for LLMs / large batch jobs).

Each layer fails independently. A single layer doing all the work is
the single point of failure.

The output is a design document with named budgets, enforcement
points, observability hooks, and explicit failure-mode behaviour.

## 2. Worked implementation

### 2.1 Traffic taxonomy

The design starts by naming the traffic classes. Each class gets its
own bucket; rates are not interchangeable.

| Class | Identity | Typical RPS | Cost class |
|---|---|---|---|
| Anonymous demo | none | low | shed first |
| Free tier | JWT, `tier=free` | low | shed second |
| Paid tier | JWT, `tier=paid` | medium | preserve |
| Internal service | mTLS SPIFFE id | high | preserve |
| Platform admin | JWT, group=`platform-admin` | very low | never shed |
| Health probes | LB / kube source range | constant | never shed |

"Cost class" defines what gets shed first under pressure. The number
of classes can grow but the *ordering* must be unambiguous.

### 2.2 L3/L4 edge controls

Owned by the cloud provider's LB/DDoS layer. The platform's job is
to **configure** these, not invent them.

- SYN flood protection enabled, with the LB's default thresholds
  documented and recorded in the runbook.
- UDP allowed only for the protocols that need it (QUIC for the demo
  endpoint, none elsewhere).
- Geo-blocking only if the product genuinely has a regional scope
  AND legal/compliance reasons. Otherwise the false-positive cost is
  high.
- AS-reputation / known-botnet block lists from the provider, on,
  with the on/off switch documented as an incident-response lever.
- Connection count and new-connection-rate caps per source IP at the
  LB.

The exercise output **must include** the LB control plane (Terraform
/ Pulumi snippet) for these — not just "we turn it on".

```hcl
# Example AWS WAF rate-based rule (cloud-specific)
resource "aws_wafv2_web_acl" "edge" {
  name        = "edge"
  scope       = "REGIONAL"
  default_action { allow {} }

  rule {
    name     = "per-ip-rate"
    priority = 10
    action { block {} }
    statement {
      rate_based_statement {
        limit              = 2000          # requests / 5min / IP
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "edge-per-ip"
    }
  }
}
```

The 5-minute window above is the documented AWS WAF rate-based-rule
default; confirm the equivalent window and minimum limit for other
providers' WAFs before reusing the same number.

### 2.3 L7 token buckets at the gateway

The gateway runs a per-bucket token-bucket limiter, sourced from a
small set of dimensions. Each dimension is independent — a request
must pass *all* its applicable buckets.

| Bucket key | Window | Default budget | Action when exceeded |
|---|---|---|---|
| `route + ip` | 1 s | 20 | 429, no retry-after on anon |
| `route + ip` | 60 s | 600 | 429, `Retry-After: 30` |
| `route + tenant_id` | 1 s | from plan | 429 + `X-RateLimit-Reset` |
| `route + jwt.sub` | 60 s | from plan | 429 + `X-RateLimit-Reset` |
| `route + concurrency` | n/a | varies | 503 with `Retry-After: 1` |

Implementation is a global rate-limit service (Envoy ratelimit
service backed by Redis, or the cloud provider's equivalent). The
gateway communicates rate-limit descriptors per request:

```yaml
# Envoy route-level rate-limit descriptors
rate_limits:
  - actions:
      - request_headers:
          header_name: ":path"
          descriptor_key: route
      - remote_address: {}
  - actions:
      - request_headers:
          header_name: ":path"
          descriptor_key: route
      - metadata:
          descriptor_key: tenant
          metadata_key:
            key: envoy.filters.http.jwt_authn
            path:
              - key: jwt_payload
              - key: tenant
```

```yaml
# ratelimit service descriptors (Envoy ratelimit format)
domain: edge
descriptors:
  - key: route
    value: /v1/predict
    descriptors:
      - key: remote_address
        rate_limit: { unit: second, requests_per_unit: 20 }
      - key: tenant
        value: tier-paid
        rate_limit: { unit: second, requests_per_unit: 200 }
      - key: tenant
        value: tier-free
        rate_limit: { unit: second, requests_per_unit: 5 }
```

### 2.4 Concurrency, queue, and body limits

Rate (RPS) is not a sufficient control for inference. Concurrency
matters more because slow requests consume GPU minutes.

- Envoy `local_rate_limit` + `concurrency_limiter` on the
  inference route, capped to *N × inference replica count*, where N
  matches the model's documented concurrent request budget.
- Connection idle timeout (`stream_idle_timeout: 60s`) shed slow
  clients without a hard request timeout that breaks legitimate
  long-LLM responses.
- Body-size cap per route (from exercise 03) — the cheapest possible
  DoS is a 100-MB JSON request.
- Upstream queue depth bounded; reject (503) rather than queue
  forever. Queueing without a bound is a latency amplifier under
  load.

### 2.5 Per-workload admission control (inference server)

The gateway can shape arrivals, but the model server must also
self-protect:

- **Concurrency semaphore** with a hard upper bound (`min(GPU_BATCH,
  CONFIGURED_MAX)`).
- **Token-budget-aware rejection for LLMs.** A request whose input
  exceeds the remaining token budget for the window is rejected at
  the model server, not at the gateway. The gateway cannot count
  tokens. Confirm the inference framework's exposed knob for this
  (vLLM, TGI, Triton) in its own documentation when wiring it up.
- **503 with `Retry-After`** rather than 500, so callers know it is a
  capacity signal, not a defect.

### 2.6 Failure modes

| Component fails | Behaviour |
|---|---|
| Global rate-limit service unreachable | Gateway "fail open" on default bucket, "fail closed" on identity buckets. The choice is explicit: never let the limiter outage become a per-tenant escalation, but never let it become a full outage. Document which buckets fail which way. |
| Redis backing the limiter slow | Gateway timeout on rate-limit call is short (50 ms); on timeout, gateway treats as fail-open with a metric increment. Bounded blast radius. |
| Identity provider unreachable | JWTs can't be validated → 401, **not** rate-limit error. Don't conflate identity outage with capacity. |
| WAF off | Detection rule (exercise 05) alerts. Manual page. Treat as Sev-2. |

### 2.7 Headers returned to callers

Make the limiter machine-readable so well-behaved callers back off:

- `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`
  on every response from a limited route.
- `Retry-After: <seconds>` on 429.
- Never echo back the bucket name or the tenant identifier.

### 2.8 Observability hooks for exercise 05

Every layer must emit the data needed by detection:

- Edge: source IP, AS, action (allow/block), rule name.
- Gateway: bucket key, descriptor values, action, route, status.
- Upstream: concurrency utilisation, queue depth, rejection counter.

These are the inputs to "DDoS in progress" and "tenant gone rogue"
detections.

## 3. Validation steps

### 3.1 Functional checks

```bash
# Per-IP 1-second budget — 20 RPS allowed, 21st must 429
for i in $(seq 1 25); do
  curl -s -o /dev/null -w '%{http_code}\n' \
    -H "Authorization: Bearer ${TOKEN_FREE}" \
    https://edge.example.com/v1/predict &
done | sort | uniq -c
# Expect: 20×200, 5×429

# Per-tenant budget — paid tier higher than free
ab -n 1000 -c 20 -H "Authorization: Bearer ${TOKEN_PAID}" \
  https://edge.example.com/v1/predict
# Expect: 429 ratio below the free-tier baseline at equivalent load
```

### 3.2 Failure-mode checks (game day)

1. Stop the Redis backing the limiter; confirm gateway emits
   `ratelimit_error` metric, anonymous traffic still flows, paid-tier
   continues subject to local-rate-limit fallback.
2. Stop the identity provider; confirm 401s, no 429 storm, no 500s
   from the limiter.
3. Simulate a per-IP burst (`hey -z 30s -c 200`); confirm WAF
   blocks before the gateway saturates.

### 3.3 Headers and signalling

```bash
curl -sI -H "Authorization: Bearer ${TOKEN_FREE}" \
  https://edge.example.com/v1/predict \
  | grep -i 'x-ratelimit\|retry-after'
```

Confirm fields are present, monotone (Remaining decreases per
request), and reset to Limit at the window boundary.

## 4. Rubric / review checklist

| # | Criterion | 0 | 1 | 2 |
|---|---|---|---|---|
| 1 | Three independent enforcement layers (L3/4, L7, upstream) | One layer | Two | Three |
| 2 | Traffic taxonomy + cost ordering | None | Listed without ordering | Ordered with shed policy |
| 3 | Per-route budgets, not global only | Global only | Mixed | Per-route + per-tenant + per-IP |
| 4 | Concurrency limit, not just RPS | RPS only | Concurrency added globally | Per-model concurrency tied to capacity |
| 5 | Failure-mode behaviour documented per component | None | Vague | Per-component with chosen fail-open/closed |
| 6 | 429 includes `Retry-After` and `X-RateLimit-*` | Bare 429 | Some headers | All listed headers |
| 7 | Cloud LB / WAF configured (not just "turned on") | Not configured | Console click-ops | IaC artifact |
| 8 | Observability hooks at every layer feed detection | None | Edge only | All layers |
| 9 | Game-day validation executed | Not done | Functional only | Functional + failure modes |
| 10 | LLM-specific concerns addressed (concurrency, token budget) if applicable | Ignored | Mentioned | Implemented at upstream |

Pass = ≥16 / 20 with no zero scores.

## 5. Common mistakes

- **Global RPS only.** A single 1000 RPS gateway cap protects nothing
  on a route that costs a GPU-second per request; one tenant exhausts
  the budget before the limit triggers.
- **No identity in the bucket key.** Without a per-tenant key, paid
  tenants are starved by anonymous bursts.
- **Fail-closed on the rate limiter for everything.** Turns a limiter
  outage into an availability event. Pick fail-open for default
  buckets, fail-closed only for high-cost identity-keyed buckets, and
  *document* the choice.
- **Queueing without a depth bound.** Latency goes to the moon under
  light overload; the system looks degraded, then dies.
- **Counting wrong.** Per-IP counting where every request comes from
  a single corporate NAT. Per-IP needs to be combined with a second
  key (route, identity) to be useful.
- **No `Retry-After`.** Callers retry hot; the limit becomes
  amplification.
- **Rate-limiting health probes.** The LB hides healthy nodes; the
  cluster oscillates.
- **One layer doing all the work.** WAF off → full DoS; gateway off
  → unbounded GPU spend; upstream off → starved fairness across
  tenants.
- **Hand-rolled in-memory limiters per gateway replica.** Effective
  budget = configured budget × replica count, which nobody computes
  correctly.

## 6. References

- Envoy — Global rate limiting:
  https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/other_features/global_rate_limiting
- Envoy — Local rate limiting:
  https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/local_rate_limit_filter
- Envoy ratelimit service (descriptors / domains):
  https://github.com/envoyproxy/ratelimit
- IETF RFC 6585 — HTTP 429 Too Many Requests:
  https://www.rfc-editor.org/info/rfc6585/
- IETF RFC-Editor draft on RateLimit headers (track per-IETF docs as
  the standard evolves): https://www.rfc-editor.org/info/rfc9568/
  (verify the current status of the RateLimit header draft against the
  IETF datatracker at adoption time).
- Kubernetes — Service load-balancer source ranges (for trusting LB
  CIDR): https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer-source-ranges
- OWASP API Security Top 10 — Unrestricted Resource Consumption:
  https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- OWASP Machine Learning Security Top 10:
  https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS — denial-of-ML-service techniques:
  https://atlas.mitre.org/
- NIST AI RMF (Manage function — availability and resilience
  controls): https://www.nist.gov/itl/ai-risk-management-framework
