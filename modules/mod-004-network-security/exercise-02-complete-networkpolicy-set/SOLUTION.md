# SOLUTION — Exercise 02: Complete NetworkPolicy Set

> Reference solution for `mod-004-network-security` exercise 02. The
> deliverable is a complete, applicable NetworkPolicy set for a
> representative AI inference and training cluster, with a worked
> rationale and acceptance tests.

## 1. Solution overview

The exercise asks for a **complete** NetworkPolicy set for a typical
ML cluster. "Complete" here means three properties simultaneously:

1. **Default-deny on both ingress and egress** in every workload
   namespace. Anything that should be reachable or able to reach out
   is an explicit allow.
2. **Per-tier allows**: ingress (gateway) → inference → feature store
   → model registry → control-plane services, with no other path open.
3. **System-traffic carve-outs**: DNS, metrics scrape, and the API
   server, all minimised and explicit.

A namespace without an egress allow for DNS is effectively offline.
A namespace without an egress allow for the metric scraper drops out
of observability. These two are the most common omissions in
learner-submitted policy sets.

The solution is implementation-grade YAML targeting the upstream
`networking.k8s.io/v1` NetworkPolicy API, so it works on any CNI that
implements that API (see exercise 01).

## 2. Worked implementation

### 2.1 Cluster model assumed

Namespaces in scope:

| Namespace | Role |
|---|---|
| `ingress` | Edge gateway (Envoy / NGINX) — receives traffic from outside the cluster. |
| `ml-inference` | Online model servers (gRPC/HTTP). |
| `ml-training` | Batch training jobs (Job/Argo Workflow pods). |
| `feature-store` | Read-path feature lookup service. |
| `model-registry` | Read-mostly model artifact store. |
| `kube-system` | DNS (`kube-dns` / CoreDNS), CNI agent, kube-proxy. |
| `monitoring` | Prometheus scrapers, OpenTelemetry collector. |

External egress targets used by ML workloads:

- Object storage for model artifacts and datasets (CIDR-stable inside
  the VPC; FQDN otherwise — note FQDN egress is CNI-specific and
  *not* part of stock NetworkPolicy v1).
- Container registry (pulls handled by kubelet, not by the pod).
- Telemetry sink (OTLP collector inside the cluster only).

### 2.2 Default-deny baseline (apply to every workload namespace)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: ml-inference
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

Apply this — varying only the `namespace:` — to every workload
namespace: `ml-inference`, `ml-training`, `feature-store`,
`model-registry`, `ingress`. Do **not** apply default-deny to
`kube-system` or `monitoring`; those are managed separately.

### 2.3 DNS egress carve-out (apply to every workload namespace)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-dns
  namespace: ml-inference
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

Without this, no pod can resolve the cluster DNS service and the
default-deny renders the namespace silently broken.

### 2.4 Metrics scrape carve-out (apply to every workload namespace)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-metrics-scrape
  namespace: ml-inference
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: model-server
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
          podSelector:
            matchLabels:
              app.kubernetes.io/name: prometheus
      ports:
        - protocol: TCP
          port: 9090
```

Adapt `podSelector` and `port` per workload. The point is that the
scrape source is named explicitly; "anything in `monitoring`" is too
broad if other tenants share that namespace.

### 2.5 Ingress gateway → inference

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-from-gateway
  namespace: ml-inference
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: model-server
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress
          podSelector:
            matchLabels:
              app.kubernetes.io/name: edge-gateway
      ports:
        - protocol: TCP
          port: 8080
```

### 2.6 Inference → feature store

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-to-feature-store
  namespace: ml-inference
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: model-server
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: feature-store
          podSelector:
            matchLabels:
              app.kubernetes.io/component: read-api
      ports:
        - protocol: TCP
          port: 8081
```

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-from-inference
  namespace: feature-store
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: read-api
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ml-inference
          podSelector:
            matchLabels:
              app.kubernetes.io/component: model-server
      ports:
        - protocol: TCP
          port: 8081
```

Note the **symmetric** pair: egress on the calling side, ingress on
the called side. A policy that only specifies egress will silently
fail if the callee's default-deny ingress is in place.

### 2.7 Inference → model registry (read-only)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-to-model-registry
  namespace: ml-inference
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: model-server
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: model-registry
          podSelector:
            matchLabels:
              app.kubernetes.io/component: artifact-api
      ports:
        - protocol: TCP
          port: 8082
```

The inference workloads need read-only registry access at startup
(model load). Training workloads need write access; they go in the
training namespace's policy below.

### 2.8 Training → registry (write) and external object storage

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-training-writes
  namespace: ml-training
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: trainer
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: model-registry
          podSelector:
            matchLabels:
              app.kubernetes.io/component: artifact-api
      ports:
        - protocol: TCP
          port: 8082
    - to:
        - ipBlock:
            cidr: 10.50.0.0/16   # VPC CIDR for the artifact bucket endpoint
            except:
              - 10.50.200.0/24   # cluster-internal pods reuse this CIDR — exclude
      ports:
        - protocol: TCP
          port: 443
```

Object-storage egress is expressed as a CIDR. FQDN/SNI-based egress
requires a CNI that supports it (Cilium L7) or an egress gateway.

### 2.9 Inference egress to OTLP collector (telemetry)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-to-otel-collector
  namespace: ml-inference
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: model-server
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
          podSelector:
            matchLabels:
              app.kubernetes.io/name: otel-collector
      ports:
        - protocol: TCP
          port: 4317
```

### 2.10 Cross-namespace deny is *implicit*

Once every workload namespace has default-deny in §2.2, no cross-namespace
traffic is allowed unless an explicit ingress *and* egress allow exist.
The temptation to add explicit `deny` policies should be resisted —
NetworkPolicy is allow-only; "deny" is the absence of a matching allow.

### 2.11 Bill of materials

The complete policy set (per namespace) totals:

| Namespace | Policies required |
|---|---|
| `ml-inference` | default-deny, dns-egress, metrics-ingress, gateway→inference ingress, inference→feature-store egress, inference→registry egress, inference→otlp egress |
| `ml-training` | default-deny, dns-egress, metrics-ingress, training→registry egress, training→object-store egress |
| `feature-store` | default-deny, dns-egress, metrics-ingress, inference→feature-store ingress |
| `model-registry` | default-deny, dns-egress, metrics-ingress, inference→registry ingress, training→registry ingress |
| `ingress` | default-deny, dns-egress, metrics-ingress, external→gateway ingress (from LB CIDR), gateway→inference egress |

Total: ~24 NetworkPolicy resources. Anything significantly fewer is
likely missing a symmetric ingress/egress or a system carve-out.

## 3. Validation steps

### 3.1 Static validation

```bash
# Lint and dry-run apply all policies
kubectl apply --server-side --dry-run=server -f policies/

# OPA/conftest policy-as-code check (if used)
conftest test policies/ --policy ../policy-as-code/network-policy/
```

Schema correctness is necessary but not sufficient. The harder
check is **reachability**.

### 3.2 Reachability matrix

Build a small matrix of (source pod, destination pod, expected
outcome) and run it before and after applying the policies. A
minimal harness with `kubectl debug`/`netshoot`:

```bash
# Allowed: inference -> feature-store (port 8081)
kubectl -n ml-inference debug deploy/model-server \
  -it --image=nicolaka/netshoot -- \
  curl -sS --max-time 3 -o /dev/null -w "%{http_code}\n" \
  http://read-api.feature-store.svc:8081/healthz
# Expect: 200

# Denied: inference -> external internet
kubectl -n ml-inference debug deploy/model-server \
  -it --image=nicolaka/netshoot -- \
  curl -sS --max-time 3 -o /dev/null -w "%{http_code}\n" \
  https://example.com
# Expect: connection timeout / 000

# Denied: training -> feature-store (training should not read features)
kubectl -n ml-training debug job/trainer \
  -it --image=nicolaka/netshoot -- \
  curl -sS --max-time 3 -o /dev/null -w "%{http_code}\n" \
  http://read-api.feature-store.svc:8081/healthz
# Expect: timeout
```

Every expected-allow that fails and every expected-deny that succeeds
is a bug in the policy set.

### 3.3 Policy decision logging

Confirm that the CNI logs denied flows. Without that, debugging will
be silent and detection rules in exercise 05 will be blind. The CNI's
flow exporter (Hubble, Calico flowlogs, Antrea flow exporter) must be
on.

## 4. Rubric / review checklist

| # | Criterion | 0 | 1 | 2 |
|---|---|---|---|---|
| 1 | Default-deny on ingress *and* egress in every workload namespace | Missing | Ingress only | Both |
| 2 | DNS egress carve-out present in every namespace | Missing | Some namespaces | All |
| 3 | Metrics scrape ingress carve-out, narrowly scoped | Missing | Open `monitoring` namespaceSelector with no podSelector | podSelector narrows to scraper identity |
| 4 | Each cross-namespace flow has symmetric ingress + egress policies | One-sided | Mixed | Symmetric |
| 5 | Training and inference have different policy sets (training is not a superset of inference) | Same | Mostly differentiated | Justified separation |
| 6 | External egress (object store) uses CIDR or documented FQDN mechanism | Open | CIDR but no `except` for cluster overlap | CIDR + `except`, or FQDN with CNI support |
| 7 | No `deny` policies attempted (NetworkPolicy is allow-only) | Misuse | Some confusion | Correct |
| 8 | Reachability matrix executed and recorded | Not done | Partial | Complete pass |

Pass = ≥12 / 16 with no zero scores.

## 5. Common mistakes

- **Forgetting egress DNS.** Pods can't resolve services after
  default-deny applies. Symptom: every connection times out, even
  in-cluster.
- **Asymmetric policies.** Allowing egress from A to B without an
  allowing ingress on B fails closed. Symptom: half the calls work
  (the ones to namespaces that haven't yet adopted default-deny).
- **Over-broad `namespaceSelector`.** `namespaceSelector: {}` matches
  every namespace; combined with `podSelector: {}` it allows the whole
  cluster. Almost always wrong.
- **Using NetworkPolicy to "deny" traffic.** The API is allow-only;
  removing an allow is how you deny. Authors who try to write a deny
  rule end up adding *no* effect or, worse, ordering confusion that
  hides the actual policy.
- **Allowing ingress to a Service.** NetworkPolicy targets pods, not
  Services. Selectors operate on pod labels; selecting the Service
  name does nothing.
- **Trusting `hostNetwork: true` pods to obey policy.** They don't.
  Admission policy must block `hostNetwork` outside the daemonsets
  that genuinely require it.
- **Allowing the whole VPC CIDR for object storage.** The VPC CIDR
  usually overlaps the pod CIDR. Use the bucket-endpoint subnets
  explicitly and `except:` the pod CIDR.
- **FQDN egress without CNI support.** `networking.k8s.io/v1` does
  not support FQDN. FQDN egress requires a CNI extension (Cilium L7)
  or an egress gateway.

## 6. References

- Kubernetes — NetworkPolicy reference:
  https://kubernetes.io/docs/concepts/services-networking/network-policies/
- Kubernetes — recipes (deny-all, allow-DNS, etc.):
  https://kubernetes.io/docs/concepts/services-networking/network-policies/#default-policies
- Kubernetes — `kubernetes.io/metadata.name` automatic namespace label:
  https://kubernetes.io/docs/concepts/services-networking/network-policies/#targeting-a-namespace-by-its-name
- MITRE ATLAS (lateral movement, exfiltration techniques at the
  network layer):
  https://atlas.mitre.org/
- OWASP Machine Learning Security Top 10 (ML06 - AI Supply Chain
  Attacks, ML07 - Transfer Learning Attack: relevant to constraining
  registry and dataset egress paths):
  https://owasp.org/www-project-machine-learning-security-top-10/
- NIST AI RMF (Map → Measure → Manage; the policy set is a *Manage*
  control implementing a *Map*ped data-flow):
  https://www.nist.gov/itl/ai-risk-management-framework
