# SOLUTION — Exercise 03: Microsegmentation Plan (3 Layers)

> Read this *after* attempting the exercise.

## 1. Solution overview

This exercise is an implementation exercise: at least four
Kubernetes NetworkPolicy manifests, two Istio AuthorizationPolicy
manifests, and a written plan for three application-layer
decisions that the mesh cannot enforce.

The YAML in this solution is **statically valid** against:

- `networking.k8s.io/v1` `NetworkPolicy` per the Kubernetes
  documentation
  (https://kubernetes.io/docs/concepts/services-networking/network-policies/).
- `security.istio.io/v1` `AuthorizationPolicy` per the Istio
  reference
  (https://istio.io/latest/docs/reference/config/security/authorization-policy/).

A learner who pastes these into a cluster with a NetworkPolicy-
enforcing CNI (Cilium, Calico) and Istio installed should see
the policies admitted. Whether they *work* depends on the
namespaces, labels, and ServiceAccounts being set up to match
the Exercise 02 identity design — these manifests reuse those
labels and SAs.

Three properties drive every choice below:

1. **Default-deny is non-negotiable.** A NetworkPolicy file
   that omits default-deny has rules that are decorative; the
   cluster permits everything anyway. The default-deny is
   policy #1 for a reason.
2. **Allow narrowly.** Allows that name a namespace alone
   ("anything in `features` can call anything in `recs`") are
   the most common failure mode and are quality-criterion
   failures in this exercise.
3. **Mesh ≠ application.** The mesh authorizes calling
   identity → method. The application authorizes tenant
   identity → resource. Both are needed.

## 2. Implementation (worked answer)

The remainder of this section is the worked artifact.

---

### SmartRecs Microsegmentation Plan

**Author:** _reference solution_
**Date:** 2026-05
**Reference workload identity design:** Exercise 02 of this module
([`../exercise-02-workload-identity-design/SOLUTION.md`](../exercise-02-workload-identity-design/SOLUTION.md)).

#### Layer 1 — L3/L4 NetworkPolicy

Each policy is preceded by its purpose and followed by a brief
note on what it does and does not catch.

##### Policy 1.1 — Default-deny in `recs`

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: recs
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

- **Threat mitigated.** Implicit east-west allow in
  Kubernetes — any pod in any namespace can reach any pod in
  `recs` by default. This policy turns the namespace into
  deny-by-default.
- **Threat not mitigated, requires a higher layer.** Doesn't
  authorize *who* can call *which method*. A compromised
  workload that *is* allowed to reach a serving pod (e.g.,
  the gateway) can still call any HTTP path the pod exposes.
  Mesh authorization (Layer 2) is required for that.

The same default-deny is applied in `features`, `edge`,
`recs-train`, `gov`, and `notebooks` namespaces. Only the
namespace name changes; all other fields are identical.

##### Policy 1.2 — Gateway → serving allow

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: gateway-can-call-serving
  namespace: recs
spec:
  podSelector:
    matchLabels:
      app: model-serving
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: edge
          podSelector:
            matchLabels:
              app: gateway
      ports:
        - protocol: TCP
          port: 8080
```

- **Threat mitigated.** Bypass paths from any non-`edge`
  pod to `model-serving`. Note the `podSelector` under
  `from` is co-located with `namespaceSelector`, which —
  per the
  [Kubernetes NetworkPolicy spec](https://kubernetes.io/docs/concepts/services-networking/network-policies/#networkpolicy-resource) —
  is an AND, not an OR. A `from:` block with two separate
  list items would have meant OR.
- **Threat not mitigated, requires a higher layer.** A
  malicious gateway pod could still call `/admin/*` paths
  on serving (if any exist) at L7. Method/path scoping is
  Layer 2.

##### Policy 1.3 — Serving → feature-store allow

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: feature-api-from-recs-serving
  namespace: features
spec:
  podSelector:
    matchLabels:
      app: feature-api
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: recs
          podSelector:
            matchLabels:
              app: model-serving
      ports:
        - protocol: TCP
          port: 8080
```

- **Threat mitigated.** Any pod outside `recs/model-serving`
  trying to reach `feature-api`. Notebook pods, governance
  pods, and other teams' serving pods are blocked at L4.
- **Threat not mitigated, requires a higher layer.** A
  `recs/model-serving` pod could ask for *any tenant's*
  features. Tenant-scoping is application-layer (see
  Layer 3, Decision 1).

##### Policy 1.4 — Training-job egress allow (warehouse)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: trainer-egress-warehouse-and-s3
  namespace: recs-train
spec:
  podSelector:
    matchLabels:
      app: trainer
  policyTypes:
    - Egress
  egress:
    # DNS resolution
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
    # Warehouse (private VPC IP range; the warehouse IP is
    # pinned via a Service of type ExternalName upstream).
    - to:
        - ipBlock:
            cidr: 10.40.0.0/16
      ports:
        - protocol: TCP
          port: 5432
    # S3 over the VPC endpoint (HTTPS).
    - to:
        - ipBlock:
            cidr: 10.50.0.0/16
      ports:
        - protocol: TCP
          port: 443
```

- **Threat mitigated.** A compromised training pod cannot
  egress to arbitrary internet hosts or to internal services
  outside the warehouse / S3 paths. CIDR-based allow is
  acceptable here because cluster CNIs cannot evaluate
  hostnames in standard `NetworkPolicy` (only Cilium's
  `CiliumNetworkPolicy` extends to hostnames; the exercise
  uses the standard `networking.k8s.io/v1` API).
- **Threat not mitigated, requires a higher layer.** Within
  the allowed warehouse / S3 ranges, the pod can read any
  data its IAM credential allows. Per-run scoping of the
  warehouse credential (Vault dynamic secrets) and of the
  S3 path (per-run identity, Exercise 02) is what cuts
  blast radius further. DNS exfiltration via the internal
  resolver is still possible at L7; runtime detection
  (Module 08 / Falco) is the next layer of catch.

#### Layer 2 — Mesh authorization

The cluster is assumed to have `PeerAuthentication: STRICT`
applied mesh-wide (single `PeerAuthentication` in
`istio-system`); a default-deny `AuthorizationPolicy` is
applied per namespace before any allow policy, so absence of
an allow means deny.

##### Policy 2.1 — Gateway-only access to serving `/v1/predict`

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: serving-recs-deny-all
  namespace: recs
spec:
  selector:
    matchLabels:
      app: model-serving
  action: ALLOW
  # No rules => no requests permitted.
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: serving-recs-allow-gateway
  namespace: recs
spec:
  selector:
    matchLabels:
      app: model-serving
  action: ALLOW
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/edge/sa/gateway"
      to:
        - operation:
            methods: ["POST"]
            paths: ["/v1/predict"]
```

- **Allowed.** `cluster.local/ns/edge/sa/gateway` calling
  `POST /v1/predict`.
- **Denied.** Every other principal, every other method, every
  other path — including `GET /healthz`, `POST /v1/admin/*`,
  and any non-gateway caller. Per the
  [Istio AuthorizationPolicy reference](https://istio.io/latest/docs/reference/config/security/authorization-policy/),
  the empty-rules ALLOW policy creates a deny-by-default
  selector that the second policy then opens narrowly.

##### Policy 2.2 — Read-only feature-api access from `recs/model-serving`

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: feature-api-deny-all
  namespace: features
spec:
  selector:
    matchLabels:
      app: feature-api
  action: ALLOW
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: feature-api-allow-serving-read
  namespace: features
spec:
  selector:
    matchLabels:
      app: feature-api
  action: ALLOW
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/recs/sa/model-serving"
      to:
        - operation:
            methods: ["GET"]
            paths: ["/features/v1/*"]
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: feature-api-deny-writes
  namespace: features
spec:
  selector:
    matchLabels:
      app: feature-api
  action: DENY
  rules:
    - to:
        - operation:
            methods: ["POST", "PUT", "PATCH", "DELETE"]
```

- **Allowed.** `cluster.local/ns/recs/sa/model-serving` calling
  `GET /features/v1/*`.
- **Denied.** All other principals, all write methods (the
  explicit DENY makes the intent unmistakable; per the Istio
  reference, DENY policies are evaluated before ALLOW), and
  paths outside `/features/v1/*`.

Note: combining an empty-rules ALLOW (deny-by-default) with an
explicit-method DENY is redundant in pure semantics — the
empty-rules ALLOW already blocks writes. The explicit DENY is
present for **reviewability**: a reviewer skimming the file
sees "writes are denied" without having to reason about the
deny-by-default semantics of an empty-rules policy.

#### Layer 3 — Application-layer authorization

The mesh authorizes the *workload identity*. It does not know:

- Which tenant a request is on behalf of.
- Which model version a request is intended for.
- Whether a per-resource consent flag has been revoked.

Three concrete decisions in SmartRecs cannot be made at the
mesh layer.

##### Decision 1 — Per-tenant feature access

- **What decision.** Whether the calling serving pod is
  permitted to fetch features for tenant `T`.
- **Data needed.** The customer's identity (carried as the
  on-behalf-of JWT from the gateway), and a lookup of which
  tenants the calling workload is currently provisioned for
  (stored in the feature-store's authz table or in an OPA
  data bundle).
- **Trustworthiness of the data.** The JWT is signed by
  SmartRecs' IdP and verified at the feature-store entry
  point (JWKS retrieval via mTLS to the IdP). The mesh
  guarantees the request came from `recs/model-serving`,
  but the tenant claim must come from a *signed* token, not
  from a custom request header that any pod can set.
- **What happens if wrong.** Cross-tenant data exposure —
  tenant A's serving pod returns tenant B's features. This
  is the classic confused-deputy failure in multi-tenant ML
  systems (lecture-notes §4.4). Detection is hard because
  the mesh logs show a valid identity calling a valid path;
  only the application's authorization log shows the
  mismatch.

##### Decision 2 — Per-version model-artifact access

- **What decision.** Whether the calling serving pod is
  permitted to load model version `vN`.
- **Data needed.** The serving identity's SPIFFE URI
  (carries `/version/vN`) and the version requested in the
  load operation.
- **Trustworthiness.** The version in the SPIFFE URI is
  attested at SVID issuance (see Exercise 02 attestation
  selectors — the version label is set by the deployment
  controller, not author-mutable). The requested version
  comes from the pod's own config, so it must match the
  URI; if they diverge, the load is rejected.
- **What happens if wrong.** A serving pod loads a model
  it should not be serving (e.g., a candidate model
  someone forgot to gate). The mesh allows the call to S3;
  only the artifact-service application logic catches the
  mismatch.

##### Decision 3 — Audit-log append-only enforcement

- **What decision.** Whether a writer can append to the
  audit log (yes) versus mutate or delete entries (no).
- **Data needed.** The calling principal (governance,
  serving, training all append; nothing should mutate) and
  the operation (`append`, `read`, `mutate`, `delete`).
- **Trustworthiness.** Operation is determined by the API
  method invoked on the audit-log service. The principal
  is from the mesh-verified SVID.
- **What happens if wrong.** An attacker that gains a
  governance SVID could rewrite history. The audit-chain
  design (Module 07) provides tamper evidence — but
  detection after the fact is poor consolation. The
  application authorization is the prevention layer.

##### Why these can't be made at the mesh

- The mesh sees the *workload identity* and the *path*, not
  the JWT claims, not the model version stamped on the
  request, not the operation semantics (`append` vs
  `mutate`).
- A pattern like `paths: ["/features/v1/tenant/A/*"]` at the
  mesh layer would only work if tenancy were in the URL —
  it normally isn't, because tenancy lookup requires
  validating a signed token.
- OPA-as-an-Envoy-ext-authz can move some application
  decisions closer to the mesh, but the decision logic is
  still application logic (Module 09 covers the
  policy-as-code pattern). The placement changes; the
  layer responsibility doesn't.

#### Cross-layer coverage table

| Threat | L3/L4 (NetworkPolicy) | Mesh (AuthorizationPolicy) | Application |
|---|---|---|---|
| Pod in `notebooks` calls `model-serving` | Blocked (1.2 — no allow for `notebooks` namespace) | Would also block (no notebook principal in policy 2.1) | n/a |
| Compromised `model-serving` pod calls `/v1/predict` on a *different* model serving in same ns | Allowed at L4 | Blocked (2.1 only allows gateway principal) | n/a |
| `model-serving` reads tenant B's features when caller is tenant A | Allowed | Allowed (correct workload identity, correct path) | **Blocked here** (Decision 1) |
| Training pod exfiltrates to public internet | Blocked (1.4 — CIDR allowlist) | n/a (egress) | n/a |
| Governance pod attempts to call `/v1/predict` | Blocked (no allow in `recs` from `gov`) | Blocked (2.1 deny) | n/a |
| Serving pod loads wrong model version | Allowed | Allowed | **Blocked here** (Decision 2) |
| Attacker with stolen governance SVID attempts to mutate audit log | Allowed | Allowed | **Blocked here** (Decision 3) |
| DNS exfiltration from training pod via internal resolver | Allowed (DNS allowed in 1.4) | n/a | n/a (caught by runtime detection — Module 08) |

#### Acknowledged gaps

- **DNS-channel exfiltration** is not closed by these three
  layers alone. The runtime-detection Falco rule from
  [`projects/project-1-zero-trust/falco-rules/ml-platform.yaml`](../../../projects/project-1-zero-trust/falco-rules/ml-platform.yaml)
  (`Suspicious egress from ML pod`) is the safety net.
- **Compromised CNI / mesh control plane** would invalidate
  large parts of these policies. Pod Security Standards
  (`restricted` profile) and admission control on the
  control-plane components is the assumed background
  (Module 09).
- **Application bugs in the tenant-authorization check** are
  the highest residual risk. Property tests that fuzz
  cross-tenant requests are the maintenance burden the
  application team owns.
- **Hostname-based egress** is not expressible in standard
  `NetworkPolicy`. If SmartRecs adopts Cilium,
  `CiliumNetworkPolicy` with `toFQDNs` closes this gap; until
  then, CIDR-pinning per-VPC service is the workaround.

---

## 3. Validation steps

For the YAML:

1. **Schema validation.** `kubectl apply --dry-run=server -f
   <file>` against a cluster with the relevant CRDs installed
   confirms the manifests parse and conform.
2. **Default-deny effective check.** Create a test pod in
   `recs` with no NetworkPolicy targeting it; confirm
   ingress and egress are denied via `kubectl exec
   <test-pod> -- nc -zv <other-pod-ip> 8080`.
3. **Gateway → serving allow check.** Run the same
   `nc` from a pod labeled `app=gateway` in `edge`;
   confirm port 8080 reachable.
4. **Mesh deny check.** From a pod with the
   `recs/model-serving` SA, call
   `POST /v1/predict` on the serving service; expect 403
   (Istio returns RBAC denials as HTTP 403). From the
   gateway pod, expect the configured 200.
5. **Mesh write-deny check.** From the
   `recs/model-serving` pod, call `POST /features/v1/foo`
   on the feature-api; expect 403.

For the application-layer plan:

1. Cross-reference Decision 1 with the multi-team thought
   experiment from Exercise 02 — same conclusion (tenant
   isolation cannot live in the mesh).
2. Confirm Decision 2 is consistent with the per-version
   serving identity in Exercise 02.

## 4. Rubric / review checklist

| # | Criterion | Pass condition |
|---|---|---|
| 1 | Default-deny in `recs` present | First NetworkPolicy in plan |
| 2 | ≥4 NetworkPolicies | Default-deny + gateway→serving + serving→feature + training egress |
| 3 | No namespace-wide allows | Every allow uses `podSelector`, not bare `namespaceSelector` |
| 4 | NetworkPolicy AND/OR semantics correct | `from:` block authors understand co-located selectors AND |
| 5 | 2 AuthorizationPolicies present | Gateway→serving and serving→feature |
| 6 | Mesh policies key on `principals:` | SPIFFE-style principals, not IP, namespace, or labels |
| 7 | Method scoping present | `methods: [POST]` and `methods: [GET]` used correctly |
| 8 | Default-deny at mesh layer present | Empty-rules ALLOW or explicit DENY on the selector |
| 9 | ≥3 application-layer decisions | Tenant access, model-version, audit-log append, or equivalents |
| 10 | Each application decision answers all 4 sub-questions | What/data/trust/wrong |
| 11 | Cross-layer coverage table | Each row shows which layer catches the threat |
| 12 | Acknowledged gaps section | At least 2 honest residuals (e.g., DNS exfil, application bug) |

A common borderline case: the YAML is correct but the
application-layer section is one sentence per decision. Push
back — the four sub-questions per decision are the test of
understanding.

## 5. Common mistakes

- **Missing default-deny.** The allow rules are decorative
  without it; the cluster permits everything.
- **Allowing whole namespaces.** A
  `namespaceSelector: { matchLabels: name: features }` with
  no co-located `podSelector` allows every pod, present and
  future, in that namespace. Almost always too broad.
- **NetworkPolicy AND/OR confusion.** Two list items under
  `from:` are an OR; selectors co-located in a single list
  item are an AND. Mixing these up silently widens or
  narrows the policy.
- **Cilium-only syntax in a vanilla file.** `toFQDNs` is a
  `CiliumNetworkPolicy` field, not standard NetworkPolicy.
  If the manifests claim to be vanilla, they must avoid
  Cilium extensions.
- **`AuthorizationPolicy` with no default-deny.** Without
  an empty-rules ALLOW or an explicit DENY against the
  selector, the policies are additive but do not close out
  callers that aren't named.
- **Mesh policies that key on namespace, not principal.**
  `from.source.namespaces` exists but it does not
  authenticate the workload — only the namespace it ran in.
  Identity-keyed authorization uses `principals`.
- **Treating mesh authorization as if it could enforce
  per-tenant access.** This is the most common conceptual
  error; the application-layer section exists to fix it.
- **Conflating mesh DENY with HTTP 401/403.** Istio
  AuthorizationPolicy denials return HTTP 403 (`RBAC: access
  denied`), not 401. Application returns 401 for
  authentication failures.

## 6. References

- **Kubernetes NetworkPolicy.**
  https://kubernetes.io/docs/concepts/services-networking/network-policies/
  Sections "NetworkPolicy resource" and "Behavior of `to`
  and `from` selectors" are the relevant ones for AND/OR
  semantics.
- **Kubernetes ServiceAccount.**
  https://kubernetes.io/docs/concepts/security/service-accounts/
  Referenced for the SA-to-principal mapping in Istio.
- **Istio AuthorizationPolicy reference.**
  https://istio.io/latest/docs/reference/config/security/authorization-policy/
- **Istio Security concepts.**
  https://istio.io/latest/docs/concepts/security/
- **NIST SP 800-204A — Building Secure Microservices-based
  Applications Using Service Mesh.**
  https://csrc.nist.gov/pubs/sp/800/204/a/final
- **NIST SP 800-207 §3.4 (variations on the zero-trust
  approach).** https://csrc.nist.gov/pubs/sp/800/207/final
- **Module 02 lecture notes §4 (microsegmentation), §5
  (defense in depth applied to a serving stack).**
- **Cross-reference:**
  [`projects/project-1-zero-trust/istio/authz-policy.yaml`](../../../projects/project-1-zero-trust/istio/authz-policy.yaml)
  for the deployed reference, and
  [`projects/project-1-zero-trust/SOLUTION.md`](../../../projects/project-1-zero-trust/SOLUTION.md)
  for the Cilium-vs-Istio trade-off discussion.
