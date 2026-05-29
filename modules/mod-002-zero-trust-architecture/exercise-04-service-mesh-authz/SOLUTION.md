# SOLUTION — Exercise 04: Service-Mesh Authorization Policy

> Read this *after* attempting the exercise.

## 1. Solution overview

This exercise asks for the **minimum set** of Istio
`AuthorizationPolicy` resources to allow the eight listed traffic
flows and nothing else, in a mesh where mTLS is `STRICT` and
default authorization is `DENY` (per the exercise setup).

A defensible answer has three properties:

1. **Identity-keyed.** Every rule uses `from.source.principals`
   keyed on the SPIFFE-style principal Istio derives from a
   workload's SVID
   (`cluster.local/ns/<ns>/sa/<sa>`). Namespace selectors are
   not used as a substitute.
2. **Method- and path-scoped.** `methods:` and `paths:` narrow
   what each principal can call, even within the same target
   service.
3. **Per-tenant scoping on the shared feature-api.** This is
   the only non-trivial design choice in the exercise. The
   `training-recs` workload may call
   `/features/admin/training-export/recs/*` but not
   `/features/admin/training-export/fraud/*`, even though both
   live on the same service. Path scoping plus principal
   scoping makes this enforceable in the mesh.

The note in the exercise that "default authorization is DENY"
means the mesh denies anything no `AuthorizationPolicy` explicitly
allows. In stock Istio, default-deny is achieved by applying an
empty-rules `ALLOW` (a policy with no `rules:`) to the
target selector — or, equivalently, by relying on the global
configuration the operator has set. This solution adopts the
exercise's premise and writes only the allow policies, then notes
the deny semantics explicitly.

## 2. Implementation (worked answer)

The remainder of this section is the worked artifact.

---

### Mesh Authorization Plan

**Author:** *reference solution*
**Date:** 2026-05
**Mesh:** Istio 1.x, `PeerAuthentication: STRICT` mesh-wide,
default authorization is `DENY`.
**API reference:** Istio AuthorizationPolicy
(https://istio.io/latest/docs/reference/config/security/authorization-policy/).

#### Background — the principal format

Istio derives the source principal of a request from the SVID
on the calling sidecar's mTLS cert. The principal is
formatted as `<trust-domain>/ns/<ns>/sa/<sa>` and, by Istio
convention, matched in `AuthorizationPolicy` rules **without**
the leading `spiffe://` (i.e., the same value appears as
`cluster.local/ns/recs/sa/model-serving`). Trust domain
`cluster.local` is the Istio default unless overridden.

For SmartRecs, this solution assumes the conventional
`<workload>` ServiceAccount name in each namespace (e.g.,
`sa: gateway` in `edge`, `sa: serving-recs` in `recs`).
Adjust the SA names if your environment differs; the
structure is what matters.

#### Policy 1 — `gateway` → `serving-recs` (`POST /v1/predict`)

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: serving-recs-allow-gateway-predict
  namespace: recs
spec:
  selector:
    matchLabels:
      app: serving-recs
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

- **Allowed.** `gateway` calling `POST /v1/predict`.
- **Denied by absence.** Every other principal, every other
  method, every other path on `serving-recs`. In particular,
  `serving-fraud` cannot call `serving-recs` (no allow rule
  for it).

#### Policy 2 — `gateway` → `serving-fraud` (`POST /v1/score`)

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: serving-fraud-allow-gateway-score
  namespace: fraud
spec:
  selector:
    matchLabels:
      app: serving-fraud
  action: ALLOW
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/edge/sa/gateway"
      to:
        - operation:
            methods: ["POST"]
            paths: ["/v1/score"]
```

#### Policies 3–6 — feature-api access

All four `feature-api` access rules are colocated in one
namespace and one selector (`app: feature-api`). The exercise
asks for the minimum set; for `feature-api`, that is **one**
`AuthorizationPolicy` resource with multiple rules, plus a
per-tenant scoping rule for the `training-*` workloads.

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: feature-api-allow-mesh-reads
  namespace: features
spec:
  selector:
    matchLabels:
      app: feature-api
  action: ALLOW
  rules:
    # Policy 3 — serving-recs reads the standard feature space.
    - from:
        - source:
            principals:
              - "cluster.local/ns/recs/sa/serving-recs"
      to:
        - operation:
            methods: ["GET"]
            paths: ["/features/v1/*"]

    # Policy 4 — serving-fraud reads the standard feature space.
    - from:
        - source:
            principals:
              - "cluster.local/ns/fraud/sa/serving-fraud"
      to:
        - operation:
            methods: ["GET"]
            paths: ["/features/v1/*"]

    # Policy 5 — training-recs reads both the standard feature
    # space and its OWN training-export prefix.
    - from:
        - source:
            principals:
              - "cluster.local/ns/recs-train/sa/training-recs"
      to:
        - operation:
            methods: ["GET"]
            paths:
              - "/features/v1/*"
              - "/features/admin/training-export/recs/*"

    # Policy 6 — training-fraud reads both the standard feature
    # space and its OWN training-export prefix.
    - from:
        - source:
            principals:
              - "cluster.local/ns/fraud-train/sa/training-fraud"
      to:
        - operation:
            methods: ["GET"]
            paths:
              - "/features/v1/*"
              - "/features/admin/training-export/fraud/*"

    # Policy 8 — governance reads feature metadata only.
    - from:
        - source:
            principals:
              - "cluster.local/ns/gov/sa/governance"
      to:
        - operation:
            methods: ["GET"]
            paths: ["/features/v1/metadata/*"]
```

The cross-tenant separation is enforced by the
**combination** of principal + path. `training-recs` does not
appear in any rule whose path starts with
`/features/admin/training-export/fraud/`, and the mesh
default-deny stops the request before any application code
runs. The audit trail records the principal that was denied.

#### Policy 7 — `governance` → all serving (`GET /v1/healthz`, `GET /v1/model-card`)

Because the serving workloads live in different namespaces
(`recs`, `fraud`), policy 7 is implemented as one
`AuthorizationPolicy` *per namespace*, both keyed on the
same governance principal. The exercise's "minimum set"
constraint is at the policy-content level, not the file
count; this is structurally minimal because cross-namespace
selectors are not supported by `AuthorizationPolicy`.

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: serving-recs-allow-governance-read
  namespace: recs
spec:
  selector:
    matchLabels:
      app: serving-recs
  action: ALLOW
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/gov/sa/governance"
      to:
        - operation:
            methods: ["GET"]
            paths: ["/v1/healthz", "/v1/model-card"]
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: serving-fraud-allow-governance-read
  namespace: fraud
spec:
  selector:
    matchLabels:
      app: serving-fraud
  action: ALLOW
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/gov/sa/governance"
      to:
        - operation:
            methods: ["GET"]
            paths: ["/v1/healthz", "/v1/model-card"]
```

#### Belt-and-braces — explicit DENY for write methods on feature-api

The mesh's default-deny already blocks write methods on
`feature-api` (no allow rule names them). The following
explicit DENY is **redundant** in pure semantics, but it
appears in the file for the same reviewability reason
discussed in Exercise 03: a reviewer reading the policies
sees "writes are denied on feature-api" without having to
reason about default-deny coverage.

```yaml
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

Per the Istio reference, DENY policies are evaluated before
ALLOW policies, so this overrides any future ALLOW that
slipped in by mistake.

#### Coverage table

| Source | Destination | Method | Path | Allowed? | Policy enforcing |
|---|---|---|---|---|---|
| `gateway` | `serving-recs` | `POST` | `/v1/predict` | ✓ | Policy 1 |
| `gateway` | `serving-fraud` | `POST` | `/v1/score` | ✓ | Policy 2 |
| `serving-recs` | `feature-api` | `GET` | `/features/v1/*` | ✓ | Policy 3 |
| `serving-fraud` | `feature-api` | `GET` | `/features/v1/*` | ✓ | Policy 4 |
| `training-recs` | `feature-api` | `GET` | `/features/v1/*` | ✓ | Policy 5 |
| `training-recs` | `feature-api` | `GET` | `/features/admin/training-export/recs/*` | ✓ | Policy 5 |
| `training-fraud` | `feature-api` | `GET` | `/features/v1/*` | ✓ | Policy 6 |
| `training-fraud` | `feature-api` | `GET` | `/features/admin/training-export/fraud/*` | ✓ | Policy 6 |
| `governance` | `serving-recs` | `GET` | `/v1/healthz`, `/v1/model-card` | ✓ | Policy 7 (recs) |
| `governance` | `serving-fraud` | `GET` | `/v1/healthz`, `/v1/model-card` | ✓ | Policy 7 (fraud) |
| `governance` | `feature-api` | `GET` | `/features/v1/metadata/*` | ✓ | Policy 8 (within feature-api allow) |
| `training-recs` | `feature-api` | `GET` | `/features/admin/training-export/fraud/*` | ✗ | Default-deny (no rule names this) |
| `serving-recs` | `serving-fraud` | `POST` | `/v1/score` | ✗ | Default-deny (Policy 2 only names `gateway`) |
| `serving-fraud` | `serving-recs` | `POST` | `/v1/predict` | ✗ | Default-deny (Policy 1 only names `gateway`) |
| `gateway` | `feature-api` | any | any | ✗ | Default-deny (no allow names `gateway` on `feature-api`) |
| `governance` | `serving-recs` | `POST` | `/v1/predict` | ✗ | Default-deny (Policy 7 only allows `GET`) |
| `serving-recs` | `feature-api` | `POST` | `/features/v1/foo` | ✗ | Policy `feature-api-deny-writes` (and default-deny) |
| `training-recs` | `feature-api` | `GET` | `/features/v2/*` | ✗ | Default-deny (Policy 5 only names `/features/v1/*` and the export prefix) |

#### Attack scenarios

These walk through what would happen if each constraint
were violated. The point is to show that the policies
catch the failure modes the exercise explicitly named.

1. **`training-recs` tries to call
   `/features/admin/training-export/fraud/...`.**
   - Mesh receives the request, sees principal
     `cluster.local/ns/recs-train/sa/training-recs`, sees
     no allow rule whose `paths:` matches the request, so
     the default-deny returns HTTP 403 (Envoy `RBAC:
     access denied`).
   - Audit log records the deny with both the principal
     and the path.
   - If Policy 5 had been written with `paths:
     ["/features/admin/training-export/*"]` (no per-tenant
     subpath), this attack would succeed silently — the
     mesh would allow it, the application would receive
     the call, and `fraud` training data could be
     exfiltrated to the `recs` team. This is the most
     load-bearing path-pattern choice in the policy set.

2. **`serving-recs` tries to call `serving-fraud`
   (`POST /v1/score`).**
   - Mesh sees principal `cluster.local/ns/recs/sa/serving-recs`,
     finds no allow on `serving-fraud` naming this
     principal, default-denies.
   - This catches the "lateral movement after a serving pod
     compromise" failure mode.

3. **`gateway` tries to call `feature-api`.**
   - No allow rule on `feature-api` names `gateway`.
     Default-denied. This is the
     gateway-confused-deputy prevention; the gateway
     should call serving, and serving should call the
     feature store. Gateway calling the feature store
     would bypass the inference path's per-tenant
     authorization.

4. **`governance` tries to call `POST /v1/predict` on
   `serving-recs`.**
   - Policy 7 (recs) allows `governance` only on `GET`
     methods. The mesh default-denies the `POST`. Catches
     governance scope-creep into the inference path
     (lecture-notes §3.5 — governance is read-only on
     every service it can call).

5. **`gateway` token replay on `serving-recs`.** The mesh
   confirms the *workload* identity (the gateway's SVID)
   but does not validate the customer JWT. If `gateway`
   is compromised, requests to `serving-recs` still
   appear to come from `gateway` and are allowed.
   Tenant-isolation enforcement is application-layer
   (Exercise 03 Layer 3); the mesh's job here is the
   workload-to-workload edge only.

#### What this still does not catch

- **Application-layer authorization.** The mesh does not
  know whether `serving-recs`, calling
  `/features/v1/customer/42`, is acting on behalf of the
  customer that owns `42`. Per-tenant authorization lives
  in the application (or in an OPA sidecar — Module 09).
  This is the lecture-notes §4.4 "mesh is necessary,
  insufficient" point.
- **Supply chain.** If `serving-recs` is running an
  unauthorized image, the mesh still treats its SVID as
  valid because attestation happened at SVID issuance, not
  at every request. Admission control on the image digest
  (Module 09 / project-4 supply chain) is the layer that
  catches this.
- **Inference-time evasion.** ML01 / OWASP ML01 evasion
  attacks come from authenticated paying customers via the
  gateway. The mesh allows the request (gateway → serving,
  POST /v1/predict). Adversarial robustness, input
  validation, and query-pattern detection (Modules 06, 11)
  are what address this class — not mesh authorization.
- **DoS within allowed flows.** A bug in `serving-recs`
  that spams `feature-api` with `GET /features/v1/*` is
  per-policy allowed. Rate limits and per-tenant quotas
  belong at the gateway (NIST SP 800-204A §3.5) or in an
  L7 rate-limit service.

---

## 3. Validation steps

1. **Schema validation.** `kubectl apply --dry-run=server`
   each file. With Istio CRDs installed, manifests parse and
   admit.
2. **Coverage table re-derivation.** For each row in the
   table, reason from the policy text alone — do not look at
   the table while reasoning. If your reasoning matches the
   table, the policy text is the source of truth.
3. **Failure injection (if mesh available).** Apply the
   policies to a sandbox namespace, then run a script that
   issues each of the deny rows in the table from a pod
   with the named SA. Expect HTTP 403 on every deny row
   and 200 on every allow row.
4. **Path-confusion test.** Issue a request from
   `training-recs` to `/features/admin/training-export/fraud/x`.
   Confirm 403. Then change the path to
   `/features/admin/training-export/recs/../fraud/x` and
   re-issue; Envoy normalizes paths before matching, so the
   request should still be 403 — but this is the place to
   verify your Envoy `path_normalization` setting matches
   expectation (the
   [Istio docs on path normalization](https://istio.io/latest/docs/reference/config/networking/destination-rule/)
   call out the configuration explicitly).
5. **Principal extraction sanity check.** Capture the
   request in Envoy access logs and confirm the principal
   matches the expected SPIFFE URI. If Envoy reports a
   different principal than expected, the workload's
   ServiceAccount or its mTLS cert is not what you think.

## 4. Rubric / review checklist

| # | Criterion | Pass condition |
|---|---|---|
| 1 | `from.source.principals` used | All allow rules key on SPIFFE-style principals, not namespaces |
| 2 | Method scoping | `methods:` present and correct in every rule |
| 3 | Path scoping | `paths:` present and correct; per-tenant export prefix split |
| 4 | All 8 listed flows present | Coverage table covers every required row |
| 5 | All listed denials present | Coverage table includes the 4+ constraint denials |
| 6 | `training-recs` cannot reach fraud-export | Policy text and table both confirm |
| 7 | `serving-recs` cannot call `serving-fraud` | Confirmed by absence of allow + table row |
| 8 | `gateway` cannot call `feature-api` | Confirmed by absence of allow + table row |
| 9 | `governance` is read-only everywhere it can call | Methods limited to `GET` in every governance rule |
| 10 | Minimum set | Policies aggregated by selector where possible; not one file per flow without reason |
| 11 | Attack-scenario walkthroughs | At least 3 walkthroughs reasoning from a single mistake to a concrete exfiltration |
| 12 | "Does not catch" section | At least 3 honest gaps (application-layer, supply chain, evasion, etc.) |

A common borderline case: the policies are correct but the
attack-scenario walkthroughs are bulleted abstract claims.
Push back — each walkthrough should trace a specific request
through the policy chain to its outcome.

## 5. Common mistakes

- **Using namespace selectors instead of principals.**
  `from.source.namespaces` exists but only matches the
  *namespace* the call originates from, not the
  authenticated identity. Identity-keyed authorization
  uses `principals`.
- **Forgetting to deny anything.** The exercise's
  default-deny premise makes deny implicit, but learners
  who do not state that premise often produce policies
  that work in their head and fail in any non-deny-by-
  default cluster. Restate the assumption.
- **Allowing the broad `/features/admin/training-export/*`
  path.** This silently breaks cross-team isolation —
  `training-recs` and `training-fraud` would each see the
  other's training data. The per-tenant subpath is the
  exercise's stated non-trivial concern.
- **One policy per flow without aggregation.** Eight flows
  do not require eight files. The `feature-api` selector
  can host four rules in one policy; readability wins.
- **Mixing ALLOW and DENY without understanding evaluation
  order.** Per the Istio reference, DENY is evaluated
  before ALLOW; an explicit DENY can shadow an allow you
  wrote elsewhere.
- **Path normalization not considered.** A path like
  `/features/admin/training-export/recs/../fraud/x` should
  be normalized; verify your Envoy config does so. If it
  doesn't, the per-tenant split is bypassable with
  path traversal.
- **Treating mesh authz as the tenant-isolation answer.**
  The mesh authorizes the *workload* identity; per-tenant
  data access is application-layer. Exercises 03 and 04
  reinforce the same point because it is the most common
  conceptual error in the field.

## 6. References

- **Istio AuthorizationPolicy reference.**
  https://istio.io/latest/docs/reference/config/security/authorization-policy/
- **Istio Security concepts.**
  https://istio.io/latest/docs/concepts/security/
- **Istio Authorization How-To.**
  https://istio.io/latest/docs/tasks/security/authorization/
- **NIST SP 800-204A — Building Secure Microservices-based
  Applications Using Service-Mesh Architecture.**
  https://csrc.nist.gov/pubs/sp/800/204/a/final
- **NIST SP 800-204B — Attribute-based Access Control for
  Microservices-based Applications Using a Service Mesh.**
  https://csrc.nist.gov/pubs/sp/800/204/b/final
- **NIST SP 800-207 §3.3 (decision frameworks).**
  https://csrc.nist.gov/pubs/sp/800/207/final
- **SPIFFE ID specification** (principal format).
  https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md
- **Module 02 lecture notes §4.3 (mesh authorization), §4.4
  (application authorization), §5 (defense-in-depth walk-
  through), Appendix B (common misconceptions).**
- **Cross-reference:**
  [`projects/project-1-zero-trust/istio/authz-policy.yaml`](../../../projects/project-1-zero-trust/istio/authz-policy.yaml)
  for the deployed reference at smaller scale (single team).
