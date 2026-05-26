# SOLUTION — Zero-Trust ML Infrastructure

> Read this *after* attempting the learning-side project. This file explains
> the design decisions behind the reference implementation, what is
> deliberately simplified, and what would need hardening for production.

## What problem this solves

A multi-tenant ML platform sits between two threats:

1. **Lateral movement** — a compromised training pod or notebook reaches
   feature stores, model registries, or other tenants.
2. **Identity laundering** — a workload claims to be something it isn't,
   either to escalate, exfiltrate, or poison.

Zero-trust assumes neither network position nor namespace is a sufficient
boundary. Every request is authenticated, authorized, encrypted in
transit, and logged.

## Architecture decisions and *why*

### Why Istio for mTLS instead of native CNI mTLS

Istio gives you `PeerAuthentication: STRICT` mesh-wide with one CR and
mTLS-aware `AuthorizationPolicy` keyed on the workload SAN. The
alternative — Cilium with WireGuard + L7 policy — has lower steady-state
overhead and no sidecar, but trades policy expressiveness and the rich
Envoy observability surface.

This curriculum picks Istio because most ML-platform readers will already
have ingress, retries, and outlier detection wired through Envoy.
*If your platform is already on Cilium L7 policy, that is a reasonable
substitute — the design intent is identical.*

### Why SPIFFE / SPIRE for identity (vs. ServiceAccount tokens)

ServiceAccount tokens are bound to a namespace, not to a workload's
identity, and they don't rotate by default. SPIFFE issues a short-lived
SVID per workload, attested by node + pod selectors, and rotates
automatically. The audit trail keys cleanly off `spiffe://trust-domain/ns/<ns>/sa/<sa>`.

### Why Vault + External Secrets Operator (vs. Sealed Secrets)

Sealed Secrets are git-safe but static — rotation requires a re-encrypt.
ESO pulls from Vault's KV/database/PKI engines and reconciles every N
seconds, so credential rotation is centralized and revocable. The
trade-off is one more managed dependency.

### Why Falco rules on top of admission policies

Kyverno (admission) stops disallowed objects at apply time. Falco
(runtime) catches what slipped through, e.g. a pod that opened a shell
into a model artifact path or contacted an unexpected egress target.
ML-specific rules in `falco-rules/ml-platform.yaml` catch the patterns
that matter to this domain (model file write outside `/models`, GPU
metric exfiltration via DNS, etc.).

## How to read the code

Execution-order reading path:

1. `istio/peer-authentication.yaml` — turn the whole mesh into mTLS-only.
2. `istio/authz-policy.yaml` — explicit allow list keyed on workload identity.
3. `falco-rules/ml-platform.yaml` — what we flag at runtime.
4. `tests/penetration.sh` — try to bypass each control in the order it
   would be exercised by an attacker who got code execution in a training pod.

The `penetration.sh` script is the most useful artifact here: it doubles
as the acceptance criterion for "is zero-trust actually wired up?"

## What's deliberately simplified

- **No HSM-backed CA.** Istio's default Citadel uses an in-cluster CA. A
  real production deployment would mount a HashiCorp Vault PKI or external
  KMS-backed CA so the root key never lives in a pod.
- **No external trust-domain federation.** Single SPIFFE trust domain only.
- **No L7 quotas.** Per-tenant request budgets live in the platform API,
  not here.
- **No audit-chain implementation in this folder.** It's cross-referenced
  to the governance project where the tamper-evident hash chain is
  actually implemented.

## Cross-references for deeper coverage

| Topic | Where the deeper implementation lives |
|---|---|
| NetworkPolicy default-deny + tenant allows | `engineer-solutions/mod-104 exercise-14-resource-quotas-multitenancy` |
| Secret management with Vault + ESO | `engineer-solutions/mod-109 exercise-07-secret-management` |
| Kyverno admission policies | `engineer-solutions/mod-109 exercise-08-policy-as-code/kyverno` |
| Tamper-evident audit log | `mlops-learning/projects/project-4-governance/src/audit` |
| SBOM + signing + supply chain | `engineer-solutions/mod-103 exercise-10-sbom-and-supply-chain` |

## Production gap checklist

If you were taking this design from curriculum to production, you would
need to add (in priority order):

- [ ] External KMS-backed root CA for Istio (no in-cluster CA private key)
- [ ] Trust-domain federation if you have multiple clusters
- [ ] L7 per-tenant rate limits at the platform API gateway
- [ ] CSI driver-based secret injection so secrets never hit the API server
- [ ] Continuous policy testing (`kyverno test`, OPA conftest in CI)
- [ ] eBPF-based egress identity (Cilium or Tetragon) for L4 visibility
- [ ] Encrypted etcd + envelope encryption for `Secret` resources
- [ ] Backup and recovery story for SPIRE server state

## Validation

The `tests/penetration.sh` script is the acceptance test. Each
documented control should result in a "blocked" outcome. If a control
fails open, the script reports it explicitly — that is the bug, not the
script.

## Time budget for studying this solution

- **Skim**: 30 min — read this file, scan the manifests, read the README cross-references.
- **Deep**: 4–6 hours — re-implement each manifest from scratch, then run `penetration.sh` and explain every block in your own words.
