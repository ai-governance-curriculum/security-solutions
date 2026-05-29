# SOLUTION — Exercise 02: Vault Deployment Plan

## 1. Solution overview

The deliverable is a deployment plan for a centralised secrets-manager
that an ML platform can adopt as the *one* source of truth for
workload secrets. The plan must cover topology, unseal/keying, auth
methods that workloads will actually use, policy model, audit, backup,
and a phased migration off the legacy stores listed in exercise-01.

This solution uses HashiCorp Vault Open Source as the reference
implementation because (a) it has authoritative public documentation
for the components needed here, (b) it covers every secret class an ML
platform encounters (KV, dynamic DB, PKI, transit, OIDC issuer), and
(c) cloud-native equivalents (AWS Secrets Manager + KMS, GCP Secret
Manager, Azure Key Vault) inherit the same design questions. The
section "Design decisions" calls out which choices port to the
cloud-managed services and which do not.

The exercise is design-based. The deliverable is the plan document
itself; the validation steps describe how to dry-run the plan before
committing to it.

## 2. Implementation (worked answer)

### 2.1 Target topology

- **Vault cluster**: 5 server pods on Kubernetes, integrated-storage
  (Raft) backend, anti-affinity across 3 availability zones (2/2/1).
- **Unseal**: KMS auto-unseal using the cloud KMS root key
  (`alias/vault-unseal`). Root key access restricted to the Vault
  workload identity; no human principals on the key policy.
- **Recovery keys**: 5 of 9 threshold, distributed to nominated
  custodians (Platform Security, SRE, Security Engineering) — never
  combined in one location. Recovery keys never enter the cluster.
- **Networking**: Vault exposed only inside the cluster on a
  `ClusterIP` service plus a private internal Ingress for tooling.
  No public exposure. mTLS between clients and Vault using cluster
  internal CA.
- **Storage encryption**: Raft snapshots inherit Vault's barrier
  encryption at rest; the snapshot bucket itself is KMS-encrypted,
  versioned, has MFA-delete enabled, and has an object-lock policy
  aligned with retention. (Seal wrap is Vault Enterprise only; the
  OSS plan relies on barrier + bucket-side KMS for the same control
  surface.)
- **Observability**: audit device (file sink + forwarder to the SIEM),
  Prometheus telemetry, structured server logs to the platform log
  pipeline.

A separate Vault cluster is *not* deployed per environment. Instead a
single cluster serves all environments using namespace separation
(`prod/`, `staging/`, `dev/` top-level mounts and matching policies).
This is documented because the obvious-sounding "one Vault per env"
costs an order of magnitude more operational time without changing
the blast radius — the Vault cluster itself is the trust root in both
designs.

### 2.2 Auth methods (mapped to actual consumers)

| Consumer | Auth method | Why |
|---|---|---|
| Kubernetes workloads (training jobs, inference pods, controllers) | `kubernetes` auth method, bound to ServiceAccount + namespace. | Native cluster identity; no static token shipped to the pod. |
| CI/CD (GitHub Actions, GitLab CI) | `jwt`/OIDC auth method using the provider's OIDC issuer. | Eliminates the long-lived Vault token in CI secret store; see exercise-04. |
| Cloud-native services (Lambda, ECS, GCE, etc.) | Cloud-IAM auth (`aws`, `gcp`, `azure`). | Workload identity already exists; reusing it avoids a second auth surface. |
| Humans (operators, oncall) | `oidc` auth method against the corporate IdP, with hardware-MFA enforced. | Single sign-on; ephemeral Vault tokens; revocable centrally. |
| Break-glass / emergency | Sealed Vault root token in tamper-evident envelope, regenerated and re-sealed each use; audited. | Recovers Vault from total auth-method failure. |
| Argo CD / GitOps | Vault Agent sidecar with Kubernetes auth + per-application policy. | Avoids placing a long-lived token in Argo CD's repo-secret store. |
| Vault Agent on bare-metal/legacy hosts | `approle` with response-wrapped Secret-ID handed out by a short-lived bootstrap process. | Workload identity does not exist on these hosts; AppRole is the documented bridge. |

Static token auth is *not* enabled. The default token mount remains
for service tokens that auth methods generate dynamically.

### 2.3 Secret engines (mapped to inventory tiers)

| Engine | Mount path | What it handles |
|---|---|---|
| `kv-v2` | `prod/kv/*`, `staging/kv/*`, `dev/kv/*` | Last-resort static secrets (vendor API keys with no OIDC option). Versioned with metadata. |
| `database` | `prod/database/*` | Dynamic Postgres/MySQL credentials for the feature store and metadata DB. Default TTL 1h, max 24h. |
| `aws` (or `gcp`/`azure`) | `prod/cloud/aws/*` | Short-lived cloud credentials for jobs that cannot use IRSA/workload identity. |
| `pki` | `prod/pki/internal/*` | Internal CA issuing service certificates (inference gateway, MLflow, internal mTLS). Leaf TTL 24-72h. |
| `transit` | `prod/transit/model-artifacts`, `prod/transit/training-data` | Encryption-as-a-service for at-rest encryption of model artefacts and sensitive training data without the workload holding the key. |
| `ssh` (CA mode) | `prod/ssh/ops` | Short-lived signed SSH certificates for operators reaching legacy bastions. |
| `identity` + `oidc` | `prod/identity/oidc` | Issues short-lived OIDC tokens to workloads that need to assert identity to third-party SaaS (e.g. cloud OIDC trust). |

Each engine is *only* mounted in environments that need it. A given
engine has at most one canonical mount path; aliases are not used.

### 2.4 Policy model

The policy model is **role-scoped, environment-scoped, capability-minimised**:

```
<env>/<workload>/<capability>
```

Example (HCL):

```hcl
# policy: prod/inference/read
path "prod/kv/data/inference/*" {
  capabilities = ["read"]
}

path "prod/database/creds/inference-read" {
  capabilities = ["read"]
}

path "prod/transit/decrypt/model-artifacts" {
  capabilities = ["update"]
}

path "prod/pki/internal/issue/inference" {
  capabilities = ["update"]
}
```

Rules:

1. **No `*` wildcards above the workload directory.** A policy may
   wildcard the path *under* its workload (`prod/kv/data/inference/*`)
   but never above it.
2. **No `sudo` capability outside `admin/*` policies.** `sudo` defeats
   the policy layer.
3. **Every policy is generated from a template parameterised by
   `(env, workload, capability)`.** Hand-edited policies are blocked
   in CI to prevent capability drift.
4. **Admin policies are emergency-only and have their own audit
   stream** with a non-bypassable alert on use.
5. **Token TTLs are inherited from the auth method**: workload tokens
   1h max; human tokens session-bound and capped at 8h.

### 2.5 Audit

- Two independent audit devices: a local file sink (tamper-evident,
  rotated daily) and a syslog/network sink to the SIEM. A single sink
  must not be load-bearing — losing one device must not silently
  disable audit.
- Audit log HMAC keys rotated annually as part of the platform
  cryptoperiod review.
- Every `auth/*/login`, every `sudo`-capability use, every policy
  change, and every root-token-equivalent operation generates a
  high-priority SIEM event.
- Audit retention: aligned with the regulatory regime applicable to
  the platform; default 1 year online + 6 years archived.


### 2.6 Backup, recovery, and key custody

- Raft snapshots every 4 hours; off-cluster, multi-region storage.
- Snapshot restore drilled quarterly into an isolated environment;
  drill measures **time to first successful auth**, not just "Vault
  is up".
- Recovery keys rotated yearly. The rotation drill validates each
  custodian individually before destroying the previous shares.
- Disaster-recovery replica cluster (Vault Enterprise feature) is
  *not* assumed here; the equivalent OSS posture is rapid restore
  from snapshot + DNS cutover.

### 2.7 Migration plan from existing stores

Two-phase, time-boxed, **strangler-pattern** migration of the
exercise-01 inventory into Vault:

**Phase 0 — preconditions (week 1).**

- Vault cluster stood up and auth methods enabled.
- Audit pipeline confirmed end-to-end (test event reaches SIEM).
- Backup/restore drill passed.
- A single canary workload (low blast-radius, owned by the platform
  team) onboarded to Vault. *No production traffic onboarded until
  the canary has run for a full week without alert.*

**Phase 1 — read paths (weeks 2-6).**

- All T2 read-only secrets (e.g. read-only DB roles, monitoring
  tokens) moved behind dynamic engines or kv-v2.
- Old static credentials kept side-by-side and revoked only after a
  full deploy cycle validates the new path. Each migrated row in the
  inventory flips its "Storage today" column on commit.

**Phase 2 — write paths and signing material (weeks 7-12).**

- T1 production-write secrets migrated, starting with the most
  rotation-painful (DB admin → dynamic; vendor API keys → kv-v2 with
  rotation hooks; model-registry write → OIDC-derived short-lived
  token; PKI → Vault PKI).
- T0 root keys (KMS root, signing-CA root) are *not* moved into Vault.
  Their custody model stays in HSM/KMS; Vault holds intermediate
  certificates and short-lived signers.

**Phase 3 — decommission (week 13+).**

- The legacy stores listed in exercise-01 (GitHub Actions secrets,
  Kubernetes Secrets, laptop credential files) are deleted only after
  the inventory shows zero remaining consumers.
- The deletion itself is the validation step — broken consumers will
  scream within one deploy cycle.

### 2.8 Design decisions and *why*

- **Integrated storage (Raft), not Consul.** Removes the external
  dependency and shrinks the trust surface; Consul is only justified
  when you already operate it at scale for service discovery.
- **Auto-unseal, not Shamir at every restart.** Restarts during an
  incident must not require humans to type in unseal keys; auto-unseal
  with a hardware-rooted KMS preserves the "no single key in any one
  place" property while removing the human-in-the-loop.
- **One cluster, namespaced.** A second cluster doubles operational
  cost without halving blast radius; the trust root remains the same
  KMS key.
- **No static Vault tokens.** Static tokens recreate the exact problem
  the secrets manager exists to solve.
- **Dynamic credentials wherever the downstream supports them.** A
  static DB password rotated quarterly is still a password an attacker
  can steal between rotations; a dynamic credential with a 1h TTL is
  not.
- **Transit for model-artifact encryption.** Storing raw KMS data keys
  alongside model artefacts puts both in one bucket; routing through
  Vault's transit engine keeps the key material out of the workload's
  reach.

### 2.9 What is deliberately deferred

- **Performance replication and DR replication.** Available only in
  Vault Enterprise; the OSS plan substitutes snapshot/restore drills.
- **Vault namespaces.** Enterprise feature; the OSS plan substitutes
  mount-path prefixes and policy templating.
- **Hardware security modules under Vault itself.** The KMS-rooted
  auto-unseal already provides HSM-backed sealing; HSM-rooted seal
  inside Vault adds operational cost and is justified only by an
  explicit compliance mandate.


## 3. Validation steps

1. **Plan review.** Walk the plan with one representative from each
   consumer team (ML platform, data platform, SRE, CI). Each must
   identify their workloads in §2.2 and confirm the auth method works
   for them. A row no one claims is a row that will not migrate.
2. **Threat-model review.** Apply STRIDE to the Vault cluster itself:
   - Spoofing: can a pod from another namespace assume an inference
     ServiceAccount? Confirmed via the policy binding test.
   - Tampering: is audit configured *before* secret data is written?
   - Repudiation: confirm audit covers every privileged path.
   - Information disclosure: confirm `kv-v2` versions are pruned per
     the retention policy.
   - Denial of service: confirm Raft quorum survives a 1-AZ outage.
   - Elevation of privilege: confirm no policy grants `sudo` outside
     the break-glass policy.
3. **Dry-run in a non-production cluster.**
   - Deploy the topology described in §2.1.
   - Onboard the canary workload from §2.7 Phase 0.
   - Trigger an unseal event by rotating the KMS key alias; confirm
     Vault recovers without human intervention.
   - Force a leader change by deleting the leader pod; confirm clients
     fail-over within the documented SLO.
4. **Audit pipeline end-to-end test.** Generate a known-bad event
   (login with an unknown ServiceAccount) and confirm it lands in the
   SIEM as a high-priority alert.
5. **Backup restore drill.** Restore the latest snapshot into a
   standalone cluster; measure time-to-first-successful-auth and time
   to read a representative production secret. Both must beat the
   documented RTO.
6. **Policy regression suite.** A test harness asserts each policy
   denies what it should deny (read attempts on adjacent workloads,
   wildcards above the workload directory, write attempts from
   read-only policies). The suite runs in CI on every policy change.

## 4. Rubric / review checklist

| Criterion | Pass | Partial | Fail |
|---|---|---|---|
| **Topology** | HA, multi-AZ, no public exposure, auto-unsealed by hardware-rooted KMS. | HA but single-AZ, or unseal mechanism unclear. | Single node or public exposure. |
| **Unseal & recovery** | KMS auto-unseal + recovery keys with named custodians and rotation cadence. | Auto-unseal but no recovery-key custody plan. | Manual unseal in production; recovery keys held by one person. |
| **Auth methods** | Each consumer class has a non-static method and a documented onboarding. | Mostly non-static, but one class still uses static tokens. | Static tokens default; no consumer mapping. |
| **Engines** | Dynamic engines used wherever downstream supports them; transit/PKI in use. | Only kv-v2 used; dynamic engines mentioned but not deployed. | kv-v2 only, with no migration plan to dynamic. |
| **Policy model** | Templated, capability-scoped, no wildcards above workload, `sudo` confined to break-glass. | Templated but with wildcards, or `sudo` used in routine policies. | Hand-edited policies, frequent `sudo`. |
| **Audit** | Two independent sinks, SIEM-integrated, with a tested alert. | One sink, integrated. | Audit disabled or unreachable. |
| **Backup** | Snapshots scheduled, restored under drill, RTO measured. | Snapshots taken but never restored. | No backup plan. |
| **Migration** | Phased, with a canary, side-by-side before cutover, decommission gated on inventory parity. | Phased but no canary or no decommission gate. | "Big-bang" cutover. |
| **Risk transparency** | Deferred features (DR replica, HSM, namespaces) named and justified. | Some deferrals implicit. | Plan claims feature parity it does not have. |

## 5. Common mistakes

- **One Vault per environment because "isolation".** The trust root
  is the cluster itself; multiple Vaults multiply operational burden
  without changing blast radius. Use mount paths + policy.
- **Storing the unseal keys "in Vault".** Recovery/unseal keys must
  live outside any system Vault can compromise. KMS root key access
  must not depend on Vault.
- **Static Vault tokens in CI.** Defeats the whole point. Use OIDC
  auth (see exercise-04).
- **Enabling `sudo` because the policy is "tricky".** `sudo` bypasses
  the capability layer; the policy is supposed to be tricky.
- **No audit drill.** Audit is silently broken in most outages until
  the day it is needed. Drill it.
- **No snapshot restore drill.** Snapshots that have never been
  restored have a non-trivial probability of being unrestorable.
- **Migration without a canary.** Forces every team to bear the cost
  of finding the first bug.
- **Migration without decommission.** Old paths stay forever, and the
  inventory keeps two storage rows per secret.
- **Treating dynamic engines as optional.** Static DB credentials are
  rotated; dynamic DB credentials are *bounded*. Bounded beats
  rotated.
- **Vault namespaces in OSS plan.** Namespaces are Enterprise; OSS
  plans must substitute mount-path prefixes.

## 6. References

- HashiCorp Vault — official documentation: <https://developer.hashicorp.com/vault/docs>
  - Integrated storage / Raft: <https://developer.hashicorp.com/vault/docs/configuration/storage/raft>
  - Auto-unseal: <https://developer.hashicorp.com/vault/docs/concepts/seal>
  - Kubernetes auth: <https://developer.hashicorp.com/vault/docs/auth/kubernetes>
  - JWT/OIDC auth: <https://developer.hashicorp.com/vault/docs/auth/jwt>
  - Database secrets engine: <https://developer.hashicorp.com/vault/docs/secrets/databases>
  - PKI secrets engine: <https://developer.hashicorp.com/vault/docs/secrets/pki>
  - Transit secrets engine: <https://developer.hashicorp.com/vault/docs/secrets/transit>
  - Audit devices: <https://developer.hashicorp.com/vault/docs/audit>
- NIST SP 800-57 Part 1 Rev. 5, *Recommendation for Key Management* —
  <https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final>
- NIST SP 800-53 Rev. 5, controls `IA-5`, `SC-12`, `SC-13`, `AU-2`,
  `AU-9` — <https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final>
- NIST AI Risk Management Framework — Govern function, asset and
  identity management: <https://www.nist.gov/itl/ai-risk-management-framework>
- OWASP Secrets Management Cheat Sheet —
  <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>
- MITRE ATLAS — <https://atlas.mitre.org/> (techniques targeting
  ML-pipeline credentials).

