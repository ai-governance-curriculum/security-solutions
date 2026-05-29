# SOLUTION — Exercise 01: Secrets Inventory

## 1. Solution overview

A secrets inventory is the prerequisite control for every other secrets
practice — you cannot rotate, scope, or audit what you have not first
named. The deliverable is a structured catalogue that captures every
secret an ML platform depends on, classifies each by sensitivity and
blast radius, and assigns an owner accountable for its lifecycle.

This solution shows a worked inventory for a representative ML platform
(training cluster + feature store + model registry + inference
service), the decision rules behind each column, and a rubric reviewers
can apply to learner submissions.

The exercise is design-based; the artifact is a table plus a written
rationale, not running code.

> The specific systems and counts below are illustrative for the
> exercise scenario. They must match the learner's local scenario when
> grading a real submission.

## 2. Implementation (worked answer)

### 2.1 Inventory schema (the columns that matter)

| Column | Why it is in the inventory |
|---|---|
| **ID** | Stable handle the rotation playbook and incident runbook can reference. |
| **Name / purpose** | Human-readable description (e.g. "S3 read-only key for training-data bucket"). |
| **Type** | API key, OAuth client secret, database password, signing key, TLS private key, encryption key, SSH key, JWT signing secret, webhook secret, service-account token. |
| **System / consumer** | Which workload reads the secret (training job, inference pod, CI runner, data ingest job). |
| **Storage location today** | Where it physically lives *right now* (Vault path, KMS key ARN, Kubernetes Secret, env var, CI variable, `~/.aws/credentials` on a laptop, hard-coded in a repo). |
| **Issuer / source of truth** | Which system mints it (cloud IAM, Vault PKI, internal CA, third-party SaaS). |
| **Classification** | Sensitivity tier (see 2.2). |
| **Blast radius** | What an attacker can do with one disclosure (read one bucket / write to the model registry / sign artefacts trusted by production). |
| **Rotation cadence** | Current cadence + target cadence (see exercise-03). |
| **Last rotated** | Date of last rotation; blank means "unknown — investigate". |
| **Owner (team / person)** | Single accountable owner per row. Shared ownership = no ownership. |
| **Auth method preferred** | If this secret could be replaced by a short-lived credential, name the mechanism (workload identity, OIDC federation, IRSA, SPIFFE SVID). |
| **Notes / migration plan** | Free text — e.g. "scheduled to retire when feature-store moves to IRSA". |

### 2.2 Classification tiers (decision rules)

| Tier | Rule of thumb | Examples in an ML platform |
|---|---|---|
| **T0 — Root** | Loss compromises the issuance system itself. | KMS root keys, Vault root token, cloud organisation-root access keys, signing CA private key. |
| **T1 — Production privileged** | Loss yields production write/admin or model-supply-chain integrity loss. | Model-signing keys, model-registry write tokens, production database admin credentials, Kubernetes cluster-admin kubeconfig, GitHub Actions secrets that mint OIDC tokens for prod. |
| **T2 — Production read** | Loss yields data exfiltration but not production write. | Read-only S3 access keys for training datasets, read-only DB credentials, monitoring API tokens. |
| **T3 — Pre-production / sandbox** | Loss is bounded to non-production environments. | Dev/staging service accounts, sandbox SaaS API keys. |
| **T4 — Public / non-secret** | Misclassified secrets. They should not be in this inventory at all; tracking them surfaces the misclassification. | Public OAuth client IDs treated as secrets; pre-shared "tokens" that are in fact public webhook URLs. |

Two principles drive these tiers:

1. **Blast radius beats secret length.** A 4-character production
   webhook token used by a model-deployment robot is T1; a 64-character
   developer token to a sandbox is T3.
2. **Issuance authority is its own tier.** Anything that can mint other
   secrets (KMS root, Vault root, CA private key) is T0 regardless of
   how it is consumed, because a single compromise collapses everything
   beneath it.

### 2.3 Worked inventory (representative ML platform)

The following is a worked example for an ML platform with: a training
cluster on Kubernetes, an S3 / object-store data lake, MLflow as model
registry, a Postgres feature store, an inference service behind an API
gateway, and GitHub Actions as CI.

> Counts and ARNs are placeholders for exercise context.

| ID | Name | Type | System | Storage today | Class | Blast radius | Cadence (current → target) | Owner | Preferred auth |
|---|---|---|---|---|---|---|---|---|---|
| SEC-001 | KMS CMK — model-artifacts bucket | Symmetric data-key wrapping key | S3 | AWS KMS (`alias/ml-model-artifacts`) | T0 | All model artifacts decryptable | Annual (auto) | Platform Security | KMS (no replacement needed) |
| SEC-002 | Model-signing private key | Asymmetric signing key | CI / release | Sigstore Fulcio (keyless) | T1 | Forged model attestations accepted at admission | Per-build (keyless) | ML Platform | Sigstore keyless OIDC |
| SEC-003 | MLflow registry write token | Bearer token | CI runner | GitHub Actions secret | T1 | Inject malicious model versions | 90d (manual) → on-demand via OIDC | ML Platform | OIDC → short-lived token |
| SEC-004 | Feature-store DB admin password | Database credential | Migrations job | Vault `database/creds/migrate` | T1 | Read + write all features | Dynamic (per-job, 1h TTL) | Data Platform | Vault dynamic secret |
| SEC-005 | Feature-store DB read role | Database credential | Inference service | Vault `database/creds/read` | T2 | Read all feature rows | Dynamic (per-pod, 1h TTL) | Data Platform | Vault dynamic secret |
| SEC-006 | Training-data S3 read key | IAM access key | Training jobs | IRSA (no static key) | T2 | Read training datasets | n/a (no key) | ML Platform | IRSA |
| SEC-007 | Inference TLS server cert | TLS private key | Inference gateway | cert-manager + Vault PKI | T1 | Impersonate inference endpoint | 30d (auto) | Platform Security | Vault PKI |
| SEC-008 | GitHub Actions → AWS OIDC trust | Trust relationship | CI | IAM role trust policy | T1 (config) | Any repo with this binding can assume the role | Reviewed on each policy change | Platform Security | OIDC (no static key) |
| SEC-009 | Argo CD → Git read deploy key | SSH key | GitOps | Argo CD secret | T1 | Read of GitOps manifests | 180d (manual) → SSO app token | Platform Security | GitHub App installation token |
| SEC-010 | PagerDuty webhook | Bearer token | Alertmanager | Kubernetes Secret | T2 | Trigger false pages / suppress real ones | 180d (manual) | SRE | Webhook signing + token rotation |
| SEC-011 | OpenAI API key (eval pipeline) | Vendor API key | Eval CI job | GitHub Actions secret | T1 | Cost exfiltration; data sent to external API | 90d (manual) → vendor OIDC if available | ML Platform | Vendor short-lived token if supported |
| SEC-012 | Slack incoming webhook | Webhook URL | Bot | Repo `.env.example` (**misuse**) | T4 → fix | None as designed; flagged here because devs treat it as a secret | n/a | SRE | Move out of `.env.example`; treat as public |

The last row is intentional: a good inventory surfaces both
under-protected secrets and *over*-protected non-secrets. Both waste
operational effort.

### 2.4 Decision rationale (what reviewers should look for)

- **Every secret has exactly one owner.** Shared ownership ("Platform
  team") means no one rotates it. Name a person or a single oncall
  rotation.
- **Static long-lived credentials are flagged with a migration path.**
  The "Preferred auth" column is not aspirational decoration — it is
  the queue for exercise-02 (Vault) and exercise-04 (keyless CI).
- **Issuance-tier secrets (T0) are separated.** They have their own
  access list, audit channel, and break-glass procedure; they should
  not appear in the same table cells as T2 read tokens at runtime,
  even if they share columns here.
- **Storage location is the *current* truth, not the intended truth.**
  If half the inventory says "Kubernetes Secret" when the target is
  Vault, the migration backlog is now visible.
- **Unknown rotation dates are treated as findings.** A blank "Last
  rotated" column is the highest-signal entry in the inventory.

### 2.5 What goes outside the inventory

- **Public OAuth client IDs**, public keys, certificates, and other
  non-secret cryptographic material. Track them as configuration.
- **Per-user developer credentials** (personal SSO tokens, individual
  laptop SSH keys). They are governed by IAM/identity processes; the
  inventory tracks *workload* secrets.
- **Ephemeral derived material** (in-memory session keys, JWTs derived
  from a longer-lived signing key). The signing key is in the
  inventory; the JWT is not.

## 3. Validation steps

1. **Coverage check.** Pick three production services at random and
   read their deployment manifests, Terraform, and CI pipelines. Every
   `Secret`, `secretKeyRef`, `${{ secrets.* }}`, env var with `KEY`,
   `TOKEN`, or `PASSWORD` in the name, and every cloud IAM principal
   used by the workload must appear in the inventory or be explained.
2. **Owner check.** Send each row to its named owner. If anyone
   replies "this is not mine", the row is unowned — find an owner
   before continuing.
3. **Classification spot-check.** For every T1 row, write one sentence
   describing what an attacker does in the first ten minutes after
   compromise. If the sentence is weaker than for any T2 row, the
   tiers are wrong.
4. **Issuance check.** Confirm each row's "Issuer" column points to
   exactly one system. Two issuers means duplicate secrets — pick one
   and decommission the other.
5. **Cross-reference to scanning.** Run a credential scanner (Gitleaks,
   TruffleHog, or equivalent) across application repos, infrastructure
   repos, container images, and CI logs. Every finding must either
   match an inventory row or be added as a new one.
6. **Cross-reference to runtime.** List the secrets actually mounted
   into running pods (`kubectl get secret -A`, plus any external
   secrets the pods retrieve). Reconcile against the inventory.

## 4. Rubric / review checklist

| Criterion | Pass | Partial | Fail |
|---|---|---|---|
| **Coverage** | Inventory matches discovery (repos + runtime + CI scan) within 5%. | One or two known classes missing (e.g. webhook tokens). | Whole categories absent. |
| **Schema** | All required columns present and populated. | Missing one column or one column populated for < 50% of rows. | Free-form list without schema. |
| **Classification** | T0/T1/T2/T3 distinctions are defensible per the rules in §2.2. | Tiers exist but some rows are clearly mis-tiered. | One tier used for everything. |
| **Ownership** | One named owner per row; no "team@" placeholders. | Mix of named and team owners. | Owner column blank or "ops". |
| **Blast radius** | Concrete per row (which system, which data). | Generic phrases like "data leak". | Column absent. |
| **Migration path** | Long-lived secrets have a named replacement mechanism. | Some rows flagged, others ignored. | No replacement plan. |
| **Issuance hygiene** | T0 secrets separated, with distinct access list. | T0 mixed in but flagged. | T0 not distinguished. |
| **Honesty about gaps** | "Unknown" / "investigate" entries are present where appropriate. | Some unknowns hidden as guesses. | Inventory looks complete but is fabricated. |

## 5. Common mistakes

- **Listing the secret store rather than the secrets.** "Vault" is not
  an inventory entry; the individual paths within Vault are.
- **Inventory only of the secret store.** Vault contains some secrets;
  the rest are in GitHub Actions variables, `.env` files, laptops, and
  Terraform state. An inventory limited to one store misses most of
  the surface.
- **Conflating secrets with identities.** A service account *has* a
  token; the token is the secret. Listing "service account foo" without
  the token disclosure path makes the rotation row meaningless.
- **Tier inflation.** Marking everything T1 because "all secrets are
  important". Tiers exist to drive *prioritisation*; a flat tier is no
  tier.
- **Ignoring CI secrets.** GitHub Actions / GitLab CI variables are
  long-lived bearer tokens with production blast radius; they are
  routinely the highest-impact entries and the most-often-omitted.
- **Counting public material as secret.** Public keys and public OAuth
  client IDs in the inventory inflate volume and obscure real risk.
- **"Rotation: as needed".** This is a synonym for "never". If a
  cadence is not in days, it is not a cadence.
- **No migration path column.** Without it, the inventory becomes a
  status report rather than a backlog.

## 6. References

- OWASP Secrets Management Cheat Sheet —
  <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>
  (inventory, classification, lifecycle guidance).
- OWASP Machine Learning Security Top 10 —
  <https://owasp.org/www-project-machine-learning-security-top-10/>
  (ML-specific abuse cases motivating tiering of model-signing and
  model-registry credentials).
- MITRE ATLAS — <https://atlas.mitre.org/>
  (techniques against ML systems that depend on credential disclosure,
  notably `Valid Accounts` analogues in the ATLAS matrix).
- NIST AI Risk Management Framework —
  <https://www.nist.gov/itl/ai-risk-management-framework>
  (Govern/Map functions: asset and dependency inventories).
- NIST SP 800-57 Part 1 Rev. 5, *Recommendation for Key Management* —
  <https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final>
  (cryptoperiods, classification of key material).
- NIST SP 800-53 Rev. 5, control families `CM-8` (system component
  inventory) and `IA-5` (authenticator management) —
  <https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final>.

