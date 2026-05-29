# SOLUTION — Exercise 04: Keyless CI Design

## 1. Solution overview

"Keyless CI" is the goal of removing long-lived credentials from CI/CD
systems by replacing them with short-lived, workload-bound tokens
minted at job time via OpenID Connect (OIDC) federation. The
deliverable is a design that (a) lets a CI job push container images,
model artefacts, and infrastructure changes to production without any
long-lived secret in the CI store, and (b) signs the artefacts it
produces with keyless signatures (Sigstore Cosign + Fulcio + Rekor) so
that downstream verifiers can validate them without holding a public
key per signer.

This solution presents a worked design for GitHub Actions → AWS (the
most commonly examined combination) with notes on porting to GCP,
Azure, and GitLab CI. The exercise is design-with-implementation; the
config snippets are statically valid and grounded in the upstream
documentation cited in §6.

## 2. Implementation (worked answer)

### 2.1 Reference architecture

```
                    ┌─────────────────────────────┐
                    │   GitHub Actions runner     │
                    │  (job claim → OIDC token)   │
                    └────────────┬────────────────┘
                                 │  signed JWT (audience: cloud STS)
                ┌────────────────┼──────────────────────────┐
                ▼                ▼                          ▼
    ┌──────────────────┐  ┌──────────────────┐    ┌─────────────────────┐
    │  AWS STS         │  │  Sigstore Fulcio │    │  Vault (OIDC auth)  │
    │ AssumeRoleWith-  │  │ short-lived cert │    │ short-lived token   │
    │   WebIdentity    │  │ bound to claim   │    │ scoped policy       │
    └────────┬─────────┘  └────────┬─────────┘    └──────────┬──────────┘
             │ STS creds (1h)      │ x509 + Rekor entry      │ Vault token (≤job TTL)
             ▼                     ▼                         ▼
       ECR / S3 push        Cosign sign + attest       Pull build-time secrets
                                                       (vendor API keys etc.)
```

Two pillars:

1. **No stored credentials.** Every token the job uses is minted on
   demand from the OIDC claim, with a TTL ≤ job duration.
2. **Every artefact is signed and attested** by a transient identity
   bound to the same OIDC claim, recorded in a public (or internal)
   transparency log.

### 2.2 Cloud federation (push path)

**AWS — IAM OIDC provider + role trust policy.**

```yaml
# .github/workflows/build-and-push.yml
name: build-and-push
on:
  push:
    branches: [main]

permissions:
  id-token: write   # required for OIDC token issuance
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Assume AWS role via OIDC
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::111111111111:role/ci-ml-build
          aws-region: us-east-1
          # No access keys.

      - name: Build, sign, push (see §2.3)
        run: ./scripts/build-sign-push.sh
```

The IAM role trust policy uses GitHub's OIDC provider and scopes the
trust to specific subjects:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub":
            "repo:my-org/ml-platform:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

Subject conditions are the *only* control preventing unrelated repos
or branches from assuming the role. The pattern above:

- Pins to a single repo (`my-org/ml-platform`).
- Pins to a single ref (`main`). Tag-driven release roles pin to
  `ref:refs/tags/*`.
- Never uses `repo:my-org/*` — a wildcard at the org level allows any
  repo in the org (or any fork temporarily under the org) to assume
  the role.

The role's permissions policy is the minimum necessary: `ecr:Push` to
the specific repository, `s3:PutObject` to the model-artifact prefix,
and nothing else. CloudTrail records every `AssumeRoleWithWebIdentity`
with the OIDC `sub` claim attached, so audits trace artefacts back to
the workflow file and commit.

**GCP — Workload Identity Federation.** The equivalent uses
`WorkloadIdentityPool` + `WorkloadIdentityProvider` with an attribute
mapping that gates by `repository`, `ref`, and `workflow_ref`. The
GitHub action `google-github-actions/auth@v2` performs the exchange.

**Azure — federated identity credentials on an App Registration**,
scoping `subject` and `issuer` analogously.

**GitLab CI** issues its own OIDC tokens (`CI_JOB_JWT_V2`); the same
cloud-side configuration applies with the GitLab issuer.

### 2.3 Artefact signing (keyless) and attestation

```bash
#!/usr/bin/env bash
# scripts/build-sign-push.sh
set -euo pipefail

IMAGE="111111111111.dkr.ecr.us-east-1.amazonaws.com/ml-inference"
TAG="$(git rev-parse --short HEAD)"
REF="${IMAGE}:${TAG}"

# 1) Build (reproducible-ish — pinned base, no implicit network).
docker buildx build --pull --no-cache --provenance=true -t "${REF}" .

# 2) Push to a registry the cluster pulls from. No registry creds in
#    CI — the STS credentials from §2.2 authenticate to ECR.
docker push "${REF}"

# 3) Keyless sign. Cosign mints a short-lived x509 cert from Fulcio
#    bound to the OIDC identity of this workflow run and records the
#    signature in Rekor's transparency log.
COSIGN_EXPERIMENTAL=1 cosign sign --yes "${REF}"

# 4) In-toto SLSA provenance attestation, also keyless.
cosign attest --yes --predicate provenance.json \
  --type slsaprovenance "${REF}"

# 5) (ML-specific) Sign the model artefact the same way.
cosign sign-blob --yes \
  --output-signature model.sig \
  --output-certificate model.crt \
  ./artefacts/model.tar.gz
aws s3 cp ./artefacts/model.tar.gz \
  s3://ml-artefacts/${TAG}/model.tar.gz
aws s3 cp ./model.sig "s3://ml-artefacts/${TAG}/model.sig"
aws s3 cp ./model.crt "s3://ml-artefacts/${TAG}/model.crt"
```

Verification at the cluster (Kyverno / Sigstore policy controller):

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: require-ml-inference-keyless
spec:
  images:
    - glob: "111111111111.dkr.ecr.us-east-1.amazonaws.com/ml-inference*"
  authorities:
    - keyless:
        url: https://fulcio.sigstore.dev
        identities:
          - issuer: https://token.actions.githubusercontent.com
            subject: "https://github.com/my-org/ml-platform/.github/workflows/build-and-push.yml@refs/heads/main"
      ctlog:
        url: https://rekor.sigstore.dev
```

The cluster trusts the signature only when the certificate proves:

1. The signer is the Fulcio CA.
2. The OIDC issuer is GitHub.
3. The `subject` field of the cert matches the *workflow file* and
   *ref* expected for this image stream.
4. Rekor contains the signature entry (transparency).

A model loader applies the equivalent check to model artefacts:

```python
# pseudocode
verify_keyless(
    blob_path="model.tar.gz",
    signature="model.sig",
    certificate="model.crt",
    expected_issuer="https://token.actions.githubusercontent.com",
    expected_subject_regex=(
        r"^https://github\.com/my-org/ml-platform/"
        r"\.github/workflows/build-and-push\.yml@refs/heads/main$"
    ),
    rekor_url="https://rekor.sigstore.dev",
)
```

### 2.4 Secrets the CI still needs (and how to fetch them keyless-ly)

Some inputs the build genuinely needs are not held by the cloud (e.g.
a vendor LLM API key for evaluation, an internal package registry
token). These come from Vault via OIDC auth (exercise-02 §2.2), not
from a CI secret store:

```bash
# scripts/fetch-build-secrets.sh
set -euo pipefail

JWT="${ACTIONS_ID_TOKEN_REQUEST_TOKEN}"
URL="${ACTIONS_ID_TOKEN_REQUEST_URL}"
TOKEN_RESPONSE=$(curl -sSf -H "Authorization: bearer ${JWT}" \
  "${URL}&audience=vault")

OIDC_TOKEN=$(echo "${TOKEN_RESPONSE}" | jq -r '.value')

VAULT_TOKEN=$(vault write -field=token auth/jwt/login \
  role=ci-ml-build jwt="${OIDC_TOKEN}")
export VAULT_TOKEN

# Pull short-lived build-time secrets; TTL ≤ job runtime.
LLM_KEY=$(vault kv get -field=key prod/kv/eval/llm-vendor)
export LLM_KEY
```

`role=ci-ml-build` in Vault constrains the bound subject the same way
the AWS trust policy does, so a different workflow cannot trade its
token for these secrets. The Vault token TTL is shorter than the job
timeout; when the job ends, all credentials are gone.

### 2.5 Threats this design addresses (and how)

| Threat | Mitigation |
|---|---|
| Long-lived CI secret stolen from GitHub Actions secret store. | No long-lived credentials stored; nothing to steal. |
| Forked repository runs malicious workflow in the org. | Subject condition pins to the canonical repo + branch + workflow file. |
| Compromised maintainer pushes a malicious workflow to `main`. | Same federation works, *but* the artefact signature ties the resulting image to a specific workflow file + commit. Detection is via Rekor log monitoring; branch protection + required reviews are still needed to prevent the push. |
| Image swapped between push and pull. | Cluster admission policy verifies the signature and rejects unsigned images. |
| Model swapped between push and load. | Model loader verifies the cosign blob signature. |
| Replay of a stolen short-lived token. | Token is bound to the cloud STS audience; STS credentials are bound to a single role and expire ≤1h. |
| Transparency-log absence (signature created off-log). | Cluster policy requires Rekor entry; absence = rejection. |

What this design does *not* address by itself:

- Compromise of the OIDC issuer (GitHub) — defended by transparency
  log audit and out-of-band attestation review.
- Compromise of the Fulcio CA — defended by Rekor's transparency log
  + cross-checking signing identities.
- Build determinism — keyless signing proves the *signer*, not the
  *build inputs*. SLSA provenance attestations close part of that
  gap; reproducible builds close more.
- Compromised model training data — see project-3 / mod-007.

### 2.6 Design decisions

- **Sigstore keyless (Cosign + Fulcio + Rekor)** rather than GPG or
  HSM-pinned signing keys. Short-lived certs bound to OIDC identities
  remove the key-storage burden and add a public transparency
  guarantee.
- **OIDC federation to the cloud directly**, not via a self-hosted
  "broker" pod that holds a long-lived cloud key on behalf of CI. A
  broker reintroduces the long-lived secret.
- **OIDC federation to Vault for in-cluster secrets**, rather than a
  long-lived Vault token in GitHub Actions secrets.
- **Subject-pinned trust**, not org-wide trust. The trust policy must
  name the specific repository, branch/tag, and (ideally) workflow
  file.
- **Signature *and* attestation**, not signature alone. A signature
  proves "this artefact came from a trusted signer"; an attestation
  proves "this artefact was built with these inputs by that
  pipeline".
- **Cluster-side verification**, not CI-side verification. The CI
  runner is not a trust anchor; the cluster's admission controller
  is.
- **Model artefacts treated like containers.** A poisoned model with
  a clean container produces a clean image signature; the model needs
  its own signature.

### 2.7 What this solution deliberately omits

- Self-hosted Sigstore (internal Fulcio + Rekor). Operationally
  significant; only relevant when public Sigstore is disallowed by
  policy.
- HSM-rooted release signing layered over keyless. Justified for
  release-grade artefacts; not a default.
- Reproducible builds with bit-for-bit verification. Cosign signs
  the artefact; reproducibility is a separate property.
- Cross-cloud federation (one OIDC token traded across multiple
  clouds in one job). Doable but adds complexity; usually it is
  cleaner to split per-cloud jobs.

## 3. Validation steps

1. **Static checks.**
   - The IAM role trust policy's `sub` condition contains no wildcard
     above the repository.
   - The role's permissions policy is the minimum set required to
     push the named artefact (no `*` on `Resource`, no `iam:*`).
   - The GitHub workflow has `permissions: id-token: write` and no
     long-lived credential reads.

2. **Federation test.**
   - Trigger the workflow from `main`; confirm an AWS access-key-free
     `aws sts get-caller-identity` succeeds and the resulting role
     matches the expected role.
   - Trigger the workflow from a branch *other* than `main`;
     federation must fail (`AccessDenied` from STS) because the `sub`
     condition does not match.
   - Trigger the workflow from a fork; federation must fail.

3. **Signing test.**
   - Build a deliberately unsigned image and attempt to deploy it via
     the cluster admission policy; deployment must be rejected.
   - Build a signed image but tamper with the manifest in registry;
     cosign verification must fail.
   - Build a signed image with a different workflow file; the
     ClusterImagePolicy must reject it (`subject` mismatch).

4. **Attestation test.**
   - Confirm the in-toto provenance attestation references the
     correct commit and builder. A divergence between the provenance
     and the deployed image must be rejected by the policy.

5. **Vault federation test.**
   - From the workflow, exchange the OIDC token for a Vault token
     and read a secret. Confirm the Vault audit log shows the
     correct `bound_audiences`, `bound_subject`, and TTL.
   - Attempt the same exchange with a forged `audience` claim;
     Vault must reject.

6. **Transparency check.**
   - Confirm every signed image has a Rekor entry. Stand up a
     periodic verifier that scans Rekor for entries signed under
     unexpected subjects (a basic transparency-log monitor).

7. **Negative drill.**
   - Disable the cluster ClusterImagePolicy temporarily; verify the
     monitoring catches the policy gap before any production
     deployment.

## 4. Rubric / review checklist

| Criterion | Pass | Partial | Fail |
|---|---|---|---|
| **No stored long-lived credentials** | All cloud + secrets-manager access via OIDC federation. | One long-lived token retained "temporarily" with retirement plan. | CI secret store still holds production credentials. |
| **Subject pinning** | Trust policies pin to repo + branch/tag + workflow file. | Trust policies pin only to repo + branch. | Trust policies use org-wide wildcards. |
| **Least privilege** | Role permissions reduce to the specific artefact paths. | Permissions broad but bounded to one service. | Role is `*:*` or admin. |
| **Artefact signing** | Cosign keyless for images *and* model artefacts. | Images signed, models not. | No signing. |
| **Attestation** | SLSA provenance attestation alongside signature. | Signature only. | None. |
| **Transparency** | Rekor entry required by verifier; monitor in place. | Rekor entry recorded but not required. | None. |
| **Verifier placement** | Verification happens at admission (cluster) and at model load. | Verification only at CI side. | No verifier. |
| **Threat coverage** | Fork, branch swap, image swap, model swap, replay all addressed and tested. | Some threats addressed but no tests. | Threat model implicit. |
| **Documentation honesty** | What is *not* addressed (HSM, reproducibility, issuer compromise) is named. | Some gaps named. | Plan implies full coverage. |

## 5. Common mistakes

- **`StringEquals` on `sub` with a wildcard**: writing
  `repo:my-org/*` lets any repo in the org assume the role; writing
  `repo:my-org/ml-platform:*` lets any branch/tag/workflow in that
  repo assume the role. Pin to the specific ref or workflow file.
- **OIDC + a long-lived "backup" key.** "Just in case" defeats the
  point. There is no backup key.
- **Verifying signatures in CI rather than at admission.** CI is
  trusted code path; production must verify independently.
- **Signing images but not models.** A clean image + poisoned model
  passes signature checks and fails at inference.
- **Forgetting to set `permissions: id-token: write`.** Without it,
  the workflow cannot mint an OIDC token. Defaulting to "all
  permissions" instead is the wrong fix.
- **Using `actions/aws` (or equivalent) with stored access keys** in
  the same workflow that also tries OIDC. The action falls back
  silently to the static keys, and the OIDC path is never exercised.
- **No Rekor monitoring.** Signatures recorded in a log nobody reads
  give equal weight to legitimate and forged entries.
- **Reusing a single role for build, push, and deploy.** Multiple
  small roles with separate trust policies bound to separate
  workflows give a meaningful audit trail; one big role does not.
- **Self-hosting Sigstore because "compliance"** without first
  verifying compliance actually requires it. The operational burden
  is large.

## 6. References

- GitHub Actions OIDC — *Configuring OpenID Connect in cloud
  providers*:
  <https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect>
- GitHub Actions OIDC for AWS:
  <https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services>
- AWS — IAM OIDC identity providers / `AssumeRoleWithWebIdentity`:
  <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html>
- GCP — Workload Identity Federation:
  <https://cloud.google.com/iam/docs/workload-identity-federation>
- Azure — Federated identity credentials:
  <https://learn.microsoft.com/azure/active-directory/workload-identities/workload-identity-federation>
- Sigstore project — Cosign / Fulcio / Rekor:
  <https://docs.sigstore.dev/>
- Sigstore Policy Controller for Kubernetes admission:
  <https://docs.sigstore.dev/policy-controller/overview/>
- SLSA (Supply-chain Levels for Software Artifacts):
  <https://slsa.dev/>
- HashiCorp Vault — JWT/OIDC auth method:
  <https://developer.hashicorp.com/vault/docs/auth/jwt>
- NIST SP 800-204D (Strategies for the Integration of Software
  Supply Chain Security in DevSecOps CI/CD Pipelines):
  <https://csrc.nist.gov/publications/detail/sp/800-204d/final>
- NIST AI Risk Management Framework — Govern / Map (supply-chain
  controls for AI components):
  <https://www.nist.gov/itl/ai-risk-management-framework>
- OWASP Machine Learning Security Top 10 (ML07 / ML10 — supply
  chain, model poisoning):
  <https://owasp.org/www-project-machine-learning-security-top-10/>
- MITRE ATLAS — supply-chain compromise techniques against ML:
  <https://atlas.mitre.org/>

