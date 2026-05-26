# SOLUTION — Secure ML CI/CD

> Read this *after* attempting the learning-side project. This file
> explains the design decisions behind the pipeline, what makes it
> "secure" rather than just "automated", and what is deliberately
> simplified.

## What problem this solves

A standard CI/CD pipeline answers "does this build pass tests?" — a
*secure* CI/CD pipeline answers four additional questions before any
artifact reaches production:

1. **Provenance** — what built this, from what source, on what
   infrastructure? (SLSA levels)
2. **Composition** — what is *in* this artifact? (SBOM)
3. **Integrity** — is what I'm running what was built? (signing +
   attestation verification at admission)
4. **Trust path** — at every step, who signed off, with what authority?

For ML the picture is broader still: the artifact isn't just a
container, it's also a model file with its own provenance (training
data, training code, training run ID).

## Architecture decisions and *why*

### Why cosign + Sigstore (not GPG, not HSM-only)

GPG has poor key-rotation ergonomics in CI and a confused trust model
(WoT in a context that wants identity-bound trust). HSM-only signing
works but takes weeks to operationalize. Cosign with keyless signing
(OIDC-bound transient keys, recorded in Rekor's transparency log) is
the modern default — short-lived keys, public verifiability, no
private-key management.

A real production deployment can layer HSM-backed keys on top for the
cases that require them (release signing), keeping keyless for everyday
build artifacts.

### Why in-toto attestations layered on cosign signatures

Cosign answers "this artifact is signed by X." in-toto attestations
add: "this artifact was built by *this* pipeline, on *this* commit, with
*these* dependencies, producing *these* outputs." Admission policies
then verify the attestation, not just the signature.

### Why Kyverno admission policies at the cluster boundary

You can verify signatures and attestations at deploy time in the CI
runner — but that's the wrong place. CI is trusted code; the cluster
is where untrusted artifacts could land via any pathway (manual
`kubectl apply`, GitOps sync, third-party operator). Verifying at
admission means *every* path that creates a pod is forced through the
same trust check.

### Why model artifact signing in addition to container signing

Container signing covers code; it does *not* cover the model file
that gets pulled at runtime from an MLflow registry or S3 bucket. A
poisoned model with a clean container produces a clean signature but
a backdoored prediction surface. `model-signing/sign_model.sh` applies
cosign to the model artifact itself, and the serving runtime verifies
before loading.

### Why a GitOps promotion path (vs. direct push)

CI pushes artifacts; GitOps pulls them. The cluster never has a CI
credential. A compromised CI runner can only push to an artifact
registry — it cannot directly mutate a cluster. The promotion across
environments goes through a Git PR with reviewers, which is itself
auditable.

## How to read the code

Execution-order reading path:

1. `ci-examples/secure-pipeline.yml` — top to bottom is the build flow:
   checkout → SBOM → vulnerability scan → build → sign → attest → push.
2. `model-signing/sign_model.sh` — how the model artifact gets the same
   treatment as the container.
3. `tests/bypass_attempts.sh` — the threat model in executable form:
   each test simulates an attacker trying to skip a control.
4. Cross-reference to `engineer-solutions/mod-103 ex-10` for the
   reference SBOM + supply-chain pipeline, and to
   `engineer-solutions/mod-109 ex-08` for the Kyverno admission policies
   that verify the produced attestations at the cluster.

## What's deliberately simplified

- **No reproducible builds.** A truly reproducible build (bit-for-bit
  identical output from identical inputs) requires a Nix-style build
  system or careful flag-pinning. The pipeline here pins versions but
  does not guarantee determinism.
- **No air-gapped registry mirror.** A regulated deployment would mirror
  every external image into an internal registry with scanning at ingress.
- **No automated CVE-triage workflow.** Vulnerability scanning produces
  a report; humans triage. The hand-off is documented but not
  automated.
- **Single signing identity.** Production typically uses multiple
  identities (CI, release manager, release engineer) with role-bound
  signing keys.

## Cross-references for deeper coverage

| Topic | Where the deeper implementation lives |
|---|---|
| SBOM generation + signed attestations | `engineer-solutions/mod-103 exercise-10-sbom-and-supply-chain` |
| Vulnerability remediation workflow | `engineer-solutions/mod-103 exercise-12-vulnerability-remediation` |
| GitOps with ArgoCD | `engineer-solutions/mod-109 exercise-06-gitops-argocd` |
| Kyverno admission policies | `engineer-solutions/mod-109 exercise-08-policy-as-code/kyverno` |
| Multi-env promotion pipeline | `engineer-solutions/mod-109 exercise-10-multi-environment-promotion` |
| Audit chain for model deployments | `mlops-learning/projects/project-4-governance/src/audit/log.py` |

## Production gap checklist

- [ ] Reproducible builds (Nix, or pinned + locked toolchain)
- [ ] Air-gapped internal registry mirror with scanning at ingress
- [ ] Automated CVE-triage with SLA-driven escalation
- [ ] Role-bound signing identities (release vs. CI)
- [ ] Hardware-backed root of trust for release-signing identities
- [ ] Continuous attestation revalidation (not just at admission)
- [ ] Build-system provenance achieving SLSA level 3 or 4
- [ ] Verifiable model lineage (training dataset hashes signed alongside the model)

## Validation

`tests/bypass_attempts.sh` is the acceptance test. Each step in the
script tries to:

- Deploy a container without a signature.
- Deploy a container with a signature but no attestation.
- Deploy a container with an attestation that references the wrong commit.
- Load a model without a valid signature.

Each attempt must be rejected. If any succeeds, find which control
failed open before moving on.

## Time budget for studying this solution

- **Skim**: 45 min — read this file, scan the pipeline YAML, run
  `bypass_attempts.sh` against a local cluster.
- **Deep**: 1 week — re-implement the pipeline against a different
  registry and a different model store. Most of the learning happens
  when you have to wire the attestation verification policy yourself.
