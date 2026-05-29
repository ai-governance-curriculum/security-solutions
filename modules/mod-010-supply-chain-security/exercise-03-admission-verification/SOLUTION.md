# SOLUTION — Exercise 03: Admission Verification Configuration

Reference solution for configuring a Kubernetes admission controller
to verify Sigstore signatures and SLSA attestations before pods are
admitted.

## 1. Solution overview

The exercise asks for a working admission configuration that:

- Rejects any pod whose image is not signed by the expected identity.
- Rejects any pod whose image is signed but missing a SLSA provenance
  attestation that names the expected source repository.
- Logs (does not block) on first rollout so failures can be
  attributed before enforcement is turned on.
- Has a documented break-glass path that does not silently disable
  verification.

Two equivalent reference implementations are provided. Both are
official, supported projects; choose one per cluster, not both.

- **Sigstore policy-controller** — sigstore.dev's purpose-built
  admission controller. Configuration model is a `ClusterImagePolicy`
  CRD.
- **Kyverno** — general-purpose policy engine with a `verifyImages`
  rule that calls the cosign verification library under the hood.
  Used when a cluster already standardizes on Kyverno for other
  policy needs.

Both speak the same Sigstore verification model (Fulcio identity +
Rekor transparency log entry) per the Sigstore documentation.

## 2. Worked implementation

### Option A — sigstore policy-controller

Installation: per the Sigstore *policy-controller* documentation.
The policy below requires images in the `ml-prod` namespace to be
signed by the build workflow's identity and to carry a SLSA v1.0
provenance attestation.

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: require-signed-and-attested
spec:
  images:
    - glob: "ghcr.io/example/**"
  authorities:
    - name: ci-keyless
      keyless:
        url: https://fulcio.sigstore.dev
        identities:
          - issuer: https://token.actions.githubusercontent.com
            subjectRegExp: >-
              ^https://github.com/example/inference-svc/\.github/workflows/signed-build\.yml@refs/tags/v.*$
      ctlog:
        url: https://rekor.sigstore.dev
      attestations:
        - name: slsa-provenance
          predicateType: https://slsa.dev/provenance/v1
          policy:
            type: cue
            data: |
              predicate: {
                buildDefinition: {
                  externalParameters: {
                    workflow: {
                      repository: "https://github.com/example/inference-svc"
                    }
                  }
                }
              }
```

Namespace selector enables only where intended:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: ml-prod
  labels:
    policy.sigstore.dev/include: "true"
```

### Option B — Kyverno

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-and-attested
spec:
  validationFailureAction: Enforce
  background: false
  webhookTimeoutSeconds: 30
  rules:
    - name: verify-image-signature
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [ml-prod]
      verifyImages:
        - imageReferences:
            - "ghcr.io/example/*"
          attestors:
            - entries:
                - keyless:
                    issuer: https://token.actions.githubusercontent.com
                    subject: >-
                      https://github.com/example/inference-svc/.github/workflows/signed-build.yml@refs/tags/v*
                    rekor:
                      url: https://rekor.sigstore.dev
          attestations:
            - type: https://slsa.dev/provenance/v1
              attestors:
                - entries:
                    - keyless:
                        issuer: https://token.actions.githubusercontent.com
                        subject: >-
                          https://github.com/slsa-framework/slsa-github-generator/.github/workflows/*
                        rekor:
                          url: https://rekor.sigstore.dev
              conditions:
                - all:
                    - key: "{{ buildDefinition.externalParameters.workflow.repository }}"
                      operator: Equals
                      value: https://github.com/example/inference-svc
```

### Rollout strategy

Two-phase rollout to avoid breaking running workloads:

**Phase 1 — Audit (Warn).** Deploy with
`validationFailureAction: Audit` (Kyverno) or
`mode: warn` (policy-controller `ClusterImagePolicy.spec.mode`). For
a documented window (e.g. one week), every reject becomes a
policy-report event but the pod still runs. Triage the list, fix the
producers.

**Phase 2 — Enforce.** Flip to `Enforce` / `enforce`. Workloads that
still produce events at this point are pre-identified exceptions —
file each as a tracked policy exception, not a silent allow.

### Break-glass

A break-glass that disables the entire policy is itself a supply-chain
risk. The supported pattern:

- A namespace-scoped exception with an annotation that names a
  ticket, an owner, and an expiry timestamp.
- A scheduled job (or external monitoring) that alerts when the
  exception is still in place after the expiry.
- The exception is committed via GitOps so the audit trail is the
  same as any other policy change.

Do **not** add a "cluster-admin bypass" label or annotation. The
controller is the trust boundary; an admin annotation that bypasses
the controller moves the trust boundary onto whoever has the
annotation.

## 3. Validation steps

1. **Positive test.** Deploy a pod whose image is signed by the
   pinned identity and carries the SLSA attestation. It must be
   admitted.
2. **Missing-signature test.** Push a stray image to the registry
   without signing. Deploy. It must be rejected with a message
   naming the missing signature.
3. **Wrong-identity test.** Sign an image with a different OIDC
   identity (e.g. a fork's workflow). It must be rejected with a
   message naming the identity mismatch.
4. **Wrong-source-repo test.** Sign an image correctly but supply a
   provenance attestation whose `externalParameters.workflow.repository`
   does not match. It must be rejected on the attestation check, not
   on the signature.
5. **Rekor-down failure mode.** Block egress to `rekor.sigstore.dev`
   on a test node and observe the controller's behavior. The
   documented behavior must match what the exercise describes — the
   common safe default is *fail closed*. Decide and document.
6. **Break-glass test.** Apply an exception with an expired
   annotation. The monitoring path must page within the documented
   SLA. If it does not, the exception process is not load-bearing —
   redesign it.

## 4. Rubric — review checklist

| Check | Pass criteria |
|---|---|
| Identity is pinned (`issuer` + `subject`/`subjectRegExp`) | Both fields named |
| Attestation type is required, not just signature | `slsaprovenance` / `https://slsa.dev/provenance/v1` referenced |
| Rollout has an audit phase | Audit / warn mode and triage window documented |
| Break-glass is time-bound and observable | Annotation expiry + alert documented |
| Behavior when Rekor is unreachable is named | Fail-closed or fail-open chosen explicitly |
| Policy lives under GitOps | Yes |
| Negative tests are written down and run | At least three from §3 |
| No `cluster-admin` blanket bypass | Reviewer confirms absence |

## 5. Common mistakes

- **Pinning only the OIDC issuer.** `issuer:
  token.actions.githubusercontent.com` matches *every* GitHub Actions
  workflow on the public Internet. Without a subject pin, anyone who
  can run GitHub Actions can sign for your policy. Always pair issuer
  with subject.
- **Verifying signature but not attestation.** A signature only says
  "someone signed this digest." It does not say "from this source
  repo, on this workflow." For supply-chain integrity, the
  attestation check is the load-bearing one.
- **Going straight to Enforce.** Without an audit phase, the first
  enforcement event is a production outage during business hours.
  Start in audit, triage, then enforce.
- **A blanket bypass label.** Any unconditional allow that an
  attacker who reaches the cluster can apply nullifies the policy.
- **Forgetting the model artifact.** The admission controller covers
  *images*. Models are pulled at runtime by the workload. The
  serving runtime must perform the equivalent `cosign verify-blob`
  check itself (see exercise-02). The cluster policy is not enough.
- **Allowing wildcard image references.** `glob: "*"` or
  `imageReferences: ["*"]` includes the controller's own images,
  init containers, and any sidecar. Either scope to namespaces and
  registries you control, or pair with explicit allow-lists for
  third-party images.

## 6. References

- Sigstore documentation — <https://docs.sigstore.dev/>
- Sigstore policy-controller — referenced from the Sigstore project
  documentation
- Kyverno `verifyImages` rule — Kyverno project documentation
- SLSA v1.0 — <https://slsa.dev/spec/v1.0/>
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>
- MITRE ATLAS — <https://atlas.mitre.org/>
- Local cross-reference: [`projects/project-4-secure-cicd`](../../../projects/project-4-secure-cicd)
