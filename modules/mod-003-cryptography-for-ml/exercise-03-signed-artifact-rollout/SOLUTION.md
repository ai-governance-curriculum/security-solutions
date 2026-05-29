# SOLUTION — Exercise 03: Signed-Artifact Rollout Plan

> Read this *after* drafting your own rollout. It is the worked plan,
> the policy artifacts, and the rubric.

## 1. Solution overview

The goal is to ship a signed-artifact policy that covers every
*executable* the ML platform consumes — container images, base OS
images, Helm charts, ML model weights, and the build attestations that
prove how each was produced — and to do it in phases so that a broken
signer or stale public key cannot take production down.

The reference stack is:

- **Signing:** Sigstore `cosign` (Ed25519 / ECDSA P-256, or keyless via
  Fulcio + Rekor transparency log).
- **Provenance:** in-toto attestations following the **SLSA**
  framework, currently SLSA v1.0.
- **Verification:** an admission controller (Kyverno / Gatekeeper /
  policy-controller / Connaisseur) that runs `cosign verify` on every
  image and refuses unsigned or unverified images.
- **Trust roots:** Sigstore public good (default) or a private
  Fulcio/Rekor (preferred for enterprise) so the trust chain doesn't
  depend on a third party.

The rollout is **observe → enforce in dev → enforce in prod**, with a
break-glass procedure and a key-compromise drill.

## 2. Implementation — worked answer (the rollout)

### 2.1 Inventory of artifacts that must be signed

| Artifact class                     | Producer                        | Signer family (from KMP) |
|------------------------------------|----------------------------------|--------------------------|
| Base OS images                     | platform team (or vendor)        | KF-11 (CI signer)        |
| Application container images       | service CI                       | KF-11                    |
| Helm charts / Kustomize bundles    | platform CI                      | KF-11                    |
| ML model weights (`.safetensors`)  | training pipeline                | KF-06 (model signing hot)|
| Model metadata + datasets manifest | training pipeline                | KF-06                    |
| Eval / red-team report             | evaluation pipeline              | KF-06                    |
| Third-party model imports          | platform team (re-signed)        | KF-06                    |
| SLSA build provenance              | build platform (GitHub OIDC etc) | KF-11 (keyless)          |

KF-06 and KF-11 are the families defined in
[[exercise-01-key-management-plan]] §2.3.

### 2.2 Trust topology

- **Model signing root** (KF-05) lives in an offline HSM. It signs a
  short-lived **model signing intermediate** (KF-06) used by the
  training pipeline.
- **CI signing** uses Sigstore *keyless* with the OIDC identity of
  the build runner (e.g., `repo:owner/name:ref:refs/heads/main`).
  Public good Fulcio + Rekor is the default; private Fulcio/Rekor is
  the production option for an org with compliance requirements.
- **Verification trust bundle** is pinned per environment:
  - dev: Sigstore public good
  - staging + prod: private Fulcio root + Rekor public key

Trust roots are distributed via the **TUF** repository that Sigstore
ships with (`root.json`) — admission controllers refresh the bundle
from there on a schedule.

### 2.3 Signing flow (per artifact class)

#### Container image
```sh
# CI step — keyless, OIDC-bound identity.
COSIGN_EXPERIMENTAL=1 cosign sign \
  --yes \
  "${IMAGE}@${DIGEST}"

# Produce + attach SLSA provenance.
cosign attest --yes \
  --predicate provenance.json \
  --type slsaprovenance \
  "${IMAGE}@${DIGEST}"

# Produce + attach SBOM.
cosign attest --yes \
  --predicate sbom.spdx.json \
  --type spdxjson \
  "${IMAGE}@${DIGEST}"
```

Always sign by digest, never by tag — tags are mutable and a tag-only
signature is a known weakness.

#### Model artifact (registered as an OCI artifact)
```sh
# Bundle model + metadata into an OCI artifact (model.ref).
cosign sign --yes --key awskms:///alias/model-signing-hot \
  "${MODEL_REGISTRY}/${MODEL}@${DIGEST}"

# Attest evaluation report.
cosign attest --yes --key awskms:///alias/model-signing-hot \
  --predicate eval-report.json \
  --type https://mlplat.example.com/attestations/model-eval/v1 \
  "${MODEL_REGISTRY}/${MODEL}@${DIGEST}"
```

For weights stored as files (not OCI), use `cosign sign-blob` and
publish the signature alongside the artifact, *or* publish the file via
OCI (recommended; gets you Rekor entries for free).

### 2.4 Verification policy

The reference policy is a Kyverno `ClusterPolicy` (Gatekeeper /
policy-controller policies look similar). One block per signer
identity; an image must satisfy *at least one* per its registry.

```yaml
# verify-images.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-platform-images
spec:
  validationFailureAction: Enforce
  background: false
  webhookTimeoutSeconds: 30
  rules:
    # A Kyverno verifyImages rule entry verifies signatures OR
    # attestations, not both — see Kyverno docs. Split into two
    # named rules so the same image must satisfy both checks.
    - name: app-images-keyless-signature
      match:
        any:
          - resources: { kinds: [Pod] }
      verifyImages:
        - imageReferences:
            - "ghcr.io/mlplat/*"
            - "registry.mlplat.example.com/apps/*"
          mutateDigest: true
          required: true
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/mlplat/*/.github/workflows/*@refs/heads/main"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: https://rekor.sigstore.dev

    - name: app-images-keyless-attestation
      match:
        any:
          - resources: { kinds: [Pod] }
      verifyImages:
        - imageReferences:
            - "ghcr.io/mlplat/*"
            - "registry.mlplat.example.com/apps/*"
          required: true
          attestations:
            - predicateType: https://slsa.dev/provenance/v1
              attestors:
                - entries:
                    - keyless:
                        subject: "https://github.com/mlplat/*/.github/workflows/*@refs/heads/main"
                        issuer: "https://token.actions.githubusercontent.com"
                        rekor:
                          url: https://rekor.sigstore.dev

    - name: model-artifacts-kms
      match:
        any:
          - resources: { kinds: [Pod] }
      verifyImages:
        - imageReferences:
            - "models.mlplat.example.com/*"
          required: true
          attestors:
            - entries:
                - keys:
                    publicKeys: |
                      -----BEGIN PUBLIC KEY-----
                      <PEM of KF-06 public key, rotated via GitOps>
                      -----END PUBLIC KEY-----
```

A second policy block enforces that an in-toto SLSA-provenance
attestation exists with the expected `builder.id` and `buildType`.

For non-K8s consumers (Vertex / SageMaker / on-host runtimes),
implement the same checks with `cosign verify` and `cosign verify-attestation`
in the model loader as a pre-load step.

### 2.5 Rollout phases

The blast radius of "refuse all unsigned images" is the entire cluster;
do this in phases.

| Phase | Duration | Action                                                                 | Exit criterion                                                                 |
|-------|----------|------------------------------------------------------------------------|--------------------------------------------------------------------------------|
| 0     | 2 weeks  | Sign all platform-owned images in CI. Do **not** verify.               | 100% of platform CI jobs emit cosign sig + provenance + SBOM.                  |
| 1     | 2 weeks  | Deploy Kyverno in `Audit` mode for `verify-platform-images`.           | Audit reports show zero unsigned platform images in dev / staging.             |
| 2     | 1 week   | Switch dev to `Enforce`.                                               | No new dev incidents attributable to verification.                             |
| 3     | 2 weeks  | Switch staging to `Enforce`. Onboard model artifacts.                  | All model registry artifacts signed by KF-06.                                  |
| 4     | 1 week   | Run a **break-glass + key-compromise drill** in staging.               | Drill PASSES (see §2.7).                                                       |
| 5     | 2 weeks  | Switch prod to `Enforce`, image policy first.                          | Prod admission decisions clean for 7 days.                                     |
| 6     | 2 weeks  | Enforce model-artifact verification on inference + training runtimes.  | All model loads in prod present a verified signature + eval attestation.       |

Every phase is rollback-safe: a single policy `Action: Audit` reverts
enforcement.

### 2.6 Break-glass procedure

Used when production is broken *because of verification* and the fix
can't ship through the normal signed path. Steps:

1. Page security on-call + platform on-call.
2. Apply the pre-staged `disable-verify-images` policy (annotated
   `break-glass=true`) **scoped to the affected namespace only**.
3. Deploy the fix.
4. Within 60 minutes, remove the break-glass policy and re-verify.
5. File an incident report including: who paged, why bypass was
   needed, what shipped unsigned, how it was made signed afterwards.

The break-glass policy must:
- Be scoped to a namespace, not cluster-wide.
- Auto-expire (CronJob deletes it after 1h).
- Emit an audit event to the SIEM.

### 2.7 Key-compromise drill

Required exit criterion for phase 4.

1. Inject a "compromised" KF-06 by adding a second public key to the
   verifier in a controlled namespace.
2. Sign a malicious-looking artifact with the rogue key.
3. Confirm admission allows it (proves the test is valid).
4. Revoke the rogue key by removing it from the verifier policy and
   adding it to a deny-list / Rekor monitor query.
5. Confirm admission now denies it.
6. Time-to-detect, time-to-revoke, and time-to-remediate are recorded.

The same drill is repeated annually.

### 2.8 Monitoring

- **Rekor monitor.** Query Rekor (`rekor-cli search --email <signer>`)
  on a schedule for entries that don't correspond to a known build.
- **Admission decisions.** Export Kyverno / policy-controller metrics:
  `policy_results_total{result="fail"}` and alert on a step change.
- **Cert-manager** monitors KF-06 cert expiry for the model signing
  intermediate.
- **Inference loader** logs `model_verify=ok|fail` for every load.

## 3. Validation steps

A reviewer / CI job can confirm:

1. Sign a test image in CI; `cosign verify` succeeds against the
   policy bundle.
2. Push an image without a signature; admission rejects it with a
   recognizable error mentioning the policy rule.
3. Tamper with a signed image's layer; `cosign verify` fails on
   digest mismatch.
4. Tamper with a SLSA attestation predicate; `cosign verify-attestation`
   fails.
5. Tag-only reference is rejected (`mutateDigest: true` in policy
   normalizes tag → digest at admission; unresolvable digest = deny).
6. The break-glass policy auto-expires.
7. Rotating the KF-06 public key via GitOps does not cause downtime
   (verify both old and new keys are accepted during the overlap).
8. The Rekor monitor query returns the known list and nothing else.

## 4. Rubric / review checklist

Score 0 / 1 / 2; pass at ≥80%.

| #  | Criterion                                                                            | Pts |
|----|--------------------------------------------------------------------------------------|-----|
| 1  | Artifact inventory covers images, charts, models, eval reports, SLSA provenance      | 2   |
| 2  | Distinct signer families for CI (KF-11) and model artifacts (KF-06)                  | 2   |
| 3  | Model signing root (KF-05) is offline; intermediate (KF-06) is short-lived           | 2   |
| 4  | All artifacts referenced by digest, never by tag                                     | 2   |
| 5  | SLSA provenance + SBOM attached for every artifact                                   | 2   |
| 6  | Admission policy enforces signature *and* required attestation predicate types       | 2   |
| 7  | Rollout has Audit → Enforce phases with explicit exit criteria                       | 2   |
| 8  | Break-glass procedure: scoped, auto-expiring, audited                                | 2   |
| 9  | Key-compromise drill scripted; results recorded                                      | 2   |
| 10 | Rekor / transparency-log monitor wired to alerting                                   | 2   |
| 11 | Verification runs both at admission and at model-load (defense in depth)             | 2   |
| 12 | Plan names owner, on-call rotation, and review cadence                               | 2   |
| **Total** |                                                                               | **24** |

## 5. Common mistakes

- **Signing by tag.** `cosign sign image:latest` signs whatever
  `latest` pointed to at signing time; that pointer can be moved.
  Sign by `@sha256:...`.
- **Single signing key for everything.** Mixing CI + model + Helm
  signers under one key makes scoped revocation impossible. Use
  separate families.
- **Online signing root.** A KMS-resident root signing model
  intermediates means a KMS admin can mint trust. Keep the root
  offline; rotate the intermediate frequently.
- **No transparency log.** Without Rekor (or a private equivalent),
  there is no way to detect a key compromise that produces
  back-dated signatures. Always log to a transparency log.
- **Enforce mode in prod on day one.** Cluster-wide unsigned admission
  failures are an outage. Run Audit first, gather data, iterate.
- **Break-glass with no expiry.** A bypass that nobody removes becomes
  permanent. Use a CronJob to delete the break-glass policy.
- **Verifying images but not models.** The whole point of the ML
  platform is the model — leaving its load path unverified is the
  single biggest gap.
- **No SLSA provenance.** A signature proves *someone* signed it; a
  provenance attestation proves *who built it from what source*.
  Verify both.
- **Trusting Sigstore public good in prod without monitoring.** It is
  designed to be public; if you depend on it, monitor it. Many orgs
  run a private Fulcio + Rekor.
- **Skipping the drill.** Until you have rotated a "compromised"
  signing key once in staging, your incident response is theoretical.

## 6. References

- SLSA v1.0 — https://slsa.dev/spec/v1.0/
- in-toto specification — https://github.com/in-toto/docs/blob/main/in-toto-spec.md
- Sigstore project — https://www.sigstore.dev/
- cosign CLI reference — https://docs.sigstore.dev/cosign/signing/overview/
- Rekor (transparency log) — https://docs.sigstore.dev/rekor/overview/
- Fulcio (code-signing CA) — https://docs.sigstore.dev/certificate_authority/overview/
- TUF (The Update Framework) — https://theupdateframework.io/
- OCI Artifacts / Distribution spec — https://github.com/opencontainers/distribution-spec
- Kyverno `verifyImages` reference —
  https://kyverno.io/docs/writing-policies/verify-images/sigstore/
- Sigstore policy-controller — https://docs.sigstore.dev/policy-controller/overview/
- OWASP Machine Learning Security Top 10 (ML06 — AI Supply Chain
  Attacks) — https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS (ML supply-chain TTPs) — https://atlas.mitre.org/
- NIST AI RMF 1.0 (Govern/Manage; provenance requirements) —
  https://www.nist.gov/itl/ai-risk-management-framework
- NIST SP 800-218 *Secure Software Development Framework (SSDF)* —
  https://csrc.nist.gov/pubs/sp/800/218/final
