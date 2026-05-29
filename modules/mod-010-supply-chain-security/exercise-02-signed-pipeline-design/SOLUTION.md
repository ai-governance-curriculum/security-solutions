# SOLUTION — Exercise 02: Signed-Pipeline Design

Reference solution for designing a CI pipeline that produces signed,
attested artifacts for an ML inference service plus its model file.

## 1. Solution overview

The exercise asks for a pipeline design — not a fully running build.
The deliverable is:

- A diagram or ordered list of stages.
- An annotated reference workflow showing the trust-relevant steps.
- A short rationale for each control: what it defends against, what
  alternative was rejected, and where the verifier will check it.

The minimum bar:

- The pipeline produces both an image **and** a model file.
- Both have a Sigstore-bound identity attached (keyless signing via
  Fulcio / Rekor) per the Sigstore documentation.
- A SLSA-style provenance attestation is produced for each.
- The verifier identity is named — the downstream admission control
  is the *consumer* and must be referenced, not skipped.

## 2. Implementation — worked design

### Stage list (build → verify)

1. Checkout.
2. SAST / secret scan.
3. SBOM generation.
4. Build container image, capture digest.
5. Train (or fetch) model, capture model file digest.
6. Vulnerability scan against the image; fail on configured severity.
7. Sign image with cosign keyless.
8. Attest image with SLSA provenance + SBOM predicates.
9. Sign model file with `cosign sign-blob` keyless.
10. Attest model file (custom predicate referencing training dataset
    digest and training run ID).
11. Publish: push image to registry, upload model file to artifact
    store. Signatures and attestations follow the artifact (OCI for
    the image, blob + sig + cert for the model).
12. Optional: open a GitOps PR that pins the new digests; the cluster
    sync runs the verifier.

### Reference workflow (GitHub Actions, annotated)

```yaml
name: signed-build
on:
  push:
    tags: ['v*']

permissions:
  contents: read
  packages: write
  id-token: write      # narrow scope: only this workflow needs OIDC

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      image-digest: ${{ steps.build.outputs.digest }}
      model-digest: ${{ steps.model.outputs.sha256 }}
    steps:
      - uses: actions/checkout@v4

      # --- SBOM, scan, build (omitted; see project-4-secure-cicd) ---

      - id: build
        uses: docker/build-push-action@v6
        with:
          context: .
          push: true
          tags: ghcr.io/${{ github.repository }}/svc:${{ github.ref_name }}

      - id: model
        run: |
          python train.py --out model.safetensors
          # safetensors avoids the pickle deserialization class of risk
          # (background: Hugging Face safetensors docs)
          echo "sha256=$(sha256sum model.safetensors | awk '{print $1}')" \
            >> "$GITHUB_OUTPUT"

      - uses: sigstore/cosign-installer@v3

      # Sign the image (keyless — Fulcio-issued cert bound to this
      # workflow's OIDC identity, recorded in Rekor).
      - env:
          IMG: ghcr.io/${{ github.repository }}/svc
          DIGEST: ${{ steps.build.outputs.digest }}
        run: cosign sign --yes "${IMG}@${DIGEST}"

      # Sign the model file.
      - run: |
          cosign sign-blob --yes \
            --output-signature model.safetensors.sig \
            --output-certificate model.safetensors.cert \
            model.safetensors

      - uses: actions/upload-artifact@v4
        with:
          name: model
          path: |
            model.safetensors
            model.safetensors.sig
            model.safetensors.cert

  attest:
    needs: build
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
    with:
      image: ghcr.io/${{ github.repository }}/svc
      digest: ${{ needs.build.outputs.image-digest }}
    permissions:
      id-token: write
      packages: write
      actions: read
```

### Design rationale

**Why keyless Cosign (not GPG, not long-lived KMS keys).** Sigstore
keyless binds a signature to an OIDC identity for the duration of a
short-lived Fulcio certificate (Sigstore docs: *Quickstart* and
*Fulcio*). No private-key material to rotate or leak. Verifiers can
pin the expected certificate identity instead of trusting a key fingerprint.

**Why a reusable workflow generates provenance (not an inline step).**
SLSA v1.0 Build L3 requires that provenance be non-forgeable by
tenants of the build platform. Putting provenance generation inside
the same job as user-controlled steps fails that requirement. The
`slsa-github-generator` reusable workflow runs in a context the user
job cannot mutate, which is what makes the L3 claim defensible.

**Why sign the model file separately from the image.** Container
signatures cover *the image*, not files pulled at runtime from a
model store. A clean image that loads a tampered model passes
container verification but serves attacker-controlled output. This
matches the *ML supply chain compromise* technique catalogued in
MITRE ATLAS and the AI supply chain risk noted in the OWASP Machine
Learning Security Top 10.

**Why `safetensors` and not pickle for the model file.** Python
pickle deserialization permits arbitrary code execution; a poisoned
pickle in a public model registry is a documented attacker
technique (MITRE ATLAS — *ML Supply Chain Compromise: Model*).
`safetensors` parses tensor data without invoking `__reduce__`.

**Why two predicates (provenance + SBOM, plus a custom predicate for
the model).** SLSA provenance answers *who built this and from what
source*. SBOM answers *what's inside it*. A model-specific predicate
references the training dataset digest and training run, which is the
information a downstream verifier needs to detect a data-poisoning
swap. None of these is redundant; each maps to a different question.

**Why the pipeline does not deploy.** Signing in the build pipeline
and verifying at admission are deliberately split. CI is allowed to
push artifacts; only the cluster, via its admission controller, is
allowed to admit them. A compromised CI runner with this design can
poison the *next* build, but it cannot directly deploy untrusted code
to the cluster.

## 3. Validation steps

1. Run the workflow end-to-end against a throwaway repo and tag.
2. From a different machine with only public network access:
   - `cosign verify` the image, pinning
     `--certificate-identity-regexp` to the build workflow path and
     `--certificate-oidc-issuer https://token.actions.githubusercontent.com`.
   - `cosign verify-blob` the model file with the same identity pin.
   - `cosign verify-attestation --type slsaprovenance1` on the image.
3. Confirm Rekor has an entry per signature
   (`rekor-cli search --sha <digest>`).
4. Run `slsa-verifier verify-image` against the image; it must pass
   with the source repository pin.
5. Try the negative cases:
   - A copy of the image retagged with a manual `docker push` (no
     signature) must fail verification.
   - The original signature attached to a different image digest must
     fail.
   - A modified model file with the original signature must fail
     `cosign verify-blob`.

## 4. Rubric — review checklist

| Check | Pass criteria |
|---|---|
| Both image *and* model are signed | Yes / no |
| Signing identity is pinned by the verifier | `--certificate-identity*` flag(s) named in the design |
| Keyless signing rationale references Sigstore docs | Yes |
| Provenance is generated outside the user-controlled job | Reusable workflow or equivalent named |
| `id-token: write` is scoped to the signing job only | Yes |
| Model file format avoids arbitrary-code deserialization | safetensors or equivalent justified |
| Verifier location is documented | Admission controller or GitOps verifier referenced |
| Negative tests are listed | At least three documented failure cases |

## 5. Common mistakes

- **Signing in the same job that builds and lets users run arbitrary
  scripts.** Defeats the non-forgeable provenance requirement of SLSA
  Build L3.
- **Trusting any signature.** Without an identity pin, an attacker
  who can also push to Sigstore (anyone with a GitHub account, by
  design) produces "a valid signature" — just not yours. Always
  pin `--certificate-identity` and `--certificate-oidc-issuer`.
- **Signing the image but not the model.** Common ML-specific
  oversight; flagged by both OWASP ML Top 10 and MITRE ATLAS.
- **Treating a passing Rekor query as verification.** Rekor confirms
  *that a signature was recorded*; it does not prove *who* signed it
  or *what* was signed without the certificate identity check.
- **Storing the cosign private key in a CI secret.** Keyless is the
  documented Sigstore default; long-lived private keys re-introduce
  the rotation problem that Fulcio is designed to eliminate.
- **Skipping the negative tests.** A pipeline that has never failed
  a verification has not proven the verifier works.

## 6. References

- Sigstore documentation — <https://docs.sigstore.dev/>
- Sigstore Cosign overview and keyless quickstart —
  <https://docs.sigstore.dev/cosign/signing/overview/>
- SLSA v1.0 — <https://slsa.dev/spec/v1.0/>
- `slsa-framework/slsa-github-generator` — referenced from
  <https://slsa.dev/>
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>
- MITRE ATLAS, *ML Supply Chain Compromise* — <https://atlas.mitre.org/>
- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>
- Local cross-reference: [`projects/project-4-secure-cicd`](../../../projects/project-4-secure-cicd)
