# SOLUTION — Exercise 01: SLSA Self-Assessment

Reference solution for the SLSA self-assessment exercise. Read after
attempting the exercise; the goal is to show what a defensible
self-score looks like and which evidence backs it.

## 1. Solution overview

The learner inventories their build pipeline against SLSA v1.0 and
assigns a Build Track level (L1, L2, or L3) with evidence for each
requirement. The deliverable is a written self-assessment plus
remediation items for any unmet requirement.

Key reminders before scoring:

- SLSA v1.0 defines only the **Build Track** (L1–L3). Source and
  Dependencies tracks are listed as future work in the specification.
  Do not assign "Source L3" or "L4" against v1.0 — they do not exist
  yet.
- The level applies to a specific package produced by a specific
  build, not to "the org." A team can have L3 for their main service
  image and L1 for an internal helper image — assess each artifact.
- The bar is *who produced the provenance*, *how strongly the build
  environment is isolated*, and *whether the provenance is verifiable*.
  Source-code controls are not in scope of the v1.0 Build Track.

Source: SLSA v1.0 specification (<https://slsa.dev/spec/v1.0/>).

## 2. Implementation — worked answer

Worked example: a learner team that builds a Python inference service
container in GitHub Actions and signs it with `cosign` (keyless).

### Inventory of the build

| Item | Value |
|---|---|
| Artifact | `ghcr.io/example/inference-svc` |
| Build system | GitHub Actions hosted runners |
| Provenance format | SLSA Provenance v1 via `slsa-framework/slsa-github-generator` |
| Signing | Cosign keyless, recorded in Rekor |
| Verifier | `slsa-verifier` in CD pipeline; Kyverno at the cluster |

### Walk through each Build Track requirement

**Build L1 — Provenance exists.**

| Requirement (paraphrased from SLSA v1.0) | Status | Evidence |
|---|---|---|
| Provenance describes how the package was built | Met | `slsa-github-generator` emits a `provenance.intoto.jsonl` per release |
| Provenance is distributed to consumers | Met | Attached to the GitHub release and to the OCI image via `cosign attach` |

**Build L2 — Hosted build platform with signed provenance.**

| Requirement | Status | Evidence |
|---|---|---|
| Build runs on a hosted build platform | Met | GitHub-hosted runner, not self-hosted |
| Build platform generates and signs the provenance | Met | Provenance signed via Sigstore by the `slsa-github-generator` reusable workflow |
| Provenance is verifiable using the build platform's signing identity | Met | Signed by the GitHub Actions OIDC identity for the reusable workflow; Rekor entry recorded |

**Build L3 — Hardened build platform.**

| Requirement | Status | Evidence |
|---|---|---|
| Build runs are isolated from one another | Met | Documented by the GitHub-hosted runner model; one ephemeral VM per job |
| Provenance is non-forgeable by tenants of the build platform | Met | Signing happens in the reusable workflow's trusted context; user steps cannot mint the same signing identity |
| Build environment is not tamperable by the build steps themselves | Partial | Steps run as root inside the runner; the *workflow* cannot tamper with the *generator* but it could exfiltrate secrets if `id-token: write` is over-granted |

### Self-assigned level and remediation

The team self-assigns **L3 with one open item** for the partial L3
requirement. Remediation:

- Restrict the `id-token: write` permission to jobs that actually need
  it, in line with the GitHub OIDC documentation.
- Add a step that emits the runner image digest into the provenance
  for downstream verifiers.

If either of those is unresolved at audit time, drop to L2.

### Anti-pattern caught during the worked example

The team initially scored L3 because their `cosign sign` command ran
inside the same job as the user-defined build steps. A user step
could in principle alter the digest before signing. Moving signing
into the `slsa-framework/slsa-github-generator` reusable workflow
puts the signer outside the tenant-controlled job, which is what L3
requires.

## 3. Validation steps

A peer reviewer should be able to reproduce the score in under thirty
minutes.

1. Open the artifact's release and confirm a `*.intoto.jsonl` (or
   in-toto attestation in OCI) is attached.
2. Run `slsa-verifier verify-artifact` (or `verify-image`) against the
   artifact + the provenance, with the expected source repository
   pinned. The verifier must succeed with the documented identity.
3. Check the Rekor transparency log entry for the artifact digest
   (e.g. `rekor-cli search --sha <digest>`). The Fulcio certificate
   subject must match the build workflow identity claimed in the
   self-assessment.
4. For L3 claims, confirm the signing step runs in a reusable workflow
   the user code cannot modify (read the `uses:` reference in the
   release workflow).
5. Re-run the assessment using a recent build (not a cherry-picked
   green one). The score must hold on a representative sample.

## 4. Rubric

| Dimension | Excellent (3) | Acceptable (2) | Inadequate (1) |
|---|---|---|---|
| Scope statement | Names the specific artifact(s) and excludes anything not assessed | Names one artifact | "Our pipeline" with no artifact specified |
| Requirement-by-requirement evidence | Each L1/L2/L3 requirement cited verbatim from the spec with linked evidence | Most requirements cited with evidence | Score asserted without per-requirement evidence |
| Verifiability | Provenance can be independently verified by the reviewer | Verifier runs but identity check is missing | No verification path described |
| Honest gap acknowledgement | Partial / not-met items are called out with a remediation owner | Gaps acknowledged generally | Score inflated; gaps hidden |
| Use of authoritative sources | Quotes SLSA v1.0 text and links to it | References SLSA but uses paraphrased requirements only | Invented or v0.1 levels (L4) cited |

Passing threshold: average ≥ 2 across all dimensions, with no
dimension scored 1.

## 5. Common mistakes

- **Scoring L4 against v1.0.** SLSA v1.0 caps the Build Track at L3.
  L4 existed in v0.1 and was removed; see the SLSA Build Levels page.
- **Treating the level as org-wide.** SLSA levels are per-package.
  Claiming "we are L3" without naming the artifact is meaningless.
- **Scoring L3 with self-hosted runners that user code can mutate.**
  L3 requires the build environment to be non-tamperable by build
  steps. A self-hosted runner that pulls user-controlled config does
  not meet this without additional isolation.
- **Conflating "we sign with cosign" with L2.** L2 requires the build
  platform to sign the provenance — not the user. A `cosign sign`
  step run in the user's job is closer to L1 with a signature.
- **Citing OWASP or ATLAS as if they assign SLSA levels.** They do
  not. They are useful for threat framing; the level itself comes
  from the SLSA specification.
- **Ignoring source provenance because v1.0 has no source track.**
  Note it as out-of-scope rather than invent a score. Document branch
  protection, signed commits, and review controls separately.

## 6. References

- SLSA v1.0 specification — <https://slsa.dev/spec/v1.0/>
- SLSA Build Track levels — <https://slsa.dev/spec/v1.0/levels>
- `slsa-framework/slsa-github-generator` (official project) —
  referenced from the SLSA project page
- Sigstore / Rekor documentation — <https://docs.sigstore.dev/>
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>
  (background framing for ML supply chain risks)
- MITRE ATLAS — <https://atlas.mitre.org/> (attacker techniques,
  background)
- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>
  (governance framing for self-assessment evidence)
