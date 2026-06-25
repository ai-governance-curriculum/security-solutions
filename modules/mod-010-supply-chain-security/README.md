# mod-010-supply-chain-security — Solutions

Reference solutions for the supply-chain-security module of
[`ai-infra-security-learning`](https://github.com/ai-governance-curriculum/security-learning).

The module covers four supply-chain concerns specific to ML systems:

1. **Provenance** — knowing what built an artifact and from what source
   (SLSA framework).
2. **Integrity** — signing build outputs, model files, and datasets so
   tampering is detectable (Sigstore: Cosign / Fulcio / Rekor).
3. **Verification** — enforcing those signatures at the cluster
   boundary instead of trusting the producer (admission controllers).
4. **External artifact vetting** — applying the same provenance and
   integrity discipline to model weights pulled from public hubs.

## Exercise coverage

| Exercise | Type | Solution form |
|---|---|---|
| [exercise-01-slsa-self-assessment](exercise-01-slsa-self-assessment) | Design | Worked self-assessment + rubric |
| [exercise-02-signed-pipeline-design](exercise-02-signed-pipeline-design) | Design + reference YAML | Annotated pipeline + decision rationale |
| [exercise-03-admission-verification](exercise-03-admission-verification) | Implementation | Kyverno + sigstore policy-controller examples |
| [exercise-04-hugging-face-vetting](exercise-04-hugging-face-vetting) | Design | Vetting checklist + worked example + rubric |
| [exercise-05-supply-chain-incident-runbook](exercise-05-supply-chain-incident-runbook) | Design | Runbook + tabletop rubric |

## Authoritative references used across the module

- SLSA — <https://slsa.dev/>
- Sigstore documentation — <https://docs.sigstore.dev/>
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>
- MITRE ATLAS — <https://atlas.mitre.org/>
- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>
- OpenSSF Scorecard — <https://openssf.org/scorecard/>

## Cross-references in this repo

- [`projects/project-4-secure-cicd`](../../projects/project-4-secure-cicd) — capstone-scale
  pipeline that exercises every control covered by this module.
