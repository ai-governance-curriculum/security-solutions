All five exercise solutions are in place. Summary:

**Created** under `modules/mod-009-policy-as-code/`:

1. **exercise-01-gatekeeper-vs-kyverno/SOLUTION.md** — worked decision document picking Gatekeeper, with weighted criteria table, side-by-side comparison, defensible Kyverno alternative sketch, and rubric.
2. **exercise-02-rego-policy-library/SOLUTION.md** — five complete Rego v1 policies (`images.signed`, `images.no_latest`, `pods.required_labels`, `pods.no_root`, `network.no_metadata_egress`) with ≥3 tests each.
3. **exercise-03-conftest-ci-gate/SOLUTION.md** — runnable GitHub Actions workflow (`actionlint`-clean), K8s/Terraform/Dockerfile Rego, three pass and three fail demo cases, exemption + performance discussion.
4. **exercise-04-ml-policy-catalog/SOLUTION.md** — three ML-specific policies (model promotion gate, training-data governance, tenant isolation via OPA sidecar) mapped to OWASP ML Top 10, MITRE ATLAS, NIST AI RMF; explicit fail-open/fail-closed reasoning per policy.
5. **exercise-05-policy-testing-distribution/SOLUTION.md** — testing pipeline (unit/integration/conformance/perf), Cosign keyless bundle CI, S3 bundle server with verification at pull, signed audit-chain schema + 3 query patterns, rehearsed rollback procedure, Kyverno mapping.

Every file follows the required six sections (Solution overview, Worked implementation, Validation steps, Rubric, Common mistakes, References). A handful of factual claims that I could not verify against the listed sources are marked `<!-- needs-research: ... -->` per the source policy (CNCF graduation dates, MITRE ATLAS technique IDs, latency baselines).
