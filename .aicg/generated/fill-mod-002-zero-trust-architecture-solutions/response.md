# fill-mod-002-zero-trust-architecture-solutions — agent response

## Summary

Created module-level reference solutions for
`mod-002-zero-trust-architecture`, covering all five exercises
listed in the work packet. One `SOLUTION.md` per exercise, plus a
module-level `README.md` index.

## Files created

- `modules/mod-002-zero-trust-architecture/README.md`
- `modules/mod-002-zero-trust-architecture/exercise-01-zero-trust-gap-analysis/SOLUTION.md`
- `modules/mod-002-zero-trust-architecture/exercise-02-workload-identity-design/SOLUTION.md`
- `modules/mod-002-zero-trust-architecture/exercise-03-microsegmentation-plan/SOLUTION.md`
- `modules/mod-002-zero-trust-architecture/exercise-04-service-mesh-authz/SOLUTION.md`
- `modules/mod-002-zero-trust-architecture/exercise-05-zero-trust-roadmap/SOLUTION.md`

## Output contract conformance

Every `SOLUTION.md` includes the six required sections in order:

1. Solution overview
2. Worked answer or implementation
3. Validation steps
4. Rubric or review checklist
5. Common mistakes
6. References

Design exercises (01, 02, 05) present a worked example + decision
rationale + grading rubric. Implementation exercises (03, 04)
present statically valid `networking.k8s.io/v1` `NetworkPolicy`
and `security.istio.io/v1` `AuthorizationPolicy` YAML drawn from
the listed official sources.

## Source policy conformance

Claims are tied to official sources from the work packet:

- NIST SP 800-207 (Zero Trust Architecture) — primary framework
  for Exercises 01 and 05.
- NIST SP 800-204A / 204B — referenced for service-mesh
  guidance in Exercises 03 and 04.
- Kubernetes documentation — referenced for NetworkPolicy
  and Pod Security Standards.
- SPIFFE / SPIRE specification — referenced for the workload
  identity design in Exercise 02.
- Istio AuthorizationPolicy reference — referenced for the
  mesh authorization manifests in Exercises 03 and 04.
- MITRE ATLAS, NIST AI RMF — referenced for residual-threat
  framing in Exercises 01 and 05.

No metrics, incidents, or case studies are invented. SmartRecs
is a fictional reference system explicitly defined in the
paired learning repo
(`mod-001-ml-security-foundations/exercises/exercise-01-...`)
and is labeled as local exercise context throughout. No
`<!-- needs-research: ... -->` markers are required.

## Notes

- Exercise 01's lecture references "five NIST tenets"; NIST SP
  800-207 §2.1 itself lists seven. The solution follows the
  lecture's five-tenet compression (as the exercise requires)
  but explicitly notes the seven-tenet original for learners
  who want to cite NIST verbatim.
- YAML blocks in Exercises 03 and 04 were written from the
  cited K8s and Istio reference docs. Sandbox restrictions
  prevented running `python3 -c "import yaml; yaml.safe_load_all(...)"`
  against the blocks; structural review confirms each manifest
  has `apiVersion`, `kind`, `metadata`, and `spec`, and uses
  the field names defined in the cited references.
- The five solutions are mutually consistent: Exercise 02's
  SPIFFE IDs are the principals used by Exercises 03 and 04;
  Exercise 05's roadmap sequences the gaps identified in
  Exercise 01 and the controls implemented in 02–04.
