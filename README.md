# AI Governance · Security Engineer — Solutions Repository

<!-- aicg:site-banner -->
> 🎓 Part of the free, open-source **AI Career Curriculum** ecosystem — [Infrastructure](https://github.com/ai-infra-curriculum) · [ML Engineering](https://github.com/ml-engineering-curriculum) · [AI Engineering](https://github.com/ai-engineering-curriculum) · [Governance](https://github.com/ai-governance-curriculum). Live cohorts &amp; team programs: **[ai-infra-curriculum.github.io](https://ai-infra-curriculum.github.io/)**.
<!-- /aicg:site-banner -->

<!-- aicg:sponsor -->
> 💜 **[Sponsor this curriculum](https://github.com/sponsors/ai-governance-curriculum)** — sponsorships keep the whole open-source AI Career Curriculum free and moving.
<!-- /aicg:sponsor -->

Reference solutions for [`ai-infra-security-learning`](https://github.com/ai-governance-curriculum/security-learning).

The security track covers securing ML infrastructure, models, data, and
pipelines end-to-end. The deliverables are a mix of working code,
configuration, threat models, and policy documents — security
engineering is fundamentally a cross-discipline role.

## Repository Structure

```
ai-infra-security-solutions/
├── README.md
├── CONTRIBUTING.md
├── CURRICULUM.md
├── LEARNING_GUIDE.md
├── SOLUTIONS_INDEX.md
├── modules/                # exercise solutions per learning module
├── projects/               # 5 capstone-grade project solutions
├── guides/                 # cross-module references
└── resources/
```

## Capstone Projects

The 5 capstone projects each have a working reference implementation,
falco/istio policy bundles, and a SOLUTION.md design-rationale document:

| Project | Focus |
|---|---|
| [project-1-zero-trust](projects/project-1-zero-trust) | Zero-trust networking for ML services (Istio, SPIFFE, falco). |
| [project-2-compliance](projects/project-2-compliance) | Compliance automation and audit chains. |
| [project-3-adversarial-defense](projects/project-3-adversarial-defense) | Adversarial-robustness testing and runtime defense. |
| [project-4-secure-cicd](projects/project-4-secure-cicd) | Supply-chain security: SLSA, Sigstore, Cosign keyless. |
| [project-5-security-operations](projects/project-5-security-operations) | SOC patterns for ML platforms (detections, triage, runbooks). |

The capstone synthesis exercise from the learning track (`mod-012`,
NorthBridge Health scenario) is graded against rubrics rather than a
single-reference implementation — see the
[learning repo](https://github.com/ai-governance-curriculum/security-learning).

## Module Solutions

Module-level exercise solutions live under `modules/`. Where exercises
are **design-based** (threat models, DPIAs, tabletop exercises), the
"solution" is a worked example plus a grading rubric rather than
executable code. Where exercises are **implementation-based**
(policies, scanners, attestation pipelines), the solution is a
runnable reference.

See [`SOLUTIONS_INDEX.md`](SOLUTIONS_INDEX.md) for a full inventory.

## Cross-Cutting Principles

1. **Security engineering is policy + code, not just code.** The
   solutions deliberately include written threat models, policy text,
   and operational runbooks alongside the implementation artifacts.
2. **Detections are tested.** Every detection rule has a regression
   test (simulated attack input → expected alert).
3. **Defense-in-depth is the rule.** No single control is treated as
   load-bearing on its own.

## How to Read This Repo

- **Aspiring security engineer**: start with `project-1-zero-trust`
  and read the SOLUTION.md before opening the code.
- **Existing security engineer cross-training on ML**: jump to
  `project-3-adversarial-defense` and `project-4-secure-cicd` —
  these are the ML-specific muscles.
- **Platform / infra engineer adding security duties**:
  `project-1-zero-trust` + `project-5-security-operations` together
  cover the day-to-day surface.

## Prerequisites

- [Engineer track](https://github.com/ai-infra-curriculum/ai-infra-engineer-learning) recommended.
- Comfort with container runtimes, Kubernetes, and at least one cloud's IAM model.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). New detection rules,
alternative threat-model framings, and updated regulatory mappings
are especially welcome — security content rots quickly.

## License

See [`LICENSE`](LICENSE).

---

<!-- aicg:maintained-by -->
Maintained by [VeriSwarm.ai](https://veriswarm.ai)
