# Project 4 Solution — Secure ML CI/CD

Reference for [learning project 4](https://github.com/ai-governance-curriculum/security-learning/tree/main/projects/project-4-secure-cicd).

## Cross-references (where the working artifacts live)

| Stage | Reference |
|---|---|
| Image build + scan + sign + attest | [engineer-solutions/mod-103 ex-10](https://github.com/ai-infra-curriculum/ai-infra-engineer-solutions/tree/main/modules/mod-103-containerization/exercise-10-sbom-and-supply-chain) |
| Vulnerability remediation workflow | [engineer-solutions/mod-103 ex-12](https://github.com/ai-infra-curriculum/ai-infra-engineer-solutions/tree/main/modules/mod-103-containerization/exercise-12-vulnerability-remediation) |
| GitOps with ArgoCD | [engineer-solutions/mod-109 ex-06](https://github.com/ai-infra-curriculum/ai-infra-engineer-solutions/tree/main/modules/mod-109-infrastructure-as-code/exercise-06-gitops-argocd) |
| Kyverno admission policies | [engineer-solutions/mod-109 ex-08](https://github.com/ai-infra-curriculum/ai-infra-engineer-solutions/tree/main/modules/mod-109-infrastructure-as-code/exercise-08-policy-as-code) |
| Multi-env promotion | [engineer-solutions/mod-109 ex-10](https://github.com/ai-infra-curriculum/ai-infra-engineer-solutions/tree/main/modules/mod-109-infrastructure-as-code/exercise-10-multi-environment-promotion) |
| Model artifact signing | see `model-signing/` below |

## Layout

```
project-4-secure-cicd/
├── README.md
├── ci-examples/secure-pipeline.yml  # full CI: build + scan + sign + attest + push
├── model-signing/sign_model.sh      # cosign-sign model artifacts in MLflow
└── tests/bypass_attempts.sh
```
