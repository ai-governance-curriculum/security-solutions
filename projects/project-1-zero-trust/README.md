# Project 1 Solution — Zero-Trust ML Infrastructure

Reference for [learning project 1](https://github.com/ai-governance-curriculum/security-learning/tree/main/projects/project-1-zero-trust).

## Components + where to find them

| Component | Implementation location |
|---|---|
| NetworkPolicy default-deny + allow | [engineer-solutions/mod-104 ex-14](https://github.com/ai-infra-curriculum/ai-infra-engineer-solutions/tree/main/modules/mod-104-kubernetes/exercise-14-resource-quotas-multitenancy) + [mlops-solutions/mod-09 ex-04 (pod security + NetworkPolicy)](https://github.com/ai-infra-curriculum/ai-infra-mlops-solutions/tree/main/modules/09-security/exercise-04) |
| mTLS via Istio | see `istio/` below |
| SPIFFE identity | see `spire/` below |
| Vault + ESO | [engineer-solutions/mod-109 ex-07](https://github.com/ai-infra-curriculum/ai-infra-engineer-solutions/tree/main/modules/mod-109-infrastructure-as-code/exercise-07-secret-management) |
| Falco runtime | see `falco-rules/` below |
| Kyverno admission | [engineer-solutions/mod-109 ex-08](https://github.com/ai-infra-curriculum/ai-infra-engineer-solutions/tree/main/modules/mod-109-infrastructure-as-code/exercise-08-policy-as-code/kyverno) |
| Audit chain | [mlops-learning project-4-governance src/audit](https://github.com/ai-infra-curriculum/ai-infra-mlops-learning/tree/main/projects/project-4-governance/src/audit) |

## Layout

```
project-1-zero-trust/
├── README.md
├── istio/
│   ├── peer-authentication.yaml    # mTLS enabled mesh-wide
│   ├── authz-policy.yaml            # service-to-service authZ
│   └── destination-rule.yaml
├── spire/
│   ├── server.yaml
│   └── workload-attestor.yaml
├── falco-rules/
│   └── ml-platform.yaml             # ML-specific anomaly rules
└── tests/
    └── penetration.sh                # try to bypass each control
```
