# SOLUTION — Exercise 04: ML-Specific Policy Catalog

> Read this *after* attempting the learning-side exercise. This file
> ships three ML-specific Rego policies (model promotion, training-
> data governance, tenant isolation), each with explicit
> failure-mode reasoning. The hardest call in this exercise is
> *fail-open vs. fail-closed* per policy; the catalog below states
> that decision for every rule.

## 1. Solution overview

The exercise asks for at least three ML-specific policies — policies
that exist *because* the platform runs ML and would not show up on a
generic infra checklist. Each policy needs:

- Real Rego with ≥ 5 `test_*` rules.
- A note on **where it runs** (admission, sidecar ext-authz, or CI).
- A note on **audit-chain evidence** produced.
- A note on **failure mode** (what happens if OPA is unavailable).

The threats addressed map back to the official taxonomies:

- **Model promotion gate** — OWASP ML06:2023 (AI Supply Chain
  Attacks) plus tampered-model and unsafe-deployment risks named in
  NIST AI RMF's Manage / Map functions. MITRE ATLAS techniques such
  as `AML.T0010 ML Supply Chain Compromise` and `AML.T0018 Backdoor
  ML Model` are the adversary-side framing.
- **Training-data governance** — OWASP ML02:2023 (Data Poisoning) and
  NIST AI RMF data-provenance expectations; MITRE ATLAS
  `AML.T0020 Poison Training Data` and `AML.T0019 Publish Poisoned
  Datasets`.
- **Tenant isolation (feature store)** — application-layer
  authorization gap, mapped to OWASP ML05:2023 (Model Theft) /
  ML04:2023 (Membership Inference) when cross-tenant feature reads
  are the leak path.

<!-- follow-up: confirm the exact ATLAS technique IDs above
against atlas.mitre.org before citing externally; IDs are stable but
the SmartRecs threat model has not been mapped formally. -->

## 2. Worked implementation

### 2.1 Policy 1 — Model Promotion Gate

**Purpose.** A model artifact may only be promoted to a production
serving slot if every gate signal is present and within bound.

**Where it runs.** Two surfaces, same Rego:

- **CI (Conftest) at promotion time.** Reads the proposed
  `ModelDeployment` manifest, the model card, and the signature
  attestation; blocks the PR if any gate fails.
- **Admission (Gatekeeper) on the `ModelDeployment` CR.** Re-enforces
  the same gates at apply time so a manual `kubectl apply` cannot
  bypass CI.

**Inputs.** Combined into `input` by the engine:

- `input.review.object` — the `ModelDeployment` CRD.
- `input.data.cosign.verified` — set of verified model artifact
  digests + signing identity (populated by the external-data
  provider from Module 03 / Exercise 02).
- `input.data.model_cards[<digest>]` — model card with `accuracy`,
  `fairness.disparate_impact`,
  `adversarial_robustness.robust_accuracy_eps_8_255`, fetched at
  evaluation time.
- `input.data.baselines[<model_id>]` — the current production
  baseline metrics for comparison.
- `input.data.approvals[<digest>]` — set of recorded approvals from
  the audit chain (Module 07).

**Audit-chain evidence.** Every decision emits to the audit chain:
the model digest, the decision (allow/deny), the violations list,
the signing identity, the approver identity, the policy version,
and a UTC timestamp. See Exercise 05 §"Audit-chain integration."

**Failure mode.** **Closed.** If OPA or the external-data provider
is unavailable, model promotion is denied. This is acceptable
because promotion is a deliberate human operation; a stuck promotion
is preferable to a silent ungated promotion. Operators receive a
page (`PolicyEngineDown`); a documented break-glass override
requires two senior engineer sign-offs and is itself audited.

```rego
# policies/mlops/model_promotion.rego
package mlops.model_promotion
import rego.v1

# Tunable thresholds (lifted from input.data so they can be
# environment-scoped without code changes).
default thresholds := {
    "accuracy_drop_pct": 0.5,                           # max drop vs. baseline (percentage points)
    "disparate_impact_max": 1.25,                       # OWASP-aligned upper bound
    "robust_accuracy_drop_pct": 5.0,                    # adversarial robustness drop allowed
}

thresholds := input.data.thresholds if input.data.thresholds

deny contains msg if {
    not signed
    msg := sprintf("model digest %q is not Cosign-signed", [model_digest])
}

deny contains msg if {
    signed
    identity := input.data.cosign.verified[model_digest].identity
    not identity in input.data.allowed_signers
    msg := sprintf("model signed by unexpected identity %q", [identity])
}

deny contains "model card missing accuracy field" if {
    signed
    not card.accuracy
}

deny contains msg if {
    signed
    card.accuracy
    baseline := input.data.baselines[input.review.object.spec.modelId].accuracy
    drop_pct := (baseline - card.accuracy) * 100
    drop_pct > thresholds.accuracy_drop_pct
    msg := sprintf("accuracy regression: drop %.2fpp exceeds %.2fpp threshold",
                   [drop_pct, thresholds.accuracy_drop_pct])
}

deny contains msg if {
    signed
    di := card.fairness.disparate_impact
    di > thresholds.disparate_impact_max
    msg := sprintf("disparate impact %.2f exceeds %.2f", [di, thresholds.disparate_impact_max])
}

deny contains msg if {
    signed
    robust := card.adversarial_robustness.robust_accuracy_eps_8_255
    baseline := input.data.baselines[input.review.object.spec.modelId].robust_accuracy_eps_8_255
    drop_pp := (baseline - robust) * 100
    drop_pp > thresholds.robust_accuracy_drop_pct
    msg := sprintf("adversarial robustness drop %.2fpp exceeds %.2fpp",
                   [drop_pp, thresholds.robust_accuracy_drop_pct])
}

deny contains msg if {
    signed
    not approved
    msg := sprintf("no recorded human approval for digest %q", [model_digest])
}

# Helpers
model_digest := input.review.object.spec.modelDigest
signed if input.data.cosign.verified[model_digest]
card := input.data.model_cards[model_digest]
approved if {
    some approval in input.data.approvals[model_digest]
    approval.role == "ml-release-approver"
}

# Tests
baseline_data := {
    "thresholds": {"accuracy_drop_pct": 0.5, "disparate_impact_max": 1.25, "robust_accuracy_drop_pct": 5.0},
    "allowed_signers": ["https://github.com/smartrecs-org/recs/.github/workflows/release.yml@refs/heads/main"],
    "cosign": {"verified": {"sha256:good": {
        "identity": "https://github.com/smartrecs-org/recs/.github/workflows/release.yml@refs/heads/main",
    }}},
    "model_cards": {"sha256:good": {
        "accuracy": 0.91,
        "fairness": {"disparate_impact": 1.10},
        "adversarial_robustness": {"robust_accuracy_eps_8_255": 0.60},
    }},
    "baselines": {"recs-v1": {"accuracy": 0.91, "robust_accuracy_eps_8_255": 0.62}},
    "approvals": {"sha256:good": [{"role": "ml-release-approver", "by": "alice"}]},
}

test_deny_unsigned_model if {
    result := deny with input as {
        "review": {"object": {"spec": {"modelDigest": "sha256:rogue", "modelId": "recs-v1"}}},
        "data": baseline_data,
    }
    count([m | m := result[_]; contains(m, "not Cosign-signed")]) == 1
}

test_deny_low_accuracy if {
    bad := json.patch(baseline_data, [{"op": "add",
        "path": "/model_cards/sha256:good/accuracy", "value": 0.85}])
    result := deny with input as {
        "review": {"object": {"spec": {"modelDigest": "sha256:good", "modelId": "recs-v1"}}},
        "data": bad,
    }
    count([m | m := result[_]; contains(m, "accuracy regression")]) == 1
}

test_deny_fairness_regression if {
    bad := json.patch(baseline_data, [{"op": "add",
        "path": "/model_cards/sha256:good/fairness/disparate_impact", "value": 1.40}])
    result := deny with input as {
        "review": {"object": {"spec": {"modelDigest": "sha256:good", "modelId": "recs-v1"}}},
        "data": bad,
    }
    count([m | m := result[_]; contains(m, "disparate impact")]) == 1
}

test_deny_robustness_drop if {
    bad := json.patch(baseline_data, [{"op": "add",
        "path": "/model_cards/sha256:good/adversarial_robustness/robust_accuracy_eps_8_255",
        "value": 0.50}])
    result := deny with input as {
        "review": {"object": {"spec": {"modelDigest": "sha256:good", "modelId": "recs-v1"}}},
        "data": bad,
    }
    count([m | m := result[_]; contains(m, "adversarial robustness drop")]) == 1
}

test_deny_no_approval if {
    bad := json.patch(baseline_data, [{"op": "add",
        "path": "/approvals/sha256:good", "value": []}])
    result := deny with input as {
        "review": {"object": {"spec": {"modelDigest": "sha256:good", "modelId": "recs-v1"}}},
        "data": bad,
    }
    count([m | m := result[_]; contains(m, "no recorded human approval")]) == 1
}

test_allow_full_compliance if {
    result := deny with input as {
        "review": {"object": {"spec": {"modelDigest": "sha256:good", "modelId": "recs-v1"}}},
        "data": baseline_data,
    }
    count(result) == 0
}
```

### 2.2 Policy 2 — Training-Data Governance

**Purpose.** Prevent a `TrainingJob` from running unless its dataset
references are signed, have a documented retention policy, and (if
privacy-classified) have a privacy budget set.

**Where it runs.** Gatekeeper admission on the `TrainingJob` CRD. A
secondary Conftest gate on the proposed manifests catches the same
issues at PR time.

**Audit-chain evidence.** For every accepted job: dataset
references, signing identities, retention class, and (if applicable)
the privacy budget setting. For denies: the violations list. Drives
SOC 2 + GDPR audit queries on data lineage.

**Failure mode.** **Closed.** A `TrainingJob` that cannot prove
dataset provenance is denied. This blocks legitimate experimentation
when the OPA engine is down, which is acceptable — training is a
batch operation and a short delay is preferable to ungoverned data
processing.

```rego
# policies/mlops/training_data_governance.rego
package mlops.training_data_governance
import rego.v1

deny contains msg if {
    input.review.object.kind == "TrainingJob"
    some ds in input.review.object.spec.datasets
    not ds.provenance.signed
    msg := sprintf("dataset %q has no signed provenance attestation", [ds.id])
}

deny contains msg if {
    input.review.object.kind == "TrainingJob"
    some ds in input.review.object.spec.datasets
    ds.classification == "regulated"
    not ds.retention
    msg := sprintf("regulated dataset %q has no retention policy set", [ds.id])
}

deny contains msg if {
    input.review.object.kind == "TrainingJob"
    some ds in input.review.object.spec.datasets
    ds.classification == "regulated"
    ds.retention
    not ds.retention.maxDays
    msg := sprintf("regulated dataset %q retention block missing maxDays", [ds.id])
}

deny contains msg if {
    input.review.object.kind == "TrainingJob"
    some ds in input.review.object.spec.datasets
    ds.classification == "privacy"
    not has_privacy_budget(input.review.object.spec)
    msg := sprintf("privacy-classified dataset %q requires spec.privacyBudget", [ds.id])
}

has_privacy_budget(spec) if {
    spec.privacyBudget.epsilon
    spec.privacyBudget.delta
}

# Tests
test_deny_unsigned_dataset if {
    result := deny with input as {"review": {"object": {
        "kind": "TrainingJob",
        "spec": {"datasets": [{"id": "ds-1", "classification": "open",
                               "provenance": {"signed": false}}]},
    }}}
    count(result) == 1
}

test_deny_regulated_no_retention if {
    result := deny with input as {"review": {"object": {
        "kind": "TrainingJob",
        "spec": {"datasets": [{"id": "ds-1", "classification": "regulated",
                               "provenance": {"signed": true}}]},
    }}}
    count(result) == 1
}

test_deny_regulated_no_max_days if {
    result := deny with input as {"review": {"object": {
        "kind": "TrainingJob",
        "spec": {"datasets": [{"id": "ds-1", "classification": "regulated",
                               "provenance": {"signed": true},
                               "retention": {}}]},
    }}}
    count(result) == 1
}

test_deny_privacy_no_budget if {
    result := deny with input as {"review": {"object": {
        "kind": "TrainingJob",
        "spec": {"datasets": [{"id": "ds-1", "classification": "privacy",
                               "provenance": {"signed": true}}]},
    }}}
    count(result) == 1
}

test_allow_privacy_with_budget if {
    result := deny with input as {"review": {"object": {
        "kind": "TrainingJob",
        "spec": {
            "privacyBudget": {"epsilon": 1.0, "delta": 0.00001},
            "datasets": [{"id": "ds-1", "classification": "privacy",
                          "provenance": {"signed": true}}],
        },
    }}}
    count(result) == 0
}

test_allow_open_signed if {
    result := deny with input as {"review": {"object": {
        "kind": "TrainingJob",
        "spec": {"datasets": [{"id": "ds-1", "classification": "open",
                               "provenance": {"signed": true}}]},
    }}}
    count(result) == 0
}
```

### 2.3 Policy 3 — Tenant Isolation (Feature Store)

**Purpose.** The feature store accepts read requests over gRPC. Each
request includes the caller's tenant identity (from the SPIFFE SVID
in Module 02's zero-trust foundation) and a list of feature keys
namespaced by tenant. The policy enforces that the caller can only
read feature rows whose tenant matches their identity, unless the
caller has an explicit cross-tenant grant.

**Where it runs.** OPA sidecar to the feature-store service, called
via Envoy ext-authz (or the service's own gRPC interceptor). This is
*not* a Kubernetes admission policy — it's request-time
authorization on every API call.

**Audit-chain evidence.** Every request decision is written to the
audit chain: caller SVID, tenant scope requested, feature keys,
decision, latency. Aggregated to detect cross-tenant fishing.

**Failure mode.** **Closed.** A request cannot be authorized if OPA
is unreachable. The feature-store client sees a `503` and retries
with backoff. This is the right trade-off because the feature-store
serves prediction-time requests where stale data is preferable to
leaked data; the upstream model-serving service can return a
fallback prediction or fail-open at its own level if the product
demands it.

<!-- follow-up: confirm the fallback policy with the model-
serving team — this assumes "OPA down = feature-store down" and that
the serving team has a documented degraded-prediction path. -->

```rego
# policies/mlops/tenant_isolation.rego
package mlops.tenant_isolation
import rego.v1

default allow := false

allow if {
    caller_tenant := input.attributes.caller.tenant
    every key in input.request.feature_keys {
        key_tenant := tenant_of(key)
        key_tenant == caller_tenant
    }
}

allow if {
    caller_tenant := input.attributes.caller.tenant
    grant := input.data.cross_tenant_grants[caller_tenant]
    every key in input.request.feature_keys {
        key_tenant := tenant_of(key)
        key_tenant in grant.tenants
        time.now_ns() < grant.expires_ns
    }
}

# Feature keys look like "tenant/<id>/feature/<name>".
tenant_of(key) := tenant if {
    parts := split(key, "/")
    parts[0] == "tenant"
    tenant := parts[1]
}

# Tests
sample_grants := {
    "tenant-a": {"tenants": {"tenant-b"}, "expires_ns": 9999999999999999999},
}

test_allow_same_tenant if {
    allow with input as {
        "attributes": {"caller": {"tenant": "tenant-a"}},
        "request": {"feature_keys": ["tenant/tenant-a/feature/clicks"]},
        "data": {"cross_tenant_grants": sample_grants},
    }
}

test_deny_cross_tenant_no_grant if {
    not allow with input as {
        "attributes": {"caller": {"tenant": "tenant-c"}},
        "request": {"feature_keys": ["tenant/tenant-a/feature/clicks"]},
        "data": {"cross_tenant_grants": sample_grants},
    }
}

test_allow_cross_tenant_with_grant if {
    allow with input as {
        "attributes": {"caller": {"tenant": "tenant-a"}},
        "request": {"feature_keys": ["tenant/tenant-b/feature/views"]},
        "data": {"cross_tenant_grants": sample_grants},
    }
}

test_deny_mixed_keys if {
    not allow with input as {
        "attributes": {"caller": {"tenant": "tenant-a"}},
        "request": {"feature_keys": [
            "tenant/tenant-a/feature/clicks",
            "tenant/tenant-c/feature/clicks",
        ]},
        "data": {"cross_tenant_grants": sample_grants},
    }
}

test_deny_expired_grant if {
    expired := {"tenant-a": {"tenants": {"tenant-b"}, "expires_ns": 1}}
    not allow with input as {
        "attributes": {"caller": {"tenant": "tenant-a"}},
        "request": {"feature_keys": ["tenant/tenant-b/feature/views"]},
        "data": {"cross_tenant_grants": expired},
    }
}

test_deny_malformed_key if {
    not allow with input as {
        "attributes": {"caller": {"tenant": "tenant-a"}},
        "request": {"feature_keys": ["bogus-key"]},
        "data": {"cross_tenant_grants": {}},
    }
}
```

### 2.4 Catalog summary

| # | Policy | Surface | Decision | Failure mode |
|---|--------|---------|----------|--------------|
| 1 | mlops.model_promotion | Conftest CI + Gatekeeper admission | deny on any violation | Closed (block promotion if engine down) |
| 2 | mlops.training_data_governance | Gatekeeper admission on TrainingJob | deny on any violation | Closed (block job if engine down) |
| 3 | mlops.tenant_isolation | OPA sidecar / ext-authz at the feature-store edge | default-deny `allow` | Closed (503 to caller) |

## 3. Validation steps

```bash
# 1) Tests pass.
opa test policies/mlops/ -v

# 2) Spot-check policy 1 with a failing input.
opa eval -d policies/mlops/model_promotion.rego \
  -i tests/fixtures/promotion-bad-accuracy.json \
  "data.mlops.model_promotion.deny"

# 3) Confirm tenant isolation under the ext-authz contract.
opa eval -d policies/mlops/tenant_isolation.rego \
  -i tests/fixtures/feature-store-cross-tenant.json \
  "data.mlops.tenant_isolation.allow"
# Expected: false

# 4) Confirm fail-closed behavior at the gateway layer (engine down):
#    Envoy ext-authz timeout produces HTTP 503 to the caller. This is
#    a runtime invariant, not a Rego invariant — test with an
#    integration test in the feature-store service repo.
```

## 4. Rubric / review checklist

| Area | Weight | What "pass" looks like |
|------|--------|-----------------------|
| Three real ML-specific policies | 20 | Not generic infra rules; tied to ML threats |
| Real Rego that parses | 15 | `opa test` runs; no syntax errors |
| ≥ 5 tests per policy | 15 | Each policy covers happy path + 4 failure modes |
| Where-it-runs named | 10 | Admission / sidecar / CI explicit per policy |
| Audit-chain evidence schema | 10 | Lists the fields recorded, ties to Module 07 |
| Failure mode reasoned | 10 | Fail-open vs. fail-closed stated with reason |
| Inputs come from `input.data` | 10 | Thresholds, allow-lists, signers externalized |
| Threat mapping | 10 | OWASP ML / MITRE ATLAS / NIST AI RMF references named |

Pass threshold: **75 / 100**.

Auto-fail conditions:

- Pseudo-Rego.
- Treats every policy as "block on failure" without considering
  fail-open scenarios at the application layer.
- Tests only cover happy path.
- No evidence integration with the audit chain.
- Skips the tenant-isolation policy or replaces it with a duplicate
  admission rule (it must demonstrate the sidecar pattern).

## 5. Common mistakes

1. **Hard-coding thresholds in the rule head.** Lifting them to
   `input.data.thresholds` lets ops change the bound without a code
   review and lets tests vary thresholds independently.
2. **Treating tenant isolation as an admission policy.** Admission
   runs at CRD apply time; the cross-tenant read happens at request
   time. The two surfaces require different engines.
3. **Adding fairness checks without a baseline.** A `disparate
   impact ≤ 1.25` rule fires on the *first* model promotion ever and
   blocks bootstrap. Provide a baseline-bootstrap path (initial
   promotion records its own baseline) or document the manual
   override.
4. **Conflating Cosign signature with attestation.** Signature
   confirms "an artifact was signed"; the attestation conveys *what
   was attested*. The promotion gate must check both — see Module 03
   and Project 4.
5. **Fail-open on the tenant-isolation sidecar.** A misconfigured
   Envoy ext-authz timeout that fails open is silently bypassing the
   policy in production. The sidecar config plus the upstream
   service-mesh defaults must both fail closed.
6. **Skipping the privacy-budget check on privacy-classified data.**
   Without an `epsilon, delta` constraint the differential-privacy
   guarantee is meaningless.
7. **Treating "approver = the proposer" as legitimate approval.**
   The audit-chain query must distinguish proposer from approver;
   the test `test_deny_no_approval` confirms the rule, but the
   audit-chain ingestion side also has to enforce it.

## 6. References

Official sources:

- OWASP Machine Learning Security Top 10:
  <https://owasp.org/www-project-machine-learning-security-top-10/>
- MITRE ATLAS (matrix and techniques): <https://atlas.mitre.org/>
- NIST AI Risk Management Framework (AI RMF 1.0):
  <https://www.nist.gov/itl/ai-risk-management-framework>
- OPA Rego v1 documentation:
  <https://www.openpolicyagent.org/docs/policy-language>
- OPA Envoy plugin (ext-authz pattern):
  <https://www.openpolicyagent.org/docs/envoy-introduction>
- Sigstore / Cosign:
  <https://docs.sigstore.dev/cosign/overview/>
- in-toto attestation framework: <https://in-toto.io/>

Cross-references:

- Module 03 / Project 4 — Cosign + in-toto attestation pipeline that
  supplies `input.data.cosign.verified`.
- Module 07 — audit-chain schema this catalog writes into.
- Module 02 — SPIFFE/SPIRE workload identity that supplies the
  `caller.tenant` field for the tenant-isolation policy.
- Exercise 02 — base Rego idioms reused here.
- Exercise 05 — packaging, signing, and distribution of this catalog.
