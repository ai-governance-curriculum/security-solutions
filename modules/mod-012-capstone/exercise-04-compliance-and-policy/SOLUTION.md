# SOLUTION — Capstone Exercise 04: Compliance and Policy Program

> Read this *after* attempting the exercise. The aim is a defensible
> compliance and policy program for the ML system scoped in
> Exercises 01 and 02 — not a recitation of every framework.

## 1. Solution overview

The exercise asks for a compliance and policy program that is (a)
grounded in a recognised AI risk-management framework, (b) expressed
as machine-checkable policy where possible, and (c) operable by the
team that will run the system. A passing answer must:

- Adopt NIST AI RMF 1.0's four-function structure
  (**Govern / Map / Measure / Manage**) as the program's spine, and
  map every policy artifact to one of the four functions.
- Distinguish "policy" (a written rule the org agrees to live by)
  from "control" (the mechanism that enforces or evidences the rule).
  Every policy in the program has either an enforcing control
  (preferred) or a named manual control with a review cadence.
- Express enforceable policy as **policy-as-code** where the
  enforcement chokepoint supports it (OPA admission for Kubernetes
  resources, registry promotions, and IaC; Conftest / OPA Gatekeeper
  for repo-time checks).
- Show the operating model: who proposes policy, who approves it,
  who runs the exceptions process, and what evidence is collected
  for audits.

A weak submission lists frameworks (SOC 2, ISO 27001, EU AI Act)
without describing how policy actually gets *enforced* day to day.

## 2. Implementation

### 2.1 Framework choice and rationale

The program adopts **NIST AI RMF 1.0** as the primary structural
framework because (a) it is explicitly designed for AI/ML systems,
(b) its four functions map cleanly to operating practice (governance,
context, measurement, response), and (c) regulators and customers
increasingly reference it.

Sector-specific frameworks (e.g., SOC 2, ISO 27001) are mapped as
overlays — each control inherits from NIST AI RMF and is additionally
tagged with the SOC 2 trust-services criterion it satisfies, so audit
evidence is collected once and reused.

### 2.2 Program structure (NIST AI RMF 1.0 four-function spine)

| Function | What lives here | Owner | Example artifacts |
|----------|-----------------|-------|-------------------|
| **Govern** | The org-level decisions: AI use policy, risk appetite, roles, exception process. | Head of Security + Legal + Head of ML | AI-use policy; model risk-appetite statement; exception register; quarterly board report. |
| **Map** | Per-system context: what is this model, who uses it, what data, what risks. | ML product owner + Security architect | Model card; system context document; threat model (Ex-01); deployment scope statement. |
| **Measure** | Evidence collection: metrics, evaluations, audits, monitoring outputs. | ML platform + SecOps | Holdout-set evaluation reports; fairness slice reports; drift dashboards; SBOM diff reports; control test results. |
| **Manage** | Response and decisions: incident response, retraining, retiring models, exception decisions. | Incident commander + ML product owner | Incident postmortems; retraining decisions; exception approvals; sunset plans. |

Each artifact carries a `nist-ai-rmf-function` tag so quarterly
program reviews can confirm coverage across all four functions.

### 2.3 Policies (the rules)

The program defines a small number of policies that are unambiguous
and testable. Each is owned by a named role and has an enforcing
control or a manual control with a review cadence.

| Policy ID | Statement | Enforcing control | Manual control | Owner |
|-----------|-----------|-------------------|----------------|-------|
| POL-AI-001 | Production models must carry a published model card before serving traffic. | OPA admission on model-serving deployment rejects manifests without a model-card artifact. | Quarterly card audit. | ML product owner |
| POL-AI-002 | Production models must be promoted only by a four-eyes review with two distinct approvers from different teams. | OPA gate on registry promotion requires two attesting signatures. | None. | Security + ML product |
| POL-AI-003 | Training data classified `restricted` must be trained with differentially-private SGD with epsilon ≤ N (set in the data inventory). | Training pipeline reads dataset class and applies DP-SGD; release gate verifies privacy accountant. | Annual review of epsilon value. | ML platform |
| POL-AI-004 | Any model with a fairness slice regression > X% on the gold holdout must not be promoted. | Evaluation step writes report; OPA gate consumes the report. | None. | ML product owner |
| POL-AI-005 | All container images and model artifacts in production must be signed by an allow-listed signer. | Cosign verification at admission; registry signing policy. | None. | Platform security |
| POL-AI-006 | Production access to feature stores requires a Vault-issued, short-lived credential. | Vault dynamic secrets; no static credentials in image. | Quarterly scan for static credentials. | Platform security |
| POL-AI-007 | High-impact incidents require a written postmortem within 10 business days. | Ticket templated by incident-tracker; SLA breach paged. | SecOps program review. | Incident commander |
| POL-AI-008 | Exceptions to policy require a written justification, an expiry date no longer than 90 days, and approval by the policy owner. | Exception register tracked in policy repo; auto-expiry. | Monthly exception review. | Head of Security |

### 2.4 Policy-as-code: a worked Rego example

The example below is the kind of policy expected for POL-AI-002 (four-
eyes model promotion). It is illustrative and intentionally minimal —
real policies will reference an organisation's actual identity
provider and pipeline metadata.

```rego
package mlplatform.registry.promotion

# Default deny: a promotion request is rejected unless this policy
# evaluates to allow.
default allow := false

allow if {
    input.action == "promote"
    count_distinct_signers >= 2
    count_distinct_teams >= 2
    not signer_is_requester
    valid_attestation
}

count_distinct_signers := count({s | s := input.signatures[_].signer_id})

count_distinct_teams := count({t | t := input.signatures[_].team})

signer_is_requester if {
    some s in input.signatures
    s.signer_id == input.requester.id
}

valid_attestation if {
    input.attestation.predicate.type == "https://in-toto.io/Statement/v1"
    input.attestation.signer_id in data.signers.allow_list
}
```

The accompanying test set (Conftest or OPA test) exercises:

- A two-signature request from one team → deny.
- A two-signature request from two teams where one signer is the
  requester → deny.
- A two-signature request from two teams, neither signer is the
  requester, attestation present → allow.
- A two-signature request with a signer not in the allow-list →
  deny.

Tests live in the policy repo and run on every PR; broken policy is
caught at PR time, not at incident time.

### 2.5 Audit and evidence model

For each policy the program defines a single source of evidence so
that audits are not exercises in archaeology.

| Policy | Evidence source | Retention | Refresh cadence |
|--------|-----------------|-----------|-----------------|
| POL-AI-001 | Model card storage + admission decision logs | 7 years | Continuous |
| POL-AI-002 | Registry promotion audit log with signer IDs | 7 years | Continuous |
| POL-AI-003 | Privacy accountant snapshot per training run | 7 years | Per training run |
| POL-AI-004 | Promotion evaluation report | 7 years | Per promotion |
| POL-AI-005 | Cosign verification events in admission audit log | 7 years | Continuous |
| POL-AI-006 | Vault audit log | 1 year | Continuous |
| POL-AI-007 | Postmortem repository | 7 years | Per incident |
| POL-AI-008 | Exception register | Lifetime + 3 yrs | Continuous |

### 2.6 Operating model

- **Policy proposal.** Any team may propose a new policy or change.
  Proposals are PRs in the policy repo with rationale, expected
  enforcement, and rollout plan.
- **Approval.** The policy owner approves; the AI governance group
  is informed; Legal reviews any policy whose enforcement could
  affect customers.
- **Rollout.** New OPA policies are deployed in `dryrun` mode for a
  named period (default 14 days), with violation counts reported;
  enforcement is toggled only after violation noise drops below an
  agreed threshold.
- **Exceptions.** Exceptions follow POL-AI-008 — they are time-
  bounded, named, and approved by the policy owner. Standing
  exceptions are a smell; the exception register is reviewed monthly.
- **Quarterly review.** The governance group reviews the program
  against the AI RMF four functions; missing coverage drives the
  next quarter's policy backlog.

### 2.7 Decision rationale (what a reviewer wants to read)

- **Why NIST AI RMF as the spine, not SOC 2 / ISO.** SOC 2 and ISO
  controls map well to general SaaS hygiene but do not name AI-
  specific concerns (model drift, fairness regressions, training-
  time poisoning). AI RMF does. Sector frameworks then overlay onto
  the same controls.
- **Why policy-as-code at the chokepoint, not at PR time only.** PR-
  time checks rely on developer cooperation; admission checks reject
  the bad state regardless of how it arrived. PR-time checks remain
  as a fast feedback loop.
- **Why dryrun before enforce.** A new policy that fires on
  legitimate but unanticipated workflows breaks the team's trust in
  policy-as-code. Dryrun + violation triage is the cheapest way to
  catch the surprises before enforcement.

## 3. Validation steps

1. **Function coverage.** Confirm at least one artifact tagged to
   each of Govern / Map / Measure / Manage.
2. **Policy testability.** For every policy, confirm there is either
   an enforcing control or a named manual control with a review
   cadence.
3. **Rego tests pass.** Run `opa test policies/` and confirm green.
4. **Audit trail closure.** For every policy, confirm an evidence
   source is named and a retention is set.
5. **Exception process is alive.** Confirm exception register exists,
   has expiry dates, and has been reviewed in the last 30 days.

## 4. Rubric / review checklist

| Criterion | Weight | Pass condition |
|-----------|--------|----------------|
| NIST AI RMF function spine used | 10 | All four functions appear with owners and example artifacts. |
| Policies are testable, not aspirational | 15 | Each policy can be evaluated as pass/fail without interpretation. |
| Enforcing control per policy (or justified manual) | 15 | Each policy has an enforcing control or a manual control with cadence. |
| Working Rego example with tests | 15 | Example policy + tests included and the Rego is syntactically valid. |
| Audit-evidence table present | 10 | One source of evidence per policy, with retention. |
| Exception process defined | 10 | POL-AI-008 (or equivalent) is described, time-bounded, and reviewed. |
| Sector-framework overlay shown | 5 | At least one SOC 2 / ISO 27001 mapping is included. |
| Rollout plan named | 5 | Dryrun → enforce cadence and violation-noise threshold are stated. |
| Out-of-scope frameworks called out | 5 | Frameworks deferred (e.g., EU AI Act high-risk tier) are named and justified. |
| References cited | 10 | Official sources linked. |

## 5. Common mistakes

- **Listing frameworks without policies.** "We will comply with SOC
  2" is not a program; SOC 2 controls must be instantiated as
  specific policies and evidence.
- **Aspirational policies.** "All models must be fair" — not
  testable. "No model with > X% slice regression on the gold
  holdout may be promoted" — testable.
- **PR-time checks only.** Easy to bypass; the chokepoint is the
  admission gate.
- **No exception process.** Real-world exceptions happen; without a
  named process they become silent risk acceptance.
- **No dryrun.** A policy that breaks promotion on day one will be
  disabled by the on-call engineer; the program's reputation does
  not recover quickly.
- **Audit-by-archaeology.** If the evidence source is "search Slack",
  the audit will fail.

## 6. References

- NIST AI Risk Management Framework (AI RMF 1.0) — <https://www.nist.gov/itl/ai-risk-management-framework>
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>
- MITRE ATLAS — <https://atlas.mitre.org/>
