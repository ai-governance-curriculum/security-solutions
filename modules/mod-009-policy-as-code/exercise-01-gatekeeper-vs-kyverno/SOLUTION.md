# SOLUTION — Exercise 01: Gatekeeper vs. Kyverno Choice

> Read this *after* attempting the learning-side decision document. The
> goal here is not to mark one tool "winner" — both projects are
> production-grade, CNCF-graduated admission controllers. The goal is to
> show how a weighted decision is *defended* given SmartRecs' specific
> constraints, and how the Rego-portability question changes the answer.

## 1. Solution overview

The exercise is a design deliverable: a 2–3 page decision document
choosing Gatekeeper or Kyverno for SmartRecs. There is no single right
answer — both tools are CNCF Graduated projects (Gatekeeper graduated
November 2024; Kyverno graduated June 2025) and both can enforce the
required policies. The grader is checking that the learner:

- Names explicit, weighted criteria *before* picking.
- Compares both tools on each criterion.
- Acknowledges what is *worse* about the pick.
- Engages with the **Rego-portability** question — the load-bearing
  argument once Conftest and Terraform validation enter scope.

This solution presents the **Gatekeeper choice** as the worked
example, because the constraints listed (Conftest in scope, Terraform
validation in scope over the next 12 months) tilt the weighted score
toward Rego portability. A defensible Kyverno answer is sketched at the
end of section 2 so graders can recognize both forms.

## 2. Worked answer or implementation

### 2.1 Decision document (Gatekeeper path)

```markdown
# Gatekeeper vs. Kyverno: Decision for SmartRecs

## Audience
Engineering leadership, platform lead, security lead.

## TL;DR
We are adopting **OPA Gatekeeper** as SmartRecs' Kubernetes admission
controller. The decisive factor is **Rego portability**: the same policy
language drives Conftest (CI gates) and Terraform plan validation, both
of which are in the 12-month roadmap. We accept higher policy-author
friction (Rego learning curve, ConstraintTemplate/Constraint split) as
the cost of a single policy language across the program.

## Decision criteria

| # | Criterion | Weight | Why this matters for SmartRecs |
|---|-----------|--------|--------------------------------|
| 1 | Rego portability across CI, Kubernetes, Terraform | 25 | Conftest + Terraform validation are in 12-month roadmap; one language = lower total cost of ownership |
| 2 | Policy-author friction (time to first useful policy) | 15 | Only 2 people (security + 1 platform) will author; learning curve is real but bounded |
| 3 | Built-in mutation + image-verification | 15 | We need Cosign signature verification at admission (Module 03 link) |
| 4 | Audit-chain integration for SOC 2 Type 2 | 15 | Every deny needs a queryable, signed audit record |
| 5 | Maturity and CNCF status | 10 | Both are CNCF Graduated; near-tie |
| 6 | Operational complexity (CRDs, upgrades, HA) | 10 | Platform team owns it; must be sustainable for a 6-person team |
| 7 | Community + ecosystem (policy libraries) | 10 | Faster bootstrapping if known-good policies exist upstream |

Weights sum to 100. Weights were set by the security lead and platform
lead together; documented in `docs/decisions/0007-policy-engine.md`.

## Side-by-side

| Criterion | Gatekeeper | Kyverno |
|-----------|-----------|---------|
| Rego portability | **Native** — same Rego runs in Conftest, Terraform OPA provider, app sidecar | Kyverno policies are YAML, not portable; would require parallel Rego library for non-K8s gates |
| Policy-author friction | Higher — Rego is its own paradigm; ConstraintTemplate + Constraint split adds indirection | Lower — YAML feels like Kubernetes manifests; faster ramp |
| Mutation + image verification | Mutation is GA; image verification via `external-data` provider or Gatekeeper-provider-cosign | Built-in `verifyImages` rule with native cosign/notary support |
| Audit-chain integration | Decisions logged via webhook + audit policy; Gatekeeper-audit subsystem produces violation reports for existing resources | Native PolicyReport CRD (Kubernetes Policy Reports API); reports queryable via kubectl |
| CNCF maturity | Graduated (Nov 2024) <!-- follow-up: confirm exact graduation date if cited in customer-facing doc --> | Graduated (Jun 2025) <!-- follow-up: confirm exact graduation date if cited in customer-facing doc --> |
| Operational complexity | Higher: ConstraintTemplates, Constraints, ConfigSync, audit-pod | Lower: ClusterPolicy CRD is one object; webhook + reports controller |
| Community policy libraries | `gatekeeper-library` upstream catalog | `kyverno/policies` upstream catalog |

## Decision

**Gatekeeper.** The weighted scores are close; the tiebreaker is
criterion 1 (Rego portability, weight 25). Because Conftest and
Terraform validation are committed roadmap items, the marginal cost of
a second policy language (Rego for Conftest + YAML for Kyverno)
exceeds the marginal cost of the steeper Rego learning curve for our
two authors.

## Trade-offs accepted

1. **Higher author friction.** Rego is harder than Kyverno YAML for a
   policy newcomer. Mitigation: pair-programming on the first 5
   policies, `opa test` examples in the policy repo, code review by
   security lead on every PR for the first quarter.
2. **Image verification path is less direct.** Kyverno's `verifyImages`
   is more ergonomic than Gatekeeper's external-data provider pattern.
   Mitigation: adopt `gatekeeper-provider-cosign` (or equivalent
   external-data integration) and treat the integration as a Module 03
   deliverable.
3. **Audit reporting is less native.** Kyverno's PolicyReport CRD is
   nicer than Gatekeeper's audit pod for ad-hoc queries. Mitigation:
   ship decisions to the audit-chain pipeline (Module 07) regardless of
   engine, so the engine's native report isn't the primary surface.

## Migration considerations

SmartRecs has neither engine in production today. Future migration
risks:

- If we later move to Kyverno, the Rego library still applies to
  Conftest and Terraform; only the K8s admission policies need
  rewriting in Kyverno YAML.
- If we adopt Sentinel for Terraform (HashiCorp's policy language), the
  Rego-portability advantage shrinks because the Terraform half moves
  off Rego. Re-evaluation trigger documented below.

## Re-evaluation triggers

Revisit this decision if any of these become true:

1. SmartRecs adopts Sentinel for Terraform Cloud or HCP — collapses the
   Rego-portability advantage.
2. The platform team grows past 12 engineers and policy authoring is
   distributed broadly — Kyverno's lower friction starts to dominate.
3. Gatekeeper drops external-data Cosign support, or `verifyImages`-
   equivalent ergonomics arrive (track Gatekeeper roadmap).
4. SOC 2 auditors push back on Gatekeeper's audit-pod evidence model.

## Open questions

- Who owns the `gatekeeper-provider-cosign` deployment? (Likely
  security; needs confirmation with platform.)
- Bundle distribution: pull-from-S3 vs. GitOps — answered in Exercise 05.
- Do we run Gatekeeper in dry-run for the first 30 days per policy? Yes
  (see Exercise 05 conformance-test step).
```

### 2.2 Defensible Kyverno alternative — the short form

A Kyverno answer is defensible if the learner:

- Argues that the *current* roadmap weight of Conftest/Terraform is
  overstated relative to a 12-month horizon that has a high chance of
  changing.
- Cites the `verifyImages` Cosign integration as worth ~15 weight on
  its own because Module 03 is the immediate next module.
- Acknowledges that Conftest can still run Rego authored from scratch
  for the non-K8s surface, and the cost of dual languages is bounded
  because only the security lead writes both.
- Names the same re-evaluation triggers in reverse: revisit if the Rego
  surface (Conftest + Terraform OPA) gets larger than the K8s
  admission surface.

Both choices pass if the *reasoning* is rigorous and the trade-offs
are named.

## 3. Validation steps

This is a design exercise; validation is review-based.

1. **Self-check the format.** All seven sections from the exercise spec
   are present (criteria, side-by-side, decision, trade-offs accepted,
   migration, re-evaluation, open questions / Rego portability).
2. **Weighted criteria sanity check.** Weights sum to 100. No single
   criterion has weight > 30 unless explicitly justified. The
   Rego-portability question has a non-zero weight.
3. **Both tools score on every criterion.** No criterion has a blank
   cell or "N/A — depends" on either side.
4. **Trade-offs are concrete.** Each trade-off names a mitigation, not
   "we'll deal with it later."
5. **Reflection questions answered.** Sentinel-for-Terraform scenario,
   "just pick one" objection, and signal-for-wrong-choice are
   addressed at the bottom of the doc.

## 4. Rubric / review checklist

| Area | Weight | What "pass" looks like |
|------|--------|-----------------------|
| Explicit weighted criteria | 20 | ≥ 5 criteria; weights sum to 100; rationale per criterion |
| Side-by-side on each criterion | 20 | No blank cells; specific differences (not "both are good") |
| Decision with reasons | 15 | Names the dominant criterion that tipped the call |
| Trade-offs accepted | 15 | Names 2+ things that are *worse* about the choice and a mitigation per trade-off |
| Migration considerations | 10 | Reasons about both directions (adopting and later switching) |
| Re-evaluation triggers | 10 | Concrete, observable triggers (not "if things change") |
| Rego portability addressed | 10 | Explicitly engages with Conftest/Terraform implications |

Pass threshold: **75 / 100**. A doc that hits 90+ is also tight enough
to skim in 5 minutes.

Auto-fail conditions:

- No weighted criteria (just narrative).
- Picks based on "feels better" or "more popular" without criterion
  backing.
- "It depends on context" with no decision.
- Skips the Rego-portability question entirely.

## 5. Common mistakes

1. **Treating "CNCF Graduated" as a differentiator.** Both projects are
   graduated; this criterion should be near-tied unless the doc
   explains why one's graduation trajectory is more relevant.
2. **Confusing Kyverno with kyverno-json.** kyverno-json is a separate
   tool for non-Kubernetes policy on JSON/YAML; do not cite it as
   parity with Conftest's Rego coverage.
3. **Quoting performance benchmarks without a source.** Both engines'
   admission-latency behavior depends on cluster size and policy
   complexity. If a benchmark is cited, link the source; otherwise
   leave performance out of the weighted criteria or note it as an
   open question.
4. **Treating mutation as Gatekeeper-only.** Gatekeeper added
   mutation; both engines mutate. The honest comparison is on
   ergonomics, not capability.
5. **Skipping the operational-complexity criterion.** A 6-person team
   has to *run* the engine; the choice is not only about the policy
   language.
6. **Letting "Kyverno is newer therefore better" or "Gatekeeper is older
   therefore safer" drive the decision.** Both are mature.

## 6. References

Official project documentation (load-bearing for any factual claim):

- OPA Gatekeeper documentation — <https://open-policy-agent.github.io/gatekeeper/>
- Kyverno documentation — <https://kyverno.io/docs/>
- Open Policy Agent (Rego language) — <https://www.openpolicyagent.org/docs/>
- Conftest — <https://www.conftest.dev/>
- CNCF Graduated and Incubating Projects listing — <https://www.cncf.io/projects/>
- Kubernetes Policy Reports API (used by Kyverno) — <https://kyverno.io/docs/policy-reports/>
- Sigstore / Cosign — <https://docs.sigstore.dev/>

Cross-references inside this curriculum:

- Module 03 (image signing / Cosign) — admission-time verification path
  determines the image-verification criterion weight.
- Module 07 (audit chain) — both engines feed the same downstream
  audit-chain consumer; engine-specific reporting is secondary.
- Exercise 05 (this module) — bundle distribution + rollback plan
  assumes Gatekeeper but is engine-agnostic in structure.
