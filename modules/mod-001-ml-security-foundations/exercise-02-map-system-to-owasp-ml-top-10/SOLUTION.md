# SOLUTION — Exercise 02: Map SmartRecs to OWASP ML Top 10

> Read this *after* writing your own coverage matrix. The reference matrix
> is one defensible answer; reasonable matrices will differ in priority
> ordering and effort estimates. What should match is which items get
> Adequate / Partial / Inadequate, and what kind of work would close the
> gap.

## 1. Solution overview

This matrix maps the SmartRecs system (Exercise 01) against the OWASP
Machine Learning Security Top 10. The category names and IDs used here
are those published by the OWASP project (see References). The
assignment requires honest "applies" judgments and concrete fixes; the
matrix below treats every item as applicable unless the system
description makes it inapplicable on its face, which the prompt warns
is the common failure mode.

Three findings drive the executive summary:

- **ML02 (data poisoning) and ML10 (model poisoning)** combine into the
  largest concrete risk because of the closed feedback loop. Every
  authenticated tenant has a write path into tomorrow's training data.
- **ML05 (model theft / extraction)** is realistic given the per-request
  prediction API and tiered rate limit. A paid-tier subscription buys
  enough query budget to replicate a non-trivial fraction of the
  ranking surface.
- **ML06 (AI supply chain)** is a credible *upstream* risk that
  SmartRecs has no visibility into today — the training pipeline pulls
  from an analytics warehouse and the artifact store without any stated
  provenance check.

## 2. Worked answer — coverage matrix

The OWASP ML Top 10 items used below are those published in the OWASP
ML Security Top 10 project. SmartRecs context is from Exercise 01.

| ID | Title (OWASP) | Applies? | Why (one sentence) | Current controls | Coverage | Required additions | Effort |
|---|---|---|---|---|---|---|---|
| ML01 | Input Manipulation Attack | YES | Adversarial query patterns can degrade ranking quality or trigger tail-latency paths in the recommender. | Per-tenant rate limit (1k/100k RPM). | Inadequate | Add a per-tenant input-distribution monitor (e.g., KL-divergence between recent query feature distribution and a rolling 7-day baseline, alert at KL > 0.1); reject malformed payloads at the gateway. | 2 wk |
| ML02 | Data Poisoning Attack | YES | The closed feedback loop ingests click/purchase events from authenticated tenants into the next training run with no outlier detection. | None at the data layer. Tier-based RPM caps inference, not feedback. | Inadequate | Per-tenant outlier detection on feedback rates and event-type ratios; quarantine queue for events from accounts flagged in the last 24h; per-tenant cap on feedback events (not just inference requests). | 3 wk |
| ML03 | Model Inversion Attack | YES | A model trained on customer behavior can leak training-data attributes via targeted queries against the prediction API. | None specific to inversion. | Inadequate | Output post-processing: round confidence scores, suppress top-K beyond N=10, deny repeated targeted queries against the same `customer_id`. Document risk for the legal/privacy team. | 2 wk |
| ML04 | Membership Inference Attack | YES | The model returns top-K recommendations and is queryable per request, which is the standard membership-inference surface. | None specific. | Partial | Aggregate-only output (already the case at top-10), plus suppression of confidence scores in the response. Confirm `customer_id` cannot be supplied verbatim and probed. | 1 wk |
| ML05 | Model Theft (Stealing / Extraction) | YES | Paid-tier 100k RPM × 30 days = ~2.6B queries; enough to extract a usable surrogate of a recommender. | Tiered RPM. | Inadequate | Per-tenant query budgets *for distinct items queried*, not just request volume; watermarking of model outputs; detection signal on entropy-of-queries-over-time per tenant. | 4 wk |
| ML06 | AI Supply Chain Attacks | YES | Training pulls warehouse data and writes to the artifact store with no stated provenance check at either end. | None stated. | Inadequate | Sign training artifacts (Sigstore/cosign) and verify signatures at pod startup; pin warehouse data extracts to a hash recorded in the training job manifest; record build provenance (SLSA-style). | 4 wk |
| ML07 | Transfer Learning Attack | NO (low applicability) | SmartRecs trains from its own event data, not a pretrained public model. The attack vector requires an untrusted pretrained base. | N/A | Adequate | None — but if a future iteration starts fine-tuning a pretrained model (cf. GlobalRecs in Exercise 04), re-evaluate immediately. | 0 wk |
| ML08 | Model Skewing | YES | Feedback events from a small set of dominant stores will steer ranking; without per-tenant quality metrics this is invisible. | None. | Inadequate | Per-tenant ranking-quality metric (e.g., per-tenant NDCG@10 on held-out feedback); alert when a tenant's quality regresses > 1 σ over 7 days. | 3 wk |
| ML09 | Output Integrity Attack | YES | Recommendations are consumed directly by tenant frontends; tampering in transit or at the gateway changes what shoppers see. | HTTPS termination at the gateway. | Partial | Sign or HMAC the prediction response with a per-tenant key; let the tenant verify (optional but useful for high-trust tenants); ensure the gateway → pod hop is mTLS. | 2 wk |
| ML10 | Model Poisoning | YES | Closely related to ML02 but at the *artifact* layer: the promotion-and-pull pipeline has no signature verification at pod startup, so a write to `recs-prod` deploys silently. | Manual ticket approval before promotion. | Inadequate | Cosign-signed artifacts + verification at pod startup; codified promotion acceptance criteria (evaluation deltas, drift bound, signed attestation from the training pipeline); separate writer/promoter IAM roles. | 3 wk |

### Executive summary

**Top three gaps by impact.**

1. **ML02 (Data Poisoning) + ML10 (Model Poisoning).** Treat these as
   one program. SmartRecs has both a poisoning *channel* (feedback loop)
   and a poisoning *target* (the artifact + alias pipeline). Either alone
   would be top-tier; combined, a single compromised tenant credential
   can both shift training data and increase the likelihood a malicious
   `recs-vN` looks "good enough" to pass the manual promotion gate.
2. **ML06 (Supply Chain).** The training job's data extract and the
   serving pod's artifact pull are the two places trust is being
   *granted* without evidence. The fix (signing + verification +
   provenance recording) is well-understood and largely buys down
   several other items at once (ML10 directly, ML01 indirectly).
3. **ML05 (Model Theft).** Easiest to overlook because it is not a
   sudden-impact attack. But the prediction API and the paid tier's
   query budget make extraction realistic, and SmartRecs has *no*
   query-diversity signal today.

**Why these three, not the alternatives.** ML01 (input manipulation) is
real but bounded by per-tenant rate limits and self-correcting on the
next retrain. ML03/ML04 (inversion / membership) are real but limited
in business impact for a *recommender* (vs. a medical or fraud model).
ML08 (skewing) is high-impact but a lagging indicator of ML02 — fix
ML02 and the rate of ML08 incidents drops. The top-three pick targets
the *first-cause* threats with the largest blast radius.

**Proposed sequencing.**

- **Quarter 1:** ML10 artifact signing + verification (small,
  unblocks others); ML02 feedback outlier detection MVP; ML06 pin
  training data extracts by hash.
- **Quarter 2:** Codified promotion acceptance criteria (closes the
  human gap in ML10); ML08 per-tenant quality metric; ML05 query-
  diversity detector.
- **Quarter 3:** ML01 input-distribution monitor; ML03 output
  post-processing; ML09 response signing.

This sequence prioritizes *evidence at trust boundaries* (Q1), then
*observability on attacker behavior* (Q2), then *defensive hardening
of the request/response surface* (Q3). The exercise's lecture notes
§6 sequencing pattern (identity → audit → controls) is preserved at
the program level.

## Implementation

The deliverable is the coverage matrix; turning it into engineering
work follows the quarterly sequencing above:

1. **Publish the matrix in the team wiki** so OWASP ML IDs become
   first-class labels used in PRs and incident write-ups.
2. **Open one ticket per gap row** (`ML02 — sign and verify model
   artifact at pod startup`), tagged with the OWASP ID and the
   quarter from §2.10.
3. **Add the OWASP ID column to the existing risk register** so this
   matrix and the broader risk view don't drift.
4. **Re-score the matrix at each quarter boundary.** A control that
   was "partial" should either move to "yes" or be re-justified;
   silently leaving "partial" rows is how coverage rots.

## 3. Validation steps

1. **Row completeness.** Every row has all six columns filled. "I don't
   know" is not "N/A."
2. **Applicability defense.** Each `NO` has a one-sentence defense
   (here, only ML07). Multiple `NO`s without a defense is the classic
   failure mode.
3. **Engineering, not aspiration.** Each `Required additions` cell
   names a concrete control (signal + threshold, tool, or contract),
   not "improve security."
4. **Effort credibility.** Estimates are in eng-weeks and cover the
   work, not a single morning. Signing + verification realistically
   takes a sprint plus rollout; extraction-detection realistically
   takes a quarter.
5. **Cross-check against Exercise 01.** Every High-priority gap from
   Exercise 01 should map to an Inadequate or Partial row here. If a
   gap from your threat model is not visible in this matrix, decide
   whether you missed it in the matrix or it belongs in a different
   framework (which is itself a useful observation — see Reflection 2
   in the exercise prompt).

## 4. Rubric / review checklist

Pass if the matrix scores at least 8 of the following 10.

- [ ] All ten rows present, no skipped IDs
- [ ] Applicability column is mostly YES with concrete reasoning
- [ ] Any NO defended in one sentence
- [ ] Current-controls column distinguishes "have a control" from "have one that addresses *this* item"
- [ ] Coverage is mixed (some Adequate, some Partial, some Inadequate)
- [ ] Required additions are engineering tasks with a concrete metric or contract
- [ ] Effort estimates are credible (weeks, not days for cross-cutting work)
- [ ] Executive summary names the *top three* gaps and defends the ranking against an alternative
- [ ] Sequencing in the summary is justified (foundations before features)
- [ ] Matrix length ≤ 2 pages plus executive summary

## 5. Common mistakes

- **Marking ML07 (Transfer Learning) as applicable** without re-reading
  the system. SmartRecs does not start from a pretrained base model.
  GlobalRecs (Exercise 04) does, and the same item is `Inadequate` there.
- **Marking ML04 (Membership Inference) `Adequate`** because the API
  returns aggregates. Aggregates limit but do not eliminate the attack
  — confidence scores and repeated targeted queries leak information.
- **Calling ML06 (Supply Chain) `N/A` because we don't use third-party
  models.** The pipeline still has a *trust transition* at the data
  extract and at the artifact store. Supply chain is internal too.
- **Confusing ML02 and ML10.** ML02 attacks the *training data*; ML10
  attacks the *model artifact*. SmartRecs is exposed to both.
- **Effort estimates of "1 week" for cross-cutting work.** Signing,
  monitoring, and outlier-detection programs each take multiple
  iterations. Calibrate against the size of the team (5 engineers,
  no dedicated security).
- **Treating "we have an audit log" as control coverage.** An audit
  log is investigation infrastructure, not a preventive control.

## 6. References

- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>
  (category list, IDs, and descriptions used in section 2)
- MITRE ATLAS — <https://atlas.mitre.org/>
  (used in the executive summary's threat sequencing; tactic vocabulary
  reused in Exercise 03)
- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>
  (MAP/MEASURE/MANAGE functions inform the matrix structure and the
  Q1–Q3 sequencing rationale)
- Local exercise context: SmartRecs threat model in
  `modules/mod-001-ml-security-foundations/exercise-01-threat-model-a-small-ml-system/SOLUTION.md`
