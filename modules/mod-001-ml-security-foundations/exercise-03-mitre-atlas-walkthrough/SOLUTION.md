# SOLUTION — Exercise 03: MITRE ATLAS Walkthrough

> Read this *after* writing your own walkthrough. The reference uses the
> default scenario from the exercise prompt (a SmartRecs competitor wants
> to replicate ranking quality without paying for the underlying data and
> training). Other defensible scenarios produce different chains.

## 1. Solution overview

The default scenario is a **model-replication** attack: the competitor's
goal is a usable surrogate of SmartRecs' ranking model, not destruction
or financial gain. This maps onto MITRE ATLAS as primarily a
*Reconnaissance → ML Model Access → Collection → ML Attack Staging →
Exfiltration → Impact* chain, with `Initial Access` reduced to "buy a
paid subscription" because the adversary chose a legal entry point.

Three observations drive the walkthrough:

- **The earliest detection** is at *Collection*: a paid tenant generating
  a query pattern that looks like extraction (high entropy of distinct
  `item_id`s queried, low entropy of `customer_id`, high request
  diversity over a sustained window).
- **The latest useful detection** is at *Impact*: the competitor's
  surrogate appears in the market with suspicious similarity in
  recommendation ordering. Detection at this stage is forensic, not
  preventive.
- **The detection gap** is ML Attack Staging — the adversary's offline
  training of a surrogate happens on infrastructure SmartRecs has no
  visibility into and produces no signal SmartRecs can see.

## 2. Worked answer — walkthrough

### 2.1 Adversary

A competitor recommendation vendor with technical staff capable of
training models. They have a budget of ~$50k and a 6-month timeline.
They are not nation-state — they will not burn credentials or buy
zero-days. They have already taken the legal step of becoming a paid
SmartRecs tenant under a shell entity.

### 2.2 Goal and constraints

**Goal.** Produce an internal recommendation model whose ranking
correlates strongly enough with SmartRecs' production model that the
competitor can claim parity in sales conversations and stop paying
SmartRecs.

**Constraints.**

- Stay within the paid-tier 100k RPM quota (drawing attention by
  exceeding it would invite churn-prevention outreach).
- Avoid actions that look obviously like ToS violations; the legal
  ToS risk caps how aggressive the queries can look.
- 6 months and $50k cover compute and a small team but not unlimited
  query budget.

### 2.3 Tactic chain walkthrough

The tactic names below are the ATLAS tactics the exercise prompt lists.
The walkthrough skips Defense Evasion, Persistence, Privilege
Escalation, Credential Access, Command and Control, and Execution
because the adversary does not need an in-environment foothold —
their access is legitimate.

#### Reconnaissance

**What the adversary does.** Reads SmartRecs public marketing, press
releases, and the public API documentation. Maps the response schema
(top-K, with or without confidence scores), the rate limits, and the
free-vs-paid feature deltas. Identifies any tenant onboarding flow
that gives a free trial without billing friction.

**Signal it produces.** None unique to the adversary — they look like
any other prospect doing competitive analysis. Public docs are public.

**Detection that would fire.** None realistic. SmartRecs cannot
distinguish hostile reconnaissance from sales prospecting at this stage.

#### Resource Development

**What the adversary does.** Stands up training infrastructure in a
public cloud (a few `g5` GPU instances, ~$30k of the budget). Builds
a query-orchestrator that will issue paid-tier requests at the RPM
quota and store responses. Acquires a paid SmartRecs subscription
under a shell tenant.

**Signal it produces.** A new tenant signup. Payment from an entity
the sales team has never spoken with. Possibly a corporate email
domain with low reputation.

**Detection that would fire.** A *fraud / churn* check during
onboarding could flag low-reputation domains, but that's a business
control, not a security one. No security detection at this stage in
the current SmartRecs design.

#### Initial Access

**What the adversary does.** Logs in as the paid tenant via the
HTTPS API using the issued API key. Sets up the orchestrator to use
that key.

**Signal it produces.** A legitimate authenticated session. Indistinguishable
from any other paid tenant's first API call.

**Detection that would fire.** None. This is access granted, not
access stolen.

#### ML Model Access

**What the adversary does.** Begins issuing inference requests against
the recommendation API. The orchestrator selects query inputs to
maximize diversity (different `item_id`s, varied user contexts) and
records the top-10 responses.

**Signal it produces.** Sustained inference traffic at or near the
paid-tier ceiling. Distribution of request features over time
gradually drifts away from a "normal customer" pattern toward a
near-uniform query distribution over the product catalog.

**Detection that would fire.** With current SmartRecs controls, only
the rate-limit alert at the ceiling — which the adversary stays under
on purpose. *No* feature-distribution detector exists today.

#### Discovery

**What the adversary does.** Probes the API for boundary behaviors —
how the model handles cold-start users, edge categories, deliberately
malformed queries (to learn the validation layer). Confirms whether
confidence scores or ranks are returned.

**Signal it produces.** A burst of probing requests that look slightly
different from the steady-state extraction queries — more variety,
including malformed inputs.

**Detection that would fire.** A WAF-style anomaly detector could
catch the malformed requests if one existed; SmartRecs has none. The
gateway's input validation would silently 400 the malformed inputs,
which is a *signal* but not currently surfaced.

#### Collection

**What the adversary does.** Runs the extraction campaign continuously
for ~4 months. Collects on the order of 100M–1B `(input, top-10)`
pairs (within the 100k RPM budget). Stores them in their training data
lake.

**Signal it produces.** *This is the highest-signal stage.* The
adversary's tenant generates a query stream whose distribution looks
unlike a real e-commerce store: high entropy over distinct queried
items, low entropy over customer_id, ratio of unique items queried
to total queries near 1, no diurnal pattern matching a real shopper
day.

**Detection that would fire.** With the **proposed** detector from
the Exercise 02 mitigation (ML05): a per-tenant `query_diversity`
score sustained above a threshold over a multi-day window. *Without*
that detector, this stage produces no alert today.

#### ML Attack Staging

**What the adversary does.** Trains a surrogate model on the collected
pairs. Iterates on the training recipe (architecture, loss, sampling).
Periodically issues a small "validation" query batch against the live
API to measure agreement.

**Signal it produces.** The validation query bursts look like
miniature copies of the Collection stage. Otherwise, this stage
happens entirely on infrastructure SmartRecs cannot observe.

**Detection that would fire.** None. This is the **detection gap**.

#### Exfiltration

**What the adversary does.** Moves the collected pairs and trained
surrogate to their internal serving infrastructure.

**Signal it produces.** Egress traffic from the adversary's own
infrastructure — not SmartRecs'.

**Detection that would fire.** None on the SmartRecs side. The
egress happened on the adversary's network. The only SmartRecs-side
signal is the trailing low-rate of validation queries.

#### Impact

**What the adversary does.** Stops paying SmartRecs. Deploys their
surrogate model into their own product. Markets recommendation
quality competitive with SmartRecs.

**Signal it produces.** Subscription churn. Public-facing product
parity claims by the competitor.

**Detection that would fire.** Customer churn analytics may flag the
account loss, but as a business event, not a security event. *Post
hoc* detection: comparing recommendation rankings between SmartRecs
and the competitor on a controlled input set would show suspicious
correlation, but this is forensic.

### 2.4 First realistic detection point

**Collection.** Specifically, a per-tenant query-diversity signal:
sustained ratio of unique queried `item_id`s to total queries above a
threshold, over a window long enough to defeat day-of bursts. This is
the earliest point at which the adversary's behavior diverges
*observably* from a real tenant's behavior on a surface SmartRecs
already controls.

**Why not earlier?** Reconnaissance and Resource Development happen
off-platform; SmartRecs has no observation. Initial Access and ML
Model Access individually look like legitimate paid-tier use. The
adversary's early-stage queries are intentionally indistinguishable.
The point of divergence is the *aggregate distribution* of queries
over weeks — which requires having a baseline.

### 2.5 Last realistic detection point

**Late Collection / early ML Attack Staging.** The cross-validation
query bursts the adversary issues during surrogate training produce
the last in-platform signal. After surrogate training completes, the
adversary's queries stop and any detection signal goes with them.

Once the competitor's surrogate launches publicly (Impact), detection
is forensic — useful for evidence and ToS enforcement, not for
preventing harm.

### 2.6 Detection gaps

The gap is **ML Attack Staging**. The adversary trains a surrogate on
infrastructure SmartRecs has no visibility into and produces no
signal in the SmartRecs platform during that phase. SmartRecs can
make Collection more detectable and Impact more provable, but the
staging phase is inherently external.

A secondary gap is **Resource Development**: the adversary signs up
as a tenant, and SmartRecs has no integrated fraud / risk check on
tenant onboarding for shell entities. A telco-grade vendor would
have this; SmartRecs at its current scale does not.

### 2.7 Recommended detection additions

In priority order, mapped to where they fire:

1. **Per-tenant query-diversity detector** (Collection). Compute
   `unique_items_queried / total_requests` over a rolling 14-day
   window per tenant. Alert when the ratio exceeds the 99th percentile
   of normal tenants and stays above for ≥ 7 days. Pages the on-call.
2. **Per-tenant feature-distribution drift detector** (ML Model Access
   → Collection). KL-divergence between the tenant's recent query
   feature distribution and a 30-day baseline; alert on sustained
   high divergence. Catches adversaries who keep diversity moderate
   but pick atypical regions of feature space.
3. **Tenant onboarding risk check** (Resource Development). Integrate
   a domain-reputation / payment-fraud signal into the signup flow.
   Flag low-confidence signups for human review rather than auto-
   provisioning a paid tier.
4. **Periodic similarity audit on competitor outputs** (Impact,
   forensic). Maintain a benchmark query set; if a credible competitor
   product is suspected to have copied, run the benchmark and compare
   ranking correlation. This is a slow, deliberate control — useful
   for ToS enforcement.

### 2.8 Mini-exercise responses (optional)

**A. Counter-scenario ($25k, 3 months).** Resource Development gets
tighter — fewer GPU hours, smaller surrogate. Collection has to be
sharper — adversary issues fewer queries but picks them more
deliberately, which *increases* the feature-distribution-drift
signal and *decreases* the raw-volume signal. Net: the rate-limit
ceiling becomes irrelevant; the query-diversity detector becomes
even more important.

**B. Insider variant.** An insider with read access to the model
artifact does not need Collection at all — they exfiltrate the
artifact directly. ML Model Access and Collection collapse into a
single artifact-read event. The relevant detection moves from query
patterns to **artifact store access audit**: who pulled the model,
to where, when. Detections that fire on insiders that don't fire on
outsiders: object-store read from an IP outside the cluster CIDR;
access by a principal whose role doesn't normally read the artifact.

**C. Pseudo-Sigma for the first detection point.** A rule sketch — not
syntactically perfect — that an engineer could implement:

```yaml
title: Tenant query pattern resembles model extraction
id: smartrecs-ml-extraction-v1
status: experimental
description: |
  Sustained high query diversity per tenant. Recommender extraction
  campaigns tend to query a large fraction of the catalog with little
  customer-ID variation, which is unlike real e-commerce traffic.
logsource:
  product: smartrecs
  service: api-gateway
detection:
  selection:
    event_type: 'inference_request'
  filter_window: 14d
  aggregations:
    - tenant_id:
        unique_items_queried_ratio: '>0.7'   # vs. normal-tenant p99
        request_count: '>1000000'            # min volume to matter
        sustained_days: '>=7'
  condition: selection AND aggregations
level: medium
fields:
  - tenant_id
  - unique_items_queried_ratio
  - request_count
falsepositives:
  - Catalog-coverage analytics tools run by a tenant
  - New tenant onboarding (cold-start exploration)
```

## Implementation

The walkthrough is the artifact; the implementation work is closing
the detection gaps it surfaces.

1. **Convert §2.7 detection additions into detection-engineering
   tickets.** Each recommended detection (query-diversity, response-
   entropy, artifact-fetch alert, kill switch) gets one ticket with
   the ATLAS tactic/technique IDs in the title so the link to this
   document survives.
2. **Walk the chain at design-review time.** When a new feature
   touches the inference path or the artifact pipeline, replay §2.3
   against the proposed design and flag any tactic where the new
   feature *removes* a detection point.
3. **Refresh the adversary profile (§2.1) annually** or when the
   tenant mix changes materially — a switch from SMB tenants to
   enterprise tenants changes both the budget and the timeline.
4. **Tabletop the chain with on-call ops once.** The first-realistic
   and last-realistic detection points (§2.4–§2.5) become concrete
   only when someone has to actually answer the page.

## 3. Validation steps

1. **Realism check.** Re-read the Adversary section. The adversary
   has a budget, a timeline, technical capacity, and constraints. If
   your adversary is omniscient or omnipotent, the chain becomes
   unfalsifiable.
2. **Signal naming.** For every tactic you include, you have named
   *what would appear* in logs, metrics, or business behavior. If a
   tactic only has "what the adversary does," rewrite the row.
3. **Detection-point defense.** You can articulate why the first
   detection is not earlier and why the last detection is not later.
4. **Gap honesty.** The gap is concrete (a specific stage on a
   specific surface), not "we have no detection."
5. **Skip justification.** Any tactic you skipped has a one-line
   justification (why it doesn't apply). The exercise prompt names
   "skipping tactics without justification" as a failure mode.

## 4. Rubric / review checklist

Pass at ≥ 7 of 10.

- [ ] Adversary section is concrete (capability, budget, timeline,
      constraints)
- [ ] Every applicable ATLAS tactic has both "what the adversary does"
      and "what signal it produces"
- [ ] Skipped tactics have a justification
- [ ] First-detection point is defended against an earlier choice
- [ ] Last-detection point is defended against a later choice
- [ ] At least one detection-point choice survives a "what if the
      adversary stays under the threshold" challenge
- [ ] The detection gap is named (stage + surface), not generic
- [ ] Recommended detections are concrete (signal + threshold + surface
      + responder)
- [ ] Total length is 2–3 pages; not padded
- [ ] If the optional Sigma was attempted, it includes false-positive
      considerations

## 5. Common mistakes

- **Adversary is unrealistic.** A nation-state with a zero-day budget
  defeats every detection. The exercise prompt explicitly calls out
  realism as the quality bar.
- **Every tactic is "detectable."** If your walkthrough fires an alert
  at every stage, you are over-claiming the SmartRecs detection
  posture.
- **Skipping `Initial Access` without saying so.** In this default
  scenario, Initial Access is "buy a subscription" — a one-line note
  is sufficient, but it has to be there.
- **Generic detection recommendations.** "Improve monitoring" is the
  failing-mode example. Detections must specify the signal, the
  threshold, and the surface.
- **Treating Reconnaissance as where detection should start.** Public
  reconnaissance is invisible. The walkthrough is stronger when it
  *names* the earliest point where the adversary's behavior diverges
  from legitimate use.
- **Conflating Impact with detection.** Impact in this scenario is a
  business event (subscription churn). Forensic detection at Impact
  is useful for ToS enforcement, not for preventing harm.

## 6. References

- MITRE ATLAS — <https://atlas.mitre.org/>
  (tactic vocabulary in section 2.3; matrix view for the chain)
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>
  (ML05 Model Theft cross-reference for Section 2.7 recommendation #1)
- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>
  (MEASURE function shapes the "signal it produces" / "detection that
  would fire" structure used per tactic)
- Local exercise context: SmartRecs threat model in
  `modules/mod-001-ml-security-foundations/exercise-01-threat-model-a-small-ml-system/SOLUTION.md`
