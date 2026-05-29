# Exercise 02 — Defense Plan with Quantified Trade-offs

> Read this *after* you have produced your own defense plan. This file
> is a reference defense plan, the rationale for each choice, and the
> rubric you can grade your own answer against.

## 1. Solution overview

The exercise asks the learner to take the threat enumeration from
exercise-01 (or an equivalent one) and produce a *defense plan*. The
deliverable has three parts:

1. **A defense table** — one row per in-scope threat, naming the
   primary defense, any secondary layer, the cost the defense imposes,
   and the residual risk it leaves behind.
2. **A trade-off discussion** — for each defense, what gets worse when
   you turn it on (clean accuracy, latency, training cost, operational
   complexity) and how you would measure that cost in your environment.
3. **A roll-out plan** — which defenses ship first, which need an
   experimental period, and which require a written decision from the
   product/risk owner before they go live.

The plan is **threat-driven**, not technique-driven. The reviewer
should be able to draw a line from each defense back to the OWASP ML
Top 10 / MITRE ATLAS row it answers.

## 2. Worked answer — implementation

### 2.1 Defense table

The threat IDs T1–T6 below reuse the enumeration from
`exercise-01-robustness-assessment/SOLUTION.md` §2.2.

| Threat (T1–T6) | Primary defense | Secondary layer | Cost dimension | Residual risk |
|---|---|---|---|---|
| T1 Evasion (white-/grey-box) | PGD-based adversarial training | Input feature anomaly detection (OOD gate) | Clean accuracy drop; longer training time | Attacks outside the trained ε-ball |
| T2 Transfer evasion | Same adversarial training | Backbone hardening / refusal to use untrusted upstream weights | Same | Strong surrogate attackers |
| T3 Membership inference | DP-SGD with budgeted (ε, δ) | Output truncation (top-1 label only, no probability vector) | Clean accuracy drop; (ε, δ) budget accounting overhead | Non-zero leakage at any finite ε |
| T4 Model extraction | Per-tenant query rate limits | Query auditing + similar-query detection | Operational complexity; latency at the gateway | Long-horizon, low-rate extraction |
| T5 Data poisoning | Signed dataset manifests + diff-on-merge for training data | Activation-clustering / spectral-signature scan pre-deploy (see exercise-03) | Process friction; storage for raw + processed copies | Sophisticated label-flipping that evades both gates |
| T6 Backdoor | Same as T5 + targeted trigger-detection scan | Honeypot / canary-trigger monitoring at inference | Same; plus inference-time scoring overhead | Triggers crafted to evade known detectors |

Notes:

- **Adversarial training** is the standard defense against the
  evasion-attack family. PGD-based adversarial training was
  established by Madry et al. ("Towards Deep Learning Models Resistant
  to Adversarial Attacks", ICLR 2018) as the modern baseline;
  single-step defenses (FGSM-only) over-fit to single-step attackers
  and collapse under multi-step attacks.
- **DP-SGD** provides a privacy guarantee at training time, expressed
  as an (ε, δ) budget. See exercise-04 for the configuration
  walk-through. The defense is against membership-inference and
  related leakage, not against evasion.
- **Per-tenant rate limits** are an *economic* defense, not a
  mathematical one. They raise the cost of extraction; they do not
  prove it impossible.
- **Signed datasets + diff-on-merge** is the upstream control for the
  poisoning family. The cross-link is
  `projects/project-4-secure-cicd/SOLUTION.md`, which covers the
  signing infrastructure (Cosign, Sigstore) in depth.

### 2.2 Trade-off discussion (per defense)

The point of this section is to make the cost concrete. Each defense
gets the same template:

- *What gets worse when it is on?*
- *How will we measure that cost?*
- *Who owns the threshold for "acceptable cost"?*

**Adversarial training.**
- Worse: clean accuracy drops; training time grows roughly with the
  number of attack steps per batch.
- Measure: run the benchmark in
  `projects/project-3-adversarial-defense/benchmark/robustness.py` —
  it reports clean accuracy with and without adversarial training, and
  robust accuracy at ε ∈ {2/255, 4/255, 8/255}. Numbers are
  environment-specific; record yours rather than copying any.
- Owner: ML/product owner signs off on the clean-accuracy floor.

**DP-SGD.**
- Worse: clean accuracy drops as ε shrinks; gradient clipping +
  noise raise per-step compute; you must maintain an (ε, δ) ledger
  across training runs to avoid silently exhausting the budget.
- Measure: train with `noise_multiplier` swept across at least three
  values; report (ε, δ) at end-of-training plus clean accuracy
  for each. See exercise-04 for the worked configuration.
- Owner: privacy/legal owns the (ε, δ) target; ML owns the accuracy
  floor.

**Per-tenant rate limits.**
- Worse: legitimate high-volume tenants may hit limits; you need a
  tier override path.
- Measure: 95th-percentile query rate per tenant over a 30-day window.
  The limit goes above that with margin; you alert on tenants whose
  recent rate approaches the limit.
- Owner: product owns the tier-policy; security owns the limit math.

**Signed manifests + diff-on-merge.**
- Worse: dataset ingestion is no longer "rsync and go" — every update
  requires a signature + a reviewable diff. The org needs key
  management.
- Measure: time-to-ingest a new dataset version (lead-time metric);
  number of poisoning candidates caught at the diff gate.
- Owner: data platform owns the signing infra; security owns the
  policy that rejects unsigned data.

**Output truncation (top-1 only).**
- Worse: customers who consume probability vectors lose them; the
  API contract changes.
- Measure: count downstream consumers using `prob[*]` fields.
- Owner: product, with security input. This is often the most painful
  defense to land because it is product-visible.

### 2.3 Roll-out plan

Order matters: ship the cheap, broadly applicable controls first;
defer expensive controls until you have evidence they buy what you
think they buy.

1. **Wave 1 (process + gateway).** Per-tenant rate limits, output
   truncation, signed dataset manifests, diff-on-merge for training
   data. None of these touch the model; failure modes are observable
   at the gateway/pipeline layer.
2. **Wave 2 (training-time).** Adversarial training. Run an A/B
   between hardened and baseline model; promote when the
   clean-accuracy regression is within the product floor and robust
   accuracy is materially better on the benchmark.
3. **Wave 3 (privacy).** DP-SGD. This wave is where you may need
   external sign-off (privacy review, sometimes legal) because the
   (ε, δ) target is a policy decision, not just an engineering one.
4. **Wave 4 (detection layers).** Activation clustering / spectral
   signature scanning of training data; query-similarity detection
   for extraction; canary-trigger monitoring for backdoors. These are
   the highest-cost, lowest-coverage layers; ship after the cheaper
   waves have absorbed the obvious risk.

Each wave has an exit criterion (e.g. "Wave 2 exits when robust
accuracy at ε = 8/255 is stable across two model versions"). Without
the exit criterion, waves drag and nothing graduates to "load-bearing."

## 3. Validation steps

A solution is valid if:

1. Every in-scope threat from the assessment has at least one named
   primary defense.
2. Every defense has a cost dimension *and* a residual-risk note. A
   defense without residual risk has not been read carefully.
3. The trade-off for each defense names *what* gets worse and *how to
   measure it*, not just "there is a trade-off."
4. The roll-out plan has an order, an exit criterion per wave, and a
   named owner per decision.
5. The plan distinguishes mathematical defenses (DP-SGD) from
   economic ones (rate limits). They are not interchangeable.

## 4. Rubric

Total points: 30. Suggested cut: ≥24 pass, ≥27 production-ready.

| Section | Criterion | Points |
|---|---|---|
| Defense table | Each in-scope threat has a primary defense | 4 |
| Defense table | Each defense has a secondary layer or an explicit "no second layer, here's why" | 3 |
| Defense table | Residual risk named per defense | 3 |
| Trade-offs | Cost dimension named per defense | 3 |
| Trade-offs | Measurement plan named per defense | 3 |
| Trade-offs | Owner named per cost trade-off | 2 |
| Roll-out | Waves ordered cheap → expensive | 3 |
| Roll-out | Exit criterion per wave | 3 |
| Roll-out | At least one defense flagged as requiring external sign-off | 2 |
| Cross-ref | Plan links back to specific assessment threats | 2 |
| Sourcing | Defenses cited to research or to OWASP/ATLAS/RMF | 2 |

## 5. Common mistakes

- **Listing defenses without threats.** "We will do adversarial
  training and DP-SGD" is not a plan; it is a shopping list. Every
  defense must answer a named threat.
- **Treating rate limits as a mathematical defense.** Rate limits
  raise extraction cost, they do not bound it. State this explicitly.
- **Ignoring (ε, δ) ledger.** Privacy budget is spent across training
  runs, not per run. A team that doesn't maintain the ledger will
  silently exhaust the budget.
- **Top-1 truncation without product input.** The cheapest mitigation
  against extraction can be the most disruptive to ship if a customer
  was depending on the probability vector. Flag it for product
  *before* implementation.
- **No exit criteria.** A roll-out plan without an exit criterion per
  wave will stall in production-grey state. Defenses either graduate
  or are reverted; "experimental" is not a steady state.
- **Plan that doesn't reference the assessment.** A defense plan is
  only as defensible as the threat model it answers. If it doesn't
  cite the assessment, the reviewer cannot tell whether a threat was
  dropped on purpose or by accident.

## 6. References

- OWASP Machine Learning Security Top 10 —
  https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS — https://atlas.mitre.org/
- NIST AI Risk Management Framework (AI RMF 1.0) —
  https://www.nist.gov/itl/ai-risk-management-framework
- Sibling exercise: `exercise-01-robustness-assessment/SOLUTION.md` —
  the threat enumeration this plan answers.
- Sibling exercise: `exercise-04-dp-sgd-configuration/SOLUTION.md` —
  configuration walk-through for the DP-SGD row.
- Sibling project: `projects/project-3-adversarial-defense/SOLUTION.md`
  — reference implementation of the adversarial-training and DP-SGD
  defenses, including the benchmark mentioned above.
- Sibling project: `projects/project-4-secure-cicd/SOLUTION.md` — the
  signed-dataset / supply-chain controls referenced in T5/T6.
