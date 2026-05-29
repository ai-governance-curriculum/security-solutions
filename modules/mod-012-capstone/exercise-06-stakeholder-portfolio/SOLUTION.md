# SOLUTION — Capstone Exercise 06: Stakeholder Communication Portfolio

> Read this *after* attempting the exercise. The portfolio brings the
> capstone work to non-engineering audiences. The judgement being
> assessed is whether the author can translate the same technical
> reality into the language each audience uses to make decisions.

## 1. Solution overview

The exercise asks for a small, coherent portfolio of communication
artifacts — each one targeted at a specific audience that the ML
security program must influence. A passing answer must:

- Identify the audiences explicitly. The default set for an ML
  security program is: **board / executive sponsor**, **product /
  engineering leadership**, **operating engineers**, **customers and
  external auditors**, and **affected internal users (the people who
  consume the model's outputs)**.
- Produce one artifact per audience, in a form that audience uses
  (executive memo, slide deck outline, runbook, customer-facing
  trust page, internal FAQ).
- Keep all artifacts consistent with each other and with Exercises
  01–05. The same facts must hold; only the framing and depth differ.
- Document the editorial choices: what was emphasised for each
  audience and why, what was left out and why.

A weak submission writes the same content five times with cosmetic
changes. The point of audience-tailored communication is what each
audience needs *to decide*, not what the author wants to say.

## 2. Implementation

### 2.1 Audience map

| Audience | What they decide | What they need from the artifact | Time budget |
|----------|------------------|-----------------------------------|-------------|
| Board / executive sponsor | Investment, risk acceptance, public posture. | Top three risks, dollarised where possible; what we have done; what we plan; what we are accepting. | 5–10 min read or 10-min meeting slot. |
| Product / engineering leadership | Roadmap, staffing, prioritisation. | Where the program stands vs. roadmap; what is blocking; what tradeoffs need their decision. | 20–30 min read. |
| Operating engineers (SRE, SecOps, ML platform on-call) | Day-to-day operation. | Specific runbook actions; thresholds; escalation rules. | Read during an incident — must be skim-friendly. |
| Customers / external auditors | Trust and contract decisions. | Posture statement; standards we follow; how we evidence the controls. | 10–30 min read; cited in due-diligence questionnaires. |
| Affected internal users (e.g., risk-ops analysts consuming model scores) | How to act on outputs; how to escalate concerns. | What the model is, what its known limits are, how to flag a suspected error. | 5-min read; reread during a hard case. |

### 2.2 Artifact 1 — Executive memo (board / sponsor)

> **AI Security Program: Quarterly Posture Memo**
>
> **Audience:** Executive sponsor, board AI committee.
>
> **Headline.** Our top three AI security risks remain (1) supply-
> chain compromise of pretrained models and training libraries,
> (2) cross-tenant data exposure in the feature store, and (3)
> model extraction by abusive callers of the public scoring API.
> We are *mitigating* risks 1 and 2 to within the stated appetite
> and *accepting with monitoring* risk 3 because the residual is
> within appetite and reduction would cost roughly N% of platform
> capacity.
>
> **What we shipped this quarter.**
>
> - Signed-and-attested model promotion enforced at registry
>   admission. Synthetic unsigned promotions are rejected; weekly
>   evidence in audit log.
> - Tenant-scoped feature-store identities issued via SPIFFE.
>   Cross-tenant read attempts blocked and paged.
> - Detection coverage for model extraction now live; first
>   real-world false-positive triaged, threshold tuned.
>
> **What we plan next quarter.** Differentially-private training
> for the `restricted` data class; broader game-day exercise of
> the suspicious-promotion playbook; quarterly tabletop with the
> AI governance group.
>
> **What we are accepting.** Adversarial inputs reach the model
> ~M% of the time despite per-tenant rate limits; the residual
> falls within the stated appetite. We are monitoring the
> score-distribution alert and will revisit at next review.
>
> **What we ask of the board.** Confirmation of the appetite
> statement (attached) and approval to defer federated-learning
> controls until the data inventory shows that workload is
> active.

The memo is short on purpose. A board cannot act on a 30-page
document; they can act on a 1-page memo with a defensible
"accept / decline / defer" recommendation.

### 2.3 Artifact 2 — Engineering leadership briefing (slide outline)

A 12-slide deck for product/engineering leadership. Bullet points
indicate the *one decision* asked for on each slide.

1. **Title.** Program status — period and presenter.
2. **What the program protects.** Scope diagram from Ex-02; one
   sentence on what is in scope.
3. **Top risks (matrix).** Top five risks from Ex-01 plotted on
   likelihood × impact, with treatment status colour-coded.
4. **Quarter highlights.** Three controls that shipped; one chart
   per detection MTTD/MTTC.
5. **In-flight work.** Roadmap items currently being worked, with
   owners and target dates.
6. **Blockers.** Specific items needing leadership decision (e.g.,
   "we need to refuse three legacy customers' bypass requests or
   accept the residual model-extraction risk for those keys").
7. **Resourcing ask.** Headcount or budget request, with stated
   risk reduction.
8. **Incident review.** Recent incidents and the action items they
   produced; closure rate.
9. **Compliance status.** NIST AI RMF function coverage table;
   gaps with target close dates.
10. **External pressure.** Customer asks, audit findings, new
    regulatory items expected.
11. **Risks we are accepting.** Explicit, with rationale.
12. **Asks.** Three decisions requested today.

The deck is *outline only* — the author fills in the data each
quarter. The structure is what passes review.

### 2.4 Artifact 3 — Operating-engineer runbook (excerpt)

> **Runbook: PB-02 Model extraction (DET-02 triggered)**
>
> **You are page-recipient. The on-call partner is the model's
> owning team. Total expected time to containment: 30 minutes.**
>
> 1. Open the alert; confirm the model and the caller key.
> 2. In the admin console, rate-limit the key to 0 (temporary
>    block). Note the time in the incident channel.
> 3. Capture a sample of the last 1000 queries to the forensic
>    bucket: `mlops-forensics/<incident-id>/queries.jsonl`.
> 4. Page the model's owning team via PagerDuty service
>    `ml-product-<model-slug>`.
> 5. Open the playbook PB-02 in the policy repo. Follow the
>    containment branch (suppress confidence outputs).
> 6. If the key is an external customer key, **do not** message
>    the customer directly — page the Comms lead. Comms decides
>    when and how the customer is told.
> 7. By minute 30: incident channel must contain (a) confirmed
>    block, (b) confirmed forensic capture, (c) the model owner
>    on the call, (d) Comms paged if external key.
>
> If any step is unclear, escalate to Incident Commander on-call.
> Do not skip steps to save time; the time you save is paid back
> in the postmortem.

The runbook is written to be readable during an incident, by a
tired on-call engineer, in low-context mode. Numbered steps,
short sentences, named tools, named queues.

### 2.5 Artifact 4 — Customer / auditor trust page (outline)

A public trust page (or auditor-facing brief) for the ML system.
Sections:

1. **Purpose.** What this page is and is not.
2. **Standards we operate to.** NIST AI RMF, OWASP ML Top 10,
   MITRE ATLAS — with a one-paragraph statement of how each
   informs the program.
3. **Data handling.** What data we use, how it is classified, how
   it is protected at rest and in transit, who can access it.
4. **Model lifecycle.** How models are built, signed, evaluated,
   promoted, monitored, and retired.
5. **Tenant isolation.** Identity model and the boundaries
   between tenants.
6. **Detection and response.** A high-level statement that the
   program runs continuous detection, has named playbooks,
   exercises them, and reports postmortem timelines to executive
   review.
7. **Reporting a concern.** How a customer or external researcher
   reports a suspected security issue.
8. **Evidence on request.** What artifacts (control evidence,
   audit reports) we can share under NDA, and how to request
   them.

Every claim on the page is backed by something concrete in the
internal program (a policy, a control, a runbook). Customers
and auditors test this by asking; the page should not contain
claims the program cannot evidence.

### 2.6 Artifact 5 — Affected-user FAQ (internal)

An internal FAQ for the people whose work depends on the model
(e.g., the fraud analysts consuming scores).

> **Q1. What does this model actually do?** One paragraph in plain
> language; what input goes in, what output comes out, what
> decision it informs.
>
> **Q2. What is it not good at?** Known limits and slices where
> error rates are higher — by name, not by acronym.
>
> **Q3. If a case looks wrong, what do I do?** Concrete steps:
> open a flag in the case tool, the model team is paged on N
> flags/day, the score is *not* the decision — the analyst is.
>
> **Q4. Who sees my flag?** The ML product owner reviews flags
> weekly; flagged cases feed retraining decisions; reviewed in
> the governance group's monthly metrics.
>
> **Q5. What if I think there is a fairness problem?** Escalation
> path to the AI governance group; cases handled per the
> incident process (PB-04) if a real promotion regression is
> suspected.

The FAQ assumes the reader has no security background and
matters because the program's *real* fairness and integrity
signal often comes from the people closest to the outputs.

### 2.7 Editorial choices (what was emphasised, what was left out, why)

| Artifact | Emphasised | Left out | Why |
|----------|------------|----------|-----|
| Executive memo | Top three risks, the three decisions | Detailed control specifications | Board cannot decide at the control level; specifications obscure the asks. |
| Engineering deck | In-flight work, blockers, asks | Threat-model derivation, ATLAS technique IDs | Leadership already trusts the program is using a framework; the asks are what move work. |
| Runbook | First-30-minute actions, page-recipients | Why the threshold was set | On-call needs to act; tuning rationale lives in the rule repo. |
| Trust page | Standards adherence, lifecycle controls | Internal team names, specific tool brands | Trust pages are evergreen; specific tool names date the document and reveal infra details. |
| Affected-user FAQ | What to do; who reviews flags | Threat model, OWASP mapping | The audience makes case decisions, not security ones; security context would be noise. |

### 2.8 Consistency check

All five artifacts must agree on:

- The list of risks the program treats and accepts.
- The framework set (NIST AI RMF, OWASP ML Top 10, MITRE ATLAS).
- The names of the controls and detections.
- The escalation paths and named roles.

The portfolio includes a one-page consistency matrix listing the
five named risks across the five artifacts and confirming each
artifact says something coherent about each risk (even if "out of
scope for this audience").

## 3. Validation steps

1. **Audience reality check.** Ask one representative of each
   audience to read the artifact for them and report what
   decision they could make. If the answer is "none", the
   artifact is wrong for the audience.
2. **Consistency check.** Run the consistency matrix. Any
   contradiction is a defect.
3. **Time-budget check.** Time the reading of each artifact; the
   memo at ≥15 minutes is too long, the runbook at ≥5 minutes
   per step is too long.
4. **Evidence-backed check.** For each claim on the trust page,
   point at a control, policy, or runbook that evidences it.
5. **No-jargon check on the FAQ.** A non-security colleague reads
   the FAQ and can answer "what do I do if a case looks wrong"
   without further help.

## 4. Rubric / review checklist

| Criterion | Weight | Pass condition |
|-----------|--------|----------------|
| Five distinct audiences identified | 10 | Audience map with the decision each audience makes. |
| One artifact per audience | 15 | Each audience has a deliverable in a form that audience uses. |
| Audience-appropriate depth | 15 | Memo is short and decision-focused; runbook is action-focused; FAQ is plain language. |
| Cross-artifact consistency | 15 | Consistency matrix included; no contradictions across artifacts. |
| Editorial choices documented | 10 | What was emphasised / left out for each audience, with reason. |
| Asks are concrete | 10 | Executive memo and engineering deck end with named decisions, not "thoughts". |
| Trust page is evidence-backed | 10 | Every public claim is traceable to a control or policy. |
| Runbook is operable mid-incident | 10 | Numbered steps, short sentences, named tools and queues. |
| FAQ has a real escalation path | 5 | Affected-user FAQ tells the reader who acts on their flag and when. |
| References cited | 5 | Standards named where they belong (trust page, memo). |

## 5. Common mistakes

- **One artifact, repeated five ways.** Cosmetic changes are not
  audience tailoring; the differences are *what is emphasised and
  what is omitted*.
- **Jargon in the FAQ.** "Adversarial robustness" is not language
  for case analysts; "the model can be tricked" is.
- **Memo with no asks.** A board memo without a decision request
  is a status report; the audience cannot act on it.
- **Runbook that mixes context with steps.** Mid-incident readers
  skim; rationale belongs next to the rule, not on the runbook
  page.
- **Trust page making claims the program cannot evidence.** A
  customer or auditor will ask; an unsupported claim damages
  credibility more than the original gap would have.
- **No consistency check.** Different artifacts agreeing on
  different facts erodes trust in the whole program.

## 6. References

- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>
- MITRE ATLAS — <https://atlas.mitre.org/>
- NIST AI Risk Management Framework (AI RMF 1.0) — <https://www.nist.gov/itl/ai-risk-management-framework>
