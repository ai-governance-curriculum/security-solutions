# SOLUTION — Exercise 01: Threat-Model a Small ML System

> Read this *after* writing your own threat model. The point of the exercise
> is what *you* see before being told what to see. This document shows one
> defensible threat model for SmartRecs, not the only correct one.

## 1. Solution overview

SmartRecs is a multi-tenant recommendation service with a closed feedback
loop, a manual promotion gate, and no dedicated security engineer. The
threat model below uses STRIDE extended with three ML-specific categories
(model quality degradation, fairness regression, decision authority
overreach) as called for by the exercise.

The reference model emphasizes three findings that are easy to miss on
the first read of the system description:

- **The feedback loop is an attack surface.** Click and purchase events
  flow from authenticated tenants back into training, so any tenant with
  an API key can shift tomorrow's model without ever touching the
  artifact store.
- **The promotion step is the only mandatory human checkpoint** between
  `recs-vN` and serving — and it is described as "ticket and approval"
  with no named control on what evidence is required for approval.
- **API keys are shared per customer-store**, which means there is no
  identity to bind rate limits, audit, or revocation to *below* the
  tenant level.

These three drive the priority ranking at the end of the document.

## 2. Worked answer — SmartRecs threat model

### 2.1 System summary

SmartRecs trains a recommendation model nightly on 90 days of customer
events drawn from a shared analytics warehouse, writes a versioned
artifact to an S3-compatible store, promotes a version to `recs-prod`
through a manual ticket workflow, and serves predictions through six
pods behind an HTTPS gateway. Tenants authenticate with API keys (1k RPM
free, 100k RPM paid). Click/purchase feedback returns to the same
warehouse and seeds the next training run. Per-pod Prometheus metrics
and an S3 audit log with 30-day retention provide observability. The
team is three ML engineers, one backend engineer, and one on-call ops
engineer; no dedicated security role.

### 2.2 Assets

| Asset | Description | Why it matters |
|---|---|---|
| A1. Customer event records | 90 days of `(event_type, item_id, anonymized_customer_id, store_id, timestamp)` per tenant | Drives training; tenant-confidential; partially regulated as customer behavioral data |
| A2. Recommendation model artifact | Versioned `recs-vN` weights + serving config in the artifact store | Embodies trained behavior; theft = competitive harm; tampering = serving compromise |
| A3. `recs-prod` alias | The pointer the serving pods read at startup | Controlling this gives an attacker full serving control without touching weights |
| A4. Tenant API keys | Static credentials identifying a customer-store | Compromise = impersonation; rotation cost is high if shared internally at the tenant |
| A5. Per-tenant prediction stream | Top-10 recommendations returned per request | Mining queries can reveal preferences, catalog structure, ranking model |
| A6. Click/purchase feedback events | Behavioral signals returned to the warehouse | Direct path into training data; the *closed loop* asset |
| A7. Audit log on S3 | Per-request log, 30-day retention | Investigation primary source; deletion or backdating loses incident reconstruction |
| A8. Prometheus metrics | Per-pod operational signal | Detection surface; useful for noticing drift but not built for security signal |
| A9. Build/training infrastructure | Pipelines + warehouse credentials | Lateral path from compromise of one workload to full training control |

### 2.3 Trust boundaries

| Boundary | From → To | Who/what enforces | Known weak point |
|---|---|---|---|
| TB1 | Internet → HTTPS gateway | TLS termination + API-key check | API key is the only identity factor; no IP allowlist, no per-tenant token |
| TB2 | Gateway → model-server pods | Internal network; presumed in-cluster | Not stated whether mTLS/pod identity exists |
| TB3 | Training pipeline → artifact store | Pipeline IAM role | Write to `recs-vN` namespace; the promotion alias is a separate trust step |
| TB4 | Promotion approver → `recs-prod` alias | Ticket workflow + human approval | The approval criteria are not codified; bypass = social engineering on the approver |
| TB5 | Tenant feedback events → analytics warehouse | API key + warehouse ingestion | No stated outlier detection; raw events go to next training run |
| TB6 | Model-server pod → artifact store at startup | Pod IAM role / signed URL | Pod-startup pull means an attacker who can change the alias controls deployment |
| TB7 | Platform team domain → product team domain | RBAC / IAM | Not explicit who can rotate the API keys or rewrite the alias |

### 2.4 STRIDE+ML threat table

Columns: classical STRIDE interpretation, ML-specific extension. Each cell
is *attacker → wants → does*.

| Category | Classical | ML-specific |
|---|---|---|
| **Spoofing** | Attacker wants tenant-A recommendations by submitting requests with a stolen or guessed tenant-A API key (TB1, A4). | Attacker wants `recs-prod` to deploy *their* artifact by tricking the promotion ticket approver into approving a maliciously-prefixed `recs-vN` (TB4, A3). |
| **Tampering** | Attacker wants to replace a `recs-vN` artifact by gaining write to the artifact store path (TB3, A2). | Attacker wants to shift tomorrow's training by submitting crafted click/purchase events through their own tenant API (TB5, A6) — data poisoning of the closed loop. |
| **Repudiation** | A tenant disputes that their account generated request volume that triggered overage billing; the 30-day audit log (A7) is the only evidence and is not tamper-evident. | A tenant or insider deletes feedback events to mask poisoning. The warehouse may not preserve per-event provenance back to the API key that submitted it. |
| **Information disclosure** | Attacker wants the customer event records by extracting them via warehouse SQL access if they get a developer credential (A1). | Attacker wants to *reconstruct* training data via membership inference — query the served model with candidate `(customer, item)` pairs and observe confidence (A5). Also model inversion: extract embeddings via repeated targeted queries. |
| **Denial of service** | Attacker wants to exhaust the paid-tier 100k RPM budget by replaying captured requests against a stolen key (A4). | Attacker wants serving-tail latency to spike by crafting input distributions that hit cold paths in the recommender (A5, classical adversarial queries for resource consumption). |
| **Elevation of privilege** | Compromised pipeline pod uses its IAM role to read other tenants' warehouse partitions (A9). | A free-tier tenant uses query volume + feedback submission to learn the production model and effectively run "paid-tier" inference offline (A2 + A5 + A6 in combination). |

### 2.5 ML-specific threats (beyond STRIDE)

1. **Model quality degradation (drift, poisoning).** The closed feedback
   loop guarantees that whatever tenants do at *t* influences the model
   at *t+1*. A coordinated group of tenants submitting biased feedback
   slowly steers ranking. Likelihood is meaningful because attacker cost
   is one paid subscription; impact compounds over weeks.
2. **Fairness regression.** A model trained on 90 days of behavior from a
   small set of stores will drift toward the dominant store's catalog
   shape. New or small tenants get worse recommendations and may
   silently underperform. SmartRecs has no per-tenant model-quality
   metric, so this regression is unobserved.
3. **Decision authority overreach.** Recommendations directly influence
   what end-shoppers see. A single ranking artifact controls revenue
   for every tenant. There is no documented kill switch, override path,
   or per-tenant safe-baseline. A bad `recs-prod` promotion is, in
   effect, a platform-wide ranking incident.

### 2.6 Existing controls (honest inventory)

| Control | What it covers | What it doesn't |
|---|---|---|
| HTTPS termination at gateway | Confidentiality on the wire (TB1) | Doesn't authenticate caller beyond the API key |
| Per-tenant API key | Tenant identity | Static, shared per-store, no rotation path stated, no scope below tenant |
| Tiered rate limit (1k/100k RPM) | Crude DoS / cost limit | Doesn't bind to user-within-tenant; doesn't catch slow-and-low poisoning of the feedback channel |
| Manual promotion ticket | Human checkpoint between train and serve | Approval evidence not codified; one approver can promote anything |
| Per-pod Prometheus metrics | Operational health | Not security signal; no per-tenant model-quality metric |
| Per-request audit log (S3, 30 days) | Investigation primary source | No tamper-evidence; 30 days is short for slow attacks; not joined to model version |

### 2.7 Gaps and missing controls

The honest gap list:

- **G1. No identity below the tenant.** API keys are issued per
  customer-store and shared across teams within that store. There is no
  per-user authentication, so a compromised credential is indistinguishable
  from legitimate use.
- **G2. No input validation on the feedback channel.** Click and
  purchase events are accepted from any authenticated tenant and flow
  directly into training data with no outlier detection or rate cap on
  *event submission* (separate from inference RPM).
- **G3. Promotion criteria are not codified.** "Ticket and approval"
  with no defined acceptance evidence (e.g., evaluation metrics on a
  reference dataset, drift comparison against `recs-prod`, signed
  attestation by training pipeline). An approver can be socially
  engineered, mistaken, or rushed.
- **G4. Artifact integrity is not verified at pod startup.** Pods pull
  from `recs-prod` on startup but there is no stated signature
  verification, so a write to the artifact path silently becomes
  deployed.
- **G5. No per-tenant model-quality monitoring.** Fairness regressions
  and slow poisoning are invisible without per-tenant metrics.
- **G6. Audit retention is short and not tamper-evident.** 30 days
  forecloses investigation of slow attacks. S3 with default settings is
  not append-only.
- **G7. No documented kill switch or safe baseline.** Rolling back a
  bad `recs-prod` is implicit, not procedural.
- **G8. No declared ownership of security responsibilities** between
  platform and product teams.

### 2.8 Prioritized mitigation backlog

Priority = likelihood × impact, scaled high / medium / low. Each ranking
defended in one sentence as required.

| # | Gap | Likelihood | Impact | Priority | Defense of ranking |
|---|---|---|---|---|---|
| 1 | G3 — promotion criteria not codified | Medium | High | **High** | One approver is the only checkpoint between any `recs-vN` and serving; codifying criteria is cheap and breaks the highest-leverage failure path |
| 2 | G4 — no artifact signature at pod startup | Medium | High | **High** | If the artifact path is writable by any compromised training credential, no other control stops a malicious model reaching production |
| 3 | G2 — feedback channel has no outlier detection | High | Medium | **High** | The cost-to-attack is one paid subscription; the closed loop guarantees impact accrues; harder to fix than (1) but matters at every retrain |
| 4 | G5 — no per-tenant model-quality metric | Medium | Medium | **Medium** | Without it, slow degradation is invisible; fixing this also closes the fairness regression blind spot |
| 5 | G1 — no identity below the tenant | Low | High | **Medium** | High blast radius if a key leaks, but credential-leak detection has been a Top-10 item for years and tenant teams resist multi-user auth |
| 6 | G6 — audit retention/tamper-evidence | Medium | Medium | **Medium** | Retention is a one-line config change; tamper-evidence (object-lock or hash chain) is moderate work |
| 7 | G7 — no kill switch / safe baseline | Low | High | **Medium** | Low probability of needing it next quarter; large impact when needed; can be implemented as a single alias flip |
| 8 | G8 — security ownership not declared | Medium | Low | **Low** | Organizational, not technical; surfaces every other gap but doesn't itself defeat an attacker |

## Implementation

This is a paper exercise — the deliverable is the threat model document
itself. To move the worked answer above into action:

1. **Open tickets keyed to the backlog table (§2.8).** Each row becomes
   one ticket with the gap ID in the title (`G3 — codify promotion
   criteria`) so the threat model and the tracker stay linked.
2. **Attach the trust-boundary diagram and STRIDE+ML table** (§2.3,
   §2.4) to the team's design-review wiki page so future changes get
   reviewed against the same boundaries.
3. **Schedule a re-review trigger.** Re-run this threat model when any
   of these change: a new data source enters training, the promotion
   workflow is automated, tenant auth gains sub-tenant identity, or a
   new model family (e.g., LLM-backed recs) is added.
4. **Hand the top-three High items to engineering this sprint** (G3,
   G4, G2). The Medium tier is next-quarter scope; the Low tier is
   tracked but not committed.

## 3. Validation steps

To validate that *your* threat model is at the same quality bar as this one:

1. **Concreteness check.** For every row in your STRIDE+ML table, can
   you name (a) the attacker, (b) the asset they want, (c) the path?
   If any row reads as "spoofing — yes — possible," rewrite it.
2. **Trust-boundary symmetry check.** For each trust boundary, confirm
   the enforcer is named and that you've stated *what* it fails to
   enforce. A boundary with no weakness listed is usually under-analyzed.
3. **Feedback-loop check.** Confirm that you treated the feedback loop
   as an attack surface, not just a feature. Many learner submissions
   miss this.
4. **Calibration check.** Read your priority backlog out loud. If every
   item is High, recalibrate. If nothing is High, you have either an
   unusually mature system (SmartRecs is not) or under-prioritized.
5. **Honesty check.** Do you name controls SmartRecs is missing even
   when those gaps make SmartRecs look bad? A model that protects the
   subject is not useful.

## 4. Rubric / review checklist

When grading or self-grading, score 1 point per item — 9–10 strong,
6–8 passing, ≤5 needs rewrite.

- [ ] Assets are concrete (specific record shape, specific artifact path)
- [ ] At least 5 trust boundaries named, with enforcer and weak point
- [ ] STRIDE+ML table is filled — no empty cells, "N/A" includes a justification
- [ ] Feedback-loop / closed-loop threat appears at least once in the table
- [ ] All three lecture-notes ML categories (quality degradation, fairness, decision authority) appear
- [ ] Existing-controls inventory is honest about gaps in each control
- [ ] Gap list includes process gaps, not only technical gaps
- [ ] Prioritization defends ranking and is mixed (not all High)
- [ ] At least one identified gap is *not* the most-famous attack class
- [ ] Total length 3–5 pages; no padding

## 5. Common mistakes

- **Listing OWASP IDs as the threat.** "ML01 applies" is not a threat.
  The threat is the attacker, the asset, and the path.
- **Treating compliance as mitigation.** "We have SOC 2" does not stop
  data poisoning. The exercise prompt calls this out as a failing mode.
- **Skipping the feedback loop.** The closed loop is the system's most
  ML-specific attribute and the most-missed attack surface.
- **Marking too many STRIDE cells N/A.** "Repudiation N/A — we have an
  audit log" is the classic failure. Repudiation asks whether the
  audit log itself is tamper-evident and joined to the right identity.
- **All-High priority lists.** Forecloses sequencing and tells the
  reader nothing about where to start.
- **Hedging gaps.** "Improve monitoring" is not a gap; "no per-tenant
  model-quality metric" is.
- **Treating manual approval as a strong control.** A single human
  reviewer without codified acceptance criteria is one mistake or one
  social-engineering call away from compromise.

## 6. References

- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>
  (used for cross-referencing classical ML attack categories such as data
  poisoning and membership inference)
- MITRE ATLAS — <https://atlas.mitre.org/>
  (used for the tactic vocabulary referenced in section 2.4 and reused
  in Exercise 03)
- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>
  (MAP function provides the inventory-and-context framing used for
  sections 2.1–2.3)
- Local exercise context: SmartRecs system description in
  `lessons/mod-001-ml-security-foundations/exercises/exercise-01-threat-model-a-small-ml-system.md`
