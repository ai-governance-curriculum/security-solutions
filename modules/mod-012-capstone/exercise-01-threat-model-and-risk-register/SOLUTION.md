# SOLUTION — Capstone Exercise 01: Threat Model + Risk Register

> Read this *after* attempting the exercise. It is a worked reference,
> not a template to copy. The capstone is meant to integrate every
> earlier module — your threat model should reflect the system *you*
> chose to scope, not the example used here.

## 1. Solution overview

The exercise asks for a defensible threat model and a risk register for
an end-to-end ML system. A passing answer must:

- Pick a concrete in-scope ML system (training, registry, serving,
  data path, identities) and draw a data-flow diagram (DFD) with
  trust boundaries.
- Enumerate threats systematically using two complementary frames:
  - A general framework — STRIDE — applied to each DFD element.
  - An ML-aware framework — MITRE ATLAS tactics and techniques — to
    capture threats that STRIDE does not name (model evasion,
    extraction, poisoning, prompt injection).
- Cross-reference the OWASP Machine Learning Security Top 10 so that
  no commonly-cited ML risk is silently omitted.
- Convert each named threat into a risk-register entry with an
  explicit owner, likelihood/impact rating, treatment decision
  (mitigate / transfer / accept / avoid), and target control(s).
- Tie ratings and treatments back to a stated risk-appetite
  statement — otherwise the register cannot be defended in review.

Two anti-patterns disqualify a submission regardless of polish:

- "Threats" that are just rephrased controls ("no MFA" is a gap, not a
  threat; the threat is *credential theft of an operator account*).
- Risk ratings without any criteria — every Medium and High needs a
  rule a reader can re-derive.

## 2. Implementation

### 2.1 Scope statement (example)

> In scope: a tenant-isolated MLOps platform serving a fraud-scoring
> model. Components are (a) a feature pipeline reading from Kafka, (b)
> a training job on a Kubernetes cluster pulling features from an
> object store, (c) a model registry, (d) an online inference service
> reached through an API gateway, and (e) the human operators and CI
> systems that build and promote models. Out of scope: the upstream
> transaction system that emits Kafka events, and the downstream
> case-management UI consuming scores.

The scope statement is the single most important paragraph in the
deliverable: every subsequent threat and risk must be traceable back to
an element that is in scope.

### 2.2 Data-flow diagram (trust boundaries called out)

```
                +---------------------+
                |  Upstream Tx system | (OUT OF SCOPE)
                +----------+----------+
                           |  TLS
                ===========|=================== Trust boundary A
                           v
                +----------+----------+
                |  Kafka feature bus  |
                +----------+----------+
                           | SPIFFE workload identity
                           v
                +----------+----------+
                |  Feature pipeline   |---+
                +----------+----------+   |
                           |              | writes
                           v              v
                +----------+----------+ +-+----------------+
                |  Object store       | |  Feature store   |
                |  (training data)    | +--------+---------+
                +----------+----------+          |
                           |                     |
                ===========|=====================|===== Boundary B
                           v                     v
                +----------+----------+ +--------+---------+
                |  Training job       |<-+ CI/CD operator  |
                |  (k8s namespace)    |  |  (human + bot)  |
                +----------+----------+  +--------+--------+
                           | signed artifact + SBOM
                           v
                +----------+----------+
                |  Model registry     |
                +----------+----------+
                           | signed pull
                ===========|=================== Boundary C
                           v
                +----------+----------+
                |  Inference service  | <----- API gateway <-- Caller
                +---------------------+
```

Trust boundaries: (A) external producer to platform, (B) data plane to
control/training plane, (C) registry to runtime. Each boundary is a
required column in the threat enumeration.

### 2.3 STRIDE threat enumeration (excerpt)

| ID | Element | STRIDE | Threat statement |
|----|---------|--------|------------------|
| T-01 | Boundary A | Tampering | Malicious or buggy upstream producer publishes feature events outside expected schema, corrupting downstream feature distributions. |
| T-02 | Object store | Spoofing | Compromised training pod assumes the identity of another tenant's training pod and reads/writes the wrong dataset prefix. |
| T-03 | Training job | Elevation of Privilege | Training container escapes namespace boundaries via a kernel CVE in a base image and reads cluster secrets. |
| T-04 | Model registry | Tampering | An attacker pushes an unsigned or maliciously-signed model artifact and gets it promoted to production. |
| T-05 | Inference service | Denial of Service | Caller floods the gateway with adversarial inputs causing fallback path saturation. |
| T-06 | Operator | Repudiation | Audit log of a model-promotion action is missing or alterable, so a malicious promotion cannot be attributed. |
| T-07 | API gateway | Information Disclosure | Verbose error path leaks internal feature names that reveal protected attributes used in training. |

The full table includes one row for every STRIDE category against every
DFD element — even where the verdict is "not applicable, because …".
Empty cells are not allowed; the *reason* an element is not subject to
a STRIDE category is itself evidence the threat model was thorough.

### 2.4 ATLAS-aligned ML-specific threats (excerpt)

These extend STRIDE with adversary techniques that STRIDE does not name
directly. Each row cites an ATLAS technique ID so reviewers can verify.

| ID | Threat | ATLAS technique | DFD element |
|----|--------|-----------------|-------------|
| M-01 | Model evasion: attacker crafts inputs that bypass the classifier at inference time. | AML.T0015 Evade ML Model | Inference service |
| M-02 | Model extraction: high-volume querying steals decision boundary. | AML.T0044 Full ML Model Access | Inference service / API gateway |
| M-03 | Data poisoning: poisoned events injected upstream alter the trained model. | AML.T0020 Poison Training Data | Feature pipeline + object store |
| M-04 | ML supply chain compromise: malicious pretrained weights or library used during training. | AML.T0010 ML Supply Chain Compromise | Training job |
| M-05 | Backdoor in deployed model: trigger inputs cause targeted misclassification. | AML.T0018 Backdoor ML Model | Training job + registry |

Cross-checks against OWASP ML Top 10: M-03 maps to ML02 Data Poisoning,
M-04 maps to ML06 ML Supply Chain, M-01 maps to ML01 Adversarial
Attack, M-02 maps to ML05 Model Theft, M-05 maps to ML10 Model
Poisoning. A submission that does not perform this cross-walk is
guaranteed to leave at least one well-known ML risk out.

### 2.5 Risk register (excerpt)

Likelihood and impact are scored on a 1–5 scale defined in the scope
statement; risk score = L × I; treatment is decided against a stated
appetite (here: any residual risk ≥ 12 must be reduced before
go-live).

| Risk ID | Threat(s) | L | I | Score | Treatment | Target control | Owner | Review date |
|---------|-----------|---|---|-------|-----------|----------------|-------|-------------|
| R-01 | T-04, M-04 | 3 | 5 | 15 | Mitigate | Signed artifacts + SBOM verified at registry admission; Cosign + Sigstore policy. | Platform security | 2026-08-01 |
| R-02 | M-03 | 4 | 4 | 16 | Mitigate | Schema validation at Kafka boundary; statistical drift checks on feature distributions; quarantine on threshold breach. | Data platform | 2026-07-01 |
| R-03 | M-01, M-02 | 4 | 3 | 12 | Mitigate | Per-tenant rate limits; abuse-detection rules; output rate of confidence vectors disabled by default. | ML platform | 2026-09-01 |
| R-04 | T-02, T-03 | 2 | 5 | 10 | Mitigate | SPIFFE workload identity; namespace-scoped IAM; runtime seccomp/AppArmor profiles. | Platform security | 2026-09-01 |
| R-05 | T-06 | 2 | 4 | 8 | Accept w/ monitoring | Append-only audit log with tamper-evident hash chain; reviewed monthly. | SecOps | 2026-12-01 |

The register is not "the threat list with numbers"; threats can fold
into one risk where the treatment is the same, and a single threat can
appear in multiple risks. The *unit of work* in a register is the
treatment decision.

### 2.6 Decision rationale (what a reviewer wants to read)

- **Why STRIDE *and* ATLAS, not one or the other.** STRIDE catches
  classic confidentiality / integrity / availability threats well but
  has no vocabulary for model-specific attacks (evasion, extraction,
  poisoning). ATLAS catches the model-specific attacks but does not
  systematically walk every DFD element. Using both reduces the chance
  of a known category being missed.
- **Why ratings tie back to an appetite statement.** Without an
  appetite, "Medium" risk has no decision attached and the register
  becomes a list rather than a plan. The exercise rubric requires that
  the appetite be quoted in the submission itself.
- **Why each risk has an owner and a review date.** A register without
  ownership decays into a document of historical opinions. The owner
  is the role that can actually authorize work on the target control;
  the review date forces a re-evaluation when the system changes.

## 3. Validation steps

1. **Scope closure.** For every component in the DFD, confirm at least
   one threat row exists; for every threat, confirm it traces to a
   DFD element that is in scope.
2. **Framework coverage.** Confirm STRIDE × element coverage is
   complete (every cell either has a threat or a written "not
   applicable because"). Confirm every OWASP ML Top 10 item is either
   represented in M-rows or explicitly marked out of scope with a
   reason.
3. **Risk-register integrity.** Every register row references at least
   one threat row by ID; every High risk has a treatment that is not
   "accept"; every "accept" decision is justified against the
   appetite.
4. **Reviewer dry run.** Have a peer who did not write the model read
   the scope statement and answer: "Could you identify a threat I
   missed?" If yes, the model is incomplete.

## 4. Rubric / review checklist

| Criterion | Weight | Pass condition |
|-----------|--------|----------------|
| Scope is concrete and testable | 10 | A reader can name the in-scope and out-of-scope components without ambiguity. |
| DFD shows trust boundaries | 10 | At least two trust boundaries are drawn, and every boundary aligns with an identity / authentication change. |
| STRIDE coverage is complete | 15 | Every STRIDE × element cell is either a threat row or a justified N/A. |
| ATLAS techniques are cited by ID | 15 | At least five ML-specific threats are cited with an `AML.Tnnnn` ID. |
| OWASP ML Top 10 cross-walk present | 10 | All ten items either appear in the register or are marked out-of-scope with reason. |
| Risk-appetite statement quoted | 5 | A one-paragraph appetite is included and referenced by treatment decisions. |
| Each risk has owner + review date | 10 | No row is missing either field. |
| Treatment is not "rephrased threat" | 10 | Each "Mitigate" row names a specific control (technology + configuration), not a goal. |
| Residual risk recorded | 10 | Each mitigated row records expected residual after control is in place. |
| References cited | 5 | At least the three official sources for this module are linked from the document. |

Any submission missing the scope statement, the DFD, or the
appetite statement is rejected without scoring.

## 5. Common mistakes

- **Treating the register as a control checklist.** Listing "enable
  MFA" as a risk; MFA is a control. The risk is the threat that MFA
  treats.
- **Using STRIDE without ATLAS.** Produces a model that is excellent
  on classical infrastructure threats and silent on the ML-specific
  ones the capstone is intended to surface.
- **Ungrounded ratings.** "L=3, I=4" with no defined scale; a
  reviewer cannot tell whether two analysts would agree.
- **Aggregating threats into one giant "AI risk" row.** Loses the
  ability to assign owners and treatments meaningfully.
- **Mixing in-scope and out-of-scope freely.** If the upstream Kafka
  producers are out of scope, the threat model cannot rely on
  controls *inside* them; the boundary control becomes the unit of
  defense.
- **No review cadence.** A register written once and never updated is
  no longer a register — by month 6 it is wrong about the system.

## 6. References

- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>
- MITRE ATLAS — <https://atlas.mitre.org/>
- NIST AI Risk Management Framework (AI RMF 1.0) — <https://www.nist.gov/itl/ai-risk-management-framework>
