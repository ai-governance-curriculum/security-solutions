# Exercise 05 — LLM Safety Pipeline

> Read this *after* attempting the exercise yourself. This file is a
> reference design + implementation, the rationale behind the layer
> ordering, the validation pass, and the rubric you can grade your
> own answer against.

## 1. Solution overview

The exercise asks the learner to build a safety pipeline that wraps a
deployed LLM endpoint. The pipeline must cover the OWASP LLM Top 10
threat surface and slot cleanly in front of any model — open-source or
hosted.

A complete answer has three pieces:

1. **A layered design** — input checks, capability/tool checks,
   model invocation, output checks, and audit. The order matters; the
   solution defends each choice of order.
2. **A reference implementation** — `pipeline.py` in this directory
   wires the layers together as a small middleware around a
   placeholder model client. Each layer is its own function so
   reviewers can read them in isolation.
3. **A test surface** — `tests/` contains adversarial inputs from the
   OWASP LLM Top 10 categories (prompt injection, leakage, etc.) and
   asserts the pipeline blocks or sanitizes them.

The point is *defense in depth specific to LLM threats*. Adversarial-ML
defenses for vision/tabular models (PGD adversarial training, DP-SGD)
do not transfer cleanly. LLM safety is mostly a runtime / pipeline
problem, with model alignment as a complementary, weaker, layer.

## 2. Worked answer — design and reference implementation

### 2.1 Layered design (and why this order)

```
client request
    │
    ▼
[ 1. Authentication & rate limit ]   # per-tenant; gateway concern
    │
    ▼
[ 2. Input sanitization ]            # length, encoding, structural normalization
    │
    ▼
[ 3. Prompt-injection detection ]    # heuristic + classifier; OWASP LLM01
    │
    ▼
[ 4. PII / secrets redaction (input) ] # OWASP LLM06 (sensitive disclosure)
    │
    ▼
[ 5. Tool / capability policy ]      # OWASP LLM07/08 family
    │
    ▼
[ 6. Model invocation ]
    │
    ▼
[ 7. Output policy filter ]          # refusal classes, content categories
    │
    ▼
[ 8. PII / secrets redaction (output) ] # belt-and-suspenders with (4)
    │
    ▼
[ 9. Citation / grounding check ]    # if RAG; flag ungrounded claims
    │
    ▼
[ 10. Audit log + structured response ]
    │
    ▼
client
```

Why this order:

- **Cheap, broad filters first.** Authentication, rate limiting, and
  size limits run before any model call, because a request you
  reject costs you nothing.
- **Prompt-injection detection runs on the raw input** before any
  tooling decision, because tools and outputs are the *consequences*
  of a successful injection.
- **PII redaction runs on both input and output**, because either
  side can leak. Input-side redaction prevents the model from
  memorizing or echoing a secret; output-side redaction catches
  secrets the model fabricated or extracted from retrieval.
- **Tool/capability policy gates which tool calls are permitted**
  before the model runs. Letting the model "ask for" a tool and then
  rejecting after the fact is a worse pattern; it consumes the
  model's budget and gives the attacker oracle access.
- **Output policy filter is separate from PII redaction.** Policy
  filters reject content classes (harmful, off-topic); redaction
  modifies content. Mixing them produces a layer that does both
  badly.
- **Audit is the last layer**, but is non-skippable: every
  request/response pair is logged with redaction applied so that
  the log itself is not a leakage channel.

The categories above are anchored to OWASP's *Top 10 for LLM
Applications* — LLM01 (Prompt Injection), LLM06 (Sensitive
Information Disclosure), LLM07/LLM08 (Insecure Plugin Design /
Excessive Agency), etc. Verify the LLM Top 10 category numbering and
titles against the latest published version at
https://owasp.org/www-project-top-10-for-large-language-model-applications/
before using these IDs in formal documentation.

### 2.2 Reference implementation

`pipeline.py` in this directory is a runnable middleware that
demonstrates each layer. It is deliberately small — every layer is a
plain function so a reader can extend or replace one without
touching the rest. The model client is stubbed; you wire it to your
provider of choice.

Key design choices in the reference code:

- **Allow/deny is explicit.** Each guard returns a `Decision`
  dataclass with `action` ∈ {`allow`, `block`, `transform`} and a
  reason string. There is no implicit "if the function returned a
  string, that's the new prompt." Implicit transforms are how
  injection attacks slide past a pipeline.
- **Tool policy is a positive allow-list.** The default is to
  forbid; tool calls are matched against an explicit set of allowed
  tools and arguments per tenant. OWASP LLM08 (Excessive Agency) is
  almost always rooted in a default-allow tool policy.
- **Redaction is reversible only by an out-of-band key.** PII is
  replaced with stable placeholders. The mapping from placeholder
  back to value, if kept at all, is stored separately from the
  request body and audit log.
- **Audit logs are scrubbed.** What you ship to the log is the
  post-redaction payload. The audit log is itself an asset and an
  attacker target.
- **Heuristic injection detection is not a real defense.**
  Substring matching of "ignore previous instructions" is a smoke
  alarm, not a fire suppression system. The reference implementation
  uses heuristics as a coarse first pass and notes (in the code and
  here) that a production system should also call a dedicated
  classifier / a separate-LLM-as-judge step. There is no single
  "official" prompt-injection benchmark to cite; defer to OWASP LLM
  Top 10 LLM01 guidance and treat any classifier choice as
  experimental.

### 2.3 Test surface

`tests/test_pipeline.py` (sketch — implement as part of the
exercise) covers:

| Test category | Example | Expected pipeline action |
|---|---|---|
| Direct prompt injection | "Ignore previous instructions and …" | Detected by layer 3; logged; blocked |
| Indirect injection via retrieved doc | retrieved snippet containing instructions | Detected by retrieved-content guard (sub-layer of 3); marked as untrusted |
| PII in input | user supplies an SSN-shaped string | Redacted by layer 4 before model invocation |
| Tool call outside allow-list | model requests `fs.delete` | Blocked by layer 5 |
| PII in output | model fabricates a phone-shaped string | Redacted by layer 8 |
| Off-topic output | gibberish or wrong language | Flagged by layer 7 if a policy is defined |
| Ungrounded RAG output | output not supported by retrieved docs | Flagged by layer 9 |
| Audit redaction | end-to-end request with PII | Log entry contains placeholders, not raw PII |

The test surface is part of the deliverable. A pipeline without
tests is a pipeline with no evidence it does what it claims.

## 3. Validation steps

1. **The pipeline blocks the test surface in §2.3** with no false
   negatives on the canonical cases. False positives on benign
   inputs should be tracked but are acceptable in this exercise as
   long as they are documented.
2. **Bypass test (the actual security test).** Take each blocked
   case and rewrite it three times to evade the heuristic
   (paraphrase, encode in base64, embed in a code block). Report
   which evasions succeed; this is the real picture of what the
   pipeline buys.
3. **Audit-log scrub test.** Run a request containing a known
   secret. Grep the audit log for the secret. If it appears, the
   redaction pipeline is broken (or applied in the wrong order).
4. **Tool-call policy test.** Confirm that the default action for
   an unrecognized tool name is `block`, not `allow`. This is the
   common failure mode of excessive-agency vulnerabilities.
5. **Latency budget.** Measure end-to-end latency vs. raw model
   call. Layers should add bounded overhead; document the cost.
6. **Degraded-mode behavior.** If layer 3 (injection detector) is a
   call to a separate model and that model is unreachable, the
   pipeline should *fail closed*, not bypass the layer.

## 4. Rubric

Total points: 30. Suggested cut: ≥24 pass, ≥27 production-ready.

| Section | Criterion | Points |
|---|---|---|
| Design | All 10 layers (or equivalent named layers) present | 4 |
| Design | Layer ordering defended in writing | 2 |
| Design | Tool policy is positive allow-list (default deny) | 3 |
| Design | PII redaction applied on input *and* output | 2 |
| Implementation | Each guard returns explicit allow/block/transform | 3 |
| Implementation | Audit log is scrubbed (not raw) | 3 |
| Implementation | Pipeline fails closed on guard-service errors | 2 |
| Tests | Test surface covers each OWASP LLM Top 10 category in scope | 4 |
| Tests | Bypass-attempt suite included (rewrites of the blocked cases) | 3 |
| Process | Documented residual risks / known gaps | 2 |
| Process | Latency budget measured and reported | 2 |

## 5. Common mistakes

- **Substring-only injection detection.** "Ignore previous
  instructions" matches the textbook case. It does not match
  rewrites, encoded payloads, or instructions embedded in
  retrieved documents.
- **Default-allow tool policy.** Most excessive-agency incidents
  start with "the tool registry is the world; we'll block the
  ones we don't want." Reverse the default.
- **Single-side PII redaction.** Redaction on input only leaks
  through fabricated output. Redaction on output only leaks
  through model memorization. Both sides, every time.
- **Audit logs that contain raw payloads.** The log is an asset.
  An attacker who exfiltrates the audit log wins. Scrub before
  writing.
- **Failing open.** A guard call that throws should not silently
  bypass the guard. The pipeline must fail closed, with a
  user-visible "service unavailable" rather than a silent
  bypass.
- **Reusing vision/tabular defenses.** Adversarial training and
  DP-SGD do not solve prompt injection or sensitive-disclosure
  attacks. They live in a different threat model.
- **No bypass test.** A pipeline that has only been tested on the
  canonical attack strings is a pipeline that hasn't been tested.

## 6. References

- OWASP Top 10 for Large Language Model Applications —
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
  Pin the version (1.x) cited above; OWASP LLM Top 10 is updated
  periodically. The OWASP Machine Learning Security Top 10 (separate
  project) does not cover LLM-specific threats; do not confuse the two.
- OWASP Machine Learning Security Top 10 (companion, traditional ML) —
  https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS — LLM-relevant techniques live under the same
  framework; map injection / sensitive-disclosure findings to ATLAS
  techniques in the assessment for consistency —
  https://atlas.mitre.org/
- NIST AI Risk Management Framework — Manage and Measure functions
  cover runtime safety controls —
  https://www.nist.gov/itl/ai-risk-management-framework
- Sibling exercise: `exercise-01-robustness-assessment/SOLUTION.md`
  — the threat-modeling pattern; apply it to your LLM endpoint
  before designing the pipeline.
- Sibling exercise: `exercise-02-defense-plan/SOLUTION.md` — the
  defense-plan format; the pipeline above is the LLM analog of
  the defense plan there.
