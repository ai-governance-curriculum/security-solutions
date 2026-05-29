# SOLUTION — Exercise 04: Hugging Face Model Vetting

Reference solution for vetting a model pulled from the Hugging Face
Hub before it enters an internal pipeline.

## 1. Solution overview

The exercise asks the learner to vet a specific public model and
decide whether to (a) reject, (b) accept with mitigations, or
(c) accept as-is. The deliverable is a written vetting record with
linked evidence per checklist item.

Why this matters: pulling model weights from a public hub is a
*ML supply chain compromise* surface listed in MITRE ATLAS and in
the OWASP Machine Learning Security Top 10's supply-chain entry. The
hub itself is not an authorization boundary — anyone can publish,
and there is no project-wide signature verification analogous to
Sigstore for arbitrary repos. The vetting checklist is the
compensating control.

## 2. Implementation — worked vetting record

Worked example: a learner is asked to vet a hypothetical model
`acme-org/sentiment-small` for use in an internal classifier.

### Checklist (executed in order)

**Step 1 — Identify the artifact precisely.**

| Field | Value |
|---|---|
| Repository | `acme-org/sentiment-small` |
| Pinned revision (commit SHA) | `abc123...` (whatever HEAD was when vetted) |
| Files used | `config.json`, `tokenizer.json`, `model.safetensors` |

Pin a *commit SHA*, not `main`. Hub repositories are mutable; "the
model I tested" and "the model I deploy" must be the same revision.

**Step 2 — File-format risk.**

- Prefer `*.safetensors`. The `safetensors` format does not invoke
  Python pickle and so is not a code-execution vector by
  deserialization. (Hugging Face `safetensors` documentation.)
- If only `pytorch_model.bin` (pickle) or `*.pkl` is offered, treat
  as untrusted code until proven otherwise. Either re-export to
  safetensors in an isolated environment or reject.
- Reject `*.pt` files that load via `torch.load` without
  `weights_only=True` for the same reason.

**Step 3 — Publisher and repository hygiene.**

| Signal | What to look for | Status (worked) |
|---|---|---|
| Verified org badge on Hugging Face | Present and matches the organization you expected | Present |
| Organization profile links to an externally verifiable identity (corporate site, GitHub org) | Link resolves to the expected entity | Present |
| Repository age / commit history | Long history with multiple authors > single-commit anonymous drop | Multi-author history |
| Issues/discussions show real users | Yes / no | Yes |
| Linked GitHub repo | Present | Present |
| OpenSSF Scorecard score for the linked GitHub repo | Reviewer runs Scorecard against the source repo | Mid-range; flagged for review |

Run OpenSSF Scorecard against the linked source repository (not the
HF repo itself — Scorecard is GitHub-oriented). Treat the result as
*evidence*, not as pass/fail by itself: low scores in
`Branch-Protection`, `Code-Review`, `Signed-Releases`, or
`Dangerous-Workflow` are the ones most relevant to supply-chain risk.

**Step 4 — Model card and licensing.**

- Model card present and dated.
- License compatible with internal use.
- Training data described to the extent the model card supports it
  (NIST AI RMF *MAP* function asks for provenance of training data).
- Intended use and known limitations stated.

A missing or template-only model card is not by itself a reject, but
it lowers the trust score and forces stricter mitigations downstream.

**Step 5 — Static and dynamic scans.**

- Run Hugging Face's official Pickle / Malware scanner status (shown
  in the repo UI) as a first pass. A clean status is necessary but
  not sufficient.
- If any pickle-based file is included, run `picklescan` (open-source
  scanner referenced from the Hugging Face documentation on pickle
  scanning) over the file. Treat any warning as a blocker.
- Run a load test in a sandbox: a container with no network egress
  and no write access outside `/tmp`. Load the model, run an
  inference. Confirm no unexpected network calls or filesystem
  writes via syscall tracing.

**Step 6 — Behavioral spot-check.**

- Run the model on a small set of prompts from the documented use
  case. Verify outputs are consistent with the model card.
- Run on a set of *out-of-distribution* prompts. Models with a
  hidden backdoor are most often spotted by behavior that does not
  match the documented task — sudden refusals, sudden cooperation
  with disallowed prompts, or output that includes embedded
  identifiers.
- This step does not certify the model is backdoor-free. It is a
  cheap filter against the most blatant cases.

**Step 7 — Re-host and pin.**

If accepted, copy the safetensors file and tokenizer/config to an
internal artifact store. Sign the local copy with `cosign sign-blob`
keyless (see exercise-02). Downstream pipelines pull from the
internal store; the Hugging Face URL is not referenced at runtime.

### Worked decision

`acme-org/sentiment-small` worked example:

- File format: safetensors → OK.
- Publisher: verified org, linked GitHub → OK.
- Scorecard on the source repo: low `Signed-Releases`,
  acceptable elsewhere → noted, accept with mitigation: pin commit
  SHA, internal re-sign.
- Model card: present, training data not fully described → noted,
  accept with mitigation: limit use to the documented task only.
- Pickle scanner: clean.
- Sandbox load test: no unexpected egress.
- Behavioral spot-check: consistent with model card.

**Decision: accept with mitigations.**

Mitigations recorded:

- Pin to commit SHA `abc123...`.
- Re-host in `internal-models/sentiment-small`.
- Sign the re-hosted file with Cosign keyless.
- Re-vet on any version bump (do not auto-pull `main`).

## 3. Validation steps

A reviewer should be able to reproduce the decision in under an hour.

1. From the vetting record, navigate to the pinned commit SHA on the
   Hub. Confirm the files listed are present at that SHA.
2. Re-run the pickle/safetensors check. Confirm format claims.
3. Re-run OpenSSF Scorecard against the linked source repo. Confirm
   scores in the categories the record flagged.
4. Re-load the model in the same sandbox configuration described in
   the record. Confirm no egress.
5. Confirm the internal re-hosted file's `sha256` matches the SHA
   recorded for the Hub revision. Confirm a valid Cosign signature on
   the internal copy with the expected identity pin.
6. Confirm there is a follow-up ticket for the named mitigations
   (license review, training-data review, version-bump re-vet).

## 4. Rubric

| Dimension | Excellent (3) | Acceptable (2) | Inadequate (1) |
|---|---|---|---|
| Pinning | Commit SHA recorded and used for re-host | Tag recorded, hub URL referenced | "main" or unpinned |
| File-format reasoning | Justifies safetensors over pickle with reference | Notes preference without reasoning | Loads `*.pt` / `*.pkl` without comment |
| Publisher evidence | Multi-signal: verified org, linked GitHub, Scorecard | One signal | Brand assumption only |
| Sandbox test | Documented isolation, network controls, syscall observation | Loaded in a venv | Not tested |
| Behavioral spot-check | Includes OOD prompts | In-distribution only | None |
| Re-host & internal signing | Both done, identity pinned | One done | Hub pulled at runtime |
| Decision framing | Explicit accept / accept-with-mitigations / reject with named mitigations and owners | Binary accept/reject | Implicit accept |
| Use of authoritative sources | OWASP ML Top 10, MITRE ATLAS, NIST AI RMF *MAP*, Scorecard all referenced where relevant | Some sources | Sources invented or absent |

Passing threshold: average ≥ 2 across all dimensions, with no
dimension scored 1.

## 5. Common mistakes

- **Trusting the org name.** A repo named `meta-llama-community/...`
  is not Meta. Cross-check the verified org badge and the linked
  external identity.
- **Loading `pytorch_model.bin` with `torch.load` and no
  `weights_only=True`.** This is an arbitrary-code-execution path
  by design of pickle; documented as an attacker technique under
  ATLAS *ML Supply Chain Compromise: Model*.
- **Treating a green Hub scanner badge as sufficient.** It catches
  *known* malicious patterns. It does not certify safety.
- **Vetting `main` and deploying `main` later.** Hub repos are
  mutable. Without a commit SHA pin, the deployed model is not the
  vetted one.
- **Running OpenSSF Scorecard against the Hub URL.** Scorecard is
  designed for source-code repositories; run it against the linked
  GitHub source repo, not the Hub repo itself.
- **Sandbox without network controls.** A sandbox that allows
  outbound traffic to anywhere defeats the most useful signal
  (unexpected egress on load).
- **No re-host.** Pulling directly from the Hub at deploy time means
  every revocation, takedown, or silent rewrite on the Hub side
  becomes your incident.
- **Skipping the behavioral check on the grounds that it cannot
  prove safety.** It cannot — but cheap filters catch sloppy
  backdoors. Skipping it is a mistake.

## 6. References

- OWASP Machine Learning Security Top 10 (AI supply chain attacks) —
  <https://owasp.org/www-project-machine-learning-security-top-10/>
- MITRE ATLAS — *ML Supply Chain Compromise* family —
  <https://atlas.mitre.org/>
- NIST AI Risk Management Framework, *MAP* function (data and model
  provenance) — <https://www.nist.gov/itl/ai-risk-management-framework>
- OpenSSF Scorecard — <https://openssf.org/scorecard/>
- Sigstore documentation — <https://docs.sigstore.dev/>
- Hugging Face safetensors — referenced from the Hugging Face
  documentation
- Hugging Face pickle-scanning guidance — referenced from the
  Hugging Face documentation
- Local cross-reference:
  [exercise-02 signed-pipeline-design](../exercise-02-signed-pipeline-design)
  for the internal re-sign workflow.
