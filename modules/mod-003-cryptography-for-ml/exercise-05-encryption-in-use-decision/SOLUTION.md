# SOLUTION — Exercise 05: Encryption-in-Use Decision Document

> Read this *after* drafting your own decision document. This file is
> the worked decision, the comparison matrix, the rubric, and the
> things people get wrong.

## 1. Solution overview

"Encryption at rest" and "encryption in transit" are well-understood.
**Encryption in use** — protecting data while it is being computed on —
is the harder, newer category. For an ML platform there are three
mature technology families to choose from:

| Family                          | What it does                                       | Where it runs                  |
|---------------------------------|----------------------------------------------------|--------------------------------|
| Trusted Execution Environments (TEEs) | Hardware-isolated enclaves that decrypt + compute on plaintext inside a measured boundary; remote attestation proves the boundary. | CPU enclaves (Intel SGX, Intel TDX, AMD SEV-SNP), confidential GPUs (NVIDIA H100/Hopper confidential computing). |
| Homomorphic Encryption (HE)     | Math operations performed directly on ciphertext; results decrypt to the correct plaintext answer. | General-purpose CPUs/GPUs; library-based (e.g., OpenFHE, SEAL, HEAAN). |
| Secure Multi-Party Computation (MPC) | Multiple parties jointly compute on their secret-shared inputs; no party sees the others' inputs. | Across N parties over the network. |

A decision document picks the right family (or hybrid) for a specific
ML workload, justifies it against the threat model, and is explicit
about what it does *not* protect against. The worked example below is
for "remote inference on regulated customer prompts."

Authoritative frameworks the decision must hook into:

- **NIST AI RMF 1.0** — the document is a *Govern* + *Manage*
  artifact: it names the risk, the mitigation, the residual risk, and
  the owner.
- **NIST SP 800-57 Part 1 Rev. 5** — drives key-management decisions
  for whichever family you pick.
- **OWASP ML Security Top 10** — ML02 (Data Poisoning), ML03 (Model
  Inversion), ML04 (Membership Inference) are the threats that
  in-use protection most often addresses.
- **MITRE ATLAS** — provides the adversarial-ML TTP catalog the
  threat model should reference.

## 2. Implementation — worked answer (the decision document)

### 2.1 Document metadata

- **Workload:** Inference API for "Customer-X" — a regulated SaaS
  tenant whose contract requires that prompts and responses are not
  accessible to the platform operator in plaintext.
- **Data classification:** PII + regulated business data.
- **Threat model summary:** untrusted platform operator (insider with
  host access); curious cloud provider; lateral movement from a
  compromised co-tenant pod. Side-channel attacker assumed
  out-of-scope for this workload (commodity inference, not
  cryptographic keys).
- **Owner:** ML Platform Lead.
- **Reviewers:** Sec Lead, Legal/Privacy, Customer-X TAM.
- **Review cadence:** annually, or on workload architecture change.

### 2.2 What "in use" must protect

State explicitly what plaintext exposure must be eliminated:

- Prompt contents in inference server RAM.
- KV cache for active sessions.
- Intermediate tensors during the forward pass.
- Response contents before TLS termination on the egress side.

What it does *not* need to protect (residual risk, accepted):

- Model weights (they are not customer secrets; protected by
  signing + at-rest encryption per [[exercise-01-key-management-plan]]).
- Statistical / aggregate metrics (latency, token counts) — these can
  leak distributional info; mitigate via differential privacy on
  metrics, not in-use crypto.

### 2.3 Comparison matrix

| Property                        | TEE (CPU)              | TEE (Confidential GPU) | HE (CKKS / BGV) | MPC (SS / GC)         |
|---------------------------------|------------------------|------------------------|-----------------|------------------------|
| Trust assumption                | Hardware vendor + microcode | Hardware vendor + microcode | Math (lattice assumption) | Non-collusion of N parties |
| Throughput overhead (typical, indicative)  | ~1.1–2× baseline (workload-dependent; varies by enclave + EPC pressure) | Near-native for compute, attestation overhead at session setup | 10⁴–10⁶× for nonlinear ops; lower for linear-only | 10²–10⁴× depending on circuit + bandwidth |
| Supports general DNN inference  | Yes (with porting)     | Yes (with vendor SDK)  | Linear yes; full transformer impractical today | Yes (research; limited prod) |
| Requires model re-implementation| No (typically)         | No (typically)         | Yes (HE-friendly variants) | Yes (MPC-friendly variants)|
| Remote attestation              | Yes                    | Yes                    | n/a (math)      | n/a (protocol)             |
| Hardware lock-in                | Yes (vendor + cloud SKU) | Yes (vendor + cloud SKU) | No              | No                         |
| Side-channel resistance         | Active research area; multiple academic attacks published over the years | Active research area | Strong (no plaintext exists) | Strong (no party holds plaintext) |
| Multi-party / data-collab use   | Possible with attestation-based MoU | Possible | Yes (FHE for private inference) | Native fit                 |
| Standards maturity              | Mature vendor specs; emerging open attestation (e.g., Confidential Computing Consortium) | Newer; vendor-specific | NIST PQC-adjacent; ISO/IEC 18033-6 (HE) | Active standardization (ISO/IEC 4922)|
| Practical for LLM inference     | Achievable today       | Achievable today       | Not today       | Not today                  |

The throughput numbers above are widely-cited rough orders of
magnitude, not authoritative per-workload measurements; substitute
benchmark citations from your own platform before publishing this
matrix externally.

### 2.4 Decision and rationale

**Selected approach:** Confidential GPU TEE (NVIDIA H100 confidential
computing) for the inference path; CPU TEE (Intel TDX) for the
orchestrator that handles prompt routing and decryption of the
TLS-terminated request.

Why:

1. **Throughput requirement.** Customer-X SLO is p99 < 1.5s for
   typical prompts; HE and MPC throughput overhead rule them out for
   LLM inference today.
2. **No model re-implementation.** The platform's served models are
   shared with non-Customer-X tenants; we can't re-train HE-friendly
   variants per tenant.
3. **Attestation requirement.** Customer-X contract requires
   cryptographic evidence that the workload runs in an isolated
   boundary. TEE remote attestation produces that artifact; HE/MPC
   produce protocol-level evidence that is harder for the customer's
   GRC team to verify.
4. **Threat model fit.** The threat actor is the platform operator
   and co-tenants — exactly the threat model TEEs were designed for.
   The accepted residual is side-channel research attacks that
   require very precise local conditions and have not been
   demonstrated against the production GPU configuration we use.
   The specific GPU firmware version and tracked vendor advisories
   are recorded in the platform inventory and reviewed on the patch
   cadence in §2.5.

**Hybrid plan:** Use HE for *aggregate analytics* on prompts (e.g.,
counting prompts that match a forbidden pattern) where the math is
linear and the throughput tax is acceptable. This keeps the
operational analytics pipeline from needing plaintext access.

**Rejected: MPC.** No second party operates inference; introducing one
just to use MPC adds operational complexity without solving a
non-collusion problem we don't have.

### 2.5 Operational requirements (whichever family is chosen)

Every family needs a runbook that addresses:

- **Attestation verification.** Who verifies the attestation, against
  which reference values, on every session? (Recommendation:
  customer-side verifier with the platform publishing a signed
  reference-value manifest.)
- **Key wrapping.** Plaintext keys MUST be released to the workload
  only after successful attestation. Use a KMS that supports
  attestation-gated key release (e.g., Azure Confidential Ledger /
  AWS Nitro KMS / GCP Confidential KMS, or a Vault + attestation
  plugin).
- **Patching cadence.** TEE security depends on microcode, firmware,
  and driver versions; rotate to fixed versions within X days of
  vendor advisory.
- **Side-channel monitoring.** Subscribe to vendor advisories
  (Intel-SA, AMD bulletin, NVIDIA PSIRT). Build a process for
  rapid update.
- **Failure modes.** What happens when attestation fails (cold-start
  loop / page operator / mark workload unhealthy)? Define + drill.
- **Logging.** Logs of plaintext must remain inside the TEE boundary;
  *what* is logged outside (counters, error categories, hashes) must
  be enumerated and reviewed for leakage.

### 2.6 Acceptance criteria

The decision is implemented correctly when:

1. A working customer-facing demo shows: customer encrypts to an
   attestation-bound public key → request lands in TEE → response
   returns through TLS → operator with full host access cannot
   produce plaintext from a memory dump.
2. Attestation verification report is downloadable by the customer
   on every session and signed by the platform.
3. The runbook for attestation failure is exercised in staging.
4. SIEM events fire on: attestation failure, KMS release without
   attestation, side-channel-advisory match, microcode drift.

## 3. Validation steps

A reviewer can verify the decision document by:

1. **Threat-model trace.** For each threat in the §2.1 model, point
   to the specific property of the selected technology that mitigates
   it. Any gap is a residual; residuals must be named.
2. **Sanity-check thresholds.** Throughput / latency claims must
   reference a benchmark (vendor or internal). Avoid claiming "no
   overhead" — there is always *some* overhead.
3. **Standards mapping.** AI RMF rows: this doc satisfies Govern-3
   (risk-prioritized treatment), Map-3 (impact), Manage-2 (mitigation
   selection).
4. **Negative-case check.** Pick one rejected family (e.g., HE) and
   verify the rejection rationale is specific (a number, a
   constraint), not "too slow."
5. **Operational fitness.** The runbook items in §2.5 are real, not
   wishlist; if attestation-gated key release isn't actually
   supported by the chosen KMS, the decision changes.

## 4. Rubric / review checklist

Score 0 / 1 / 2; pass at ≥80%.

| #  | Criterion                                                                       | Pts |
|----|---------------------------------------------------------------------------------|-----|
| 1  | Workload, data classification, and threat model named explicitly                | 2   |
| 2  | Plaintext exposure points enumerated (RAM, KV cache, intermediates, etc.)       | 2   |
| 3  | All three families (TEE, HE, MPC) considered                                    | 2   |
| 4  | Comparison matrix covers throughput, trust assumption, attestation, lock-in     | 2   |
| 5  | Decision references both functional fit and threat-model fit                    | 2   |
| 6  | Rejection rationale for non-selected families is specific                       | 2   |
| 7  | Attestation, key-wrapping, patch cadence, side-channel monitoring all addressed | 2   |
| 8  | Acceptance criteria include an adversary-style demonstration                    | 2   |
| 9  | Residual risk is named (what is NOT protected)                                  | 2   |
| 10 | Linked to KMP / Cert runbook / Signing rollout where they overlap               | 2   |
| 11 | Maps to AI RMF Govern/Map/Manage; cites OWASP ML / ATLAS threats                | 2   |
| 12 | Review cadence and owner named                                                  | 2   |
| **Total** |                                                                          | **24** |

## 5. Common mistakes

- **Marketing-grade throughput claims.** "No measurable overhead" is
  almost never true. Cite a benchmark with workload, sequence length,
  and batch size.
- **TEE chosen by default.** TEEs are a sound choice for many ML
  workloads but they trade a software trust boundary for a hardware
  one. If you do not need attestation, you may not need the TEE.
- **HE pitched for general LLM inference.** Today, full transformer
  inference under HE is research-grade; throughput is many orders of
  magnitude worse than plaintext. Use HE where it fits (linear
  analytics, narrow inference pipelines), not as a generic answer.
- **MPC introduced without a second party.** MPC's value is
  non-collusion across distinct parties; in a single-tenant
  deployment, it adds complexity without adding trust.
- **Ignoring side-channel risk.** No TEE family is immune to research
  attacks. The acceptable answer is "we track advisories and patch
  within N days," not "side channels are theoretical."
- **No attestation-gated key release.** A TEE without attestation
  binding is *just* memory encryption — useful, but not what you
  promised.
- **Logging plaintext outside the boundary.** Sampled requests
  written to "debug" logs negate the entire control.
- **Skipping the hybrid option.** Most real platforms end up hybrid
  (TEE for inference; classical crypto for storage; HE-for-analytics
  on narrow paths). A purist single-family choice is usually
  suboptimal.
- **Not naming what is NOT protected.** Decision docs without
  residual-risk sections cause unpleasant surprises later.

## 6. References

- NIST AI Risk Management Framework (AI RMF 1.0) —
  https://www.nist.gov/itl/ai-risk-management-framework
- OWASP Machine Learning Security Top 10 —
  https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS — https://atlas.mitre.org/
- NIST SP 800-57 Part 1 Rev. 5 (key management) —
  https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
- Confidential Computing Consortium —
  https://confidentialcomputing.io/
- Intel TDX overview —
  https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html
- Intel SGX SDK & developer docs —
  https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/overview.html
- AMD SEV-SNP whitepaper —
  https://www.amd.com/en/developer/sev.html
- NVIDIA Confidential Computing (Hopper / H100) —
  https://www.nvidia.com/en-us/data-center/solutions/confidential-computing/
- ISO/IEC 18033-6:2019 (HE) — https://www.iso.org/standard/67740.html
- ISO/IEC 4922 (Secure Multi-Party Computation) —
  https://www.iso.org/standard/80548.html
- OpenFHE — https://www.openfhe.org/
- Microsoft SEAL — https://github.com/microsoft/SEAL
