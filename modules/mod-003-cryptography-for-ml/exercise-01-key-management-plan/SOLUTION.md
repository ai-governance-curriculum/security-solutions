# SOLUTION — Exercise 01: Key Management Plan (ML Platform)

> Read this *after* you have drafted your own Key Management Plan (KMP).
> This file is the worked example, the rationale behind each decision,
> and the rubric used to grade your draft.

## 1. Solution overview

A Key Management Plan (KMP) for an ML platform must cover every
cryptographic key the platform produces *or* consumes, across the full
lifecycle (generation → distribution → use → rotation → revocation →
destruction). For an ML system specifically, the key inventory is
broader than a typical web stack because it includes:

| Asset class                     | Why it needs a key                              |
|---------------------------------|-------------------------------------------------|
| Training data at rest           | Confidentiality of PII and proprietary corpora  |
| Feature store / vector DB       | Same as above, plus integrity                   |
| Model weights at rest           | Confidentiality + IP protection                 |
| Model weights in transit        | TLS server keys for registry, inference         |
| Model artifact signatures       | Provenance and tamper-evidence (SLSA)           |
| Workload identity (SPIFFE/mTLS) | Per-workload auth across the mesh               |
| Secrets-manager root key        | Wraps every other secret                        |
| Audit log signing key           | Tamper-evident logging                          |
| Telemetry / metrics pipeline    | Optional, but recommended for sensitive logs    |

The KMP groups these into **key families**, assigns each family an
algorithm, strength, owner, custodian, rotation cadence, and destruction
procedure, and references the upstream standard that justifies the
choice.

The authoritative reference for KMP structure is **NIST SP 800-57
Part 1 Rev. 5 (Recommendation for Key Management — General)** and
**Part 2 Rev. 1 (Best Practices for Key Management Organizations)**.
The plan must be auditable against those documents.

## 2. Implementation — worked answer (the KMP itself)

### 2.1 Document metadata

- **System name:** `mlplat-prod`
- **Document version:** 1.0
- **Owner:** Platform Security Lead
- **Review cadence:** Annual + on every material architecture change
- **Cryptographic policy basis:** NIST SP 800-57 Part 1 Rev. 5,
  NIST SP 800-131A Rev. 2 (algorithm transitions), FIPS 140-3 (module
  validation), NIST SP 800-52 Rev. 2 (TLS).

### 2.2 Roles (RACI for cryptographic operations)

| Role                         | Responsibility                                            |
|------------------------------|-----------------------------------------------------------|
| Platform Security Lead       | Owns the KMP, approves exceptions, signs off rotations    |
| KMS Custodian (two-person)   | Holds break-glass to root KEK; cannot self-approve        |
| Service Owners               | Own the data-encryption keys for their service            |
| SRE / Platform Ops           | Operates rotation tooling, monitors expiry, runs IR drills|
| Internal Audit               | Verifies KMP execution against SP 800-57 controls         |
| ML Platform Lead             | Owns model-signing key policy + verification gates        |

Per SP 800-57 Part 2, no single individual should be able to extract,
export, or destroy a high-criticality key. The "two-person rule" applies
to the root KEK, model signing root, and audit-log signing root.

### 2.3 Key inventory (worked example)

Use one row per **key family**, not per individual key. Individual key
IDs are enumerated by the KMS and tracked in its audit log.

| Family ID  | Purpose                          | Algorithm / Size                  | Strength (bits)| Storage           | Owner               | Rotation     | Destruction              |
|------------|----------------------------------|-----------------------------------|----------------|-------------------|---------------------|--------------|--------------------------|
| KF-01      | Root KEK (wraps DEKs)            | AES-256 (GCM) in HSM              | 256            | FIPS 140-3 L3 HSM | Sec Lead + Custodian| 5 years      | HSM zeroize, dual control|
| KF-02      | Data store DEK (S3, RDS, EBS)    | AES-256-GCM (envelope-encrypted)  | 256            | Cloud KMS, wrapped by KF-01 | Service Owner | 1 year       | KMS schedule-delete (30d)|
| KF-03      | Feature store / vector DB DEK    | AES-256-GCM                       | 256            | Cloud KMS         | Service Owner       | 1 year       | KMS schedule-delete (30d)|
| KF-04      | Model registry artifact DEK      | AES-256-GCM                       | 256            | Cloud KMS         | ML Platform Lead    | 1 year       | KMS schedule-delete (30d)|
| KF-05      | Model signing root (cold)        | ECDSA P-384 *or* Ed25519          | 192 / 128      | Offline HSM       | ML Platform Lead    | 5 years      | HSM zeroize, dual control|
| KF-06      | Model signing intermediate (hot) | ECDSA P-256 *or* Ed25519          | 128            | Online HSM / KMS  | ML Platform Lead    | 90 days      | KMS schedule-delete      |
| KF-07      | TLS server certs (ingress)       | ECDSA P-256 (RSA-3072 fallback)   | 128 / 128      | Cert-Manager + KMS| SRE                 | 90 days      | Revoke + key delete      |
| KF-08      | mTLS workload identity (SPIFFE)  | ECDSA P-256 SVIDs                 | 128            | SPIRE node attestor| Platform Sec       | 1 hour       | Expire naturally         |
| KF-09      | Secrets manager root             | AES-256 (cloud KMS root)          | 256            | Cloud HSM / KMS   | Sec Lead            | 5 years      | KMS schedule-delete      |
| KF-10      | Audit log signing key            | Ed25519 (or ECDSA P-256)          | 128            | KMS, append-only  | Sec Lead            | 1 year       | Archive then destroy     |
| KF-11      | Build/CI image signing (cosign)  | Ed25519 (Sigstore Fulcio for OIDC)| 128            | Sigstore or KMS   | Platform Sec        | Short-lived (Fulcio) | N/A      |

**Why these algorithms.** NIST SP 800-57 Part 1 Rev. 5 §5.6.1 gives a
"security strength" mapping; 128-bit symmetric strength is the floor
through 2030+ for data of any meaningful sensitivity, and NIST
SP 800-131A Rev. 2 §1.2 makes RSA-2048 the minimum (RSA-3072 is the
12-year horizon). AES-256-GCM is the default symmetric primitive
because it is FIPS-approved, AEAD, and HSM-supported. Signing uses
ECDSA P-256 or Ed25519 for size and performance; for offline / long-lived
roots, P-384 raises the strength to 192 bits.

**Why model signing is rooted offline.** Treat the model signing chain
like a code-signing chain (Microsoft Authenticode / Apple developer-ID
model). The root signs an intermediate; the intermediate signs daily
build artifacts. Compromise of the hot intermediate is recoverable by
revoking it from the offline root; compromise of an online root is
catastrophic.

### 2.4 Lifecycle procedures

Each family must specify the following. Use the table format above for
the at-a-glance summary; document the procedures in detail below.

**Generation.** All keys MUST be generated inside a FIPS 140-3 validated
module (cloud HSM, dedicated HSM, or KMS HSM-backed key). No long-lived
key may be generated on a general-purpose VM or laptop. Generation must
be logged with operator identity and witness.

**Distribution.** Symmetric DEKs are never extracted; only the
envelope-wrapped DEK transits. Public keys are distributed via the
trust bundle (e.g., SPIRE trust bundle, cosign keyless via Fulcio
transparency log, or pinned in the model registry).

**Use.** Application code calls the KMS for `Encrypt` / `Decrypt` /
`Sign` / `Verify`; raw key material does not leave the KMS boundary
except for envelope-wrapped DEKs that are immediately discarded by the
caller after the operation.

**Rotation.** Cadence is in §2.3. Rotation is driven by automation
(e.g., cert-manager, KMS automatic rotation, SPIRE SVID expiry).
Rotation events emit a structured audit event including:
`{key_family_id, old_kid, new_kid, operator, timestamp, automated:bool}`.

**Revocation.** Every signing key family MUST publish either a CRL,
OCSP responder, or transparency-log-based revocation. For
short-lived keys (≤24h) revocation reduces to expiry and is acceptable.

**Destruction.** Cryptographic erasure is the primary technique:
schedule-deletion in cloud KMS (with a 7–30 day soft-delete grace) and
HSM zeroization for on-prem HSMs. Destruction must be witnessed and
logged.

**Backup / escrow.** Only DEKs and recovery KEKs are backed up
(within the HSM's M-of-N quorum mechanism). Signing private keys are
NEVER escrowed: their loss is acceptable; their compromise is not.

### 2.5 Algorithm transition plan

NIST SP 800-131A Rev. 2 defines when current algorithms must be
deprecated. The KMP must commit to:

- Track NIST's "disallowed after" dates for any algorithm currently in
  use. As of SP 800-131A Rev. 2, **SHA-1** is disallowed for digital
  signature generation. New signing key families therefore use SHA-256
  or stronger.
- Plan for **post-quantum migration**. NIST has standardized
  ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205). The
  KMP commits to a hybrid (classical + PQ) handshake for TLS by the
  end of the supported window. The exact rollout window is set per
  organization and recorded as a separate dated commitment in the
  KMP appendix.

### 2.6 Incident response (key compromise)

When a key is believed compromised:

1. **Contain.** Disable the key in the KMS (do not delete — preserves
   forensic value). For signing keys, push a revocation entry.
2. **Rotate.** Issue a replacement from the parent KEK / signing root.
3. **Re-encrypt or re-sign** anything still relying on the compromised
   key, prioritized by sensitivity. For DEKs this means re-encrypting
   the affected ciphertext; for signing keys it means re-signing
   current artifacts.
4. **Notify** stakeholders per the IR matrix; if customer data is
   involved, follow the breach-notification path.
5. **Post-mortem** within 5 business days, with action items tracked.

### 2.7 ML-specific considerations

These items are easy to omit if you treat the KMP as a generic web
KMP:

- **Training-data confidentiality vs. utility.** If you train on
  encrypted-at-rest data with envelope encryption (KF-02), the
  training job runs with a workload identity (KF-08) authorized to
  call `Decrypt` on that data's DEK. Audit that call separately —
  training jobs that decrypt full corpora are the biggest single
  legitimate data egress on the platform.
- **Model weights are crown jewels.** They MUST be encrypted at rest
  (KF-04) and signed at publish (KF-06). Verification at load time is
  enforced in the inference runtime (see Exercise 03).
- **Inference cache / KV cache.** A long-running LLM inference server
  may hold sensitive prompts in memory. If the threat model requires
  it, plan for memory encryption (see Exercise 05) and a
  short-rotation session key for in-memory state.
- **Feature store online vs. offline.** Two different DEK families
  often, because access patterns and audit requirements differ.

## 3. Validation steps

A reviewer (or a CI lint job) should verify:

1. Every key family in §2.3 has a non-empty value for *every* column.
2. Every algorithm choice maps to a NIST SP 800-57 Part 1 Rev. 5
   security strength of at least 112 bits (preferably ≥128).
3. No key family lists "TBD" as owner.
4. No key family rotates less often than the upper bound in
   SP 800-57 Part 1 §5.3.6 cryptoperiods, *or* the deviation is
   justified in writing and approved.
5. The IR section (§2.6) names a specific containment + rotation
   procedure for every signing key family.
6. The PQ migration commitment is present (§2.5).

A simple CI check can be a YAML representation of the inventory plus a
JSON Schema enforcing required fields. Example schema fragment:

```yaml
key_family:
  required: [id, purpose, algorithm, strength_bits, storage, owner,
             rotation_period, destruction_method]
  properties:
    strength_bits: {type: integer, minimum: 112}
    storage:       {enum: [HSM_FIPS_140_3_L3, CloudKMS, HSM_offline,
                           SPIRE, Sigstore]}
```

## 4. Rubric / review checklist

Score each item 0 / 1 / 2 (missing / partial / complete). Pass at ≥80%.

| #  | Criterion                                                                 | Pts |
|----|---------------------------------------------------------------------------|-----|
| 1  | Inventory covers data-at-rest, in-transit, signing, identity, secrets     | 2   |
| 2  | Each family names owner *and* custodian distinct from each other          | 2   |
| 3  | Algorithm + strength is at least 112-bit security per SP 800-57 Part 1    | 2   |
| 4  | Storage is FIPS 140-3 validated for every long-lived signing or wrap key  | 2   |
| 5  | Rotation cadence is within SP 800-57 cryptoperiod ranges, or justified    | 2   |
| 6  | Destruction procedure named for every family                              | 2   |
| 7  | Lifecycle (gen/dist/use/rotate/revoke/destroy) documented for each family | 2   |
| 8  | IR procedure for key compromise specifies contain → rotate → re-sign      | 2   |
| 9  | Algorithm-transition / PQ plan present                                    | 2   |
| 10 | ML-specific: model signing root is offline; weights encrypted + signed    | 2   |
| 11 | Two-person rule for root KEK, signing root, audit-log signing key         | 2   |
| 12 | KMP is auditable by an external reviewer with only the doc + KMS logs     | 2   |
| **Total** |                                                                    | **24** |

## 5. Common mistakes

- **One blob called "Encryption Keys".** A KMP collapses if there is
  no per-family breakdown — you can't reason about rotation or
  compromise blast radius.
- **Storing the signing root in the same KMS as the wrap key.** That
  KMS is now a single point of trust for both confidentiality *and*
  integrity; an operator with KMS admin can mint signatures.
- **No rotation cadence on workload identity.** SPIFFE SVIDs should
  live on the order of an hour. ServiceAccount tokens that "never
  expire" are not workload identities.
- **Forgetting model-signing.** Many KMPs cover code signing but
  treat model artifacts as data. They are executable code and need
  their own signing family (KF-05/KF-06).
- **Assuming cloud KMS == FIPS 140-3 L3.** Some KMS tiers are L2 or
  unvalidated. Pin the FIPS validation cert number in the KMP if it
  matters to your compliance posture.
- **Backing up signing private keys.** Signing keys should not be
  recoverable; loss of a signing key is an availability event, not a
  data-loss event.
- **No PQ commitment.** "We'll deal with PQ later" is a stance, but
  it should be a written, dated stance with owner.
- **Skipping the destruction step.** "Rotate" without "destroy" leaves
  retired keys sitting in the KMS forever, which expands the
  compromise surface during incident response.

## 6. References

- NIST SP 800-57 Part 1 Rev. 5, *Recommendation for Key Management:
  General* — https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
- NIST SP 800-57 Part 2 Rev. 1, *Best Practices for Key Management
  Organizations* — https://csrc.nist.gov/pubs/sp/800/57/pt2/r1/final
- NIST SP 800-131A Rev. 2, *Transitioning the Use of Cryptographic
  Algorithms and Key Lengths* — https://csrc.nist.gov/pubs/sp/800/131/a/r2/final
- NIST FIPS 140-3, *Security Requirements for Cryptographic Modules* —
  https://csrc.nist.gov/pubs/fips/140-3/final
- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) —
  https://csrc.nist.gov/projects/post-quantum-cryptography
- NIST AI Risk Management Framework (AI RMF 1.0) —
  https://www.nist.gov/itl/ai-risk-management-framework
  (Map / Measure functions reference confidentiality + integrity
  controls that this KMP implements.)
- OWASP Machine Learning Security Top 10 —
  https://owasp.org/www-project-machine-learning-security-top-10/
  (ML06 "AI Supply Chain Attacks" is what KF-05/KF-06 mitigate.)
- MITRE ATLAS — https://atlas.mitre.org/
  (ATLAS techniques on model exfiltration / supply chain map to the
  signing and encryption controls above.)
