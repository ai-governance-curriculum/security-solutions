# SOLUTION — Exercise 03: Secret Rotation Playbook

## 1. Solution overview

A rotation playbook is the operational document that turns the
exercise-01 inventory and the exercise-02 deployment plan into
*recurring* protection. The deliverable is a playbook covering:

1. The rotation policy (which secret class rotates how often, and
   why).
2. The mechanics of rotation per class (who runs it, with what
   command, in what order).
3. The fail-safe behaviour (what happens to consumers during a
   rotation, what happens if the rotation step itself fails).
4. The detection and audit story (how the team knows a rotation
   actually succeeded).

The exercise is operational; the solution is a worked playbook plus
the rationale a reviewer can grade against.

## 2. Implementation (worked answer)

### 2.1 Rotation policy by class

Rotation cadence is derived from cryptoperiod guidance (NIST SP
800-57 Part 1 Rev. 5) and from the practical blast radius of each
class. The numbers below are defensible defaults; an environment
with stronger compliance requirements tightens them.

| Class (from exercise-01) | Cadence | Trigger types | Notes |
|---|---|---|---|
| **T0 root keys** (KMS root, signing-CA root, Vault recovery keys) | Annual + on-suspicion + on-personnel-change | Time + event + role | Rotation drilled, never on-demand for the first time. |
| **T1 long-lived static credentials that *cannot* yet be dynamic** | 30-90 days | Time + event | Treated as a migration debt, not a steady state. |
| **T1 dynamic credentials** (DB roles, cloud STS, Vault PKI leaf) | Per-issuance, TTL 1-24h | Continuous | No "rotation event" — the TTL is the rotation. |
| **T1 signing identities used in CI** (model signing, container signing) | Per-build (keyless) | Continuous | See exercise-04. |
| **T2 read tokens** | 90 days | Time | Rotated as a batch; failures contained to read paths. |
| **T3 sandbox/non-prod** | 180 days | Time | Lower priority but still bounded. |
| **TLS server certs (internal CA)** | 30-72h leaves, annual intermediate | Continuous (cert-manager) | Short leaves replace rotation with re-issuance. |
| **TLS server certs (public CA)** | ≤90d (ACME) | Continuous (cert-manager / ACME) | Operationally the same as internal. |
| **SSH host keys / signed user certs** | Per-session (signed) | Continuous | Replace static host trust with CA-signed certs. |
| **Webhook signing secrets** | 180 days + on-suspicion | Time + event | Rotate with overlap window so in-flight events verify. |
| **OAuth client secrets** | 180 days + on-suspicion | Time + event | Per provider's supported overlap mechanism. |
| **Database service passwords** (where dynamic not yet available) | 30 days | Time | Migration to dynamic engine is the long-term fix. |

Three event-driven triggers always override the time-driven cadence:

1. **Suspected exposure** (gitleaks/TruffleHog hit, leaked log, lost
   laptop, terminated employee with prior access, third-party breach
   notice).
2. **Personnel change** for credentials any human has touched
   directly (T0 custodians, break-glass, sandbox admin).
3. **Dependency or library CVE** that affects the secret's
   confidentiality (e.g. a TLS library bug that may have leaked
   private keys).

### 2.2 Rotation order (the part that breaks production if wrong)

Most rotation outages are not caused by the rotation itself; they are
caused by the *order*. The rule is:

> **Add the new credential, propagate it to all consumers, verify
> consumers are using it, then revoke the old credential.**

The five rotation patterns:

**Pattern A — Overlap rotation (default for static credentials).**

```
1. Issue new credential N+1 alongside existing N.
2. Push N+1 to all consumers (config reload / pod restart / CI
   variable update). Consumers prefer N+1 but accept N.
3. Wait one full deploy cycle plus one cron cycle.
4. Confirm zero consumers still use N (audit/access logs).
5. Revoke N.
```

The wait in step 3 must exceed the slowest consumer's pickup time.
"All consumers" includes one-shot batch jobs that run weekly.

**Pattern B — Dynamic credential (preferred wherever supported).**

```
1. Workload requests credential from Vault at start of unit-of-work.
2. Vault issues a credential with TTL ≤ unit-of-work duration.
3. Credential is destroyed when TTL expires; no revocation step.
```

This pattern replaces the playbook entirely for the affected
secrets. Successful migration to Pattern B is the desired exit
condition for most rows in the inventory.

**Pattern C — Signed material with verifying parties (keys, certs).**

```
1. Issue new key K+1 and publish its public material to all
   verifiers.
2. Verifiers accept K and K+1 in parallel.
3. Re-issue artefacts under K+1 (cert renewal / re-signature).
4. Once all verifiers see only K+1 in audit, revoke K.
```

For TLS server certs handled by cert-manager + a short-lived ACME or
Vault PKI issuer, the playbook is essentially "let cert-manager run
and observe the metric"; the playbook documents the failure modes,
not the happy path.

**Pattern D — Single-consumer atomic rotation.**

For credentials with exactly one consumer and one issuer (e.g. a
webhook secret a provider pushes to one receiver), rotation collapses
to atomic update plus the next-event verification.

**Pattern E — Cryptographic re-keying (transit, encryption-at-rest).**

```
1. Bump key version on the issuer (Vault transit `rotate`).
2. New encryptions use the new version.
3. Old ciphertext continues to decrypt under the old version.
4. Background job re-encrypts existing ciphertext to the new version
   (`rewrap`).
5. Old version is marked min_decryption_version once re-encryption
   completes.
```

Pattern E does not invalidate existing data; it bounds the window in
which a compromised key version is useful.

### 2.3 Worked example — rotating the model-registry write token (SEC-003)

This is the T1 secret most often rotated by hand in real platforms
and the one most often missed. Worked end-to-end:

```
Preconditions:
- Token is currently a long-lived bearer token in a GitHub Actions
  organisation secret.
- The model-registry (MLflow) supports two valid tokens per service
  account.
- The CI workflows that build, sign, and push models are the only
  consumers (verified against exercise-01 SEC-003 consumers).

Steps:
1. Open a rotation ticket, link it to SEC-003 in the inventory.
2. Mint token N+1 in MLflow with the same scope as N.
   - Audit: confirm scope is read+write to the model-registry
     namespace only.
3. Update the GitHub Actions organisation secret MODEL_REG_TOKEN to
   N+1.
4. Re-run the model-build workflow on a representative branch. The
   workflow must:
   a. Authenticate with N+1.
   b. Push a test artefact under a dry-run tag.
   c. Sign the artefact (separately; see exercise-04).
5. Confirm in the MLflow access log that N+1 was used by the build.
6. Wait for the slowest scheduled workflow (weekly eval pipeline) to
   complete using N+1. Re-check the access log.
7. Revoke N in MLflow.
8. Update the inventory row SEC-003 "Last rotated" to today and
   close the ticket.

Rollback:
- If steps 4-6 fail under N+1, the workflows continue to function
  under N (still valid). Do not revoke N before step 7.
- If the failure is at MLflow rather than at the workflow, page the
  ML platform oncall and abort steps 7-8.

Exit to dynamic pattern:
- The standing migration plan is to replace SEC-003 with a Vault
  OIDC-derived short-lived token (Pattern B). This rotation event is
  the last manual one expected; the next "rotation" of SEC-003 is
  scheduled to be its retirement.
```

### 2.4 Calendar and scheduling

| Cadence | Mechanism |
|---|---|
| Annual (T0) | Reviewed at the annual cryptoperiod review; date held in the runbook calendar; involves named custodians. |
| 30-90 days (T1 static) | Automated where the downstream supports it (e.g. cloud rotators). Where not automated, a recurring ticket is created two weeks before due date; rotation is performed during business hours, never on a Friday. |
| 90-180 days (T2/T3) | Batched at quarter end; one platform engineer responsible for the batch. |
| TTL-bounded (Pattern B) | No calendar; monitoring confirms TTLs are within policy. |

Rotation work that is "due whenever" is rotation work that does not
happen. Every cadence above is either ticketed or alerted.

### 2.5 Failure handling

- **Rotation step itself fails.** The new credential issuance has
  failed; the old credential is still valid. Roll forward by debugging
  the issuance system; do not delete N "to force the issue".
- **Consumer fails to pick up N+1.** Investigate the consumer; N+1
  and N are both valid so production is unaffected. Do not assume the
  consumer is fine because production is fine; the next rotation will
  bite.
- **N revoked but a consumer was still using it.** This is the
  common outage. The remediation is to re-issue N (a fresh secret with
  identical permissions, *not* the original value) and restart the
  consumer; in parallel, file the gap into the consumer-discovery
  tooling (CI scan, runtime mount audit, exercise-01 cross-reference).
  Do not roll back to "before the rotation" — the rotation itself was
  correct; the inventory was incomplete.
- **Audit lag.** If audit logs are not yet showing N+1 in step 5,
  wait one more interval *before* revoking N; never proceed on
  inference alone.

### 2.6 Detection and audit

A rotation succeeds only if the audit log proves it. Every rotation
event emits:

- `secret.id` — the inventory ID.
- `secret.previous_handle`, `secret.new_handle` — opaque references
  (never the value).
- `rotated_at`, `rotated_by` (workload or human identity).
- `consumers_seen_new` — list of consumer identities observed using
  the new credential in the verification window.
- `revoked_at` — when N was destroyed.

Alerts fire when:

- A secret's age exceeds its cadence + 25%.
- A rotation event leaves `consumers_seen_new` empty (no consumer
  proved use of N+1 before N was revoked).
- A secret's audit access log shows reads of N after `revoked_at`
  (the consumer somehow has a cached value).

### 2.7 Design rationale

- **Cadence per *class*, not per *secret*.** A per-secret cadence is
  un-auditable; a per-class cadence is.
- **Dynamic is preferred over rotated.** A short TTL is a tighter
  control than a long cycle; the playbook directs migration toward
  dynamic.
- **Order matters more than speed.** Pattern A's "add, propagate,
  verify, revoke" eliminates the common outage; aggressive
  same-step revocation does not.
- **Audit is the success criterion.** Until the consumer is observed
  using the new credential, the rotation is not done.
- **Event triggers always override calendar.** A 90-day token used by
  a fired engineer rotates today, not at quarter end.

## 3. Validation steps

1. **Tabletop the playbook** with the rotation owners. Walk SEC-003
   end-to-end as written. Each owner must execute their step from the
   document alone.
2. **Dry-run rotations in non-production** for each Pattern (A, B,
   C, D, E). Time each, record the gap between issuance and
   first-consumer-confirmed-use.
3. **Inject failure**: skip step 4 in §2.3, attempt step 7. The
   alert in §2.6 must fire; revocation must be blocked.
4. **Inventory linkage.** Sample five inventory rows; for each,
   confirm the playbook says exactly which pattern applies and how to
   run it.
5. **Cadence audit.** A monitor lists secrets whose age exceeds
   cadence; the list should be empty before the playbook is signed
   off.
6. **Cross-reference exercise-05.** Confirm every rotation entry in
   this playbook is reachable from the incident runbook (the runbook
   tells you which rotation to invoke; this playbook tells you how to
   run it).

## 4. Rubric / review checklist

| Criterion | Pass | Partial | Fail |
|---|---|---|---|
| **Cadence policy** | Per-class table with justification grounded in NIST 800-57 or equivalent. | Per-class table without justification. | Single global cadence or no policy. |
| **Event triggers** | Exposure, personnel, dependency triggers all listed and override calendar. | Some triggers listed; override priority not stated. | No event triggers. |
| **Rotation order** | All five patterns documented with explicit "add-propagate-verify-revoke". | Patterns documented but verify step missing. | "Revoke and re-issue" without propagation. |
| **Worked example** | At least one inventory-linked, step-by-step rotation with rollback. | Worked example present but without rollback. | No worked example. |
| **Audit/verification** | Rotation success defined as "consumer observed using new credential". | Audit captured but not gating. | Rotation success = "credential issued". |
| **Failure handling** | Common failure modes named with remediation. | Some failure modes named. | "If it fails, ask for help". |
| **Scheduling** | Every cadence either automated, ticketed, or alerted. | Some "ad hoc" rotations. | Cadence with no scheduling. |
| **Migration to dynamic** | Static rotations flagged as transitional. | Migration mentioned but no path. | Static rotation treated as steady state. |

## 5. Common mistakes

- **Revoke before propagate.** The single most common outage. Pattern
  A exists to prevent it.
- **Cadence as aspiration.** "We rotate quarterly" with no tickets,
  alerts, or audit is the equivalent of "we don't rotate".
- **Rotating credentials a fired employee held by knowing where they
  worked, not by knowing which secrets they touched.** Inventory
  ownership (exercise-01) is the source of the rotation list, not
  org-chart inference.
- **Rotating the storage location instead of the secret.** Moving a
  token from Kubernetes Secret to Vault does not rotate the token.
- **Treating dynamic credentials as exempt from monitoring.** Pattern
  B still needs the "no TTL longer than policy" monitor.
- **Rotating signing keys without verifier overlap (Pattern C).** A
  legitimate consumer suddenly sees its trust path broken; the
  apparent outage masks whether real attestations were also broken.
- **Pattern E without `min_decryption_version`.** Encryption uses the
  new key but old ciphertext silently keeps the old key valid forever.
- **Rotation on a Friday.** Outages happen when rotation goes wrong;
  outages on Friday cost the weekend.
- **No exit criterion to Pattern B.** Static credentials get rotated
  forever instead of being replaced by dynamic ones.

## 6. References

- NIST SP 800-57 Part 1 Rev. 5, *Recommendation for Key Management* —
  cryptoperiods and rotation guidance:
  <https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final>
- NIST SP 800-53 Rev. 5, control `IA-5(1)` (authenticator management
  — change) and `SC-12` (cryptographic key establishment and
  management):
  <https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final>
- OWASP Secrets Management Cheat Sheet — rotation lifecycle:
  <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>
- HashiCorp Vault docs — dynamic secrets (Pattern B):
  <https://developer.hashicorp.com/vault/docs/secrets/databases>
- HashiCorp Vault docs — transit key rotation (Pattern E):
  <https://developer.hashicorp.com/vault/docs/secrets/transit#key-rotation>
- NIST AI Risk Management Framework — Manage function (operational
  controls for AI system dependencies):
  <https://www.nist.gov/itl/ai-risk-management-framework>
- OWASP Machine Learning Security Top 10 —
  <https://owasp.org/www-project-machine-learning-security-top-10/>
- MITRE ATLAS — <https://atlas.mitre.org/>.

