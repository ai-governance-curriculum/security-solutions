# SOLUTION — Exercise 04: Certificate Management Runbook

> Read this *after* drafting your own runbook. This file is the
> worked runbook, the rotation and revocation procedures, and the
> rubric.

## 1. Solution overview

A certificate runbook is the operational counterpart to the Key
Management Plan ([[exercise-01-key-management-plan]]). The KMP says
*what* certs and keys exist; the runbook says *how* on-call operates
them: how they're issued, rotated, monitored, revoked, and how the
team responds when something fails.

The reference profile is **RFC 5280** for X.509, the CA/Browser Forum
**Baseline Requirements** for publicly-trusted certs, **NIST SP 800-52
Rev. 2** for TLS server profiles, **RFC 8555** (ACME) for automated
issuance, and the SPIFFE specs for workload identity.

The runbook is designed so a new on-call engineer can resolve a cert
incident without paging the cert owner.

## 2. Implementation — worked answer (the runbook)

### 2.1 Certificate inventory (one row per cert family)

| Family ID | Purpose                       | Issuer (CA)                          | Tool / Controller         | Validity   | Owner                  |
|-----------|-------------------------------|--------------------------------------|---------------------------|------------|------------------------|
| CF-01     | External ingress (TLS server) | Public CA via ACME (Let's Encrypt or similar) | cert-manager `Issuer`      | 90 days    | SRE / Platform Net     |
| CF-02     | Internal API gateway (TLS)    | Private intermediate (Vault PKI)     | cert-manager `ClusterIssuer` | 30 days  | Platform Sec           |
| CF-03     | mTLS workload SVIDs           | SPIRE                                | spire-agent               | 1 hour     | Platform Sec           |
| CF-04     | mTLS service mesh mesh CA     | Istio Citadel or Istiod              | istiod                    | 24 hours (workload), 365 days (root) | Platform Sec |
| CF-05     | Model registry server         | Private intermediate (Vault PKI)     | cert-manager              | 90 days    | ML Platform Lead       |
| CF-06     | Code-signing intermediate     | Sigstore Fulcio (or private Fulcio)  | Sigstore                  | Short-lived (≤10 min for keyless) | Platform Sec |
| CF-07     | Internal CA (intermediate)    | Internal root (offline HSM)          | Vault PKI                 | 1–3 years  | Sec Lead               |
| CF-08     | Internal root CA              | Self-signed, offline HSM             | manual ceremony           | 10 years   | Sec Lead + custodian   |

This mirrors the key families in [[exercise-01-key-management-plan]]
§2.3 (KF-05/06/07/08 → CF-* counterparts).

### 2.2 Issuance procedure

Every issuance procedure must specify: who can request it, what
identity proof is required, what subject/SAN policy applies, and where
the cert lands.

#### CF-01 / CF-05 (cert-manager + ACME or Vault PKI)

Triggered by creating a `Certificate` CR:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: inference-tls
  namespace: ingress
spec:
  secretName: inference-tls
  duration: 2160h    # 90d
  renewBefore: 720h  # 30d
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  commonName: inference.mlplat.example.com
  dnsNames:
    - inference.mlplat.example.com
  privateKey:
    algorithm: ECDSA
    size: 256
    rotationPolicy: Always   # generate a new key at every renewal
  usages: [server auth]
```

Verify after issuance:
```sh
kubectl -n ingress describe certificate inference-tls
# Expect: Status.Conditions[Ready] = True; NotAfter ≈ now + 90d.
openssl s_client -connect inference.mlplat.example.com:443 \
                 -servername inference.mlplat.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

#### CF-03 (SPIFFE SVID)

Issued automatically by the SPIRE agent to the workload via the
Workload API. Operators do not issue these by hand; they configure
the registration entries:

```sh
spire-server entry create \
  -spiffeID spiffe://mlplat.example.com/ns/inference/sa/inference-sa \
  -parentID spiffe://mlplat.example.com/spire/agent/k8s_sat/prod/<node> \
  -selector k8s:ns:inference \
  -selector k8s:sa:inference-sa \
  -ttl 3600
```

#### CF-07 / CF-08 (intermediate / root)

Issued in a **key ceremony**: multi-person, witnessed, scripted,
recorded. Output: signed cert, audit log, attestation that key
material never left the HSM. Re-issued only at scheduled rotation or
in an incident.

### 2.3 Renewal / rotation

The runbook makes renewal the boring path:

- **Automated (preferred).** cert-manager renews at `renewBefore`
  (typically 1/3 of validity). SPIRE rotates SVIDs at 50% of TTL.
  cert-manager auto-rotates the private key only if `rotationPolicy:
  Always` (set it).
- **Operator-triggered.** `kubectl cert-manager renew <cert>` forces
  a renewal (use for incidents, not routine ops).
- **Cadence guideline (cryptoperiods).** Per NIST SP 800-57 Part 1,
  TLS server keys ≤ ~2 years for long-lived, 90 days for ACME-issued.
  Workload identity is short by design (≤1h).

Renewal SLOs:
- ACME-managed cert (CF-01): must renew with ≥30 days remaining.
  Alert at 21 days. Page at 14 days.
- Internal cert (CF-02/05): must renew with ≥10 days remaining.
- SVID (CF-03): must rotate every TTL; alert if `now - issued > 0.9 * ttl`.

### 2.4 Monitoring

Three classes of probes, each with an alert:

1. **Expiry probe.** External: `blackbox-exporter` `module: tls_connect`
   with `tls_cert_not_after` metric and a Prometheus alert:
   ```
   alert: CertExpiringSoon
   expr:  (probe_ssl_earliest_cert_expiry - time()) < 21 * 86400
   for:   30m
   ```
   Internal: cert-manager exposes `certmanager_certificate_expiration_timestamp_seconds`;
   alert at < 14 days.
2. **Chain / SAN probe.** Active TLS probe (see Exercise 02 §2.3)
   confirms chain validates and SAN matches expected host. Run daily.
3. **Issuer health probe.** Vault PKI: `vault read pki/health`. ACME:
   inspect cert-manager `Order` / `Challenge` failure metrics.

### 2.5 Revocation

Document the revocation path *before* you need it.

- **ACME-issued cert (CF-01).** `acme.sh --revoke <domain>` or via the
  CA's portal. Most ACME CAs implement RFC 8555 §7.6.
- **Vault PKI cert (CF-02/05).** `vault write pki/revoke serial_number=<sn>`.
  CRL is auto-generated; OCSP responder updates.
- **SPIRE SVID (CF-03).** No explicit revocation. Instead: delete the
  registration entry; SVID expires on TTL. For *immediate* revocation,
  rotate the trust bundle so the issuing CA is no longer trusted.
- **Mesh root rotation (CF-04/CF-08).** Multi-step, planned:
  publish new root → cross-sign → propagate trust bundle → revoke
  old root.

Revocation must produce: a revocation record (serial, reason code,
operator, timestamp), an OCSP/CRL update, and an audit event in the
SIEM.

### 2.6 Incident response

#### Incident A: cert expired in prod

1. **Detect.** Page from `CertExpiringSoon` or, worst case, from user
   reports of `ERR_CERT_DATE_INVALID`.
2. **Confirm.** `openssl s_client -connect host:443 </dev/null | openssl x509 -noout -dates`.
3. **Issue a replacement.**
   - cert-manager: `kubectl cert-manager renew <cert>` then watch
     `kubectl describe cert <cert>`.
   - Manual ACME: `acme.sh --issue ...`.
4. **Roll the secret out.** cert-manager updates the Secret in place;
   ingress (NGINX/Envoy) auto-reloads. If not auto-reloaded, trigger
   `kubectl rollout restart` on the gateway.
5. **Verify.** Active TLS probe from outside the cluster.
6. **Post-incident.** Why did monitoring not catch this earlier?
   Tighten the alert threshold; add the cert to the inventory if it
   was missing.

#### Incident B: CA outage (ACME down)

1. **Detect.** `Order` failures in cert-manager.
2. **Failover.** Each `Certificate` should reference an `Issuer` with
   a configured fallback (e.g., `letsencrypt-prod` → `zerossl`).
3. **If no fallback configured:** issue an emergency cert from the
   internal Vault PKI (CF-02 family), update the ingress to use it,
   document as tech-debt.

#### Incident C: private key compromise

Follow [[exercise-01-key-management-plan]] §2.6:

1. **Contain.** Mark the key compromised in the KMS / HSM; disable
   further signing.
2. **Revoke.** Revoke the cert (§2.5). Push the CRL / OCSP update.
3. **Rotate.** Issue a replacement cert with a *new* key (rotationPolicy:
   Always ensures this is the default at renewal too).
4. **Roll dependent secrets.** Any cert that was issued from the
   compromised intermediate must be rotated.
5. **Investigate.** How did the key leak? Was it on disk, in a memory
   dump, in CI logs? Close the leak.
6. **Notify** per the IR matrix.

#### Incident D: trust bundle drift

Symptom: workloads suddenly fail mTLS with "unknown CA".

1. Compare deployed trust bundle on the affected workload vs. the
   source-of-truth bundle. (`spire-agent api fetch x509` or inspect
   the mounted Secret.)
2. Force a bundle refresh (`kubectl rollout restart` or
   `spire-server bundle list`).
3. If the bundle update missed a rotation, add the previous CA back
   to the bundle (allow overlap), then re-rotate carefully.

### 2.7 On-call quick reference

The runbook ends with a one-page cheat sheet:

```
Expiring soon?    kubectl get cert -A --sort-by=.status.notAfter
Force renew:      kubectl cert-manager renew <cert> -n <ns>
Inspect cert:     openssl s_client -connect host:443 -servername host </dev/null
                  | openssl x509 -noout -text
Check chain:      openssl s_client -showcerts -connect host:443 </dev/null
Check OCSP:       openssl ocsp -issuer chain.pem -cert cert.pem \
                  -url $(openssl x509 -noout -ocsp_uri -in cert.pem)
Revoke (Vault):   vault write pki/revoke serial_number=<sn>
Revoke (ACME):    acme.sh --revoke -d <domain>
SPIRE list:       spire-server entry show
Trust bundle:     kubectl -n spire-system get cm spire-bundle -o yaml
Mesh status:      istioctl proxy-status; istioctl authn tls-check
Break glass:      see [[exercise-03-signed-artifact-rollout]] §2.6
```

## 3. Validation steps

A reviewer can drill the runbook by:

1. Picking a random cert from the inventory and confirming the listed
   owner / issuer / monitoring alert all exist.
2. Forcing a renewal on a non-critical cert and timing it end-to-end
   (target: < 5 minutes).
3. Revoking a test cert; confirm OCSP status flips to `revoked`
   within the OCSP cache TTL.
4. Pausing cert-manager and confirming the expiry alert fires before
   the cert expires.
5. Doing a tabletop "expired prod cert" and timing how long a new
   on-call takes to recover, using only the runbook.
6. Asserting that no cert in the inventory is unowned, unmonitored,
   or has validity > policy maximum.

## 4. Rubric / review checklist

Score 0 / 1 / 2; pass at ≥80%.

| #  | Criterion                                                                       | Pts |
|----|---------------------------------------------------------------------------------|-----|
| 1  | Inventory covers ingress, internal, mTLS / SVID, mesh CA, model registry, signing | 2  |
| 2  | Each family lists issuer, controller, validity, owner                           | 2   |
| 3  | Issuance procedure documented per family with example commands                  | 2   |
| 4  | Renewal SLOs (alert / page thresholds) defined and tied to monitoring           | 2   |
| 5  | Private key rotation at renewal (`rotationPolicy: Always`) called out           | 2   |
| 6  | Monitoring uses both internal (cert-manager) and external (blackbox) probes     | 2   |
| 7  | Revocation procedure documented per family; CRL/OCSP/bundle rotation covered    | 2   |
| 8  | IR procedures: expiry, CA outage, key compromise, trust bundle drift            | 2   |
| 9  | Mesh CA / root rotation has multi-step bundle propagation plan                  | 2   |
| 10 | On-call cheat sheet present                                                     | 2   |
| 11 | Validity per family ≤ NIST SP 800-57 cryptoperiod / CA/B Forum max (≤398d for public) | 2 |
| 12 | Drill cadence (tabletop) defined                                                | 2   |
| **Total** |                                                                          | **24** |

## 5. Common mistakes

- **No inventory.** "We use cert-manager" is not an inventory. List
  every cert family and an owner.
- **Validity > 398 days for a publicly-trusted cert.** CA/Browser
  Forum Baseline Requirements §6.3.2 caps validity; many public CAs
  refuse to issue longer.
- **Renewing without key rotation.** Without `rotationPolicy: Always`
  cert-manager renews the cert but keeps the old key. That defeats
  the rotation.
- **No OCSP / revocation strategy.** A leaked cert with no
  revocation path is valid until expiry.
- **Mesh root rotation = "swap the secret".** Without overlap, every
  workload using the old root drops connections at the moment of
  swap. Always cross-sign or run dual roots during overlap.
- **Single ACME CA with no fallback.** Outages happen; have a second
  `Issuer` defined.
- **SPIRE SVIDs treated as "revocable."** They're short-lived; the
  revocation primitive is "don't renew."
- **Alerting only on expiry.** Misissued SAN, invalid chain, or
  revoked-by-CA also break TLS. Probe chain validity, not just
  `not_after`.
- **No drill.** A runbook that has never been exercised is fiction.
- **Forgetting the model registry cert.** It's "just" a registry —
  but if its TLS server cert expires, inference can't pull models.

## 6. References

- RFC 5280, *Internet X.509 PKI Certificate and CRL Profile* —
  https://www.rfc-editor.org/rfc/rfc5280
- RFC 6960, *X.509 PKI Online Certificate Status Protocol (OCSP)* —
  https://www.rfc-editor.org/rfc/rfc6960
- RFC 8555, *ACME (Automatic Certificate Management Environment)* —
  https://www.rfc-editor.org/rfc/rfc8555
- CA/Browser Forum Baseline Requirements —
  https://cabforum.org/baseline-requirements-documents/
- NIST SP 800-52 Rev. 2 (TLS guidance) —
  https://csrc.nist.gov/pubs/sp/800/52/r2/final
- NIST SP 800-57 Part 1 Rev. 5 (key management; cryptoperiods) —
  https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
- cert-manager docs —
  https://cert-manager.io/docs/
- SPIFFE / SPIRE specifications —
  https://spiffe.io/docs/latest/spec/
- Istio mesh CA management —
  https://istio.io/latest/docs/tasks/security/cert-management/
- HashiCorp Vault PKI secrets engine —
  https://developer.hashicorp.com/vault/docs/secrets/pki
- OWASP Machine Learning Security Top 10 —
  https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS — https://atlas.mitre.org/
- NIST AI RMF 1.0 — https://www.nist.gov/itl/ai-risk-management-framework
