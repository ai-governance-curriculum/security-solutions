# SOLUTION — Exercise 02: TLS / mTLS Configuration Audit

> Read this *after* attempting the audit yourself. This file is the
> worked audit, the tooling, the pass/fail thresholds, and the rubric.

## 1. Solution overview

The audit answers two questions for every TLS endpoint and every mTLS
mesh boundary on the ML platform:

1. **Is the negotiation safe?** Protocol version, cipher suites,
   curves, signature algorithms, certificate chain, OCSP, HSTS.
2. **Is identity enforced?** For mTLS, does the server require a
   client cert; is the verification rooted in the trust bundle; is
   authorization keyed on the verified identity (not on the network
   path)?

The configuration baseline is **NIST SP 800-52 Rev. 2** for TLS server
configuration. The protocol references are **RFC 8446 (TLS 1.3)** and
**RFC 8446bis** clarifications. For mTLS the identity convention is
**SPIFFE** (URI SAN, `spiffe://trust-domain/...`). Cipher selection on
TLS 1.2 follows SP 800-52 Rev. 2 §3.3.1.

The deliverable is:

- An audit checklist (Section 2.2)
- A reproducible scan script (Section 2.3)
- A findings template (Section 2.4)
- A pass/fail policy that CI can enforce (Section 3)

## 2. Implementation — worked audit

### 2.1 Scope and target inventory

For an ML platform, audit at minimum:

| Endpoint class             | Examples                                              | TLS or mTLS |
|----------------------------|-------------------------------------------------------|-------------|
| External ingress           | inference API, model marketplace, dashboard           | TLS         |
| Internal API gateway       | platform control plane                                | mTLS        |
| Service mesh data plane    | Envoy sidecar to sidecar                              | mTLS        |
| Model registry             | OCI distribution endpoint, S3-compatible              | TLS + mTLS  |
| Feature store online API   | Redis / online store                                  | mTLS        |
| Training data warehouse    | object store, lakehouse JDBC/HTTPS                    | TLS         |
| Observability backends     | Prometheus remote-write, OTLP collector               | mTLS        |
| KMS / Secrets manager      | cloud KMS / Vault                                     | TLS (mTLS preferred) |

Every endpoint in production gets a row in the audit register.

### 2.2 Audit checklist

Below is the full per-endpoint checklist. Each item maps to a control
in SP 800-52 Rev. 2 or RFC 8446.

#### Protocol and version
- [ ] **TLS 1.3 supported** (SP 800-52r2 §3.1).
- [ ] **TLS 1.2 supported** if backward compat required, with the
      cipher rules in §3.3.1.
- [ ] **TLS 1.0, 1.1, SSL 3.0, SSL 2.0 disabled** (SP 800-52r2 §3.1).
- [ ] If TLS 1.3 only: confirm clients (in-cluster + external) are
      compatible.

#### Cipher suites (TLS 1.3 — the suite is implicit; verify these are offered)
- [ ] `TLS_AES_128_GCM_SHA256`
- [ ] `TLS_AES_256_GCM_SHA384`
- [ ] `TLS_CHACHA20_POLY1305_SHA256`
- [ ] No legacy / non-AEAD ciphers offered.

#### Cipher suites (TLS 1.2 — if enabled)
Per SP 800-52r2 §3.3.1, REQUIRED list (any AEAD + (EC)DHE):
- [ ] `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- [ ] `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- [ ] `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
- [ ] `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- [ ] No CBC-mode ciphers (no `_CBC_`).
- [ ] No RC4, no 3DES, no NULL, no EXPORT, no anonymous.
- [ ] No static-RSA key exchange (the suite name will lack `(EC)DHE`).

#### Key exchange / groups
- [ ] Named groups offered include `x25519`, `secp256r1` (P-256), or
      `secp384r1` (P-384) (SP 800-52r2 §3.3.2 / RFC 8446 §4.2.7).
- [ ] No `secp224r1` or weaker.
- [ ] Optional: hybrid PQ key exchange where supported (the specific
      PQ KEM identifier is pinned per stack in the audit register, e.g.
      `X25519MLKEM768` once your TLS implementation supports it).

#### Signature algorithms
- [ ] `ecdsa_secp256r1_sha256` and/or `rsa_pss_rsae_sha256` offered.
- [ ] No `*_sha1` signature algorithms (SP 800-131A r2).

#### Certificate
- [ ] X.509 v3, key size ≥ RSA-2048 or ECDSA P-256 (SP 800-131A r2).
- [ ] SAN(s) match expected hostname(s); no reliance on CN.
- [ ] Validity ≤ 398 days for publicly-trusted certs
      (CA/Browser Forum BR §6.3.2). Internal CAs MAY be longer with
      justification.
- [ ] Chain validates to a trust anchor in the deployed bundle.
- [ ] Not expired; >30 days from expiry (renewal threshold).
- [ ] Revocation: OCSP stapling enabled, or short-lived certs in use
      (≤24h), or CRL distribution point reachable.

#### HTTP layer (for HTTPS only)
- [ ] HSTS header with `max-age` ≥ 31536000 and `includeSubDomains`.
- [ ] HTTP/2 or HTTP/3 enabled where supported.

#### Server settings
- [ ] Session resumption: TLS 1.3 PSK or TLS 1.2 session tickets with
      rotated ticket key (no static ticket key).
- [ ] `secure_renegotiation` enabled where TLS 1.2 is in use (RFC 5746).
- [ ] Server prefers stronger cipher orders (TLS 1.2 only; TLS 1.3
      makes this implicit).

#### mTLS-specific
- [ ] Server requires client certificate (`SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT` in OpenSSL terms; Envoy `require_client_certificate: true`; Istio `PeerAuthentication mtls.mode: STRICT`).
- [ ] Client cert is validated against the SPIRE / mesh trust bundle,
      not the system root store.
- [ ] Authorization policy matches on **verified SPIFFE ID** (or
      issuer + SAN), not on source IP or namespace alone.
- [ ] Trust bundle rotation is automated (SPIRE bundle endpoint,
      cert-manager, or equivalent).
- [ ] Mesh-wide policy denies plaintext fallback
      (`mtls.mode: STRICT`, no `PERMISSIVE`).

### 2.3 Reproducible scan

Run two scans per endpoint: an offline parse of the server config and
an active TLS probe. Pin tool versions in CI.

#### 2.3.1 Active TLS probe (testssl.sh)

```sh
# scan-tls.sh — wraps testssl.sh with the SP 800-52r2 baseline.
# Requires testssl.sh ≥ 3.2.
set -euo pipefail

HOST="$1"     # e.g. inference.mlplat.example.com:443
OUTDIR="${2:-./audit-out}"
mkdir -p "$OUTDIR"

testssl.sh \
  --severity HIGH \
  --jsonfile "$OUTDIR/$(echo "$HOST" | tr ':/' '__').json" \
  --logfile  "$OUTDIR/$(echo "$HOST" | tr ':/' '__').log" \
  --protocols --ciphers --pfs --server-defaults \
  --headers --vulnerable \
  --warnings off --color 0 \
  "$HOST"
```

The JSON output is then evaluated against the policy in §3.

#### 2.3.2 Active TLS probe (nmap fallback)

`nmap` is universal and useful when `testssl.sh` isn't available:

```sh
nmap --script ssl-enum-ciphers,ssl-cert,ssl-dh-params \
     -p 443 inference.mlplat.example.com
```

Reject if the output shows: any `SSLv*`, `TLSv1.0`, `TLSv1.1`, any
cipher graded `D` or `E`, or DH parameters < 2048.

#### 2.3.3 mTLS probe

A plain `openssl s_client` confirms whether the server demands a
client cert:

```sh
# Should fail (no client cert) — confirms mTLS is enforced.
openssl s_client -connect ml-control.mlplat.svc:8443 \
                 -servername ml-control.mlplat.svc \
                 -tls1_3 </dev/null 2>&1 \
  | grep -E "alert (bad certificate|certificate required|handshake failure)"

# Should succeed with the right SVID.
openssl s_client -connect ml-control.mlplat.svc:8443 \
                 -cert /run/spire/certs/svid.pem \
                 -key  /run/spire/certs/svid_key.pem \
                 -CAfile /run/spire/certs/bundle.pem \
                 -tls1_3 -verify_return_error </dev/null \
  | grep -E "Verify return code: 0"
```

For Istio specifically, use `istioctl authn tls-check`:

```sh
istioctl authn tls-check <pod>.<ns> <target-service>.<ns>.svc.cluster.local
# Expect: STATUS=OK, AUTHN POLICY=mtls.mode=STRICT
```

#### 2.3.4 Static config audit

For each managed surface, also lint the config. Examples:

- **Envoy listener:** confirm `tls_minimum_protocol_version: TLSv1_2`
  (preferably `TLSv1_3`), `require_client_certificate: true`,
  `cipher_suites:` matches §2.2.
- **Istio `PeerAuthentication`:** `mtls.mode: STRICT`.
- **Istio `DestinationRule`:** `trafficPolicy.tls.mode: ISTIO_MUTUAL`.
- **NGINX:** `ssl_protocols TLSv1.3 TLSv1.2;`, `ssl_ciphers …` per
  SP 800-52r2, `ssl_prefer_server_ciphers off;` on 1.3, `ssl_session_tickets off;`
  if you can't rotate the ticket key.

### 2.4 Findings template

One block per endpoint:

```
Endpoint:          inference.mlplat.example.com:443
Scan timestamp:    2025-04-12T13:02:00Z
Scanner version:   testssl.sh 3.2
Protocol findings: TLSv1.0 enabled  [SEVERITY: HIGH, control: SP 800-52r2 §3.1]
Cipher findings:   None
Cert findings:     Validity 730d  [SEVERITY: MEDIUM, control: BR §6.3.2]
mTLS findings:     n/a (external TLS endpoint)
Recommendation:    Disable TLS 1.0/1.1 on the ingress GW; shorten
                   cert validity to ≤398d via cert-manager.
Owner:             SRE / Platform Networking
Due date:          2025-04-26
```

## 3. Validation steps

The audit must be reproducible in CI. A minimal pass/fail policy file:

```yaml
# tls-policy.yaml
required_protocols: [TLSv1.3]
allowed_protocols:  [TLSv1.3, TLSv1.2]
forbidden_protocols: [TLSv1.1, TLSv1.0, SSLv3, SSLv2]
forbidden_cipher_substrings: [_CBC_, RC4, 3DES, NULL, EXPORT, _anon_]
required_curves_any_of: [x25519, secp256r1, secp384r1]
forbidden_signature_substrings: [_sha1]
cert:
  min_rsa_bits: 2048
  allowed_ec_curves: [P-256, P-384]
  max_validity_days: 398
  min_days_to_expiry: 30
mtls:
  require_client_cert: true
  trust_bundle_source: [spire, cert-manager]
  authz_id_source_required: [spiffe_uri_san, x509_subject_san]
```

A simple Python evaluator (`evaluate.py`) loads each testssl.sh JSON
output and the policy; fails the build on any HIGH or MEDIUM finding.

Sanity checks every reviewer should perform:

1. Curl with `--tls-max 1.1` MUST fail.
2. Curl with no client cert against an mTLS endpoint MUST fail with
   "alert bad certificate" or "certificate required".
3. SPIRE workload API endpoint resolves and serves a current bundle.
4. `istioctl authn tls-check` shows `mtls.mode=STRICT` for every
   service in the mesh.
5. Cert-manager `Certificate` resources show `READY=True` and renewal
   < 30 days from expiry.

## 4. Rubric / review checklist

Score 0 / 1 / 2; pass at ≥80%.

| #  | Criterion                                                                   | Pts |
|----|-----------------------------------------------------------------------------|-----|
| 1  | Endpoint inventory is complete (covers all 8 endpoint classes above)        | 2   |
| 2  | Both active TLS probe and static config audit are performed                 | 2   |
| 3  | Forbidden protocols (TLS ≤1.1) confirmed disabled on every endpoint         | 2   |
| 4  | Cipher list matches SP 800-52r2 §3.3.1 (AEAD + (EC)DHE)                     | 2   |
| 5  | Certs: ≥2048 RSA / P-256, validity ≤398d (or justified), chain validates    | 2   |
| 6  | Revocation strategy: OCSP stapling, short-lived, or reachable CRL           | 2   |
| 7  | mTLS endpoints enforce client-cert (PERMISSIVE flagged as a finding)        | 2   |
| 8  | Authz matches on verified SPIFFE ID / SAN, not IP / namespace               | 2   |
| 9  | Findings include severity, control reference, owner, due date               | 2   |
| 10 | Scan is reproducible in CI with pinned tool versions                        | 2   |
| 11 | HSTS, secure renegotiation, no static session-ticket key checked            | 2   |
| 12 | PQ migration noted in followups (not required to be deployed)               | 2   |
| **Total** |                                                                      | **24** |

## 5. Common mistakes

- **Trusting only the ingress.** External TLS is fine, but internal
  pod-to-pod traffic is where the lateral-movement risk lives. The
  audit must cover mesh-internal traffic.
- **Cipher allow-list without forbidding CBC.** SP 800-52r2 retired
  CBC-mode suites for new deployments. They are still negotiable on
  many older configs.
- **mTLS in `PERMISSIVE` mode shipped to prod.** It permits plaintext
  fallback and undermines the entire mesh-identity model. Use
  `STRICT` and migrate workloads explicitly.
- **Authz keyed on `source.namespace`.** A compromised pod in the same
  namespace bypasses this. Key authz on the verified workload
  identity (SPIFFE URI SAN).
- **Treating expiry as the only cert health check.** Chain, SAN, key
  size, signature algorithm, and OCSP status all matter.
- **No ticket-key rotation.** Static TLS 1.2 session-ticket keys
  effectively break forward secrecy if the ticket key leaks.
- **Audit run once.** Drift happens — pin the scan in CI on every
  ingress / mesh config change.
- **Allowing TLS 1.0/1.1 "just for the legacy training cluster".**
  That cluster is on the same network as everything else; one weak
  endpoint is enough.
- **Ignoring the KMS endpoint.** Cloud KMS / Vault talks TLS to your
  workloads; audit it like any other endpoint.

## 6. References

- NIST SP 800-52 Rev. 2, *Guidelines for the Selection, Configuration,
  and Use of Transport Layer Security (TLS) Implementations* —
  https://csrc.nist.gov/pubs/sp/800/52/r2/final
- NIST SP 800-131A Rev. 2 (algorithm transitions; SHA-1 disallowed for
  signatures) — https://csrc.nist.gov/pubs/sp/800/131/a/r2/final
- RFC 8446, *The Transport Layer Security (TLS) Protocol Version 1.3* —
  https://www.rfc-editor.org/info/rfc8446/
- RFC 5746, *TLS Renegotiation Indication Extension* —
  https://www.rfc-editor.org/info/rfc5746/
- RFC 6066 (SNI), RFC 6960 (OCSP), RFC 7919 (FFDHE) — IETF Datatracker
- CA/Browser Forum *Baseline Requirements* (398-day max validity) —
  https://cabforum.org/baseline-requirements-documents/
- SPIFFE Specifications — https://spiffe.io/docs/latest/spec/
- Istio Security: PeerAuthentication / AuthorizationPolicy —
  https://istio.io/latest/docs/reference/config/security/
- Envoy TLS listener configuration —
  https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/tls.proto
- OWASP Machine Learning Security Top 10 (ML-Ops attack surface) —
  https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS (ML supply-chain and lateral-movement TTPs) —
  https://atlas.mitre.org/
- NIST AI RMF 1.0 (Manage/Govern functions reference these controls) —
  https://www.nist.gov/itl/ai-risk-management-framework
