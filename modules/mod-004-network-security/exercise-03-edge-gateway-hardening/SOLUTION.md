# SOLUTION — Exercise 03: Edge Gateway Hardening

> Reference solution for `mod-004-network-security` exercise 03. Read
> this *after* attempting the learner exercise. The deliverable is a
> hardened edge-gateway configuration plus a justification of every
> control.

## 1. Solution overview

The edge gateway is the single L7 ingress for the AI platform —
inference APIs, model registry read endpoints, signed-upload paths,
and platform admin all enter through it. Three threat classes drive
the hardening:

1. **TLS / transport** — downgrade, weak ciphers, missing SNI/ALPN
   constraints, leaking server identity.
2. **HTTP request smuggling and abuse** — oversize bodies, header
   abuse, slow-loris, CRLF injection, malformed `Host`, multiple
   `Content-Length`/`Transfer-Encoding` combinations.
3. **Authentication and identity** — anonymous traffic permitted onto
   the inference path, missing audience checks on JWTs, gateway
   logging that drops the caller identity.

The hardened reference is **Envoy**, configured both as a standalone
gateway and via Istio (`Gateway` + `EnvoyFilter`). The same principles
apply to NGINX or other L7 proxies — control mappings are listed in
§4.

## 2. Worked implementation

### 2.1 TLS posture

```yaml
# Envoy DownstreamTlsContext fragment
common_tls_context:
  tls_params:
    tls_minimum_protocol_version: TLSv1_3
    tls_maximum_protocol_version: TLSv1_3
    cipher_suites:
      - "TLS_AES_256_GCM_SHA384"
      - "TLS_AES_128_GCM_SHA256"
      - "TLS_CHACHA20_POLY1305_SHA256"
  alpn_protocols:
    - "h2"
    - "http/1.1"
  tls_certificate_sds_secret_configs:
    - name: edge-cert
require_client_certificate: false   # set true for mTLS on admin path
```

Decisions and *why*:

- **TLS 1.3 only on user-facing endpoints.** TLS 1.2 is permitted by
  many compliance regimes but supports cipher suites that have been
  documented as weak; TLS 1.3 removes the entire CBC/RSA-key-exchange
  surface. Confirm the compliance regime in scope (FedRAMP, ISO 27001,
  PCI DSS) before deciding whether TLS 1.2 must be retained.
- **ALPN explicitly listed.** Without an explicit ALPN list, clients
  can negotiate fall-back protocols the gateway did not intend to
  expose.
- **Certificate via SDS, not file mounts.** Keeps the cert lifecycle
  off-disk; the SDS provider (Istio Citadel, SPIRE, cert-manager) owns
  rotation.
- **Client cert required on the admin path only.** Inference
  endpoints terminate JWT/mTLS at L7 below.

### 2.2 HTTP-level hardening

```yaml
# Envoy HttpConnectionManager fragment
http_connection_manager:
  stat_prefix: edge
  generate_request_id: true
  request_timeout: 30s
  request_headers_timeout: 10s
  stream_idle_timeout: 60s
  max_request_headers_kb: 16
  common_http_protocol_options:
    idle_timeout: 60s
    max_headers_count: 100
    headers_with_underscores_action: REJECT_REQUEST
  http_protocol_options:
    accept_http_10: false
    allow_chunked_length: false
    enable_trailers: false
  http2_protocol_options:
    max_concurrent_streams: 100
    initial_stream_window_size: 65536
    initial_connection_window_size: 1048576
  use_remote_address: true
  xff_num_trusted_hops: 1
  normalize_path: true
  merge_slashes: true
  path_with_escaped_slashes_action: REJECT_REQUEST
  strip_matching_host_port: true
  server_header_transformation: PASS_THROUGH
  via: ""
  internal_address_config:
    unix_sockets: false
    cidr_ranges: []
```

Decisions and *why*:

- **`headers_with_underscores_action: REJECT_REQUEST`** — closes a
  well-known header-smuggling vector where `_` and `-` headers can
  shadow each other in upstream stacks.
- **`accept_http_10: false`, `allow_chunked_length: false`** —
  removes HTTP/1.0 and chunked+Content-Length combinations used in
  request-smuggling research.
- **`normalize_path` + `merge_slashes`** — prevents authz bypass by
  path-encoding tricks.
- **`path_with_escaped_slashes_action: REJECT_REQUEST`** — `%2F` in a
  path almost never matches a legitimate use; the safer default is
  reject.
- **`use_remote_address: true` and `xff_num_trusted_hops: 1`** — the
  client IP used by authz and logging comes from the L4 source unless
  exactly one trusted hop is in front (your cloud LB), preventing
  spoofed `X-Forwarded-For`.
- **`server_header_transformation: PASS_THROUGH`** plus removing
  `via` — reduces server fingerprinting. The gateway should not
  advertise version strings.

### 2.3 Request-size and body limits

```yaml
# Envoy buffer filter for body cap
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.buffer.v3.Buffer
  max_request_bytes: 1048576    # 1 MiB default for inference JSON
```

Per-route overrides allow larger bodies only on routes that genuinely
need them (model upload to the registry, batch-prediction endpoints).
A global 1 MiB default catches accidental "send the dataset to the
predict endpoint" mistakes and resists trivial body-flood DoS.

### 2.4 Authentication on the inference path

Two JWT providers are declared because the rules below reference two
distinct provider names (`platform-oidc` for inference, `platform-oidc-admin`
for `/admin`). Every name used in `rules[*].requires.provider_name`
**must** appear as a key under `providers:`; an unknown name causes
the listener configuration to be rejected at load.

```yaml
# Envoy JWT authentication
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
  providers:
    # Provider 1 of 2 — used by /v1/predict (inference path)
    platform-oidc:
      issuer: https://iam.example.com/
      audiences:
        - inference.ai-platform.example.com
      remote_jwks:
        http_uri:
          uri: https://iam.example.com/.well-known/jwks.json
          cluster: iam-jwks
          timeout: 5s
        cache_duration: 300s
      forward: false
      payload_in_metadata: jwt_payload
      from_headers:
        - name: Authorization
          value_prefix: "Bearer "
    # Provider 2 of 2 — used by /admin (administrative path);
    # required by the `/admin` rule below, distinct issuer + audience.
    platform-oidc-admin:
      issuer: https://iam-admin.example.com/
      audiences:
        - admin.ai-platform.example.com
      remote_jwks:
        http_uri:
          uri: https://iam-admin.example.com/.well-known/jwks.json
          cluster: iam-admin-jwks
          timeout: 5s
        cache_duration: 300s
      forward: false
      payload_in_metadata: jwt_payload
      from_headers:
        - name: Authorization
          value_prefix: "Bearer "
  rules:
    - match: { prefix: "/v1/predict" }
      requires:
        provider_name: platform-oidc          # declared above
    - match: { prefix: "/healthz" }
      requires: {}
    - match: { prefix: "/admin" }
      requires:
        provider_name: platform-oidc-admin    # declared above
```

Decisions and *why*:

- **`audiences` constrained per route.** A token minted for another
  service should not be accepted on the inference path. Missing
  `aud` checks are the most common gateway authn bug.
- **`forward: false`** — the gateway terminates the JWT; the upstream
  inference service trusts the gateway's identity assertion (passed
  via dynamic metadata or a signed header), so the raw token does not
  leak past the gateway.
- **JWKS cache 300 s** — bounded staleness on key rotation. Short
  enough to recover from a compromised key.
- **`/healthz` explicitly unauthenticated** — kube probes and LB
  health checks need to reach it; the route is identified explicitly
  rather than left to accidental defaults.
- **Separate `platform-oidc-admin` provider for `/admin`.** The admin
  surface uses a distinct issuer and audience so an inference token
  cannot reach administrative endpoints by accident or by token
  confusion. Each rule in `rules:` references a provider by name, so
  the admin provider must be declared alongside `platform-oidc`; the
  config otherwise fails to validate.

### 2.5 Authorization (deny by default)

```yaml
# Envoy RBAC filter — deny by default at the gateway
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC
  rules:
    action: ALLOW
    policies:
      "predict-callers":
        permissions:
          - url_path: { path: { prefix: "/v1/predict" } }
        principals:
          - metadata:
              filter: envoy.filters.http.jwt_authn
              path:
                - key: jwt_payload
                - key: scope
              value:
                string_match:
                  contains: "inference.predict"
      "admins":
        permissions:
          - url_path: { path: { prefix: "/admin" } }
        principals:
          - metadata:
              filter: envoy.filters.http.jwt_authn
              path:
                - key: jwt_payload
                - key: groups
              value:
                string_match:
                  exact: "platform-admin"
```

The default action with no matching policy is *deny*. Adding a
prefix to the gateway without adding a matching RBAC policy is how
endpoints leak.

### 2.6 Security response headers

```yaml
response_headers_to_add:
  - header:
      key: Strict-Transport-Security
      value: "max-age=63072000; includeSubDomains; preload"
    append_action: OVERWRITE_IF_EXISTS_OR_ADD
  - header:
      key: X-Content-Type-Options
      value: "nosniff"
    append_action: OVERWRITE_IF_EXISTS_OR_ADD
  - header:
      key: Content-Security-Policy
      value: "default-src 'none'"
    append_action: OVERWRITE_IF_EXISTS_OR_ADD
  - header:
      key: Referrer-Policy
      value: "no-referrer"
    append_action: OVERWRITE_IF_EXISTS_OR_ADD
response_headers_to_remove:
  - server
  - x-powered-by
```

The inference API is a JSON API, not a browser surface; a strict CSP
(`default-src 'none'`) shrinks the impact of any accidental HTML/JS
response.

### 2.7 Access logging

Access logs must record (at minimum): client IP, JWT subject and
audience, route, status, latency, request bytes, response bytes,
TLS protocol, TLS cipher, request ID, upstream identity. These
fields feed the detections in exercise 05 and the runbooks in the
project-5 SOC reference.

```yaml
access_log:
  - name: envoy.access_loggers.file
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
      path: /dev/stdout
      log_format:
        json_format:
          start_time: "%START_TIME%"
          method: "%REQ(:METHOD)%"
          path: "%REQ(:PATH)%"
          status: "%RESPONSE_CODE%"
          duration_ms: "%DURATION%"
          request_id: "%REQ(X-REQUEST-ID)%"
          client_ip: "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%"
          jwt_sub: "%DYNAMIC_METADATA(envoy.filters.http.jwt_authn:jwt_payload:sub)%"
          jwt_aud: "%DYNAMIC_METADATA(envoy.filters.http.jwt_authn:jwt_payload:aud)%"
          tls_protocol: "%DOWNSTREAM_TLS_VERSION%"
          tls_cipher: "%DOWNSTREAM_TLS_CIPHER%"
          upstream: "%UPSTREAM_HOST%"
```

### 2.8 What is deliberately not done here

- **Rate limiting and DDoS shaping** — exercise 04.
- **L7 flow telemetry / sampling for SIEM** — exercise 05.
- **Body-content inspection (WAF rules)** — out of scope; would
  belong to a downstream filter chain.

## 3. Validation steps

### 3.1 TLS posture

```bash
# Confirm TLS 1.3 only and the agreed cipher set
nmap --script ssl-enum-ciphers -p 443 edge.example.com

# Negative: TLS 1.2 must fail
openssl s_client -connect edge.example.com:443 -tls1_2 </dev/null \
  && echo FAIL || echo OK

# Confirm HSTS, no Server header
curl -sI https://edge.example.com/healthz | grep -Ei 'strict-transport-security|^server:|x-powered-by'
```

### 3.2 HTTP smuggling and abuse

```bash
# Underscore-vs-dash header smuggling — must be rejected
curl -sv https://edge.example.com/healthz -H 'X_Forwarded_For: 1.2.3.4'

# Duplicate Content-Length — must be rejected
printf 'POST /v1/predict HTTP/1.1\r\nHost: edge.example.com\r\nContent-Length: 0\r\nContent-Length: 10\r\n\r\n' \
  | openssl s_client -connect edge.example.com:443 -quiet

# %2F in path — must be rejected
curl -sI 'https://edge.example.com/v1%2Fpredict'

# Oversize headers — must be rejected with 431
curl -sI -H "X-Garbage: $(printf 'A%.0s' {1..20000})" https://edge.example.com/healthz
```

### 3.3 Authn / authz

```bash
# No token — must be 401 on /v1/predict
curl -s -o /dev/null -w '%{http_code}\n' https://edge.example.com/v1/predict

# Wrong audience — must be 401
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer ${TOKEN_WRONG_AUD}" \
  https://edge.example.com/v1/predict

# Right audience, wrong scope — must be 403
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer ${TOKEN_NO_SCOPE}" \
  https://edge.example.com/v1/predict

# Correct token — must be 200
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer ${TOKEN_OK}" \
  https://edge.example.com/v1/predict
```

### 3.4 Logging

For each successful and failed request above, confirm an access-log
line containing `request_id`, `jwt_sub`, `jwt_aud`, `tls_protocol`,
and `status`. A request that produces no log line is the most
dangerous outcome — the detection pipeline goes blind.

## 4. Rubric / review checklist

| # | Criterion | 0 | 1 | 2 |
|---|---|---|---|---|
| 1 | TLS 1.3 only on user-facing endpoints, explicit cipher list | TLS 1.0/1.1 allowed | TLS 1.2 + 1.3 | TLS 1.3 only |
| 2 | ALPN constrained; HTTP/1.0 disabled | Default | ALPN listed | ALPN + HTTP/1.0 off + chunked-length off |
| 3 | Path normalisation + reject escaped slashes | Off | Normalised only | Normalised + reject `%2F` |
| 4 | XFF trust configured with explicit hops | Default trust | Hops set, not justified | Hops set and documented |
| 5 | Body and header size caps with per-route overrides | None | Global only | Global + per-route |
| 6 | JWT validated with `aud` per route | No JWT | JWT no `aud` | JWT with `aud` + scope authz |
| 7 | Default-deny authz at gateway | Allow-all | Mixed | Default-deny + explicit allows |
| 8 | Access logs include identity + TLS + request-id fields | Default logs | JSON without identity | All required fields |
| 9 | Security headers + `Server`/`X-Powered-By` removed | None | Some | All listed |
| 10 | Negative tests in §3 all pass | None | Some | All |

Pass = ≥16 / 20 with no zero scores.

### Control mapping (NGINX equivalents)

| Envoy control | NGINX equivalent |
|---|---|
| `tls_minimum_protocol_version: TLSv1_3` | `ssl_protocols TLSv1.3;` |
| `accept_http_10: false` | `if ($server_protocol = HTTP/1.0) { return 400; }` |
| `merge_slashes` | `merge_slashes on;` |
| `path_with_escaped_slashes_action: REJECT_REQUEST` | Custom `if ($request_uri ~* "%2[fF]") { return 400; }` (prefer an NJS or `auth_request` module-level reject when available). |
| `max_request_headers_kb` | `large_client_header_buffers` + `client_header_buffer_size` |
| Buffer filter `max_request_bytes` | `client_max_body_size` (per-route via `location`) |
| Envoy RBAC | `auth_request` + upstream policy decision point |
| JWT filter | `auth_jwt` (NGINX Plus) or `lua-resty-jwt` (OpenResty) |
| Envoy access log JSON format | `log_format ... escape=json;` |

## 5. Common mistakes

- **Leaving TLS 1.2 on for "compatibility" with unspecified clients.**
  The compatibility surface should be a documented list, not "maybe
  someone".
- **Trusting `X-Forwarded-For` without `xff_num_trusted_hops`.** Authz
  decisions then rest on a header any client can send.
- **JWT validation without `aud` enforcement.** A token issued for
  another service becomes a master key for the inference path.
- **Allowing `%2F` in paths.** Authz often runs on the
  pre-normalisation path; the upstream sees the normalised form. This
  is the textbook gateway-authz-bypass primitive.
- **Per-route body caps missing.** Either the global cap is too small
  for legitimate uploads (and engineers raise it globally — the wrong
  fix) or too large (and the predict endpoint accepts megabytes of
  input).
- **Logging without identity.** The access log records *that*
  something happened, not *who* did it. Subject and audience are
  required for any meaningful detection.
- **Exposing `Server: envoy/x.y.z`.** Version disclosure shortens an
  attacker's recon step. Strip it.
- **Default-allow RBAC at the gateway.** Adding a route silently
  exposes it; this is how internal admin paths leak.

## 6. References

- Envoy — HTTP Connection Manager:
  https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/http_conn_man
- Envoy — JWT Authn filter:
  https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/jwt_authn_filter
- Envoy — RBAC filter:
  https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/rbac_filter
- Envoy — TLS:
  https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ssl
- IETF RFC 8446 — TLS 1.3:
  http://web.archive.org/web/20260515074752/https://www.rfc-editor.org/rfc/rfc8446
- IETF RFC 9110 — HTTP semantics (host, framing):
  http://web.archive.org/web/20260520194653/https://www.rfc-editor.org/rfc/rfc9110
- OWASP API Security Top 10 (referenced for API-gateway controls
  pattern):
  https://owasp.org/API-Security/
- OWASP Machine Learning Security Top 10:
  https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS (initial access via exposed inference endpoints):
  https://atlas.mitre.org/
- NIST AI Risk Management Framework:
  https://www.nist.gov/itl/ai-risk-management-framework
