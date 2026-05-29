# SOLUTION — Exercise 02: Rego Policy Library

> Read this *after* attempting the learning-side exercise. This file
> ships five complete Rego policies with tests, and explains the
> idioms (admission-review input shape, namespace filtering, the
> `count(deny) == 0` test pattern) that learners most often get wrong
> on the first attempt.

## 1. Solution overview

The exercise asks for at least five Rego policies, each in its own
file with a clear `package`, ≥ 3 `test_*` rules, and a short
documentation block. The policies enforce admission-time security
constraints for SmartRecs: image signing, no-`:latest` tags, required
labels, non-root containers, and metadata-endpoint egress blocking.

The reference library below uses **Rego v1 (`opa` 0.60+) idioms**:
`import rego.v1`, `if`-blocks for rules, `every` for quantification.
This matches the current OPA documentation and avoids the `import
future.keywords` polyfills shown in the exercise scaffold.

The grader is checking that:

- Policies parse under `opa test policies/`.
- Each policy has ≥ 3 tests covering happy path + ≥ 2 failure modes.
- Tests use `with input as ...` overrides, not stubbed mocks.
- Documentation explains *what* and *why*, tied to a SmartRecs threat.

## 2. Worked implementation

### 2.1 Repository layout

```
policies/
├── README.md
├── security/
│   ├── images/
│   │   ├── signed.rego
│   │   └── no_latest.rego
│   ├── pods/
│   │   ├── required_labels.rego
│   │   └── no_root.rego
│   └── network/
│       └── no_metadata_egress.rego
└── data/
    └── allowed_signers.json
```

### 2.2 Policy 1 — `security.images.signed`

```rego
# policies/security/images/signed.rego
package security.images.signed

# Documentation:
# Threat: an attacker (or a compromised CI runner) pushes an
#         unsigned container image to a registry SmartRecs trusts,
#         then deploys it.
# Control: every Pod container's image must be present in the set
#          of images signed by an approved SmartRecs CI identity
#          (Cosign keyless / OIDC).
# Failure mode (admission): closed (deny). An unsigned image must
#                           not run, even if the signature service
#                           is briefly stale. See Exercise 05 for
#                           the engine-down fallback.

import rego.v1

# The set of approved CI signing identities. In production this is
# loaded from the policy bundle's data/ tree (see Exercise 05).
allowed_signers := {
    "https://github.com/smartrecs-org/recs/.github/workflows/build.yml@refs/heads/main",
    "https://github.com/smartrecs-org/fraud/.github/workflows/build.yml@refs/heads/main",
}

deny contains msg if {
    input.review.object.kind == "Pod"
    some container in input.review.object.spec.containers
    not is_signed(container.image)
    msg := sprintf("container image %q is not signed by an approved SmartRecs signer", [container.image])
}

is_signed(image) if {
    image in input.data.signed_images
}

# Tests
test_deny_unsigned if {
    result := deny with input as {
        "review": {"object": {
            "kind": "Pod",
            "spec": {"containers": [{"image": "ghcr.io/random/untrusted:v1"}]},
        }},
        "data": {"signed_images": ["ghcr.io/smartrecs/recs:v1"]},
    }
    count(result) == 1
}

test_allow_signed if {
    result := deny with input as {
        "review": {"object": {
            "kind": "Pod",
            "spec": {"containers": [{"image": "ghcr.io/smartrecs/recs:v1"}]},
        }},
        "data": {"signed_images": ["ghcr.io/smartrecs/recs:v1"]},
    }
    count(result) == 0
}

test_deny_mixed_pod if {
    result := deny with input as {
        "review": {"object": {
            "kind": "Pod",
            "spec": {"containers": [
                {"image": "ghcr.io/smartrecs/recs:v1"},
                {"image": "ghcr.io/random/untrusted:v1"},
            ]},
        }},
        "data": {"signed_images": ["ghcr.io/smartrecs/recs:v1"]},
    }
    count(result) == 1
}

test_skip_non_pod if {
    result := deny with input as {
        "review": {"object": {
            "kind": "Service",
            "spec": {},
        }},
        "data": {"signed_images": []},
    }
    count(result) == 0
}
```

### 2.3 Policy 2 — `security.images.no_latest`

```rego
# policies/security/images/no_latest.rego
package security.images.no_latest

# Documentation:
# Threat: an image tagged :latest (or with no tag, which Docker
#         resolves to :latest) silently changes content over time;
#         a Pod that worked at deploy could be running attacker
#         content tomorrow.
# Control: in any namespace matching prod-*, image references must
#          use a digest (sha256:...) reference. In non-prod, :latest
#          is denied but other tags are allowed.

import rego.v1

deny contains msg if {
    input.review.object.kind == "Pod"
    some container in input.review.object.spec.containers
    is_latest(container.image)
    msg := sprintf("container image %q uses :latest or is tag-less", [container.image])
}

deny contains msg if {
    input.review.object.kind == "Pod"
    is_prod_namespace(input.review.object.metadata.namespace)
    some container in input.review.object.spec.containers
    not has_digest(container.image)
    msg := sprintf("prod namespace requires digest reference; image %q has none", [container.image])
}

is_latest(image) if endswith(image, ":latest")
is_latest(image) if not contains(image, ":")

has_digest(image) if contains(image, "@sha256:")

is_prod_namespace(ns) if startswith(ns, "prod-")

# Tests
test_deny_latest_tag if {
    result := deny with input as {
        "review": {"object": {
            "kind": "Pod",
            "metadata": {"namespace": "dev-a"},
            "spec": {"containers": [{"image": "recs:latest"}]},
        }},
    }
    count(result) == 1
}

test_deny_tagless if {
    result := deny with input as {
        "review": {"object": {
            "kind": "Pod",
            "metadata": {"namespace": "dev-a"},
            "spec": {"containers": [{"image": "recs"}]},
        }},
    }
    count(result) == 1
}

test_allow_pinned_tag_in_dev if {
    result := deny with input as {
        "review": {"object": {
            "kind": "Pod",
            "metadata": {"namespace": "dev-a"},
            "spec": {"containers": [{"image": "recs:v1.2.3"}]},
        }},
    }
    count(result) == 0
}

test_deny_pinned_tag_in_prod if {
    result := deny with input as {
        "review": {"object": {
            "kind": "Pod",
            "metadata": {"namespace": "prod-east"},
            "spec": {"containers": [{"image": "recs:v1.2.3"}]},
        }},
    }
    count(result) == 1
}

test_allow_digest_in_prod if {
    result := deny with input as {
        "review": {"object": {
            "kind": "Pod",
            "metadata": {"namespace": "prod-east"},
            "spec": {"containers": [{"image": "recs@sha256:deadbeef"}]},
        }},
    }
    count(result) == 0
}
```

### 2.4 Policy 3 — `security.pods.required_labels`

```rego
# policies/security/pods/required_labels.rego
package security.pods.required_labels

# Documentation:
# Threat: an unowned Pod survives an incident with no obvious owner;
#         cost reports cannot attribute spend; alerts route nowhere.
# Control: every Pod must carry team, owner, cost-center labels and
#          the values must be on the allowed list (from
#          input.data.allowed.{teams,owners,cost_centers}).

import rego.v1

required := {"team", "owner", "cost-center"}

deny contains msg if {
    input.review.object.kind == "Pod"
    some key in required
    not input.review.object.metadata.labels[key]
    msg := sprintf("pod is missing required label %q", [key])
}

deny contains msg if {
    input.review.object.kind == "Pod"
    value := input.review.object.metadata.labels.team
    not value in input.data.allowed.teams
    msg := sprintf("team label %q is not on the allowed list", [value])
}

deny contains msg if {
    input.review.object.kind == "Pod"
    value := input.review.object.metadata.labels["cost-center"]
    not value in input.data.allowed.cost_centers
    msg := sprintf("cost-center label %q is not on the allowed list", [value])
}

# Tests
allowed_data := {
    "allowed": {
        "teams": {"recs", "fraud"},
        "owners": {"alice", "bob"},
        "cost_centers": {"cc-100", "cc-200"},
    },
}

test_deny_missing_team if {
    result := deny with input as {
        "review": {"object": {
            "kind": "Pod",
            "metadata": {"labels": {"owner": "alice", "cost-center": "cc-100"}},
        }},
        "data": allowed_data,
    }
    count(result) == 1
}

test_deny_unknown_team if {
    result := deny with input as {
        "review": {"object": {
            "kind": "Pod",
            "metadata": {"labels": {"team": "ghost", "owner": "alice", "cost-center": "cc-100"}},
        }},
        "data": allowed_data,
    }
    count(result) == 1
}

test_deny_unknown_cost_center if {
    result := deny with input as {
        "review": {"object": {
            "kind": "Pod",
            "metadata": {"labels": {"team": "recs", "owner": "alice", "cost-center": "cc-999"}},
        }},
        "data": allowed_data,
    }
    count(result) == 1
}

test_allow_full_labels if {
    result := deny with input as {
        "review": {"object": {
            "kind": "Pod",
            "metadata": {"labels": {"team": "recs", "owner": "alice", "cost-center": "cc-100"}},
        }},
        "data": allowed_data,
    }
    count(result) == 0
}
```

### 2.5 Policy 4 — `security.pods.no_root`

```rego
# policies/security/pods/no_root.rego
package security.pods.no_root

# Documentation:
# Threat: a container running as UID 0 has too much authority
#         inside the pod and is the starting point for most
#         container-breakout chains.
# Control: in prod-* namespaces, Pods must set
#          securityContext.runAsNonRoot: true OR have runAsUser != 0
#          at pod OR container level. Containers must not override
#          this with runAsUser: 0.

import rego.v1

deny contains msg if {
    input.review.object.kind == "Pod"
    is_prod_namespace(input.review.object.metadata.namespace)
    not pod_enforces_non_root(input.review.object.spec)
    msg := "prod pod must set securityContext.runAsNonRoot=true or runAsUser>0 at pod level"
}

deny contains msg if {
    input.review.object.kind == "Pod"
    is_prod_namespace(input.review.object.metadata.namespace)
    some container in input.review.object.spec.containers
    container.securityContext.runAsUser == 0
    msg := sprintf("container %q overrides runAsUser=0 in prod namespace", [container.name])
}

pod_enforces_non_root(spec) if spec.securityContext.runAsNonRoot == true
pod_enforces_non_root(spec) if spec.securityContext.runAsUser > 0

is_prod_namespace(ns) if startswith(ns, "prod-")

# Tests
test_deny_prod_unset if {
    result := deny with input as {
        "review": {"object": {
            "kind": "Pod",
            "metadata": {"namespace": "prod-east"},
            "spec": {"containers": [{"name": "app"}]},
        }},
    }
    count(result) > 0
}

test_deny_prod_runAsUser_zero if {
    result := deny with input as {
        "review": {"object": {
            "kind": "Pod",
            "metadata": {"namespace": "prod-east"},
            "spec": {
                "securityContext": {"runAsNonRoot": true},
                "containers": [{"name": "app", "securityContext": {"runAsUser": 0}}],
            },
        }},
    }
    count(result) == 1
}

test_allow_prod_non_root if {
    result := deny with input as {
        "review": {"object": {
            "kind": "Pod",
            "metadata": {"namespace": "prod-east"},
            "spec": {
                "securityContext": {"runAsNonRoot": true},
                "containers": [{"name": "app"}],
            },
        }},
    }
    count(result) == 0
}

test_allow_dev_without_setting if {
    result := deny with input as {
        "review": {"object": {
            "kind": "Pod",
            "metadata": {"namespace": "dev-a"},
            "spec": {"containers": [{"name": "app"}]},
        }},
    }
    count(result) == 0
}
```

### 2.6 Policy 5 — `security.network.no_metadata_egress`

```rego
# policies/security/network/no_metadata_egress.rego
package security.network.no_metadata_egress

# Documentation:
# Threat: a container that can reach the cloud metadata endpoint
#         (e.g., 169.254.169.254) can obtain the node IAM
#         credentials and escalate to whatever permissions the node
#         role holds. See OWASP ML06:2023 (AI Supply Chain
#         Attacks) for the modeled chain; cloud provider docs cover
#         the underlying IMDS surface.
# Control: a NetworkPolicy attached to ML workloads must not list
#          169.254.169.254/32 (IMDSv1/IMDSv2) or fd00:ec2::254
#          (IPv6 link-local) in egress.to.ipBlock allow lists.

import rego.v1

metadata_cidrs := {
    "169.254.169.254/32",
    "169.254.170.2/32",   # ECS task metadata
    "fd00:ec2::254/128",
}

deny contains msg if {
    input.review.object.kind == "NetworkPolicy"
    some egress in input.review.object.spec.egress
    some peer in egress.to
    peer.ipBlock.cidr in metadata_cidrs
    msg := sprintf("NetworkPolicy egress allows cloud metadata CIDR %q", [peer.ipBlock.cidr])
}

deny contains msg if {
    input.review.object.kind == "NetworkPolicy"
    some egress in input.review.object.spec.egress
    some peer in egress.to
    overlaps_metadata(peer.ipBlock.cidr)
    msg := sprintf("NetworkPolicy egress CIDR %q overlaps a metadata CIDR (too broad)", [peer.ipBlock.cidr])
}

overlaps_metadata(cidr) if cidr == "0.0.0.0/0"
overlaps_metadata(cidr) if cidr == "169.254.0.0/16"

# Tests
test_deny_explicit_imds if {
    result := deny with input as {
        "review": {"object": {
            "kind": "NetworkPolicy",
            "spec": {"egress": [{"to": [{"ipBlock": {"cidr": "169.254.169.254/32"}}]}]},
        }},
    }
    count(result) == 1
}

test_deny_link_local_block if {
    result := deny with input as {
        "review": {"object": {
            "kind": "NetworkPolicy",
            "spec": {"egress": [{"to": [{"ipBlock": {"cidr": "169.254.0.0/16"}}]}]},
        }},
    }
    count(result) == 1
}

test_deny_open_egress if {
    result := deny with input as {
        "review": {"object": {
            "kind": "NetworkPolicy",
            "spec": {"egress": [{"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}]},
        }},
    }
    count(result) == 1
}

test_allow_internal_cidr if {
    result := deny with input as {
        "review": {"object": {
            "kind": "NetworkPolicy",
            "spec": {"egress": [{"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}]},
        }},
    }
    count(result) == 0
}
```

### 2.7 Top-level README

```markdown
# SmartRecs Policy Library

## Policies

| Package | Purpose | Enforcement surface |
|---|---|---|
| security.images.signed | Cosign signature required | Gatekeeper admission + Conftest CI |
| security.images.no_latest | No :latest; digest required in prod-* | Gatekeeper admission + Conftest CI |
| security.pods.required_labels | team/owner/cost-center from allow-list | Gatekeeper admission |
| security.pods.no_root | Non-root in prod-* | Gatekeeper admission |
| security.network.no_metadata_egress | Block IMDS CIDRs in NetworkPolicy egress | Gatekeeper admission + Conftest CI |

## How to test

    opa test policies/

## How to deploy

See Exercise 05 — Policy Testing + Distribution Plan.
```

## 3. Validation steps

```bash
# 1) Tests pass locally (Rego v1).
opa test policies/ -v

# Expected:
# PASS: 22/22 tests (or whatever count after additions)

# 2) Lint and format.
opa fmt --list --diff policies/    # should report no changes
opa check policies/                # syntactic sanity

# 3) Spot-check one policy against a real AdmissionReview payload.
opa eval -d policies/security/images/no_latest.rego \
  -i tests/fixtures/admission-pod-latest-tag.json \
  "data.security.images.no_latest.deny"
# Expected: a non-empty array of violation messages.

# 4) Confirm tests use both happy-path and failure-mode shapes.
grep -E "test_(allow|deny)" policies/ -R | wc -l
# Expected: at least 3 * 5 = 15 tests (matches exercise minimum).
```

## 4. Rubric / review checklist

| Area | Weight | What "pass" looks like |
|------|--------|-----------------------|
| Real, parsable Rego | 25 | `opa test` runs; no `opa check` errors |
| ≥ 5 policies | 10 | Five packages cover the five required topics |
| Tests per policy | 20 | ≥ 3 tests each; ≥ 1 happy path, ≥ 2 failure modes |
| Documentation per policy | 15 | What/why block above each policy ties to a SmartRecs threat |
| Namespace scoping | 10 | Prod-only policies cleanly restrict to prod-* |
| Data dependency externalized | 10 | Allow-lists / signers live in `data/`, not inlined into rule heads |
| Test isolation | 10 | Tests use `with input as ...`; no cross-test bleed |

Pass threshold: **75 / 100**. A 90+ library is one that already
matches the file structure used in Exercise 05's bundle layout, so the
distribution exercise is a near drop-in.

Auto-fail conditions:

- Pseudo-Rego (won't parse).
- Tests only cover happy path.
- No `package` declaration or duplicate packages across files.
- Rules use `input.review.object` without checking `kind`, producing
  false positives on unrelated resources.

## 5. Common mistakes

1. **Rego v0 vs. v1.** Mixing `import future.keywords.in` with
   `import rego.v1`, or forgetting `if` on rule heads in v1. Pick one
   and be consistent. This library uses v1.
2. **Asserting on exact error strings in tests.** `deny["specific
   message"]` couples the test to the message. Prefer
   `count(deny) == N` plus a shape check.
3. **No kind filter.** Without `input.review.object.kind == "Pod"`,
   the policy will fire on Services, ConfigMaps, etc. that lack
   `spec.containers`, producing confusing evaluations.
4. **Inlining allow-lists in the rule head.** Hard-coded signer URLs
   in `allowed_signers` make the policy un-testable across
   environments; lift to `input.data` so the bundle's `data/` tree
   governs.
5. **Confusing `runAsNonRoot: true` with `runAsUser != 0`.** They are
   *both* sufficient; the policy should accept either. The
   `pod_enforces_non_root` helper above shows the OR pattern.
6. **Forgetting digest references in prod.** A `:v1.2.3` tag in prod
   still drifts if someone re-pushes; the digest rule is what
   provides immutability.
7. **Treating the metadata endpoint as a single CIDR.** AWS adds
   ECS task metadata (169.254.170.2) and an IPv6 link-local address;
   policies that only block `169.254.169.254/32` miss those.
8. **Mocking the Cosign client.** The reference policy uses
   `input.data.signed_images` so the test bench can pre-populate the
   set; the real engine receives the same shape from an external-data
   provider. Don't inject HTTP clients into Rego.

## 6. References

Official sources:

- Open Policy Agent — Policy Language reference: <https://www.openpolicyagent.org/docs/policy-language>
- OPA — Policy Testing: <https://www.openpolicyagent.org/docs/policy-testing>
- OPA — Rego v1 migration guide: <https://www.openpolicyagent.org/docs/v0-upgrade>
- OWASP ML Security Top 10 (2023): <https://owasp.org/www-project-machine-learning-security-top-10/>
- MITRE ATLAS — Adversarial Threat Landscape for AI Systems:
  <https://atlas.mitre.org/>
- NIST AI Risk Management Framework (AI RMF 1.0):
  <https://www.nist.gov/itl/ai-risk-management-framework>
- Sigstore / Cosign documentation:
  <https://docs.sigstore.dev/cosign/overview/>

Cross-references:

- Exercise 03 reuses policies 1, 2, 3, and 4 as Conftest gates on
  Kubernetes manifests in CI.
- Exercise 04 builds three ML-specific policies (model promotion,
  training-data governance, tenant isolation) using the same
  idioms.
- Exercise 05 packages this library into a signed bundle.
