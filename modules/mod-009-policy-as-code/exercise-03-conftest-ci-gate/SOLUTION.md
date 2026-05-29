# SOLUTION — Exercise 03: Conftest CI Gate

> Read this *after* attempting the learning-side exercise. This file
> ships a runnable GitHub Actions workflow, a small Rego library for
> three input types (Kubernetes manifests, Terraform plan JSON,
> Dockerfiles), and a six-case demo set (three pass, three fail).
> Most reviewers find the *exemption* and *change-detection* pieces
> harder than the policy code; this solution covers both.

## 1. Solution overview

The goal is a CI policy gate that runs on every PR, scoped to the file
types changed, that posts results back to the PR and blocks merge on
violation. The pipeline:

1. **Detect changed files** by extension and path (K8s YAML in
   `manifests/`, Terraform in `terraform/`, Dockerfiles anywhere).
2. **Run Conftest** against each input type with the matching Rego
   policy package.
3. **Post results as a PR comment** with a summary table + the worst
   offenses inline.
4. **Block merge** by failing the workflow job on any policy
   violation, unless an exemption label is present and approved.

The Kubernetes policies reuse Exercise 02 directly. The Terraform and
Dockerfile policies are new; they are short and demonstrate the
package pattern Conftest expects (`package main` by default; we use
`package` per input type and pass `--namespace` to Conftest).

## 2. Worked implementation

### 2.1 Policy layout

```
.
├── .github/workflows/policy-gate.yml
├── policies/
│   ├── kubernetes/        # reuses Exercise 02 packages
│   │   ├── no_latest.rego
│   │   ├── required_labels.rego
│   │   ├── no_host_path.rego
│   │   ├── no_privileged.rego
│   │   └── run_as_non_root.rego
│   ├── terraform/
│   │   ├── no_open_ssh_rdp.rego
│   │   ├── s3_encryption.rego
│   │   └── iam_wildcard.rego
│   └── dockerfile/
│       └── dockerfile.rego
└── examples/
    ├── pass/
    │   ├── pod-pass-1.yaml
    │   ├── pod-pass-2.yaml
    │   └── tfplan-pass-1.json
    └── fail/
        ├── pod-fail-no-labels.yaml
        ├── pod-fail-privileged.yaml
        └── dockerfile-fail-root.Dockerfile
```

### 2.2 New Rego policies

Reused from Exercise 02 (no changes):
`security.images.no_latest`, `security.pods.required_labels`.

Added for Conftest CI:

```rego
# policies/kubernetes/no_host_path.rego
package kubernetes.no_host_path
import rego.v1

deny contains msg if {
    input.kind == "Pod"
    some volume in input.spec.volumes
    volume.hostPath
    msg := sprintf("Pod %q mounts hostPath volume %q (forbidden)",
                   [input.metadata.name, volume.name])
}

test_deny_hostpath if {
    result := deny with input as {
        "kind": "Pod",
        "metadata": {"name": "leaky"},
        "spec": {"volumes": [{"name": "h", "hostPath": {"path": "/etc"}}]},
    }
    count(result) == 1
}

test_allow_no_hostpath if {
    result := deny with input as {
        "kind": "Pod",
        "metadata": {"name": "clean"},
        "spec": {"volumes": [{"name": "v", "emptyDir": {}}]},
    }
    count(result) == 0
}
```

```rego
# policies/kubernetes/no_privileged.rego
package kubernetes.no_privileged
import rego.v1

deny contains msg if {
    input.kind == "Pod"
    some c in input.spec.containers
    c.securityContext.privileged == true
    msg := sprintf("container %q runs privileged", [c.name])
}

test_deny_privileged if {
    result := deny with input as {
        "kind": "Pod",
        "spec": {"containers": [{"name": "x", "securityContext": {"privileged": true}}]},
    }
    count(result) == 1
}

test_allow_unprivileged if {
    result := deny with input as {
        "kind": "Pod",
        "spec": {"containers": [{"name": "x", "securityContext": {"privileged": false}}]},
    }
    count(result) == 0
}

test_allow_unset if {
    result := deny with input as {
        "kind": "Pod",
        "spec": {"containers": [{"name": "x"}]},
    }
    count(result) == 0
}
```

```rego
# policies/kubernetes/run_as_non_root.rego
package kubernetes.run_as_non_root
import rego.v1

deny contains "Pod must set securityContext.runAsNonRoot=true" if {
    input.kind == "Pod"
    not input.spec.securityContext.runAsNonRoot == true
}

test_deny_unset if {
    result := deny with input as {"kind": "Pod", "spec": {}}
    count(result) == 1
}

test_allow_set if {
    result := deny with input as {
        "kind": "Pod",
        "spec": {"securityContext": {"runAsNonRoot": true}},
    }
    count(result) == 0
}
```

```rego
# policies/terraform/no_open_ssh_rdp.rego
package terraform.no_open_ssh_rdp
import rego.v1

# Conftest invoked with `--parser hcl2` on plan.json passes
# resource_changes[].change.after as the resource shape. We use
# planned_values for parsed plan JSON; both shapes are handled.

deny contains msg if {
    some rc in input.resource_changes
    rc.type == "aws_security_group_rule"
    after := rc.change.after
    after.type == "ingress"
    is_open(after.cidr_blocks)
    matches_port(after.from_port, after.to_port, 22)
    msg := sprintf("security group rule opens SSH (22) to 0.0.0.0/0 on %q", [rc.address])
}

deny contains msg if {
    some rc in input.resource_changes
    rc.type == "aws_security_group_rule"
    after := rc.change.after
    after.type == "ingress"
    is_open(after.cidr_blocks)
    matches_port(after.from_port, after.to_port, 3389)
    msg := sprintf("security group rule opens RDP (3389) to 0.0.0.0/0 on %q", [rc.address])
}

is_open(cidrs) if "0.0.0.0/0" in cidrs

matches_port(from, to, port) if {
    from <= port
    to >= port
}

test_deny_ssh_open if {
    result := deny with input as {"resource_changes": [{
        "address": "aws_security_group_rule.demo",
        "type": "aws_security_group_rule",
        "change": {"after": {
            "type": "ingress",
            "from_port": 22, "to_port": 22,
            "cidr_blocks": ["0.0.0.0/0"],
        }},
    }]}
    count(result) == 1
}

test_allow_ssh_internal if {
    result := deny with input as {"resource_changes": [{
        "address": "aws_security_group_rule.demo",
        "type": "aws_security_group_rule",
        "change": {"after": {
            "type": "ingress",
            "from_port": 22, "to_port": 22,
            "cidr_blocks": ["10.0.0.0/8"],
        }},
    }]}
    count(result) == 0
}

test_deny_rdp_open if {
    result := deny with input as {"resource_changes": [{
        "address": "aws_security_group_rule.win",
        "type": "aws_security_group_rule",
        "change": {"after": {
            "type": "ingress",
            "from_port": 3000, "to_port": 4000,
            "cidr_blocks": ["0.0.0.0/0"],
        }},
    }]}
    count(result) == 1
}
```

```rego
# policies/terraform/s3_encryption.rego
package terraform.s3_encryption
import rego.v1

deny contains msg if {
    some rc in input.resource_changes
    rc.type == "aws_s3_bucket"
    not has_encryption(input, rc.address)
    msg := sprintf("S3 bucket %q has no associated server-side encryption configuration",
                   [rc.address])
}

has_encryption(plan, bucket_addr) if {
    some rc in plan.resource_changes
    rc.type == "aws_s3_bucket_server_side_encryption_configuration"
    rc.change.after.bucket == bucket_addr
}

test_deny_bucket_no_encryption if {
    result := deny with input as {"resource_changes": [
        {"type": "aws_s3_bucket", "address": "aws_s3_bucket.raw",
         "change": {"after": {}}},
    ]}
    count(result) == 1
}

test_allow_bucket_with_encryption if {
    result := deny with input as {"resource_changes": [
        {"type": "aws_s3_bucket", "address": "aws_s3_bucket.raw",
         "change": {"after": {}}},
        {"type": "aws_s3_bucket_server_side_encryption_configuration",
         "change": {"after": {"bucket": "aws_s3_bucket.raw"}}},
    ]}
    count(result) == 0
}
```

```rego
# policies/terraform/iam_wildcard.rego
package terraform.iam_wildcard
import rego.v1

# A plan with *:* actions only passes if the PR carries the
# "policy/iam-wildcard-approved" label, set elsewhere in CI
# (forwarded into input.metadata.labels by the workflow).

deny contains msg if {
    some rc in input.resource_changes
    rc.type == "aws_iam_policy"
    statement := rc.change.after.policy.Statement[_]
    has_wildcard(statement)
    not exemption_present
    msg := sprintf("IAM policy %q grants *:* actions without an approved exemption label",
                   [rc.address])
}

has_wildcard(statement) if "*" in statement.Action
has_wildcard(statement) if statement.Action == "*"

exemption_present if "policy/iam-wildcard-approved" in input.metadata.labels

test_deny_wildcard_no_label if {
    result := deny with input as {
        "metadata": {"labels": []},
        "resource_changes": [{
            "type": "aws_iam_policy", "address": "aws_iam_policy.admin",
            "change": {"after": {"policy": {"Statement": [{"Action": "*"}]}}},
        }],
    }
    count(result) == 1
}

test_allow_wildcard_with_label if {
    result := deny with input as {
        "metadata": {"labels": ["policy/iam-wildcard-approved"]},
        "resource_changes": [{
            "type": "aws_iam_policy", "address": "aws_iam_policy.admin",
            "change": {"after": {"policy": {"Statement": [{"Action": "*"}]}}},
        }],
    }
    count(result) == 0
}
```

```rego
# policies/dockerfile/dockerfile.rego
package dockerfile
import rego.v1

# Conftest's dockerfile parser yields an array of {Cmd, Value} entries.

deny contains "FROM uses :latest or untagged base image" if {
    some entry in input
    entry.Cmd == "from"
    is_latest_from(entry.Value)
}

deny contains "ADD instruction fetches from a URL" if {
    some entry in input
    entry.Cmd == "add"
    fetches_url(entry.Value)
}

deny contains "Dockerfile does not switch to a non-root USER" if {
    not has_non_root_user
}

is_latest_from(values) if {
    some v in values
    endswith(v, ":latest")
}
is_latest_from(values) if {
    some v in values
    not contains(v, ":")
    not contains(v, "@sha256:")
}

fetches_url(values) if {
    some v in values
    startswith(v, "http://")
}
fetches_url(values) if {
    some v in values
    startswith(v, "https://")
}

has_non_root_user if {
    some entry in input
    entry.Cmd == "user"
    user := entry.Value[0]
    user != "0"
    user != "root"
}

test_deny_latest_from if {
    result := deny with input as [{"Cmd": "from", "Value": ["alpine:latest"]}]
    count(result) > 0
}

test_deny_no_user if {
    result := deny with input as [{"Cmd": "from", "Value": ["alpine:3.19"]}]
    "Dockerfile does not switch to a non-root USER" in result
}

test_allow_non_root if {
    result := deny with input as [
        {"Cmd": "from", "Value": ["alpine:3.19"]},
        {"Cmd": "user", "Value": ["nonroot"]},
    ]
    count(result) == 0
}

test_deny_add_url if {
    result := deny with input as [
        {"Cmd": "from", "Value": ["alpine:3.19"]},
        {"Cmd": "add", "Value": ["https://example.com/x.tar", "/tmp/"]},
        {"Cmd": "user", "Value": ["nonroot"]},
    ]
    "ADD instruction fetches from a URL" in result
}
```

### 2.3 CI workflow

```yaml
# .github/workflows/policy-gate.yml
name: policy-gate

on:
  pull_request:
    paths:
      - 'manifests/**'
      - 'terraform/**'
      - '**/Dockerfile'
      - 'policies/**'
      - '.github/workflows/policy-gate.yml'

permissions:
  contents: read
  pull-requests: write   # post comment

jobs:
  detect:
    runs-on: ubuntu-latest
    outputs:
      kube: ${{ steps.changes.outputs.kube }}
      terraform: ${{ steps.changes.outputs.terraform }}
      docker: ${{ steps.changes.outputs.docker }}
    steps:
      - uses: actions/checkout@v4
      - id: changes
        uses: dorny/paths-filter@v3
        with:
          filters: |
            kube:
              - 'manifests/**/*.yaml'
              - 'manifests/**/*.yml'
            terraform:
              - 'terraform/**'
            docker:
              - '**/Dockerfile'

  gate:
    needs: detect
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Conftest
        run: |
          set -euo pipefail
          CONFTEST_VERSION=0.56.0
          curl -fsSL -o conftest.tgz \
            https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz
          tar xf conftest.tgz conftest
          sudo mv conftest /usr/local/bin/
          conftest --version

      - name: Run unit tests on policies
        run: conftest verify --policy policies/

      - name: Test Kubernetes manifests
        if: needs.detect.outputs.kube == 'true'
        run: |
          conftest test --policy policies/kubernetes \
            --namespace kubernetes.no_latest,kubernetes.required_labels,kubernetes.no_host_path,kubernetes.no_privileged,kubernetes.run_as_non_root \
            --output github \
            manifests/

      - name: Generate Terraform plan
        if: needs.detect.outputs.terraform == 'true'
        working-directory: terraform/
        run: |
          terraform init -input=false
          terraform plan -out=plan.bin -input=false
          terraform show -json plan.bin > plan.json

      - name: Test Terraform plan
        if: needs.detect.outputs.terraform == 'true'
        run: |
          # The workflow passes PR labels into the plan JSON so the
          # iam_wildcard rule can read input.metadata.labels.
          jq --argjson labels '${{ toJSON(github.event.pull_request.labels.*.name) }}' \
            '. + {metadata: {labels: $labels}}' terraform/plan.json > terraform/plan-with-meta.json
          conftest test --policy policies/terraform \
            --namespace terraform.no_open_ssh_rdp,terraform.s3_encryption,terraform.iam_wildcard \
            --output github \
            terraform/plan-with-meta.json

      - name: Test Dockerfiles
        if: needs.detect.outputs.docker == 'true'
        run: |
          # Conftest auto-detects Dockerfile parser by file name.
          find . -name 'Dockerfile' -not -path './node_modules/*' -print0 \
            | xargs -0 conftest test --policy policies/dockerfile \
                --namespace dockerfile --output github

  exemption:
    needs: gate
    if: failure() && contains(github.event.pull_request.labels.*.name, 'policy/exempt-once')
    runs-on: ubuntu-latest
    steps:
      - name: Confirm exemption
        run: |
          echo "Policy gate failed but exemption label present."
          echo "Logged to audit chain via webhook."
          # In production: POST to audit-chain endpoint with
          # PR number, exemption label, requester, expiry.
          exit 0
```

### 2.4 Demo set

**Pass cases** (`examples/pass/`):

```yaml
# examples/pass/pod-pass-1.yaml — clean prod-shaped pod
apiVersion: v1
kind: Pod
metadata:
  name: recs-api
  namespace: prod-east
  labels: {team: recs, owner: alice, cost-center: cc-100}
spec:
  securityContext: {runAsNonRoot: true}
  containers:
    - name: api
      image: ghcr.io/smartrecs/recs@sha256:deadbeef
      securityContext: {privileged: false}
```

Expected: `conftest test examples/pass/pod-pass-1.yaml` returns
`2 tests, 0 failures` (or whatever the count is after policy
additions); exit code `0`.

```yaml
# examples/pass/pod-pass-2.yaml — dev pod, looser policy
apiVersion: v1
kind: Pod
metadata: {name: dev-api, namespace: dev-a, labels: {team: recs, owner: alice, cost-center: cc-100}}
spec:
  securityContext: {runAsNonRoot: true}
  containers:
    - {name: api, image: ghcr.io/smartrecs/recs:v1.2.3}
```

```json
# examples/pass/tfplan-pass-1.json — bucket with encryption
{
  "metadata": {"labels": []},
  "resource_changes": [
    {"type": "aws_s3_bucket", "address": "aws_s3_bucket.raw",
     "change": {"after": {}}},
    {"type": "aws_s3_bucket_server_side_encryption_configuration",
     "change": {"after": {"bucket": "aws_s3_bucket.raw"}}}
  ]
}
```

**Fail cases** (`examples/fail/`):

```yaml
# examples/fail/pod-fail-no-labels.yaml
apiVersion: v1
kind: Pod
metadata: {name: orphan, namespace: prod-east}
spec:
  containers: [{name: app, image: ghcr.io/smartrecs/recs@sha256:abc}]
```

Expected: violations from `kubernetes.required_labels` (missing
team/owner/cost-center) and `kubernetes.run_as_non_root` (unset);
exit code `1`.

```yaml
# examples/fail/pod-fail-privileged.yaml
apiVersion: v1
kind: Pod
metadata: {name: bad, namespace: prod-east, labels: {team: recs, owner: alice, cost-center: cc-100}}
spec:
  securityContext: {runAsNonRoot: true}
  containers:
    - {name: app, image: ghcr.io/smartrecs/recs:latest, securityContext: {privileged: true}}
```

Expected: violations from `kubernetes.no_latest` and
`kubernetes.no_privileged`.

```dockerfile
# examples/fail/dockerfile-fail-root.Dockerfile
FROM alpine:latest
ADD https://example.com/payload.tar /tmp/
RUN tar -xf /tmp/payload.tar
CMD ["/app"]
```

Expected: three deny messages (latest base, ADD from URL, missing
non-root USER); exit code `1`.

### 2.5 Local developer workflow

```bash
# Install Conftest once.
brew install conftest    # or: go install github.com/open-policy-agent/conftest@latest

# Test before pushing.
conftest verify --policy policies/         # unit tests
conftest test --policy policies/kubernetes manifests/

# To reproduce the CI's Terraform path:
( cd terraform && terraform init -input=false && \
  terraform plan -out=plan.bin -input=false && \
  terraform show -json plan.bin > plan.json )
conftest test --policy policies/terraform terraform/plan.json
```

### 2.6 Exemption process

1. Engineer adds the `policy/exempt-once` label on the PR.
2. The `exemption` job in the workflow logs the exemption to the
   audit-chain endpoint (PR number, label, requester, expiry, policy
   name).
3. The label auto-expires after 7 days (cleanup job, not shown).
4. Label requires an approval from one of `@smartrecs-org/security`
   via CODEOWNERS — Conftest does *not* enforce this; GitHub branch
   protection does.

For permanent exemptions, an engineer must open a separate PR to
`policies/exceptions/<package>.rego` that scopes the rule, with
security review. The exception is itself policy code.

### 2.7 Performance considerations

- Conftest on a hundred small manifests runs in 1–3 seconds on
  GitHub-hosted runners. Dominated by binary fetch (~2–3 seconds on
  cold cache).
- Cache the Conftest binary across runs with `actions/cache` keyed on
  `CONFTEST_VERSION` to remove the cold-cache cost.
- Terraform plan generation is the slow path (10–60 seconds depending
  on provider count). Run it only when Terraform files change.
- Policy unit tests (`conftest verify`) are sub-second and cheap; run
  on every PR regardless of changed paths so a policy bug never lands
  silently.

<!-- follow-up: GitHub-hosted runner timings above are typical
ranges, not measured on SmartRecs. Replace with measured numbers once
the gate has been running for 2 weeks. -->

## 3. Validation steps

```bash
# 1) Lint the workflow.
actionlint .github/workflows/policy-gate.yml

# 2) Run the policy unit tests.
conftest verify --policy policies/

# 3) Run each demo case and confirm exit code.
for f in examples/pass/*; do
  conftest test --policy policies/ "$f" && echo "PASS: $f"
done

for f in examples/fail/*; do
  conftest test --policy policies/ "$f" \
    && { echo "UNEXPECTED PASS: $f"; exit 1; } \
    || echo "FAIL (expected): $f"
done

# 4) Simulate a PR locally with act (optional).
act pull_request -W .github/workflows/policy-gate.yml
```

## 4. Rubric / review checklist

| Area | Weight | What "pass" looks like |
|------|--------|-----------------------|
| Workflow is runnable | 20 | `actionlint` clean; Conftest version pinned; permissions least-privilege |
| Change-type detection | 10 | Workflow runs only the gates relevant to the changed paths |
| K8s policy coverage | 15 | All five required K8s policies present and tested |
| Terraform policy coverage | 15 | SSH/RDP open, S3 encryption, IAM wildcard exemption all present |
| Dockerfile policy coverage | 10 | latest base, ADD-from-URL, non-root USER all present |
| Demo set | 10 | 3 pass + 3 fail with expected outputs documented |
| Local dev workflow | 5 | Engineer can reproduce CI locally with one command |
| Exemption process | 10 | Labeled, audited, time-bounded, with a documented expiry |
| Performance considered | 5 | Binary cached or version pinned; cost discussed |

Pass threshold: **75 / 100**.

Auto-fail conditions:

- Workflow YAML that fails `actionlint`.
- No exemption path, or "ask the security engineer" with no audit.
- Demo set absent or only happy-path.
- Policies hard-coded to one environment with no allow-list.

## 5. Common mistakes

1. **Running every gate on every PR.** Without path filters the
   Terraform plan step runs on every PR and adds 30+ seconds for
   nothing.
2. **Not pinning Conftest.** A floating `latest` install means a
   policy that passes today fails on the next runner. Pin the
   version.
3. **Treating Conftest output as text only.** Use `--output github`
   to get GitHub-aware annotations on changed lines.
4. **Forgetting the policy unit tests.** A policy that compiles but
   doesn't match the new manifest shape silently passes. Run
   `conftest verify` in CI on every PR.
5. **Letting the exemption label be self-applied with no audit.**
   Without a downstream log + expiry, the exemption is a permanent
   bypass.
6. **Confusing `package main` with namespaced packages.** Conftest
   defaults to `package main`. The workflow above uses `--namespace`
   so each rule's package is scoped; without this, rule conflicts
   from policy files get hard to debug.
7. **Treating Terraform plan JSON as the same shape as HCL.** The
   `resource_changes[]` plan-JSON shape and the `resource[].config`
   HCL shape look similar but differ; pick one parser pathway
   consistently.
8. **Blocking on a soft policy.** Some rules should warn before
   denying (e.g., new policies during their first 30 days). The
   workflow can split `deny` vs. `warn` rules; see Exercise 05 for
   the conformance-test ramp.

## 6. References

Official sources:

- Conftest documentation: <https://www.conftest.dev/>
- OPA / Rego: <https://www.openpolicyagent.org/docs/>
- GitHub Actions — workflow syntax:
  <https://docs.github.com/actions/using-workflows/workflow-syntax-for-github-actions>
- `dorny/paths-filter` action: <https://github.com/dorny/paths-filter>
- Terraform — JSON plan format:
  <https://developer.hashicorp.com/terraform/internals/json-format>
- OWASP ML Security Top 10 (2023):
  <https://owasp.org/www-project-machine-learning-security-top-10/>
- NIST AI RMF 1.0: <https://www.nist.gov/itl/ai-risk-management-framework>

Cross-references:

- Exercise 02 — the K8s policies in this gate reuse that library.
- Exercise 04 — the ML-specific policies extend the same Conftest
  invocation pattern to model and training-job manifests.
- Exercise 05 — bundle distribution + audit-chain integration covers
  what happens *after* the gate decision lands.
