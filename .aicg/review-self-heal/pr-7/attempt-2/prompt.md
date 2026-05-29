# Address review feedback on PR #7

## Goal

Reviewers (human or bot) left feedback that blocks auto-merge.
Address each blocker below with the smallest possible code
change. Do NOT rewrite scope and do NOT touch unrelated files.

## Blockers

### 1. Unresolved review thread (bot: @chatgpt-codex-connector) in `modules/mod-004-network-security/exercise-03-edge-gateway-hardening/SOLUTION.md:183`

> **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub>  Define the referenced admin JWT provider**

The JWT filter declares only `platform-oidc` under `providers`, but the `/admin` rule requires `platform-oidc-admin`. In this Envoy JWT authn config, rules reference providers by name, so copying the hardened gateway example as written leaves the admin route pointing at a missing provider and the config will not validate or enforce the intended admin authentication.

### 2. Unresolved review thread (bot: @chatgpt-codex-connector) in `modules/mod-004-network-security/exercise-02-complete-networkpolicy-set/SOLUTION.md:442`

> **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub>  Include the policies required after default-deny**

This bill of materials lists `external→gateway ingress`, `gateway→inference egress`, and registry ingress policies, but the worked implementation above never provides those manifests. Since §2.2 tells learners to put `default-deny-all` on `ingress` and `model-registry`, copying the solution blocks external traffic from entering the gateway, blocks the gatewa

## Output contract

- Edit only the files referenced by these blockers.
- Preserve the existing structure; don't delete sections.
- Do NOT touch CURRICULUM.md, README.md, or VERSIONS.md.
- Do NOT mark review threads resolved yourself — only the
  reviewer can do that. Your job is to push commits that
  address the underlying issue. Bot threads auto-resolve
  when their metric recovers; human threads stay open until
  the human resolves them.
