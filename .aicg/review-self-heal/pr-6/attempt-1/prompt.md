# Address review feedback on PR #6

## Goal

Reviewers (human or bot) left feedback that blocks auto-merge.
Address each blocker below with the smallest possible code
change. Do NOT rewrite scope and do NOT touch unrelated files.

## Blockers

### 1. Unresolved review thread (bot: @chatgpt-codex-connector) in `modules/mod-003-cryptography-for-ml/exercise-03-signed-artifact-rollout/SOLUTION.md:141`

> **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub>  Split signature and attestation verification rules**

In this Kyverno `verifyImages` item, the top-level `attestors` above are used for image signature validation and this `attestations` block is used for attestation validation in the same item. Kyverno's verifyImages docs state a rule entry verifies signatures or attestations, not both, so applying this worked policy as-is will not enforce the intended signa

## Output contract

- Edit only the files referenced by these blockers.
- Preserve the existing structure; don't delete sections.
- Do NOT touch CURRICULUM.md, README.md, or VERSIONS.md.
- Do NOT mark review threads resolved yourself — only the
  reviewer can do that. Your job is to push commits that
  address the underlying issue. Bot threads auto-resolve
  when their metric recovers; human threads stay open until
  the human resolves them.
