# Address review feedback on PR #8

## Goal

Reviewers (human or bot) left feedback that blocks auto-merge.
Address each blocker below with the smallest possible code
change. Do NOT rewrite scope and do NOT touch unrelated files.

## Blockers

### 1. Unresolved review thread (bot: @chatgpt-codex-connector) in `modules/mod-005-secrets-management/exercise-02-vault-deployment-plan/SOLUTION.md:43`

> **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub>  Do not require Enterprise seal wrap in OSS plan**

This solution says it uses Vault Open Source as the reference implementation, but this backup design requires Vault seal wrap for Raft snapshots; HashiCorp documents seal wrap as an Enterprise feature (https://developer.hashicorp.com/vault/docs/enterprise/sealwrap). In an OSS deployment this step cannot be implemented, so learners either fail the backup plan

### 2. Unresolved review thread (bot: @chatgpt-codex-connector) in `modules/mod-005-secrets-management/exercise-01-secrets-inventory/SOLUTION.md:85`

> **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub>  Treat Slack webhook URLs as secrets**

Classifying a Slack incoming webhook as T4 with no blast radius teaches learners to remove it from secret handling, but Slack's own webhook docs say to keep the URL secret and not share it publicly (https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks). Anyone with the URL can post into the configured channel, so in the scenario where this URL appear

## Output contract

- Edit only the files referenced by these blockers.
- Preserve the existing structure; don't delete sections.
- Do NOT touch CURRICULUM.md, README.md, or VERSIONS.md.
- Do NOT mark review threads resolved yourself — only the
  reviewer can do that. Your job is to push commits that
  address the underlying issue. Bot threads auto-resolve
  when their metric recovers; human threads stay open until
  the human resolves them.
