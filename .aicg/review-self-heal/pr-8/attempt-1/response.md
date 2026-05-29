Both files edited. The `git add` is awaiting permission approval — please approve so I can stage and commit. Summary of the two edits:

- `modules/mod-005-secrets-management/exercise-02-vault-deployment-plan/SOLUTION.md:40-45` — replaced "Raft snapshots encrypted with Vault's seal wrap" with barrier encryption at rest + bucket-side KMS, MFA-delete, object-lock, and an explicit note that seal wrap is Vault Enterprise only.
- `modules/mod-005-secrets-management/exercise-01-secrets-inventory/SOLUTION.md:85-93` — reclassified SEC-012 Slack incoming webhook from `T4 → fix` to `T2` with the real blast radius ("post arbitrary messages to the bound channel — fake alerts, suppression of real ones, internal phishing"), a rotate-on-disclosure → Vault `kv-v2` migration path, and reworded the trailing paragraph so the row illustrates an *under*-protected secret while pointing the *over*-protected non-secret case to §2.5.

Once `git add` is approved I'll create the commit on the current branch (no force-push, no `--no-verify`).
