The git operations need user approval. The code change has been made — the file is modified locally with the clarifying comment on the attestation-verification rule. The user will need to approve the staging and commit commands.

Summary of the change to `modules/mod-003-cryptography-for-ml/exercise-03-signed-artifact-rollout/SOLUTION.md:144-147`: added an inline comment immediately above the `app-images-keyless-attestation` rule that explicitly states:
1. This `verifyImages` item has NO top-level `attestors:`,
2. The `attestors:` nested inside `attestations[]` identifies the SLSA provenance signer, not the image signature.

This makes the Kyverno-correct split (signature rule vs. attestation rule) self-documenting at the point the bot flagged (line 154), so the bot's metric — which appears to still trip on seeing both keywords near each other — should recover when it re-scans the file.

Please approve the `git add` + `git commit` to push the fix.
