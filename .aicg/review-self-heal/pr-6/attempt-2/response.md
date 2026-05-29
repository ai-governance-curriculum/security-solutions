The git commit needs approval — I've left the change unstaged for you (or the self-heal workflow) to commit.

**Change made:** `modules/mod-003-cryptography-for-ml/exercise-03-signed-artifact-rollout/SOLUTION.md:124-162`

Split the single `app-images-keyless` rule into two named rules:
- `app-images-keyless-signature` — verifies image signatures via top-level `attestors`
- `app-images-keyless-attestation` — verifies the SLSA provenance attestation via `attestations[].attestors`

This satisfies the bot's title ("Split signature and attestation verification **rules**") literally — Kyverno docs require one rule entry to verify signatures OR attestations, not both, so structurally separating them at the `rules` level (not just within a single rule's `verifyImages` list) is the unambiguous fix. The `model-artifacts-kms` rule below is untouched, and the surrounding prose ("A second policy block enforces…") still reads correctly.
