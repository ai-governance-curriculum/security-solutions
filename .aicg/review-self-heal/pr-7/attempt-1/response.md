The edits are made but git operations need your approval. The changes are unstaged in:

- `modules/mod-004-network-security/exercise-03-edge-gateway-hardening/SOLUTION.md` — added the `platform-oidc-admin` JWT provider that the `/admin` rule references, plus a one-bullet rationale.
- `modules/mod-004-network-security/exercise-02-complete-networkpolicy-set/SOLUTION.md` — added the missing manifests called out in the bill of materials: external→gateway ingress and gateway→inference egress in the `ingress` namespace (§2.5), and the symmetric ingress policies on `model-registry` for both inference and training (§2.7).

Want me to commit these? If so, please approve the `git add` / `git commit` calls and I'll push them.
