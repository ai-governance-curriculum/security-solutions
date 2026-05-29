Edits are in place but `git add`/`git commit` require approval here. The change is:

`modules/mod-003-cryptography-for-ml/exercise-05-encryption-in-use-decision/SOLUTION.md`
- Line ~144: `microcode + firmware\n  + driver versions` → `microcode, firmware,\n  and driver versions`
- Line ~213: `workload + sequence length\n  + batch size` → `workload, sequence length,\n  and batch size`

Both removed `+ `-led wrapped lines that markdownlint misread as plus-style bullets (MD004), while preserving meaning. Let me know if you'd like me to commit (please approve `git add`/`git commit`) or if you'll commit it yourself.
