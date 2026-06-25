# Address CI failures on PR #5

## Goal

The PR you just opened failed CI. Fix the failures listed
below by editing files on the current branch. Do NOT regenerate
the content from scratch — make the minimal edit needed to
satisfy each failing check.

## Failed checks

### 1. `Markdown lint` (failure)

- Details: <https://github.com/ai-governance-curriculum/security-solutions/actions/runs/26621513019/job/78448331479>
- Annotations:
  - `.github:2` (warning): Node.js 20 actions are deprecated. The following actions are running on Node.js 20 and may not work as expected: actions/checkout@v4, DavidAnson/markdownlint-cli2-action@v16. Actions will be forced to run with Node.js 24 by default starting June 2nd, 2026. Node.js 20 will be removed from the runner 
  - `modules/mod-002-zero-trust-architecture/exercise-05-zero-trust-roadmap/SOLUTION.md:51` (failure): modules/mod-002-zero-trust-architecture/exercise-05-zero-trust-roadmap/SOLUTION.md:51:32 MD049/emphasis-style Emphasis style [Expected: asterisk; Actual: underscore] https://github.com/DavidAnson/markdownlint/blob/v0.34.0/doc/md049.md
  - `modules/mod-002-zero-trust-architecture/exercise-05-zero-trust-roadmap/SOLUTION.md:51` (failure): modules/mod-002-zero-trust-architecture/exercise-05-zero-trust-roadmap/SOLUTION.md:51:13 MD049/emphasis-style Emphasis style [Expected: asterisk; Actual: underscore] https://github.com/DavidAnson/markdownlint/blob/v0.34.0/doc/md049.md
  - `modules/mod-002-zero-trust-architecture/exercise-04-service-mesh-authz/SOLUTION.md:47` (failure): modules/mod-002-zero-trust-architecture/exercise-04-service-mesh-authz/SOLUTION.md:47:32 MD049/emphasis-style Emphasis style [Expected: asterisk; Actual: underscore] https://github.com/DavidAnson/markdownlint/blob/v0.34.0/doc/md049.md
  - `modules/mod-002-zero-trust-architecture/exercise-04-service-mesh-authz/SOLUTION.md:47` (failure): modules/mod-002-zero-trust-architecture/exercise-04-service-mesh-authz/SOLUTION.md:47:13 MD049/emphasis-style Emphasis style [Expected: asterisk; Actual: underscore] https://github.com/DavidAnson/markdownlint/blob/v0.34.0/doc/md049.md
  - `modules/mod-002-zero-trust-architecture/exercise-03-microsegmentation-plan/SOLUTION.md:50` (failure): modules/mod-002-zero-trust-architecture/exercise-03-microsegmentation-plan/SOLUTION.md:50:32 MD049/emphasis-style Emphasis style [Expected: asterisk; Actual: underscore] https://github.com/DavidAnson/markdownlint/blob/v0.34.0/doc/md049.md
  - `modules/mod-002-zero-trust-architecture/exercise-03-microsegmentation-plan/SOLUTION.md:50` (failure): modules/mod-002-zero-trust-architecture/exercise-03-microsegmentation-plan/SOLUTION.md:50:13 MD049/emphasis-style Emphasis style [Expected: asterisk; Actual: underscore] https://github.com/DavidAnson/markdownlint/blob/v0.34.0/doc/md049.md
  - `modules/mod-002-zero-trust-architecture/exercise-02-workload-identity-design/SOLUTION.md:41` (failure): modules/mod-002-zero-trust-architecture/exercise-02-workload-identity-design/SOLUTION.md:41:32 MD049/emphasis-style Emphasis style [Expected: asterisk; Actual: underscore] https://github.com/DavidAnson/markdownlint/blob/v0.34.0/doc/md049.md
  - `modules/mod-002-zero-trust-architecture/exercise-02-workload-identity-design/SOLUTION.md:41` (failure): modules/mod-002-zero-trust-architecture/exercise-02-workload-identity-design/SOLUTION.md:41:13 MD049/emphasis-style Emphasis style [Expected: asterisk; Actual: underscore] https://github.com/DavidAnson/markdownlint/blob/v0.34.0/doc/md049.md
  - `modules/mod-002-zero-trust-architecture/exercise-01-zero-trust-gap-analysis/SOLUTION.md:45` (failure): modules/mod-002-zero-trust-architecture/exercise-01-zero-trust-gap-analysis/SOLUTION.md:45:32 MD049/emphasis-style Emphasis style [Expected: asterisk; Actual: underscore] https://github.com/DavidAnson/markdownlint/blob/v0.34.0/doc/md049.md
  - `modules/mod-002-zero-trust-architecture/exercise-01-zero-trust-gap-analysis/SOLUTION.md:45` (failure): modules/mod-002-zero-trust-architecture/exercise-01-zero-trust-gap-analysis/SOLUTION.md:45:13 MD049/emphasis-style Emphasis style [Expected: asterisk; Actual: underscore] https://github.com/DavidAnson/markdownlint/blob/v0.34.0/doc/md049.md

## Output contract

- Edit ONLY files inside this repo on the current branch.
- Preserve the existing structure; do not delete sections.
- Do NOT touch CURRICULUM.md, README.md, or VERSIONS.md.
- One atomic commit covering all fixes is fine.
