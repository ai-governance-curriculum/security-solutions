All five SOLUTION.md files plus the two runnable artifacts are in place under `modules/mod-006-adversarial-ml/`.

## Summary of what shipped

```
modules/mod-006-adversarial-ml/
├── README.md                                         # index of the 5 exercises
├── exercise-01-robustness-assessment/SOLUTION.md     # design + ATLAS/OWASP mapping + rubric
├── exercise-02-defense-plan/SOLUTION.md              # defense table, trade-offs, roll-out plan
├── exercise-03-poisoning-detection/SOLUTION.md       # pipeline map, detectors, coverage matrix
├── exercise-04-dp-sgd-configuration/
│   ├── SOLUTION.md                                   # (ε, δ) defence + parameter rationale
│   └── train_dp.py                                   # runnable Opacus MNIST DP-SGD reference
└── exercise-05-llm-safety-pipeline/
    ├── SOLUTION.md                                   # 10-layer pipeline design + rubric
    └── pipeline.py                                   # runnable middleware reference
```

Each `SOLUTION.md` follows the required 6-section contract (overview / worked answer / validation / rubric / common mistakes / references) and anchors claims to the three authorized sources (OWASP ML Top 10, MITRE ATLAS, NIST AI RMF). Sibling cross-references point to `projects/project-3-adversarial-defense/SOLUTION.md` where the production-shaped reference code lives.

Claims I could not verify against the official sources without external lookup are tagged with `<!-- needs-research: ... -->` so they block auto-merge per the source policy. Those tags cover: exact MITRE ATLAS technique IDs against the current matrix, OWASP ML Top 10 / LLM Top 10 category numbering and version pinning, the specific paper citations behind activation clustering / spectral signatures / Neural Cleanse / Madry et al. / Abadi et al., and any "industry standard" ε for DP-SGD.

The two runnable artifacts (`train_dp.py`, `pipeline.py`) were written carefully but I was unable to run a `py_compile` check inside the sandbox; the SOLUTION.md files document how to run each one. Nothing is committed — only files added to the working tree.
