# Exercise 04 — DP-SGD Configuration

> Read this *after* attempting the exercise yourself. This file is a
> reference configuration, the reasoning behind each parameter, the
> validation pass, and the rubric you can grade your own answer
> against.

## 1. Solution overview

The exercise asks the learner to configure DP-SGD (differentially
private stochastic gradient descent) for a small classifier, defend
the (ε, δ) target, and demonstrate that the resulting training run
actually delivers the claimed privacy guarantee.

A complete answer has three pieces:

1. **A defended (ε, δ) target** — what privacy budget you picked and
   *why* (regulatory ask, internal policy, threat from exercise-01).
2. **A configuration** — the four parameters that govern DP-SGD
   (noise multiplier σ, clipping norm C, sample rate q, number of
   steps T), plus the accountant.
3. **Validation** — a script run that prints the achieved (ε, δ) at
   end of training, plus a utility report (clean accuracy with and
   without DP).

The reference implementation uses Opacus (PyTorch). Opacus is the
PyTorch ecosystem's mainline DP-SGD library and is the default for
the curriculum. The same parameters and the same reasoning apply if
you reach for `dp-accounting` and TensorFlow Privacy instead.

## 2. Worked answer — implementation

The companion file in this directory, `train_dp.py`, is a minimal,
runnable DP-SGD training loop on MNIST. The configuration below is
the defended set of choices in that script.

### 2.1 Defended (ε, δ) target

- **δ = 1e-5.** δ is conventionally chosen well below `1/N` where N
  is the training set size. MNIST has 60 000 training samples, so
  `1/N ≈ 1.67e-5`; `δ = 1e-5` sits below that.
- **ε = 8.** This is a deliberately permissive target chosen so the
  exercise can finish training in a few minutes on a CPU and still
  reach non-trivial accuracy. ε = 8 is **not** a recommendation for
  a production system; production targets are usually much
  tighter and the dataset is usually much larger. Before citing an
  "industry standard" ε, find a specific organization's published
  number for a comparable system rather than guessing.

A real defense of the (ε, δ) pair in production starts from the
threat model (was a *specific* attacker capability defeated?) and
from any regulatory constraint that applies — not from a
"standard" number.

### 2.2 Configuration parameters

| Parameter | Value | Rationale |
|---|---|---|
| `noise_multiplier` (σ) | derived by accountant from (ε, δ, q, T) | Higher σ = more privacy, less utility. Let the accountant solve for σ given the budget and the dataset shape; do not hand-pick. |
| `max_grad_norm` (C) | 1.0 | Standard starting point. Smaller C tightens the per-sample sensitivity bound but also clips more signal; tune empirically. |
| `batch_size` (effective) | 256 | Larger logical batch → smaller σ for a fixed (ε, δ), but exposes more privacy per training step. Opacus supports virtual / Poisson-sampled batches via `BatchMemoryManager`. |
| `epochs` | 15 | Fewer steps → less budget spent. Stop early once validation accuracy plateaus. |
| Accountant | `prv` (Privacy Random Variable) | Opacus' tighter accountant; falls back to `rdp` if PRV isn't available in your Opacus version. The moments-accountant approach from Abadi et al. 2016 is the historical baseline. |

The accountant is the part learners most often skip. Without an
accountant, DP-SGD has no claimed (ε, δ) — you've added noise to
gradients but you have not proved anything.

### 2.3 Reference training script

```python
# train_dp.py — minimal DP-SGD reference for MNIST using Opacus.
# Run:
#   pip install opacus torch torchvision
#   python train_dp.py
# Reports clean validation accuracy and the achieved (epsilon, delta).

import torch
from torch import nn, optim
from torch.utils.data import DataLoader
from torchvision import datasets, transforms

from opacus import PrivacyEngine
from opacus.utils.batch_memory_manager import BatchMemoryManager


TARGET_EPSILON = 8.0
TARGET_DELTA = 1e-5
MAX_GRAD_NORM = 1.0
EPOCHS = 15
BATCH_SIZE = 256
LR = 0.1


def build_model():
    return nn.Sequential(
        nn.Flatten(),
        nn.Linear(28 * 28, 256),
        nn.ReLU(),
        nn.Linear(256, 10),
    )


def make_loaders():
    tx = transforms.Compose([transforms.ToTensor()])
    train = datasets.MNIST("./data", train=True, download=True, transform=tx)
    test = datasets.MNIST("./data", train=False, download=True, transform=tx)
    train_loader = DataLoader(train, batch_size=BATCH_SIZE, shuffle=True)
    test_loader = DataLoader(test, batch_size=1024)
    return train_loader, test_loader


def evaluate(model, loader, device):
    model.eval()
    correct = total = 0
    with torch.no_grad():
        for x, y in loader:
            x, y = x.to(device), y.to(device)
            pred = model(x).argmax(dim=1)
            correct += (pred == y).sum().item()
            total += y.size(0)
    return correct / total


def main():
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model = build_model().to(device)
    optimizer = optim.SGD(model.parameters(), lr=LR)
    criterion = nn.CrossEntropyLoss()
    train_loader, test_loader = make_loaders()

    engine = PrivacyEngine(accountant="prv")
    model, optimizer, train_loader = engine.make_private_with_epsilon(
        module=model,
        optimizer=optimizer,
        data_loader=train_loader,
        epochs=EPOCHS,
        target_epsilon=TARGET_EPSILON,
        target_delta=TARGET_DELTA,
        max_grad_norm=MAX_GRAD_NORM,
    )

    for epoch in range(EPOCHS):
        model.train()
        with BatchMemoryManager(
            data_loader=train_loader,
            max_physical_batch_size=128,
            optimizer=optimizer,
        ) as loader:
            for x, y in loader:
                x, y = x.to(device), y.to(device)
                optimizer.zero_grad()
                loss = criterion(model(x), y)
                loss.backward()
                optimizer.step()
        acc = evaluate(model, test_loader, device)
        eps = engine.get_epsilon(TARGET_DELTA)
        print(f"epoch={epoch + 1} val_acc={acc:.4f} epsilon={eps:.2f}")

    final_eps = engine.get_epsilon(TARGET_DELTA)
    final_acc = evaluate(model, test_loader, device)
    print(f"final val_acc={final_acc:.4f} epsilon={final_eps:.2f} delta={TARGET_DELTA}")


if __name__ == "__main__":
    main()
```

The script is intentionally minimal:

- It uses `make_private_with_epsilon`, which solves for the
  `noise_multiplier` σ given the (ε, δ, epochs, sample_rate) budget.
  This is the right pattern for an exercise; it forces you to
  declare the budget instead of fiddling with σ.
- `BatchMemoryManager` lets you keep a large *logical* batch
  (favorable for the accountant) while limiting memory use to a
  smaller physical batch.
- `engine.get_epsilon(TARGET_DELTA)` is called at end of each epoch
  so you can watch the budget being spent.

### 2.4 Cross-run privacy accounting

A single training run is *not* the privacy boundary. If the same
dataset is used to train multiple models that are all released, the
privacy guarantees compose. Practical patterns:

- Maintain a written (ε, δ) ledger per dataset, debited on every
  released training run.
- Treat hyper-parameter search as **part of the budget**, not free.
- When the dataset changes materially (refreshed, expanded), the
  ledger resets in the sense that you are training on a new
  distribution — but the *prior* releases still leak about the
  prior dataset.

## 3. Validation steps

1. **The script runs to completion** and prints a final ε near the
   target. If the printed ε is well above the target, the accountant
   is being asked to do something impossible (too many epochs, too
   small a noise multiplier).
2. **Utility regression**: train the same model without DP (drop the
   `PrivacyEngine` wiring) and record clean validation accuracy.
   Report both numbers side by side. The DP run should be lower —
   if it is the same or higher, something is wrong (likely DP isn't
   actually engaged).
3. **Sanity-check noise**: with σ set to a very small value, ε should
   blow up. With σ set very large, ε should be tiny and accuracy
   should crater. Both extremes are useful smoke tests.
4. **(ε, δ) sanity**: confirm `δ < 1/N`. A target of `δ = 1e-3` on
   MNIST silently breaks the guarantee.
5. **Empirical privacy test**: implement a basic membership inference
   attack against the non-DP and DP models. The AUC should be
   materially closer to 0.5 on the DP model. This is the test that
   shows DP-SGD actually defeats the threat from
   exercise-01 §T3 and exercise-02 row T3.

## 4. Rubric

Total points: 30. Suggested cut: ≥24 pass, ≥27 production-ready.

| Section | Criterion | Points |
|---|---|---|
| Budget | (ε, δ) target is declared *with reasoning* (not "8 because the tutorial said so") | 3 |
| Budget | δ < 1/N validated explicitly | 2 |
| Config | Accountant named and chosen deliberately | 2 |
| Config | `noise_multiplier` is derived from budget (not hand-set) | 3 |
| Config | `max_grad_norm` chosen with rationale; not left at a placeholder | 2 |
| Code | Training loop wired through `PrivacyEngine` | 3 |
| Code | `BatchMemoryManager` (or equivalent) used so logical ≠ physical batch | 2 |
| Validation | Final (ε, δ) printed and near the target | 3 |
| Validation | Side-by-side utility (clean accuracy) report | 3 |
| Validation | Empirical privacy check (membership-inference AUC) | 3 |
| Process | Ledger / cross-run accounting policy stated | 2 |
| Process | Hyper-parameter search counted against the budget | 2 |

## 5. Common mistakes

- **Hand-tuning σ until accuracy looks fine.** The accountant exists
  to solve for σ from the budget. Hand-tuning σ produces a model that
  may or may not actually meet (ε, δ).
- **Picking δ ≥ 1/N.** A common error on small datasets. With δ
  comparable to 1/N, the guarantee approximately says "we may release
  an entire training record" — which is no guarantee.
- **Counting only the *deployed* run.** Privacy budget is spent
  across every released training run on the same dataset, including
  hyper-parameter sweeps that produced models you discarded but
  whose outputs leaked information.
- **Treating DP-SGD as a defense against evasion.** DP-SGD addresses
  the membership-inference / inversion family of leakage attacks. It
  does not make the model more robust to PGD or transfer attacks.
  Different threat, different defense.
- **No empirical privacy test.** The accountant proves an *upper
  bound* on leakage; it does not prove the implementation is bug-free.
  A membership-inference test against the trained model is the
  empirical cross-check.
- **Forgetting Poisson sampling.** DP-SGD's privacy analysis assumes
  Poisson sampling (each sample independently included with
  probability `q`). Standard PyTorch shuffling is not Poisson; use
  Opacus' wrapping (`make_private*` does this for you), don't roll
  your own DataLoader.

## 6. References

- OWASP Machine Learning Security Top 10 — ML04 (Membership Inference
  Attack) is the threat this exercise's defense targets —
  https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS — Membership Inference under ML Attack Staging —
  https://atlas.mitre.org/
- NIST AI Risk Management Framework — Manage function for
  privacy-impact mitigations —
  https://www.nist.gov/itl/ai-risk-management-framework
- Abadi et al., "Deep Learning with Differential Privacy", CCS 2016 —
  the moments-accountant DP-SGD paper.
- Opacus documentation — https://opacus.ai/
- Sibling exercise: `exercise-01-robustness-assessment/SOLUTION.md`
  — T3 (membership inference).
- Sibling exercise: `exercise-02-defense-plan/SOLUTION.md` — defense
  row T3.
- Sibling project: `projects/project-3-adversarial-defense/SOLUTION.md`
  — production-shaped DP-SGD wiring plus the membership-inference
  benchmark for the empirical check above.
