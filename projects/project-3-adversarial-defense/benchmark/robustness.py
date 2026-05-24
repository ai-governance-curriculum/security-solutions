"""Benchmark robustness: clean accuracy vs adversarial accuracy."""
from __future__ import annotations

import sys
sys.path.insert(0, "../attacks")

import torch
from pgd import pgd


def measure(model, test_loader, epsilon: float = 0.03) -> dict:
    """Returns clean acc + adversarial acc."""
    model.train(False)
    clean_correct = adv_correct = total = 0
    for x, y in test_loader:
        x, y = x.cuda(), y.cuda()
        with torch.no_grad():
            clean_correct += (model(x).argmax(-1) == y).sum().item()
        x_adv = pgd(model, x, y, epsilon=epsilon)
        with torch.no_grad():
            adv_correct += (model(x_adv).argmax(-1) == y).sum().item()
        total += y.size(0)
    return {
        "clean_acc": clean_correct / total,
        "adversarial_acc": adv_correct / total,
        "robustness_gap": (clean_correct - adv_correct) / total,
    }
