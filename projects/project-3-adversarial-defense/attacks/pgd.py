"""Projected Gradient Descent attack (for testing defenses)."""
from __future__ import annotations

import torch


def pgd(model, x: torch.Tensor, y: torch.Tensor,
         epsilon: float = 0.03, alpha: float = 0.01, steps: int = 10) -> torch.Tensor:
    """Generate adversarial example via PGD. eps in normalized [0, 1] space."""
    model.train(False)
    x_adv = x.clone().detach().requires_grad_(True)

    for _ in range(steps):
        out = model(x_adv)
        loss = torch.nn.functional.cross_entropy(out, y)
        grad = torch.autograd.grad(loss, x_adv)[0]
        x_adv = x_adv + alpha * grad.sign()
        x_adv = torch.clamp(x_adv, x - epsilon, x + epsilon)
        x_adv = torch.clamp(x_adv, 0, 1).detach().requires_grad_(True)
    return x_adv.detach()
