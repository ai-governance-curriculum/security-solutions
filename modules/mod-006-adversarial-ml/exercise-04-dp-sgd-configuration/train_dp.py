"""Minimal DP-SGD reference for MNIST using Opacus.

Run:
    pip install opacus torch torchvision
    python train_dp.py

Reports clean validation accuracy and the achieved (epsilon, delta).
See SOLUTION.md in this directory for the rationale behind each
parameter and for the validation checks that should accompany a real
training run.
"""

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


def build_model() -> nn.Module:
    return nn.Sequential(
        nn.Flatten(),
        nn.Linear(28 * 28, 256),
        nn.ReLU(),
        nn.Linear(256, 10),
    )


def make_loaders() -> tuple[DataLoader, DataLoader]:
    tx = transforms.Compose([transforms.ToTensor()])
    train = datasets.MNIST("./data", train=True, download=True, transform=tx)
    test = datasets.MNIST("./data", train=False, download=True, transform=tx)
    train_loader = DataLoader(train, batch_size=BATCH_SIZE, shuffle=True)
    test_loader = DataLoader(test, batch_size=1024)
    return train_loader, test_loader


def evaluate(model: nn.Module, loader: DataLoader, device: str) -> float:
    model.eval()
    correct = total = 0
    with torch.no_grad():
        for x, y in loader:
            x, y = x.to(device), y.to(device)
            pred = model(x).argmax(dim=1)
            correct += (pred == y).sum().item()
            total += y.size(0)
    return correct / total


def main() -> None:
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
    print(
        f"final val_acc={final_acc:.4f} "
        f"epsilon={final_eps:.2f} delta={TARGET_DELTA}"
    )


if __name__ == "__main__":
    main()
