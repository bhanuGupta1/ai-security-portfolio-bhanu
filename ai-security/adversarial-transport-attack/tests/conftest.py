"""
Shared fixtures for all tests.
Uses a tiny 3-class CNN that runs on CPU with no pretrained weights.
No internet access or GPU required.
"""

import pytest
import torch
import torch.nn as nn


class TinyCNN(nn.Module):
    """Minimal 3-class classifier — fast, deterministic, CPU-only."""
    def __init__(self, n_classes: int = 3):
        super().__init__()
        self.net = nn.Sequential(
            nn.Conv2d(3, 8, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.AdaptiveAvgPool2d((2, 2)),
            nn.Flatten(),
            nn.Linear(8 * 2 * 2, n_classes),
        )

    def forward(self, x):
        return self.net(x)


@pytest.fixture(scope="session")
def tiny_model():
    """Shared tiny CNN — session-scoped for speed."""
    torch.manual_seed(42)
    model = TinyCNN(n_classes=3)
    model.eval()
    return model


@pytest.fixture
def sample_image():
    """Single RGB image tensor: (1, 3, 16, 16), values in [0, 1]."""
    torch.manual_seed(0)
    return torch.rand(1, 3, 16, 16)


@pytest.fixture
def sample_label(tiny_model, sample_image):
    """True label = model's own prediction on sample_image (guaranteed correct)."""
    with torch.no_grad():
        logits = tiny_model(sample_image)
        label = logits.argmax(dim=1)
    return label


@pytest.fixture
def batch_images():
    """Batch of 5 images."""
    torch.manual_seed(1)
    return [torch.rand(1, 3, 16, 16) for _ in range(5)]


@pytest.fixture
def batch_labels(tiny_model, batch_images):
    """Labels matching the model's clean predictions."""
    labels = []
    with torch.no_grad():
        for img in batch_images:
            logits = tiny_model(img)
            labels.append(logits.argmax(dim=1))
    return labels
