"""
Transport CV Model — Loader and Wrapper
========================================
Provides a standard interface for loading image classifiers used in
transport/infrastructure CV systems.

Supports:
  - TransportCNN: lightweight CNN trained on GTSRB (German Traffic Sign
    Recognition Benchmark) — 43 traffic sign classes
  - Pretrained ResNet-18 from torchvision (ImageNet — for proof-of-concept
    attacks against a production-grade architecture)

GTSRB class reference (selected):
    0  = Speed limit (20km/h)
    1  = Speed limit (30km/h)
    14 = Stop
    17 = No entry
    33 = Turn right ahead
    38 = Keep right
"""

from __future__ import annotations

import torch
import torch.nn as nn


# ── Lightweight CNN for GTSRB / traffic sign classification ────────────────
class TransportCNN(nn.Module):
    """
    Compact convolutional network for traffic sign classification.

    Architecture:
        Conv(3→32, 3×3) → BN → ReLU → MaxPool
        Conv(32→64, 3×3) → BN → ReLU → MaxPool
        Conv(64→128, 3×3) → BN → ReLU → AdaptiveAvgPool(4×4)
        FC(128*16 → 256) → ReLU → Dropout(0.4)
        FC(256 → n_classes)

    Input:  (B, 3, H, W)  — H, W ≥ 32, values in [0, 1]
    Output: (B, n_classes) logits
    """

    def __init__(self, n_classes: int = 43):
        super().__init__()
        self.features = nn.Sequential(
            # Block 1
            nn.Conv2d(3, 32, kernel_size=3, padding=1),
            nn.BatchNorm2d(32),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(2, 2),
            # Block 2
            nn.Conv2d(32, 64, kernel_size=3, padding=1),
            nn.BatchNorm2d(64),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(2, 2),
            # Block 3
            nn.Conv2d(64, 128, kernel_size=3, padding=1),
            nn.BatchNorm2d(128),
            nn.ReLU(inplace=True),
            nn.AdaptiveAvgPool2d((4, 4)),
        )
        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(128 * 4 * 4, 256),
            nn.ReLU(inplace=True),
            nn.Dropout(0.4),
            nn.Linear(256, n_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.classifier(self.features(x))


# ── Model factory ──────────────────────────────────────────────────────────
def load_model(
    architecture: str = "transport_cnn",
    n_classes: int = 43,
    pretrained: bool = False,
    weights_path: str | None = None,
    device: str = "cpu",
) -> nn.Module:
    """
    Load a transport CV model.

    Args:
        architecture: "transport_cnn" | "resnet18"
        n_classes:    Number of output classes (43 for GTSRB)
        pretrained:   If True and architecture="resnet18", load ImageNet weights
        weights_path: Path to saved state_dict (.pt file)
        device:       "cpu" | "cuda" | "mps"

    Returns:
        nn.Module in eval mode on the specified device
    """
    if architecture == "transport_cnn":
        model = TransportCNN(n_classes=n_classes)

    elif architecture == "resnet18":
        try:
            from torchvision import models
            if pretrained:
                model = models.resnet18(weights=models.ResNet18_Weights.IMAGENET1K_V1)
            else:
                model = models.resnet18(weights=None)
            # Replace final layer for target class count
            model.fc = nn.Linear(model.fc.in_features, n_classes)
        except ImportError:
            raise ImportError(
                "torchvision is required for ResNet-18. "
                "Install: pip install torchvision"
            )
    else:
        raise ValueError(
            f"Unknown architecture '{architecture}'. "
            "Choose 'transport_cnn' or 'resnet18'."
        )

    if weights_path is not None:
        state = torch.load(weights_path, map_location=device)
        model.load_state_dict(state)

    model = model.to(device)
    model.eval()
    return model


# ── GTSRB class labels ─────────────────────────────────────────────────────
GTSRB_CLASSES = {
    0: "Speed limit (20km/h)",
    1: "Speed limit (30km/h)",
    2: "Speed limit (50km/h)",
    3: "Speed limit (60km/h)",
    4: "Speed limit (70km/h)",
    5: "Speed limit (80km/h)",
    6: "End of speed limit (80km/h)",
    7: "Speed limit (100km/h)",
    8: "Speed limit (120km/h)",
    9: "No passing",
    10: "No passing for vehicles over 3.5t",
    11: "Right-of-way at next intersection",
    12: "Priority road",
    13: "Yield",
    14: "Stop",
    15: "No vehicles",
    16: "Vehicles over 3.5t prohibited",
    17: "No entry",
    18: "General caution",
    19: "Dangerous curve (left)",
    20: "Dangerous curve (right)",
    21: "Double curve",
    22: "Bumpy road",
    23: "Slippery road",
    24: "Road narrows (right)",
    25: "Road work",
    26: "Traffic signals",
    27: "Pedestrians",
    28: "Children crossing",
    29: "Bicycles crossing",
    30: "Beware of ice/snow",
    31: "Wild animals crossing",
    32: "End of all speed and passing limits",
    33: "Turn right ahead",
    34: "Turn left ahead",
    35: "Ahead only",
    36: "Go straight or right",
    37: "Go straight or left",
    38: "Keep right",
    39: "Keep left",
    40: "Roundabout mandatory",
    41: "End of no passing",
    42: "End of no passing (3.5t)",
}


def class_name(label: int) -> str:
    """Return human-readable class name for a GTSRB label."""
    return GTSRB_CLASSES.get(label, f"Class {label}")
