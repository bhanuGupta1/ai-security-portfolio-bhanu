"""
Base class for adversarial attacks.
All attacks return a standardised AttackResult dataclass.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass

import torch
import torch.nn as nn


@dataclass
class AttackResult:
    """Structured result from a single adversarial attack."""

    original: torch.Tensor          # Original input (C, H, W)
    adversarial: torch.Tensor       # Perturbed input (C, H, W)
    original_pred: int              # Model prediction on clean input
    adversarial_pred: int           # Model prediction on adversarial input
    original_confidence: float      # Softmax confidence on clean input
    adversarial_confidence: float   # Softmax confidence on adversarial input
    perturbation_norm: float        # L-inf norm of the perturbation
    attack_success: bool            # True if prediction changed
    epsilon: float                  # Perturbation budget used
    attack_name: str                # "FGSM" | "PGD"
    n_iterations: int = 1           # Number of attack steps (1 for FGSM)

    def to_dict(self) -> dict:
        return {
            "attack": self.attack_name,
            "epsilon": self.epsilon,
            "n_iterations": self.n_iterations,
            "original_pred": self.original_pred,
            "adversarial_pred": self.adversarial_pred,
            "original_confidence": round(self.original_confidence, 4),
            "adversarial_confidence": round(self.adversarial_confidence, 4),
            "perturbation_norm": round(self.perturbation_norm, 6),
            "attack_success": self.attack_success,
        }


class AdversarialAttack(ABC):
    """
    Abstract base for white-box adversarial attacks on image classifiers.

    Subclasses must implement `attack(x, y)`.
    All attacks assume:
      - x: float tensor in [0, 1], shape (1, C, H, W)
      - y: long tensor, shape (1,), true class label
      - model: nn.Module in eval mode
    """

    def __init__(self, model: nn.Module, epsilon: float = 0.03):
        self.model = model
        self.epsilon = epsilon
        self.model.eval()

    @abstractmethod
    def attack(self, x: torch.Tensor, y: torch.Tensor) -> AttackResult:
        """Run the attack and return an AttackResult."""
        ...

    def predict(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        """Return (class_index, confidence) for input x."""
        self.model.eval()
        with torch.no_grad():
            logits = self.model(x)
            probs = torch.softmax(logits, dim=1)
            pred = probs.argmax(dim=1)
            confidence = probs.max(dim=1).values
        return pred, confidence
