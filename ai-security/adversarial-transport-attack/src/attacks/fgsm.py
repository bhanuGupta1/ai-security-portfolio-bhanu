"""
Fast Gradient Sign Method (FGSM)
=================================
Goodfellow et al. (2014) — "Explaining and Harnessing Adversarial Examples"
https://arxiv.org/abs/1412.6572

FGSM is a single-step white-box attack. It computes the gradient of the loss
with respect to the input image, then perturbs the image in the direction that
maximises the loss — bounded by epsilon in L-inf norm.

Attack equation:
    x_adv = x + ε · sign(∇_x J(θ, x, y))

Transport security context:
    A single FGSM perturbation on a traffic sign image (imperceptible to human
    eye at ε ≤ 0.05) can cause a transport CV system to misclassify a STOP
    sign as a SPEED LIMIT sign or a pedestrian crossing marker as background.
"""

from __future__ import annotations

import torch
import torch.nn as nn

from .base import AdversarialAttack, AttackResult


class FGSM(AdversarialAttack):
    """
    Fast Gradient Sign Method — single-step L-inf attack.

    Args:
        model:   PyTorch classifier (nn.Module)
        epsilon: Maximum L-inf perturbation budget (default 0.03 ≈ 8/255)
    """

    def attack(
        self,
        x: torch.Tensor,
        y: torch.Tensor,
        criterion: nn.Module | None = None,
    ) -> AttackResult:
        """
        Run FGSM attack on a single image.

        Args:
            x:         Clean input tensor, shape (1, C, H, W), values in [0, 1]
            y:         True class label tensor, shape (1,)
            criterion: Loss function (default: CrossEntropyLoss)

        Returns:
            AttackResult with original, adversarial, predictions, and metrics
        """
        if criterion is None:
            criterion = nn.CrossEntropyLoss()

        # Step 1: Record clean prediction
        orig_pred, orig_conf = self.predict(x)

        # Step 2: Forward pass with gradient tracking on input
        x_adv = x.clone().detach().requires_grad_(True)
        self.model.eval()
        output = self.model(x_adv)
        loss = criterion(output, y)

        # Step 3: Backward — compute ∇_x J
        self.model.zero_grad()
        loss.backward()

        # Step 4: Apply signed gradient perturbation
        with torch.no_grad():
            perturbation = self.epsilon * x_adv.grad.sign()
            x_adv_clamped = torch.clamp(x + perturbation, 0.0, 1.0)

        # Step 5: Evaluate adversarial example
        adv_pred, adv_conf = self.predict(x_adv_clamped)

        return AttackResult(
            original=x.detach().squeeze(0),
            adversarial=x_adv_clamped.detach().squeeze(0),
            original_pred=orig_pred.item(),
            adversarial_pred=adv_pred.item(),
            original_confidence=orig_conf.item(),
            adversarial_confidence=adv_conf.item(),
            perturbation_norm=perturbation.abs().max().item(),
            attack_success=(orig_pred.item() != adv_pred.item()),
            epsilon=self.epsilon,
            attack_name="FGSM",
            n_iterations=1,
        )
