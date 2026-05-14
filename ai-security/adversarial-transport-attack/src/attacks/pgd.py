"""
Projected Gradient Descent (PGD)
==================================
Madry et al. (2017) — "Towards Deep Learning Models Resistant to Adversarial Attacks"
https://arxiv.org/abs/1706.06083

PGD is the iterative extension of FGSM. It takes multiple small steps, each
projected back onto the L-inf epsilon-ball around the original image. With
random initialisation (PGD-r), it is considered the strongest first-order attack
and the de-facto standard for adversarial robustness evaluation.

Attack equation (per step):
    x^(t+1) = Π_{B(x,ε)} [ x^(t) + α · sign(∇_x J(θ, x^(t), y)) ]

Where:
    Π_{B(x,ε)} = clip to [x-ε, x+ε] then clip to [0, 1]
    α           = step size (typically ε/n_steps * 2.5)

Transport security context:
    PGD generates stronger adversarial examples than FGSM. At ε=0.03 with
    40 iterations, it can achieve near-100% attack success rate against
    undefended transport CV systems — while remaining visually imperceptible.
"""

from __future__ import annotations

import torch
import torch.nn as nn

from .base import AdversarialAttack, AttackResult


class PGD(AdversarialAttack):
    """
    Projected Gradient Descent — iterative L-inf attack.

    Args:
        model:      PyTorch classifier (nn.Module)
        epsilon:    Maximum L-inf perturbation budget (default 0.03)
        n_steps:    Number of PGD iterations (default 40)
        step_size:  Per-step perturbation (default None → auto: 2.5 * ε / n_steps)
        random_init: Start from random point in epsilon-ball (default True)
    """

    def __init__(
        self,
        model: nn.Module,
        epsilon: float = 0.03,
        n_steps: int = 40,
        step_size: float | None = None,
        random_init: bool = True,
    ):
        super().__init__(model, epsilon)
        self.n_steps = n_steps
        self.step_size = step_size if step_size is not None else 2.5 * epsilon / n_steps
        self.random_init = random_init

    def attack(
        self,
        x: torch.Tensor,
        y: torch.Tensor,
        criterion: nn.Module | None = None,
    ) -> AttackResult:
        """
        Run PGD attack on a single image.

        Args:
            x:         Clean input tensor, shape (1, C, H, W), values in [0, 1]
            y:         True class label tensor, shape (1,)
            criterion: Loss function (default: CrossEntropyLoss)

        Returns:
            AttackResult with original, adversarial, predictions, and metrics
        """
        if criterion is None:
            criterion = nn.CrossEntropyLoss()

        orig_pred, orig_conf = self.predict(x)

        # Initialise adversarial example
        if self.random_init:
            # Random start within L-inf epsilon-ball
            delta = torch.empty_like(x).uniform_(-self.epsilon, self.epsilon)
            x_adv = torch.clamp(x + delta, 0.0, 1.0).detach()
        else:
            x_adv = x.clone().detach()

        # PGD iterations
        for _ in range(self.n_steps):
            x_adv.requires_grad_(True)

            self.model.eval()
            output = self.model(x_adv)
            loss = criterion(output, y)

            self.model.zero_grad()
            loss.backward()

            with torch.no_grad():
                # Gradient step
                grad_sign = x_adv.grad.sign()
                x_adv = x_adv + self.step_size * grad_sign

                # Project back onto L-inf epsilon-ball centred at x
                delta = torch.clamp(x_adv - x, -self.epsilon, self.epsilon)
                x_adv = torch.clamp(x + delta, 0.0, 1.0).detach()

        adv_pred, adv_conf = self.predict(x_adv)
        perturbation_norm = (x_adv - x).abs().max().item()

        return AttackResult(
            original=x.detach().squeeze(0),
            adversarial=x_adv.detach().squeeze(0),
            original_pred=orig_pred.item(),
            adversarial_pred=adv_pred.item(),
            original_confidence=orig_conf.item(),
            adversarial_confidence=adv_conf.item(),
            perturbation_norm=perturbation_norm,
            attack_success=(orig_pred.item() != adv_pred.item()),
            epsilon=self.epsilon,
            attack_name=f"PGD-{self.n_steps}",
            n_iterations=self.n_steps,
        )
