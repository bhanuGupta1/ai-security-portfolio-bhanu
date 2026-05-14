"""
Attack Evaluator
=================
Runs FGSM and PGD attacks across a range of epsilon values and
produces structured evaluation results — attack success rate, average
confidence drop, and perturbation norms.

Used to generate the risk assessment tables in the README and report.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import torch
import torch.nn as nn

from .attacks.fgsm import FGSM
from .attacks.pgd import PGD
from .attacks.base import AttackResult

if TYPE_CHECKING:
    pass


@dataclass
class EpsilonResult:
    """Aggregate results for attacks at a single epsilon value."""
    epsilon: float
    attack_name: str
    n_samples: int
    n_successful: int
    success_rate: float
    avg_confidence_drop: float
    avg_perturbation_norm: float
    results: list[AttackResult] = field(default_factory=list, repr=False)

    def to_dict(self) -> dict:
        return {
            "epsilon": self.epsilon,
            "attack": self.attack_name,
            "n_samples": self.n_samples,
            "n_successful": self.n_successful,
            "success_rate": round(self.success_rate, 4),
            "avg_confidence_drop": round(self.avg_confidence_drop, 4),
            "avg_perturbation_norm": round(self.avg_perturbation_norm, 6),
        }


class AttackEvaluator:
    """
    Evaluates adversarial attacks across epsilon values and attack types.

    Usage:
        evaluator = AttackEvaluator(model)
        report = evaluator.evaluate(images, labels)
        evaluator.print_report(report)
    """

    DEFAULT_EPSILONS = [0.01, 0.02, 0.03, 0.05, 0.1, 0.2, 0.3]
    DEFAULT_PGD_STEPS = 40

    def __init__(
        self,
        model: nn.Module,
        epsilons: list[float] | None = None,
        pgd_steps: int = DEFAULT_PGD_STEPS,
        criterion: nn.Module | None = None,
    ):
        self.model = model
        self.epsilons = epsilons or self.DEFAULT_EPSILONS
        self.pgd_steps = pgd_steps
        self.criterion = criterion or nn.CrossEntropyLoss()

    def _run_attack_single(
        self,
        attack_cls,
        epsilon: float,
        images: list[torch.Tensor],
        labels: list[torch.Tensor],
        **kwargs,
    ) -> EpsilonResult:
        attack = attack_cls(self.model, epsilon=epsilon, **kwargs)
        results = []

        for x, y in zip(images, labels):
            if x.dim() == 3:
                x = x.unsqueeze(0)
            if y.dim() == 0:
                y = y.unsqueeze(0)
            result = attack.attack(x, y, criterion=self.criterion)
            results.append(result)

        n_successful = sum(r.attack_success for r in results)
        avg_conf_drop = sum(
            r.original_confidence - r.adversarial_confidence for r in results
        ) / len(results)
        avg_norm = sum(r.perturbation_norm for r in results) / len(results)

        return EpsilonResult(
            epsilon=epsilon,
            attack_name=results[0].attack_name if results else "unknown",
            n_samples=len(results),
            n_successful=n_successful,
            success_rate=n_successful / len(results),
            avg_confidence_drop=avg_conf_drop,
            avg_perturbation_norm=avg_norm,
            results=results,
        )

    def evaluate(
        self,
        images: list[torch.Tensor],
        labels: list[torch.Tensor],
        attacks: list[str] | None = None,
    ) -> dict[str, list[EpsilonResult]]:
        """
        Run all attacks across all epsilon values.

        Args:
            images: List of image tensors (each shape: 1×C×H×W or C×H×W)
            labels: List of label tensors (each shape: 1 or scalar)
            attacks: Which attacks to run — ["FGSM", "PGD"] (default: both)

        Returns:
            Dict mapping attack name → list of EpsilonResult (one per epsilon)
        """
        if not images:
            raise ValueError("No images provided for evaluation.")
        attacks = attacks or ["FGSM", "PGD"]
        report: dict[str, list[EpsilonResult]] = {}

        if "FGSM" in attacks:
            report["FGSM"] = [
                self._run_attack_single(FGSM, eps, images, labels)
                for eps in self.epsilons
            ]

        if "PGD" in attacks:
            report["PGD"] = [
                self._run_attack_single(
                    PGD, eps, images, labels,
                    n_steps=self.pgd_steps, random_init=True,
                )
                for eps in self.epsilons
            ]

        return report

    @staticmethod
    def print_report(report: dict[str, list[EpsilonResult]]) -> None:
        """Print a formatted attack success rate table."""
        print("\n" + "=" * 72)
        print("  ADVERSARIAL ATTACK EVALUATION — Transport CV Model")
        print("=" * 72)
        print(f"  {'Attack':<10} {'ε':>8} {'Success':>10} {'Conf Drop':>12} {'‖δ‖∞':>10}")
        print("  " + "-" * 54)

        for attack_name, results in report.items():
            for r in results:
                bar = "█" * int(r.success_rate * 20)
                print(
                    f"  {attack_name:<10} {r.epsilon:>8.3f} "
                    f"{r.success_rate:>9.1%} "
                    f"{r.avg_confidence_drop:>12.4f} "
                    f"{r.avg_perturbation_norm:>10.4f}  {bar}"
                )
            print()

        print("=" * 72)
        print(
            "  ε = perturbation budget (L-inf). "
            "‖δ‖∞ = actual max pixel change.\n"
        )

    @staticmethod
    def to_json(report: dict[str, list[EpsilonResult]]) -> str:
        """Serialise the full report to JSON."""
        data = {
            attack: [r.to_dict() for r in results]
            for attack, results in report.items()
        }
        return json.dumps(data, indent=2)
