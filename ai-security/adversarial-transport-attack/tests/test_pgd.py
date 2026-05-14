"""
Tests for PGD attack.
All tests use TinyCNN (CPU, no downloads, no GPU required).
"""

import pytest
import torch

from src.attacks.pgd import PGD
from src.attacks.base import AttackResult


class TestPGDOutput:
    """AttackResult structure and type correctness."""

    def test_returns_attack_result(self, tiny_model, sample_image, sample_label):
        pgd = PGD(tiny_model, epsilon=0.1, n_steps=5)
        result = pgd.attack(sample_image, sample_label)
        assert isinstance(result, AttackResult)

    def test_attack_name_includes_steps(self, tiny_model, sample_image, sample_label):
        pgd = PGD(tiny_model, epsilon=0.1, n_steps=10)
        result = pgd.attack(sample_image, sample_label)
        assert "PGD" in result.attack_name
        assert "10" in result.attack_name

    def test_n_iterations_recorded(self, tiny_model, sample_image, sample_label):
        pgd = PGD(tiny_model, epsilon=0.1, n_steps=7)
        result = pgd.attack(sample_image, sample_label)
        assert result.n_iterations == 7

    def test_epsilon_recorded(self, tiny_model, sample_image, sample_label):
        pgd = PGD(tiny_model, epsilon=0.04, n_steps=5)
        result = pgd.attack(sample_image, sample_label)
        assert result.epsilon == pytest.approx(0.04)


class TestPGDPerturbation:
    """Perturbation bounds — PGD must respect L-inf epsilon-ball."""

    def test_adversarial_differs_from_original(self, tiny_model, sample_image, sample_label):
        pgd = PGD(tiny_model, epsilon=0.1, n_steps=5)
        result = pgd.attack(sample_image, sample_label)
        assert not torch.allclose(result.original, result.adversarial)

    def test_perturbation_within_epsilon(self, tiny_model, sample_image, sample_label):
        epsilon = 0.05
        pgd = PGD(tiny_model, epsilon=epsilon, n_steps=10)
        result = pgd.attack(sample_image, sample_label)
        max_diff = (result.adversarial - result.original).abs().max().item()
        assert max_diff <= epsilon + 1e-5, (
            f"PGD violated L-inf bound: {max_diff:.6f} > {epsilon}"
        )

    def test_adversarial_in_valid_range(self, tiny_model, sample_image, sample_label):
        pgd = PGD(tiny_model, epsilon=0.3, n_steps=5)
        result = pgd.attack(sample_image, sample_label)
        assert result.adversarial.min() >= -1e-6
        assert result.adversarial.max() <= 1.0 + 1e-6

    def test_shapes_preserved(self, tiny_model, sample_image, sample_label):
        pgd = PGD(tiny_model, epsilon=0.1, n_steps=5)
        result = pgd.attack(sample_image, sample_label)
        assert result.original.shape == result.adversarial.shape

    @pytest.mark.parametrize("epsilon", [0.01, 0.05, 0.1, 0.3])
    def test_epsilon_bound_across_values(self, tiny_model, sample_image, sample_label, epsilon):
        pgd = PGD(tiny_model, epsilon=epsilon, n_steps=5)
        result = pgd.attack(sample_image, sample_label)
        max_diff = (result.adversarial - result.original).abs().max().item()
        assert max_diff <= epsilon + 1e-5


class TestPGDStrongerThanFGSM:
    """PGD with many steps should be at least as strong as FGSM."""

    def test_pgd_high_epsilon_succeeds(self, tiny_model, batch_images, batch_labels):
        pgd = PGD(tiny_model, epsilon=0.5, n_steps=20)
        successes = 0
        for x, y in zip(batch_images, batch_labels):
            result = pgd.attack(x, y)
            if result.attack_success:
                successes += 1
        assert successes >= 1

    def test_more_steps_does_not_violate_bounds(self, tiny_model, sample_image, sample_label):
        epsilon = 0.05
        pgd = PGD(tiny_model, epsilon=epsilon, n_steps=50)
        result = pgd.attack(sample_image, sample_label)
        max_diff = (result.adversarial - result.original).abs().max().item()
        assert max_diff <= epsilon + 1e-5


class TestPGDRandomInit:
    """Random vs deterministic initialisation."""

    def test_random_init_produces_valid_result(self, tiny_model, sample_image, sample_label):
        pgd = PGD(tiny_model, epsilon=0.1, n_steps=5, random_init=True)
        result = pgd.attack(sample_image, sample_label)
        assert isinstance(result, AttackResult)

    def test_deterministic_init_produces_valid_result(self, tiny_model, sample_image, sample_label):
        pgd = PGD(tiny_model, epsilon=0.1, n_steps=5, random_init=False)
        result = pgd.attack(sample_image, sample_label)
        assert isinstance(result, AttackResult)


class TestPGDConfidence:
    def test_confidence_in_range(self, tiny_model, sample_image, sample_label):
        pgd = PGD(tiny_model, epsilon=0.1, n_steps=5)
        result = pgd.attack(sample_image, sample_label)
        assert 0.0 <= result.original_confidence <= 1.0
        assert 0.0 <= result.adversarial_confidence <= 1.0
