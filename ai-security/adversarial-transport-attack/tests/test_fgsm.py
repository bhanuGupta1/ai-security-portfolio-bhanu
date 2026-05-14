"""
Tests for FGSM attack.
All tests use TinyCNN (CPU, no downloads, no GPU required).
"""

import pytest
import torch

from src.attacks.fgsm import FGSM
from src.attacks.base import AttackResult


class TestFGSMOutput:
    """AttackResult structure and type correctness."""

    def test_returns_attack_result(self, tiny_model, sample_image, sample_label):
        fgsm = FGSM(tiny_model, epsilon=0.1)
        result = fgsm.attack(sample_image, sample_label)
        assert isinstance(result, AttackResult)

    def test_attack_name(self, tiny_model, sample_image, sample_label):
        fgsm = FGSM(tiny_model, epsilon=0.1)
        result = fgsm.attack(sample_image, sample_label)
        assert result.attack_name == "FGSM"

    def test_n_iterations_is_one(self, tiny_model, sample_image, sample_label):
        fgsm = FGSM(tiny_model, epsilon=0.1)
        result = fgsm.attack(sample_image, sample_label)
        assert result.n_iterations == 1

    def test_epsilon_recorded(self, tiny_model, sample_image, sample_label):
        fgsm = FGSM(tiny_model, epsilon=0.05)
        result = fgsm.attack(sample_image, sample_label)
        assert result.epsilon == pytest.approx(0.05)


class TestFGSMPerturbation:
    """Perturbation bounds and image validity."""

    def test_adversarial_differs_from_original(self, tiny_model, sample_image, sample_label):
        fgsm = FGSM(tiny_model, epsilon=0.1)
        result = fgsm.attack(sample_image, sample_label)
        # Adversarial image must differ from original
        assert not torch.allclose(result.original, result.adversarial)

    def test_perturbation_within_epsilon(self, tiny_model, sample_image, sample_label):
        epsilon = 0.05
        fgsm = FGSM(tiny_model, epsilon=epsilon)
        result = fgsm.attack(sample_image, sample_label)
        max_diff = (result.adversarial - result.original).abs().max().item()
        assert max_diff <= epsilon + 1e-6, (
            f"Max perturbation {max_diff:.6f} exceeds epsilon {epsilon}"
        )

    def test_adversarial_in_valid_range(self, tiny_model, sample_image, sample_label):
        fgsm = FGSM(tiny_model, epsilon=0.3)
        result = fgsm.attack(sample_image, sample_label)
        assert result.adversarial.min() >= -1e-6
        assert result.adversarial.max() <= 1.0 + 1e-6

    def test_perturbation_norm_matches_epsilon(self, tiny_model, sample_image, sample_label):
        epsilon = 0.1
        fgsm = FGSM(tiny_model, epsilon=epsilon)
        result = fgsm.attack(sample_image, sample_label)
        assert result.perturbation_norm <= epsilon + 1e-6

    def test_shapes_preserved(self, tiny_model, sample_image, sample_label):
        fgsm = FGSM(tiny_model, epsilon=0.1)
        result = fgsm.attack(sample_image, sample_label)
        # squeeze(0) is applied in attack — result is (C, H, W)
        assert result.original.shape == result.adversarial.shape


class TestFGSMLargeEpsilon:
    """High epsilon should achieve very high success rate."""

    def test_high_epsilon_causes_misclassification(self, tiny_model, batch_images, batch_labels):
        """At ε=0.5, FGSM should flip most predictions on a tiny model."""
        fgsm = FGSM(tiny_model, epsilon=0.5)
        successes = 0
        for x, y in zip(batch_images, batch_labels):
            result = fgsm.attack(x, y)
            if result.attack_success:
                successes += 1
        # At very high epsilon, at least some attacks should succeed
        assert successes >= 1, "Expected at least 1 successful attack at ε=0.5"


class TestFGSMConfidence:
    """Confidence values are valid probabilities."""

    def test_original_confidence_in_range(self, tiny_model, sample_image, sample_label):
        fgsm = FGSM(tiny_model, epsilon=0.1)
        result = fgsm.attack(sample_image, sample_label)
        assert 0.0 <= result.original_confidence <= 1.0

    def test_adversarial_confidence_in_range(self, tiny_model, sample_image, sample_label):
        fgsm = FGSM(tiny_model, epsilon=0.1)
        result = fgsm.attack(sample_image, sample_label)
        assert 0.0 <= result.adversarial_confidence <= 1.0


class TestFGSMToDict:
    """to_dict() serialisation."""

    def test_to_dict_keys(self, tiny_model, sample_image, sample_label):
        fgsm = FGSM(tiny_model, epsilon=0.1)
        result = fgsm.attack(sample_image, sample_label)
        d = result.to_dict()
        for key in ["attack", "epsilon", "attack_success", "original_pred", "adversarial_pred"]:
            assert key in d

    def test_attack_success_is_bool(self, tiny_model, sample_image, sample_label):
        fgsm = FGSM(tiny_model, epsilon=0.1)
        result = fgsm.attack(sample_image, sample_label)
        assert isinstance(result.attack_success, bool)
