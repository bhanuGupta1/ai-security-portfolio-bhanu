"""
Tests for AttackEvaluator.
"""

import pytest
import json

from src.evaluator import AttackEvaluator, EpsilonResult


class TestEvaluatorBasic:

    def test_evaluate_returns_dict(self, tiny_model, batch_images, batch_labels):
        evaluator = AttackEvaluator(tiny_model, epsilons=[0.1, 0.3])
        report = evaluator.evaluate(batch_images, batch_labels, attacks=["FGSM"])
        assert isinstance(report, dict)
        assert "FGSM" in report

    def test_evaluate_fgsm_and_pgd(self, tiny_model, batch_images, batch_labels):
        evaluator = AttackEvaluator(tiny_model, epsilons=[0.1], pgd_steps=3)
        report = evaluator.evaluate(batch_images, batch_labels, attacks=["FGSM", "PGD"])
        assert "FGSM" in report
        assert "PGD" in report

    def test_epsilon_results_count(self, tiny_model, batch_images, batch_labels):
        epsilons = [0.01, 0.05, 0.1]
        evaluator = AttackEvaluator(tiny_model, epsilons=epsilons)
        report = evaluator.evaluate(batch_images, batch_labels, attacks=["FGSM"])
        assert len(report["FGSM"]) == len(epsilons)

    def test_epsilon_result_type(self, tiny_model, batch_images, batch_labels):
        evaluator = AttackEvaluator(tiny_model, epsilons=[0.1])
        report = evaluator.evaluate(batch_images, batch_labels, attacks=["FGSM"])
        assert isinstance(report["FGSM"][0], EpsilonResult)


class TestEpsilonResult:

    def test_n_samples_matches_input(self, tiny_model, batch_images, batch_labels):
        evaluator = AttackEvaluator(tiny_model, epsilons=[0.1])
        report = evaluator.evaluate(batch_images, batch_labels, attacks=["FGSM"])
        result = report["FGSM"][0]
        assert result.n_samples == len(batch_images)

    def test_success_rate_in_range(self, tiny_model, batch_images, batch_labels):
        evaluator = AttackEvaluator(tiny_model, epsilons=[0.1])
        report = evaluator.evaluate(batch_images, batch_labels, attacks=["FGSM"])
        result = report["FGSM"][0]
        assert 0.0 <= result.success_rate <= 1.0

    def test_n_successful_consistent(self, tiny_model, batch_images, batch_labels):
        evaluator = AttackEvaluator(tiny_model, epsilons=[0.1])
        report = evaluator.evaluate(batch_images, batch_labels, attacks=["FGSM"])
        result = report["FGSM"][0]
        assert result.n_successful == int(result.success_rate * result.n_samples)

    def test_to_dict_keys(self, tiny_model, batch_images, batch_labels):
        evaluator = AttackEvaluator(tiny_model, epsilons=[0.1])
        report = evaluator.evaluate(batch_images, batch_labels, attacks=["FGSM"])
        d = report["FGSM"][0].to_dict()
        for key in ["epsilon", "attack", "n_samples", "n_successful", "success_rate"]:
            assert key in d


class TestEvaluatorEdgeCases:

    def test_empty_images_raises(self, tiny_model):
        evaluator = AttackEvaluator(tiny_model, epsilons=[0.1])
        with pytest.raises(ValueError, match="No images"):
            evaluator.evaluate([], [], attacks=["FGSM"])

    def test_single_image(self, tiny_model, sample_image, sample_label):
        evaluator = AttackEvaluator(tiny_model, epsilons=[0.1])
        report = evaluator.evaluate([sample_image], [sample_label], attacks=["FGSM"])
        assert report["FGSM"][0].n_samples == 1


class TestEvaluatorJSON:

    def test_to_json_valid(self, tiny_model, batch_images, batch_labels):
        evaluator = AttackEvaluator(tiny_model, epsilons=[0.1])
        report = evaluator.evaluate(batch_images, batch_labels, attacks=["FGSM"])
        json_str = AttackEvaluator.to_json(report)
        data = json.loads(json_str)
        assert "FGSM" in data
        assert isinstance(data["FGSM"], list)


class TestEvaluatorModel:

    def test_transport_cnn_works_with_evaluator(self, batch_images, batch_labels):
        from src.model import TransportCNN
        model = TransportCNN(n_classes=3)
        import torch
        # Re-label for 3-class model
        import torch.nn as nn
        model.eval()
        labels = []
        with torch.no_grad():
            for img in batch_images:
                logits = model(img)
                labels.append(logits.argmax(dim=1))

        evaluator = AttackEvaluator(model, epsilons=[0.1])
        report = evaluator.evaluate(batch_images, labels, attacks=["FGSM"])
        assert "FGSM" in report
