"""
Tests for TransportCNN model and load_model factory.
"""

import pytest
import torch

from src.model import TransportCNN, load_model, class_name, GTSRB_CLASSES


class TestTransportCNN:

    def test_output_shape_43_classes(self):
        model = TransportCNN(n_classes=43)
        x = torch.rand(1, 3, 32, 32)
        out = model(x)
        assert out.shape == (1, 43)

    def test_output_shape_custom_classes(self):
        model = TransportCNN(n_classes=10)
        x = torch.rand(2, 3, 32, 32)
        out = model(x)
        assert out.shape == (2, 10)

    def test_accepts_different_input_sizes(self):
        model = TransportCNN(n_classes=43)
        for size in [16, 32, 64]:
            x = torch.rand(1, 3, size, size)
            out = model(x)
            assert out.shape == (1, 43)

    def test_output_is_logits_not_probs(self):
        """Logits should not all be in [0, 1] — they're pre-softmax."""
        model = TransportCNN(n_classes=43)
        x = torch.rand(1, 3, 32, 32)
        out = model(x)
        # At least some logits should be outside [0, 1]
        assert not torch.all((out >= 0) & (out <= 1))

    def test_eval_mode(self):
        model = TransportCNN()
        model.eval()
        assert not model.training

    def test_forward_deterministic_in_eval(self):
        model = TransportCNN()
        model.eval()
        x = torch.rand(1, 3, 32, 32)
        with torch.no_grad():
            out1 = model(x)
            out2 = model(x)
        assert torch.allclose(out1, out2)

    def test_batch_forward(self):
        model = TransportCNN(n_classes=43)
        x = torch.rand(8, 3, 32, 32)
        out = model(x)
        assert out.shape == (8, 43)


class TestLoadModel:

    def test_load_transport_cnn(self):
        model = load_model("transport_cnn", n_classes=43, device="cpu")
        assert isinstance(model, TransportCNN)

    def test_load_model_in_eval_mode(self):
        model = load_model("transport_cnn", device="cpu")
        assert not model.training

    def test_load_invalid_architecture_raises(self):
        with pytest.raises(ValueError, match="Unknown architecture"):
            load_model("unknown_arch")

    def test_custom_n_classes(self):
        model = load_model("transport_cnn", n_classes=10)
        x = torch.rand(1, 3, 32, 32)
        out = model(x)
        assert out.shape == (1, 10)


class TestGTSRBLabels:

    def test_class_name_known_label(self):
        assert class_name(14) == "Stop"
        assert class_name(17) == "No entry"
        assert class_name(0) == "Speed limit (20km/h)"

    def test_class_name_unknown_label(self):
        result = class_name(999)
        assert "999" in result

    def test_all_43_classes_defined(self):
        assert len(GTSRB_CLASSES) == 43

    def test_labels_zero_to_42(self):
        for i in range(43):
            assert i in GTSRB_CLASSES
