"""
Adversarial Attacks on AI in Transport Infrastructure
======================================================
FGSM and PGD adversarial attack framework for transport CV systems.
Maps to MITRE ATLAS adversarial ML threat taxonomy.

Quick start:
    from src.attacks import FGSM, PGD
    from src.model import load_model, TransportCNN
    from src.evaluator import AttackEvaluator
    from src.atlas import ATLAS_MAPPINGS, print_atlas_report
"""

from .attacks import FGSM, PGD, AttackResult
from .model import TransportCNN, load_model, class_name, GTSRB_CLASSES
from .evaluator import AttackEvaluator

__all__ = [
    "FGSM",
    "PGD",
    "AttackResult",
    "TransportCNN",
    "load_model",
    "class_name",
    "GTSRB_CLASSES",
    "AttackEvaluator",
]

__version__ = "1.0.0"
