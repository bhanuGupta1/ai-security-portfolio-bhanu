from .base import AdversarialAttack, AttackResult
from .fgsm import FGSM
from .pgd import PGD

__all__ = ["AdversarialAttack", "AttackResult", "FGSM", "PGD"]
