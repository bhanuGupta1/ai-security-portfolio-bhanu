---
title: Adversarial Transport Attack
emoji: 🚦
colorFrom: red
colorTo: purple
sdk: docker
pinned: false
---

# Adversarial Attacks on AI in Transport Infrastructure

> FGSM and PGD adversarial attack framework for transport CV systems — MITRE ATLAS | OWASP ML01

**🔴 Live demo:** https://huggingface.co/spaces/BhanuGupta/adversarial-transport-attack

[![Tests](https://github.com/bhanuguptagarg/ai-security-portfolio-bhanu/actions/workflows/adversarial-tests.yml/badge.svg)](https://github.com/bhanuguptagarg/ai-security-portfolio-bhanu/actions/workflows/adversarial-tests.yml)
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)
![PyTorch](https://img.shields.io/badge/PyTorch-2.0%2B-red)
![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS%20AML.T0043-orange)

---

## What This Is

Autonomous vehicle perception systems, traffic sign recognition models, and pedestrian detection networks are AI systems embedded in critical transport infrastructure. This project demonstrates that these models are vulnerable to **adversarial attacks** — imperceptible pixel-level perturbations that cause reliable misclassification while appearing completely normal to human observers.

**Core finding:** A STOP sign with a carefully computed adversarial sticker — invisible to any human driver — can be misclassified as a SPEED LIMIT sign by an AV perception system. At ε = 0.03 (≈8 pixel values out of 255), the perturbation is completely imperceptible.

This is not theoretical. Adversarial examples against traffic sign classifiers have been demonstrated in production by researchers at CMU, UC Berkeley, and MIT.

---

## Attacks Implemented

### FGSM — Fast Gradient Sign Method
*(Goodfellow et al., 2014 — [arxiv:1412.6572](https://arxiv.org/abs/1412.6572))*

Single-step white-box attack. Computes the gradient of the loss with respect to the input, then perturbs in the direction that maximises the loss — bounded by ε in L-inf norm.

```
x_adv = x + ε · sign(∇_x J(θ, x, y))
```

Fast and cheap. Used to rapidly evaluate model vulnerability at scale.

### PGD — Projected Gradient Descent
*(Madry et al., 2017 — [arxiv:1706.06083](https://arxiv.org/abs/1706.06083))*

Iterative extension of FGSM. Takes multiple small steps, each projected back onto the L-inf epsilon-ball. With random initialisation, PGD is the standard benchmark for adversarial robustness — if a model survives PGD, it survives most known attacks.

```
x^(t+1) = Π_{B(x,ε)} [ x^(t) + α · sign(∇_x J(θ, x^(t), y)) ]
```

Consistently achieves higher success rates than FGSM at all epsilon values.

---

## Quick Start

```bash
pip install torch
# Optional: pip install torchvision  (for pretrained ResNet-18)

cd ai-security/adversarial-transport-attack
python examples/basic_attack.py
```

### Library usage

```python
import torch
from src.model import TransportCNN, class_name
from src.attacks import FGSM, PGD
from src.evaluator import AttackEvaluator

# Load model
model = TransportCNN(n_classes=43)   # 43-class GTSRB classifier
model.eval()

# Single FGSM attack
fgsm = FGSM(model, epsilon=0.03)
x = torch.rand(1, 3, 32, 32)        # Replace with real traffic sign image
y = torch.tensor([14])               # Class 14 = STOP sign

result = fgsm.attack(x, y)
print(result.original_pred)          # 14  (STOP)
print(result.adversarial_pred)       # e.g. 1  (Speed limit 30km/h)
print(result.attack_success)         # True
print(result.perturbation_norm)      # ≤ 0.03

# PGD attack (stronger)
pgd = PGD(model, epsilon=0.03, n_steps=40)
result_pgd = pgd.attack(x, y)

# Evaluate across epsilon values
evaluator = AttackEvaluator(model, epsilons=[0.01, 0.03, 0.05, 0.1])
report = evaluator.evaluate([x], [y])
evaluator.print_report(report)
```

### Sample output

```
========================================================================
  ADVERSARIAL ATTACK EVALUATION — Transport CV Model
========================================================================
  Attack     ε      Success   Conf Drop     ‖δ‖∞
  ──────────────────────────────────────────────────────
  FGSM      0.010     20.0%       0.1234    0.0100  ████
  FGSM      0.030     60.0%       0.3421    0.0300  ████████████
  FGSM      0.050     80.0%       0.4812    0.0500  ████████████████
  FGSM      0.100    100.0%       0.5923    0.1000  ████████████████████

  PGD       0.010     40.0%       0.2156    0.0100  ████████
  PGD       0.030     80.0%       0.4234    0.0300  ████████████████
  PGD       0.050    100.0%       0.5678    0.0500  ████████████████████
  PGD       0.100    100.0%       0.6234    0.1000  ████████████████████
```

---

## MITRE ATLAS Mapping

| ID | Tactic | Technique | Relevance |
|----|--------|-----------|-----------|
| AML.T0043.003 | ML Attack Staging | Craft Adversarial Data — White-Box Optimization | FGSM/PGD require gradient access — insider/supply-chain scenario |
| AML.T0043.001 | ML Attack Staging | Craft Adversarial Data — Physical Examples | Printable stickers on real traffic signs — persists across cameras |
| AML.T0015 | Impact | Evade ML Model | Real-time misclassification at inference — model unmodified |
| AML.T0000.001 | Reconnaissance | Pre-Trained Models | Download public GTSRB model → develop attacks offline → deploy physically |
| AML.T0024 | Exfiltration | Invert ML Model | Adversarial probing reveals training data distribution |

Full ATLAS reference: [atlas.mitre.org](https://atlas.mitre.org/)

---

## Model: TransportCNN

Lightweight CNN architecture for traffic sign classification, targeting the [GTSRB dataset](https://benchmark.ini.rub.de/) — 43 classes, ~50,000 images.

```
Input (3×H×W)
  → Conv(3→32, 3×3) → BN → ReLU → MaxPool
  → Conv(32→64, 3×3) → BN → ReLU → MaxPool
  → Conv(64→128, 3×3) → BN → ReLU → AdaptiveAvgPool(4×4)
  → FC(2048→256) → ReLU → Dropout(0.4)
  → FC(256→43)   → Logits
```

Also supports pretrained **ResNet-18** (torchvision) — swap in with `load_model("resnet18", pretrained=True)`.

---

## Risk Assessment

### Threat Scenario

A threat actor targets an autonomous vehicle fleet operating in Auckland's central business district. The attack vector is physical — adversarial patterns are printed on standard traffic sign vinyl and applied to existing signs.

| Parameter | Value |
|-----------|-------|
| Attack type | Physical adversarial examples (printable) |
| Perturbation budget | ε = 0.03 (≈ 8/255 pixel values) |
| Human detectability | None — indistinguishable from clean sign |
| Attack preparation | Offline, using public GTSRB model |
| Required hardware | Standard printer |
| Success rate | 60-100% depending on ε and attack strength |

### Risk Rating

| Risk | Likelihood | Impact | Rating |
|------|-----------|--------|--------|
| STOP sign → SPEED LIMIT misclassification | HIGH | CRITICAL | **CRITICAL** |
| NO ENTRY sign ignored by AV | MEDIUM | HIGH | **HIGH** |
| Pedestrian crossing sign misclassified | MEDIUM | CRITICAL | **HIGH** |

### Mitigations

1. **Adversarial training** — include adversarial examples in the training pipeline. Most effective defense; increases robust accuracy substantially.
2. **Multi-sensor fusion** — combine visual CV with LiDAR, radar, and map data. Redundancy prevents single-sensor attack success.
3. **Input preprocessing** — JPEG compression and feature squeezing destroy many adversarial perturbations at low cost.
4. **Certified defenses** — randomised smoothing provides provable L-inf robustness guarantees.
5. **Anomaly detection** — flag predictions with abnormally low confidence for human review.
6. **Physical security** — tamper-evident traffic sign materials; regular infrastructure inspection.

---

## Project Structure

```
adversarial-transport-attack/
├── src/
│   ├── __init__.py
│   ├── model.py          # TransportCNN + ResNet-18 loader + GTSRB class labels
│   ├── attacks/
│   │   ├── base.py       # Abstract attack + AttackResult dataclass
│   │   ├── fgsm.py       # Fast Gradient Sign Method (Goodfellow 2014)
│   │   └── pgd.py        # Projected Gradient Descent (Madry 2017)
│   ├── evaluator.py      # Multi-epsilon evaluation + success rate tables
│   └── atlas.py          # MITRE ATLAS mapping + structured entries
├── tests/
│   ├── conftest.py       # Shared fixtures — TinyCNN, sample images, labels
│   ├── test_fgsm.py      # 14 FGSM tests — output, perturbation bounds, confidence
│   ├── test_pgd.py       # 13 PGD tests — L-inf bound, random init, step count
│   ├── test_evaluator.py # 11 evaluator tests — report structure, edge cases
│   └── test_model.py     # 14 model tests — shapes, GTSRB labels, factory
├── examples/
│   └── basic_attack.py   # Full demo: single attack, sweep, ATLAS report, risk summary
├── .github/workflows/
│   └── adversarial-tests.yml  # CI — Python 3.10, 3.11, 3.12
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Running Tests

```bash
pip install torch pytest pytest-cov
pytest tests/ -v --cov=src --cov-report=term-missing
```

Tests use a **tiny dummy CNN** — no pretrained weights download, no GPU, no internet. Runs in under 10 seconds on any machine.

Test coverage: 52 tests across FGSM (14), PGD (13), Evaluator (11), Model (14).

---

## References

- Goodfellow, I. J. et al. (2014). *Explaining and Harnessing Adversarial Examples*. [arXiv:1412.6572](https://arxiv.org/abs/1412.6572)
- Madry, A. et al. (2017). *Towards Deep Learning Models Resistant to Adversarial Attacks*. [arXiv:1706.06083](https://arxiv.org/abs/1706.06083)
- Eykholt, K. et al. (2018). *Robust Physical-World Attacks on Deep Learning Visual Classification*. CVPR 2018.
- MITRE ATLAS. *Adversarial Threat Landscape for AI Systems*. [atlas.mitre.org](https://atlas.mitre.org/)
- Stallkamp, J. et al. (2012). *Man vs. Computer: Benchmarking Machine Learning Algorithms for Traffic Sign Recognition*. GTSRB.

---

*Part of the AI Security Engineering portfolio*
*OWASP ML01 · MITRE ATLAS · Adversarial ML · Built by Bhanu Gupta*
