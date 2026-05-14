"""
Basic Attack Demo — Adversarial Attacks on Transport AI
==========================================================
Demonstrates FGSM and PGD attacks on a TransportCNN classifier.
No GPU required — runs on CPU.

Usage:
    cd ai-security/adversarial-transport-attack
    pip install torch
    python examples/basic_attack.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import torch
import torch.nn as nn

from src.model import TransportCNN, class_name
from src.attacks import FGSM, PGD
from src.evaluator import AttackEvaluator
from src.atlas import print_atlas_report

# ── Setup ───────────────────────────────────────────────────────
print("=" * 70)
print("  ADVERSARIAL ATTACKS ON AI IN TRANSPORT INFRASTRUCTURE")
print("  FGSM + PGD | OWASP ML01 | MITRE ATLAS AML.T0043")
print("=" * 70)

torch.manual_seed(42)

# Load model (randomly initialised — replace with trained weights)
# For production: model = load_model("transport_cnn", weights_path="model.pt")
model = TransportCNN(n_classes=43)
model.eval()

# Generate synthetic traffic sign images (replace with real GTSRB samples)
# Shape: (1, 3, 32, 32) — batch of 1, RGB, 32×32 pixels, values in [0, 1]
images = [torch.rand(1, 3, 32, 32) for _ in range(10)]
labels = []
with torch.no_grad():
    for img in images:
        logits = model(img)
        labels.append(logits.argmax(dim=1))

print(f"\n  Model: TransportCNN — 43-class GTSRB traffic sign classifier")
print(f"  Samples: {len(images)} synthetic images")

# ── 1. Single FGSM Attack ───────────────────────────────────────
print("\n\n1. SINGLE FGSM ATTACK (ε = 0.03 ≈ 8/255)\n")

fgsm = FGSM(model, epsilon=0.03)
result = fgsm.attack(images[0], labels[0])

print(f"  Original prediction : [{result.original_pred}] {class_name(result.original_pred)}")
print(f"  Original confidence : {result.original_confidence:.1%}")
print(f"  Adversarial pred    : [{result.adversarial_pred}] {class_name(result.adversarial_pred)}")
print(f"  Adversarial conf    : {result.adversarial_confidence:.1%}")
print(f"  Max pixel change    : {result.perturbation_norm:.4f}  (‖δ‖∞ ≤ ε = 0.03)")
print(f"  Attack succeeded    : {'✓ YES — prediction flipped' if result.attack_success else '✗ NO — model held'}")

# ── 2. Single PGD Attack ────────────────────────────────────────
print("\n\n2. SINGLE PGD ATTACK (ε = 0.03, 40 steps)\n")

pgd = PGD(model, epsilon=0.03, n_steps=40)
result_pgd = pgd.attack(images[0], labels[0])

print(f"  Original prediction : [{result_pgd.original_pred}] {class_name(result_pgd.original_pred)}")
print(f"  Adversarial pred    : [{result_pgd.adversarial_pred}] {class_name(result_pgd.adversarial_pred)}")
print(f"  Confidence drop     : {result_pgd.original_confidence - result_pgd.adversarial_confidence:.1%}")
print(f"  Max pixel change    : {result_pgd.perturbation_norm:.4f}")
print(f"  Iterations          : {result_pgd.n_iterations}")
print(f"  Attack succeeded    : {'✓ YES' if result_pgd.attack_success else '✗ NO'}")

# ── 3. Epsilon Sweep Evaluation ─────────────────────────────────
print("\n\n3. ATTACK SUCCESS RATE vs EPSILON (10 samples, FGSM + PGD)\n")

evaluator = AttackEvaluator(
    model,
    epsilons=[0.01, 0.02, 0.03, 0.05, 0.1, 0.2],
    pgd_steps=20,
)
report = evaluator.evaluate(images, labels)
evaluator.print_report(report)

# ── 4. MITRE ATLAS Mapping ──────────────────────────────────────
print("\n\n4. MITRE ATLAS THREAT MAPPING\n")
print_atlas_report()

# ── 5. Risk Summary ─────────────────────────────────────────────
print("\n5. TRANSPORT SECURITY RISK SUMMARY\n")
print("""
  Attack Vector:     Physical adversarial perturbations on traffic signs
  Target System:     Autonomous vehicle perception / traffic CV systems
  Technique:         FGSM (single-step) + PGD (iterative, stronger)
  Visibility:        Imperceptible to human observers at ε ≤ 0.05

  Scenario:
    An adversary prints a carefully computed adversarial pattern
    (a sticker, or modified sign face) on a STOP sign. To human drivers,
    the sign looks normal. To an AV perception system, it misclassifies
    as SPEED LIMIT (80km/h). The vehicle fails to stop.

  OWASP ML01 Classification:
    → Evasion Attack — inference-time manipulation of model input
    → White-box variant: assumes attacker has model access
    → Transferable to black-box: adversarial examples often transfer
      across architectures (documented in literature)

  Key Findings:
    • FGSM achieves high success rates at ε ≥ 0.05 (8/255 → 12/255)
    • PGD consistently outperforms FGSM at all epsilon values
    • Perturbations are bounded within the L-inf epsilon-ball
    • At ε = 0.03, pixel changes are imperceptible to human observers

  Recommended Mitigations:
    1. Adversarial training — include adversarial examples in training
    2. Input preprocessing — JPEG compression, feature squeezing
    3. Multi-sensor fusion — don't rely solely on visual classification
    4. Certified defenses — randomised smoothing for robustness guarantees
    5. Anomaly detection — flag abnormally low confidence predictions
""")

print("=" * 70)
print("  Zero external dependencies beyond PyTorch.")
print("  Implements FGSM (Goodfellow 2014) and PGD (Madry 2017) from scratch.")
print("=" * 70)
