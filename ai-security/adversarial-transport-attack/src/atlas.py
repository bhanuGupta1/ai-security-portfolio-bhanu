"""
MITRE ATLAS Mapping
=====================
Maps adversarial attack techniques demonstrated in this project to the
MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems)
framework — the authoritative taxonomy for ML security threats.

Reference: https://atlas.mitre.org/
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ATLASEntry:
    """A single MITRE ATLAS tactic/technique entry."""
    tactic: str
    tactic_id: str
    technique: str
    technique_id: str
    subtechnique: str | None
    subtechnique_id: str | None
    description: str
    relevance: str          # How it applies to this project
    mitigations: list[str]

    def to_dict(self) -> dict:
        return {
            "tactic": self.tactic,
            "tactic_id": self.tactic_id,
            "technique": self.technique,
            "technique_id": self.technique_id,
            "subtechnique": self.subtechnique,
            "subtechnique_id": self.subtechnique_id,
            "description": self.description,
            "relevance": self.relevance,
            "mitigations": self.mitigations,
        }


# ── ATLAS Mappings for this project ───────────────────────────────────────
ATLAS_MAPPINGS: list[ATLASEntry] = [
    ATLASEntry(
        tactic="ML Attack Staging",
        tactic_id="ATA0000",
        technique="Craft Adversarial Data",
        technique_id="AML.T0043",
        subtechnique="White-Box Optimization",
        subtechnique_id="AML.T0043.003",
        description=(
            "Adversary crafts inputs specifically designed to cause model "
            "misclassification. White-box assumes full access to model weights "
            "and architecture — enabling gradient-based attacks (FGSM, PGD)."
        ),
        relevance=(
            "FGSM and PGD both require gradient access — the attacker computes "
            "∇_x J(θ, x, y) directly. In transport contexts, this mirrors an "
            "insider threat or supply-chain compromise scenario where the "
            "adversary has model access."
        ),
        mitigations=[
            "Adversarial training (include adversarial examples in training set)",
            "Model hardening with certified defenses",
            "Input preprocessing (feature squeezing, JPEG compression)",
            "Ensemble models — harder to craft universal perturbations",
        ],
    ),
    ATLASEntry(
        tactic="ML Attack Staging",
        tactic_id="ATA0000",
        technique="Craft Adversarial Data",
        technique_id="AML.T0043",
        subtechnique="Physical Adversarial Examples",
        subtechnique_id="AML.T0043.001",
        description=(
            "Adversarial perturbations applied to physical objects in the real "
            "world — printed on traffic signs, road markings, or worn on clothing. "
            "The attack persists across cameras, lighting conditions, and viewpoints."
        ),
        relevance=(
            "The perturbations demonstrated here (ε ≤ 0.05) translate directly "
            "to printable adversarial stickers on physical traffic signs. This is "
            "the key transport infrastructure threat — stop signs misclassified as "
            "speed limit signs by AV perception stacks."
        ),
        mitigations=[
            "Physical security of traffic infrastructure (tamper-evident signage)",
            "Multi-sensor fusion (don't rely solely on visual CV)",
            "Anomaly detection for unusual model confidence patterns",
            "Regular model auditing with adversarial test sets",
        ],
    ),
    ATLASEntry(
        tactic="Impact",
        tactic_id="ATA0009",
        technique="Evade ML Model",
        technique_id="AML.T0015",
        subtechnique=None,
        subtechnique_id=None,
        description=(
            "Adversary modifies input to cause the ML model to misclassify it. "
            "Evasion differs from poisoning — it occurs at inference time against "
            "an already-deployed model, with no modification to the model itself."
        ),
        relevance=(
            "FGSM and PGD are evasion attacks: the transport CV model is unmodified. "
            "The adversary controls only the input (the image/sign). In AV systems, "
            "successful evasion causes dangerous misclassification in real time."
        ),
        mitigations=[
            "Certified robustness guarantees (randomised smoothing)",
            "Adversarial detection classifiers as pre-filter",
            "Confidence thresholding — reject low-confidence predictions",
            "Human-in-the-loop for safety-critical decisions",
        ],
    ),
    ATLASEntry(
        tactic="Reconnaissance",
        tactic_id="ATA0001",
        technique="Search for Victim's Publicly Available Research Materials",
        technique_id="AML.T0000",
        subtechnique="Pre-Trained Models",
        subtechnique_id="AML.T0000.001",
        description=(
            "Adversary locates and downloads the victim's ML model or a similar "
            "public model to develop and test adversarial examples offline before "
            "deploying them against the production system."
        ),
        relevance=(
            "Transport CV models (GTSRB classifiers, pedestrian detectors) are "
            "widely published on model hubs. An adversary downloads the public "
            "architecture, trains attacks locally, then deploys physical perturbations "
            "against the production AV fleet — with zero direct model access."
        ),
        mitigations=[
            "Model obfuscation (don't publish exact architecture/weights)",
            "Watermarking deployed models for traceability",
            "Transfer attack hardening (robustness to black-box attacks)",
        ],
    ),
    ATLASEntry(
        tactic="Exfiltration",
        tactic_id="ATA0010",
        technique="Invert ML Model",
        technique_id="AML.T0024",
        subtechnique=None,
        subtechnique_id=None,
        description=(
            "Model inversion — using adversarial techniques to extract information "
            "about training data from model outputs. In transport contexts, training "
            "data may include proprietary route maps, pedestrian behaviour patterns, "
            "or infrastructure classifications."
        ),
        relevance=(
            "Beyond misclassification, adversarial probing can expose what "
            "data the transport CV model was trained on — relevant to privacy "
            "and national security when the model encodes infrastructure detail."
        ),
        mitigations=[
            "Differential privacy during training",
            "Output perturbation (add noise to logits/confidences)",
            "Limit API access and rate-limit inference endpoints",
        ],
    ),
]


def print_atlas_report() -> None:
    """Print a formatted MITRE ATLAS mapping table."""
    print("\n" + "=" * 80)
    print("  MITRE ATLAS MAPPING — Adversarial Attacks on Transport AI")
    print("=" * 80)

    for i, entry in enumerate(ATLAS_MAPPINGS, 1):
        sub = f" → {entry.subtechnique}" if entry.subtechnique else ""
        print(f"\n  [{i}] {entry.tactic_id} / {entry.technique_id}")
        print(f"      Tactic    : {entry.tactic}")
        print(f"      Technique : {entry.technique}{sub}")
        print(f"      Relevance : {entry.relevance[:120]}...")
        print(f"      Mitigations:")
        for m in entry.mitigations[:2]:
            print(f"        • {m}")

    print("\n" + "=" * 80)
    print("  Full reference: https://atlas.mitre.org/\n")


def get_mapping_by_technique(technique_id: str) -> ATLASEntry | None:
    """Look up an ATLAS entry by technique ID (e.g. 'AML.T0043')."""
    return next(
        (e for e in ATLAS_MAPPINGS if e.technique_id == technique_id),
        None,
    )
