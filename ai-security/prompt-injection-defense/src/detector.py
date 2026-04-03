"""
Prompt Injection Detector
==========================
Rule-based detection engine with multi-pattern matching and risk scoring.

Detection pipeline:
  1. Normalize input (unicode, whitespace, case)
  2. Match all patterns in the catalog
  3. Score matches by severity and coverage
  4. Return DetectionResult with matched patterns, risk score, and recommendation

Risk scoring:
  - Each matched pattern contributes its severity score
  - Multiple matches compound (diminishing returns to avoid score inflation)
  - Final score: 0-100 (0 = clean, 100 = definitely malicious)
  - Thresholds: SAFE <20, SUSPICIOUS 20-49, HIGH_RISK 50-79, CRITICAL 80+
"""

import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .patterns import PatternCatalog, Pattern, Severity


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class PatternMatch:
    """A single pattern that matched in the input."""
    pattern_id: str
    pattern_name: str
    category: str
    severity: Severity
    severity_name: str
    matched_text: str
    start: int
    end: int
    owasp_ref: str


@dataclass
class DetectionResult:
    """
    Full result of running the detector on a single input.
    This is the primary output of the detection engine.
    """
    input_text: str
    input_length: int
    normalized_text: str
    matches: list[PatternMatch]
    risk_score: float          # 0-100
    risk_level: str            # SAFE / SUSPICIOUS / HIGH_RISK / CRITICAL
    is_injection: bool         # True if risk_score >= 50
    recommendation: str
    top_category: Optional[str]
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def match_count(self) -> int:
        return len(self.matches)

    @property
    def highest_severity(self) -> Optional[Severity]:
        if not self.matches:
            return None
        return max(m.severity for m in self.matches)

    def summary(self) -> str:
        if not self.is_injection:
            return f"CLEAN — score {self.risk_score:.0f}/100. No injection detected."
        return (
            f"{self.risk_level} — score {self.risk_score:.0f}/100. "
            f"{self.match_count} pattern(s) matched. "
            f"Top category: {self.top_category}."
        )

    def to_dict(self) -> dict:
        return {
            "risk_score": round(self.risk_score, 2),
            "risk_level": self.risk_level,
            "is_injection": self.is_injection,
            "recommendation": self.recommendation,
            "match_count": self.match_count,
            "top_category": self.top_category,
            "matches": [
                {
                    "id": m.pattern_id,
                    "name": m.pattern_name,
                    "category": m.category,
                    "severity": m.severity_name,
                    "matched_text": m.matched_text[:200],
                    "owasp": m.owasp_ref,
                }
                for m in self.matches
            ],
            "detected_at": self.detected_at,
        }


# =============================================================================
# Risk scoring
# =============================================================================

# Score contribution per match (base values, before compounding)
SEVERITY_SCORES = {
    Severity.LOW: 10,
    Severity.MEDIUM: 20,
    Severity.HIGH: 50,   # Single HIGH match = is_injection threshold (50)
    Severity.CRITICAL: 65,
}

# Risk thresholds
THRESHOLDS = {
    "SAFE": (0, 20),
    "SUSPICIOUS": (20, 50),
    "HIGH_RISK": (50, 80),
    "CRITICAL": (80, 101),
}

RECOMMENDATIONS = {
    "SAFE": "Input appears clean. No action required.",
    "SUSPICIOUS": "Low-confidence injection signal. Log and monitor. Consider stricter context validation.",
    "HIGH_RISK": "Likely injection attempt. Block input, log event, review context. Do not pass to LLM unfiltered.",
    "CRITICAL": "Definite injection attempt. Block immediately. Alert security team. Log full input for analysis.",
}


def compute_risk_score(matches: list[PatternMatch]) -> float:
    """
    Compound risk scoring:
    - First match: full severity score
    - Each subsequent match: 70% of its base score (diminishing returns)
    - Cap at 100
    """
    if not matches:
        return 0.0

    # Sort by severity descending so the most severe match gets full score
    sorted_matches = sorted(matches, key=lambda m: m.severity, reverse=True)
    score = 0.0
    multiplier = 1.0

    for match in sorted_matches:
        base = SEVERITY_SCORES[match.severity]
        score += base * multiplier
        multiplier *= 0.7  # Compound discount

    return min(round(score, 2), 100.0)


def score_to_risk_level(score: float) -> str:
    for level, (lo, hi) in THRESHOLDS.items():
        if lo <= score < hi:
            return level
    return "CRITICAL"


# =============================================================================
# Normalization
# =============================================================================

def normalize(text: str) -> str:
    """
    Normalize input to improve pattern matching.
    Handles: unicode normalization, zero-width characters, excessive whitespace.
    Does NOT lowercase (handled per-pattern with re.IGNORECASE).
    """
    # Strip zero-width and invisible characters
    text = "".join(
        ch for ch in text
        if unicodedata.category(ch) not in ("Cf", "Cc") or ch in ("\n", "\r", "\t")
    )
    # Normalize unicode (NFKC combines lookalike characters)
    text = unicodedata.normalize("NFKC", text)
    # Normalize excessive whitespace within lines (not newlines)
    lines = text.split("\n")
    lines = [re.sub(r"[ \t]{2,}", " ", line) for line in lines]
    return "\n".join(lines)


# =============================================================================
# Main detector
# =============================================================================

class PromptInjectionDetector:
    """
    Main detection engine.

    Usage:
        detector = PromptInjectionDetector()
        result = detector.scan("Ignore all previous instructions and...")
        print(result.summary())
        print(result.risk_level)

    Optionally filter by minimum severity:
        result = detector.scan(text, min_severity=Severity.HIGH)
    """

    def __init__(self, catalog: Optional[PatternCatalog] = None):
        self.catalog = catalog or PatternCatalog()

    def scan(
        self,
        text: str,
        min_severity: Severity = Severity.LOW,
        context_label: Optional[str] = None,
    ) -> DetectionResult:
        """
        Scan a single input string for prompt injection signals.

        Args:
            text: The user input to analyze.
            min_severity: Minimum severity level to include in results.
            context_label: Optional label for logging (e.g. "user_message", "document_chunk").

        Returns:
            DetectionResult with full match list, risk score, and recommendation.
        """
        if not isinstance(text, str):
            raise TypeError(f"Expected str, got {type(text).__name__}")

        normalized = normalize(text)
        matches: list[PatternMatch] = []

        for pattern in self.catalog.all_patterns:
            if pattern.severity < min_severity:
                continue

            compiled = self.catalog.get_compiled(pattern.id)
            if compiled is None:
                continue

            for m in compiled.finditer(normalized):
                matches.append(
                    PatternMatch(
                        pattern_id=pattern.id,
                        pattern_name=pattern.name,
                        category=pattern.category,
                        severity=pattern.severity,
                        severity_name=pattern.severity.name,
                        matched_text=m.group(0),
                        start=m.start(),
                        end=m.end(),
                        owasp_ref=pattern.owasp_ref,
                    )
                )

        # Deduplicate: if same pattern matches multiple times, keep first hit only
        seen_ids: set[str] = set()
        deduped: list[PatternMatch] = []
        for m in matches:
            if m.pattern_id not in seen_ids:
                deduped.append(m)
                seen_ids.add(m.pattern_id)

        risk_score = compute_risk_score(deduped)
        risk_level = score_to_risk_level(risk_score)

        # Find the most common category among matches
        top_category = None
        if deduped:
            category_counts: dict[str, int] = {}
            for m in deduped:
                category_counts[m.category] = category_counts.get(m.category, 0) + 1
            top_category = max(category_counts, key=lambda k: category_counts[k])

        return DetectionResult(
            input_text=text,
            input_length=len(text),
            normalized_text=normalized,
            matches=deduped,
            risk_score=risk_score,
            risk_level=risk_level,
            is_injection=risk_score >= 50.0,
            recommendation=RECOMMENDATIONS[risk_level],
            top_category=top_category,
        )

    def scan_batch(
        self,
        texts: list[str],
        min_severity: Severity = Severity.LOW,
    ) -> list[DetectionResult]:
        """
        Scan multiple inputs at once. Useful for document chunk analysis.
        Returns results in the same order as the input list.
        """
        return [self.scan(t, min_severity=min_severity) for t in texts]

    def is_safe(self, text: str) -> bool:
        """Quick boolean check. True if no injection detected."""
        return not self.scan(text).is_injection

    def catalog_stats(self) -> dict:
        """Return statistics about the loaded pattern catalog."""
        return self.catalog.stats()
