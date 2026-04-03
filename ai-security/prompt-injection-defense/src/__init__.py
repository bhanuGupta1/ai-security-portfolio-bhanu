"""
Prompt Injection Defense Framework
===================================
Detection, classification, and sanitization of prompt injection attacks on LLMs.

OWASP LLM Top 10: LLM01 - Prompt Injection
"""

from .detector import PromptInjectionDetector, DetectionResult
from .sanitizer import InputSanitizer
from .patterns import PatternCatalog

__all__ = [
    "PromptInjectionDetector",
    "DetectionResult",
    "InputSanitizer",
    "PatternCatalog",
]

__version__ = "1.0.0"
