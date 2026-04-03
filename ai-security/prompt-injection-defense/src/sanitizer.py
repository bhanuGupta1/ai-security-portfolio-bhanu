"""
Input Sanitizer
================
Reduces injection risk through targeted transformation of user input.
Does NOT fully remove the message — it strips known attack patterns and
escapes dangerous sequences, then returns a safer version for further processing.

Design principle:
  Sanitization is a last layer, not the first. Detection should gate
  whether input is processed at all. Sanitization makes borderline
  inputs safer to handle. It does not replace detection.

Output is always accompanied by a SanitizationReport so callers can see
what was changed and decide whether to accept the result.
"""

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SanitizationAction:
    """Describes a single transformation applied to the input."""
    action_type: str
    description: str
    original_snippet: str
    replacement: str
    count: int = 1


@dataclass
class SanitizationReport:
    """Full report of what was changed during sanitization."""
    original_text: str
    sanitized_text: str
    actions: list[SanitizationAction]
    risk_reduced: bool        # True if any changes were made
    original_length: int
    sanitized_length: int

    @property
    def action_count(self) -> int:
        return len(self.actions)

    def summary(self) -> str:
        if not self.actions:
            return "No sanitization applied. Input was clean."
        action_list = ", ".join(a.action_type for a in self.actions)
        return f"{self.action_count} transformation(s) applied: {action_list}."


# =============================================================================
# Sanitization rules
# Each rule is a tuple: (action_type, description, pattern, replacement)
# =============================================================================

# These are the most dangerous literal phrases. Strip them out.
STRIP_PATTERNS: list[tuple[str, str, str, str]] = [
    (
        "strip_delimiter_tags",
        "Remove model delimiter tags that could break conversation structure",
        r"(<\s*system\s*>|<\s*/\s*system\s*>|\[system\]|\[\/system\]|<<system>>|<\|system\|>"
        r"|\[INST\]|\[\/INST\]|<\|user\|>|<\|assistant\|>|<\|human\|>|<\|im_start\|>|<\|im_end\|>"
        r"|<<SYS>>|<</SYS>>)",
        "[removed]",
    ),
    (
        "strip_override_openers",
        "Remove classic instruction override openers",
        r"(?i)\b(ignore\s+all\s+previous\s+instructions?|disregard\s+all\s+previous\s+instructions?"
        r"|forget\s+everything\s+you\s+(were\s+)?told)\b",
        "[removed]",
    ),
    (
        "strip_jailbreak_labels",
        "Remove named jailbreak persona labels",
        r"\b(DAN|STAN|AIM|UCAR|BISH|DUDE|JAILBREAK|ANTI-DAN|KEVIN)\b",
        "[removed]",
    ),
    (
        "strip_note_to_ai",
        "Remove indirect injection markers targeting the AI",
        r"(?i)(note\s+to\s+(AI|assistant|LLM|model|language\s+model)\s*[:]\s*)",
        "[removed]",
    ),
]

# These sequences are escaped rather than removed (to preserve readability)
ESCAPE_PATTERNS: list[tuple[str, str, str, str]] = [
    (
        "escape_xml_tags",
        "Escape XML-like injection tags",
        r"<(instructions?|task|command|directive|override|inject|payload|prompt|system_prompt)\s*>",
        r"[escaped-tag:\1]",
    ),
    (
        "escape_html_comments",
        "Escape HTML comment blocks that could hide instructions",
        r"<!--(.*?)-->",
        r"[escaped-comment]",
    ),
    (
        "escape_code_block_labels",
        "Escape code block labels that claim to be system/prompt sections",
        r"```\s*(system|instructions?|prompt|directive|override)\s*\n",
        "```[escaped]\n",
    ),
]

# Normalize dangerous unicode
UNICODE_RULES: list[tuple[str, str]] = [
    ("normalize_unicode", "Normalize unicode to NFKC to collapse lookalikes"),
]

# Whitespace abuse
WHITESPACE_RULES: list[tuple[str, str, str, str]] = [
    (
        "trim_hidden_whitespace",
        "Remove excessive whitespace that could hide instructions",
        r"[ \t]{50,}",
        " ",
    ),
]


class InputSanitizer:
    """
    Transforms user input to reduce prompt injection risk.

    Usage:
        sanitizer = InputSanitizer()
        report = sanitizer.sanitize("Ignore all previous instructions and...")
        safe_text = report.sanitized_text
        print(report.summary())
    """

    def sanitize(self, text: str) -> SanitizationReport:
        """
        Apply all sanitization rules to the input text.
        Returns a SanitizationReport with the sanitized text and all changes logged.
        """
        if not isinstance(text, str):
            raise TypeError(f"Expected str, got {type(text).__name__}")

        current = text
        actions: list[SanitizationAction] = []

        # Step 1: Normalize unicode
        normalized = unicodedata.normalize("NFKC", current)
        if normalized != current:
            actions.append(SanitizationAction(
                action_type="normalize_unicode",
                description="Normalized unicode to NFKC (collapses homoglyphs and compatibility forms)",
                original_snippet=current[:100],
                replacement=normalized[:100],
            ))
            current = normalized

        # Step 2: Strip dangerous patterns
        for action_type, description, pattern, replacement in STRIP_PATTERNS:
            new_text, count = re.subn(pattern, replacement, current, flags=re.IGNORECASE | re.DOTALL)
            if count > 0:
                # Find the first match snippet for the report
                match = re.search(pattern, current, flags=re.IGNORECASE | re.DOTALL)
                snippet = match.group(0)[:100] if match else "[matched]"
                actions.append(SanitizationAction(
                    action_type=action_type,
                    description=description,
                    original_snippet=snippet,
                    replacement=replacement,
                    count=count,
                ))
                current = new_text

        # Step 3: Escape dangerous sequences
        for action_type, description, pattern, replacement in ESCAPE_PATTERNS:
            new_text, count = re.subn(pattern, replacement, current, flags=re.IGNORECASE | re.DOTALL)
            if count > 0:
                match = re.search(pattern, current, flags=re.IGNORECASE | re.DOTALL)
                snippet = match.group(0)[:100] if match else "[matched]"
                actions.append(SanitizationAction(
                    action_type=action_type,
                    description=description,
                    original_snippet=snippet,
                    replacement=replacement,
                    count=count,
                ))
                current = new_text

        # Step 4: Whitespace normalization
        for action_type, description, pattern, replacement in WHITESPACE_RULES:
            new_text, count = re.subn(pattern, replacement, current)
            if count > 0:
                actions.append(SanitizationAction(
                    action_type=action_type,
                    description=description,
                    original_snippet=f"[whitespace run of 50+ chars, {count} occurrences]",
                    replacement=replacement,
                    count=count,
                ))
                current = new_text

        return SanitizationReport(
            original_text=text,
            sanitized_text=current,
            actions=actions,
            risk_reduced=len(actions) > 0,
            original_length=len(text),
            sanitized_length=len(current),
        )

    def sanitize_batch(self, texts: list[str]) -> list[SanitizationReport]:
        """Sanitize a list of inputs. Returns reports in the same order."""
        return [self.sanitize(t) for t in texts]

    def quick_sanitize(self, text: str) -> str:
        """Convenience method — returns sanitized text only, no report."""
        return self.sanitize(text).sanitized_text
