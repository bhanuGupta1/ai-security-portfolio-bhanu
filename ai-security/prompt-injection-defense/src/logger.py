"""
Security Event Logger
======================
Structured logging for prompt injection detection events.
Outputs JSON-structured logs for SIEM integration or file analysis.
Supports alert thresholds for high-severity events.

Log levels:
  - INFO: Clean inputs (optional, disabled by default to reduce noise)
  - WARNING: SUSPICIOUS inputs (score 20-49)
  - ERROR: HIGH_RISK inputs (score 50-79)
  - CRITICAL: CRITICAL inputs (score 80+)

Alert channels:
  - Console (always on)
  - File (if log_file path is configured)
  - Custom alert callback (for integration with Slack, PagerDuty, etc.)
"""

import hashlib
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from .detector import DetectionResult


# =============================================================================
# JSON formatter for structured logging
# =============================================================================

class JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Attach extra fields if present
        for key in ("event_type", "risk_level", "risk_score", "input_hash", "match_count", "top_category"):
            if hasattr(record, key):
                log_entry[key] = getattr(record, key)
        return json.dumps(log_entry)


# =============================================================================
# Alert threshold configuration
# =============================================================================

# Map risk levels to Python log levels
RISK_TO_LOG_LEVEL = {
    "SAFE": logging.INFO,
    "SUSPICIOUS": logging.WARNING,
    "HIGH_RISK": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


def _hash_input(text: str) -> str:
    """SHA-256 hash of the input for safe logging (never log raw user input to files)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


# =============================================================================
# Main logger class
# =============================================================================

class SecurityLogger:
    """
    Structured security event logger for the prompt injection defense framework.

    Usage:
        logger = SecurityLogger()
        logger.log_detection(result)

    With file output:
        logger = SecurityLogger(log_file="security_events.jsonl")

    With alert callback:
        def my_alert(result):
            send_to_slack(result.summary())

        logger = SecurityLogger(alert_callback=my_alert, alert_threshold="HIGH_RISK")
    """

    def __init__(
        self,
        name: str = "prompt_injection_defense",
        log_file: Optional[str] = None,
        alert_callback: Optional[Callable[[DetectionResult], None]] = None,
        alert_threshold: str = "HIGH_RISK",
        log_clean_inputs: bool = False,
    ):
        self.alert_callback = alert_callback
        self.alert_threshold = alert_threshold
        self.log_clean_inputs = log_clean_inputs
        self._alert_levels = ["HIGH_RISK", "CRITICAL"]
        if alert_threshold == "SUSPICIOUS":
            self._alert_levels = ["SUSPICIOUS", "HIGH_RISK", "CRITICAL"]

        # Configure the underlying Python logger
        self._logger = logging.getLogger(name)
        self._logger.setLevel(logging.DEBUG)
        self._logger.handlers.clear()

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(JSONFormatter())
        console_handler.setLevel(logging.WARNING)  # Console only shows warnings+
        self._logger.addHandler(console_handler)

        # File handler (if configured)
        if log_file:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(JSONFormatter())
            file_handler.setLevel(logging.DEBUG)
            self._logger.addHandler(file_handler)

        self._events: list[dict] = []  # In-memory event store

    def log_detection(self, result: DetectionResult, context: Optional[str] = None) -> None:
        """
        Log a DetectionResult. Routes to the appropriate log level based on risk.
        Triggers the alert callback if the threshold is exceeded.
        """
        # Skip SAFE inputs unless explicitly enabled
        if result.risk_level == "SAFE" and not self.log_clean_inputs:
            return

        input_hash = _hash_input(result.input_text)
        log_level = RISK_TO_LOG_LEVEL.get(result.risk_level, logging.INFO)
        message = result.summary()

        extra = {
            "event_type": "prompt_injection_detection",
            "risk_level": result.risk_level,
            "risk_score": result.risk_score,
            "input_hash": input_hash,
            "match_count": result.match_count,
            "top_category": result.top_category,
        }
        if context:
            extra["context"] = context

        self._logger.log(log_level, message, extra=extra)

        # Store in memory
        event = {
            "timestamp": result.detected_at,
            "risk_level": result.risk_level,
            "risk_score": result.risk_score,
            "input_hash": input_hash,
            "match_count": result.match_count,
            "top_category": result.top_category,
            "matches": [m.pattern_id for m in result.matches],
            "context": context,
        }
        self._events.append(event)

        # Trigger alert callback if threshold is met
        if result.risk_level in self._alert_levels and self.alert_callback:
            try:
                self.alert_callback(result)
            except Exception as e:
                self._logger.error(f"Alert callback failed: {e}")

    def log_batch(self, results: list[DetectionResult], context: Optional[str] = None) -> None:
        """Log a batch of detection results."""
        for result in results:
            self.log_detection(result, context=context)

    def get_events(self, risk_level_filter: Optional[str] = None) -> list[dict]:
        """Retrieve in-memory events, optionally filtered by risk level."""
        if risk_level_filter:
            return [e for e in self._events if e["risk_level"] == risk_level_filter]
        return list(self._events)

    def stats(self) -> dict:
        """Summary statistics of all logged events."""
        if not self._events:
            return {"total_events": 0}
        risk_counts: dict[str, int] = {}
        for event in self._events:
            lvl = event["risk_level"]
            risk_counts[lvl] = risk_counts.get(lvl, 0) + 1
        return {
            "total_events": len(self._events),
            "by_risk_level": risk_counts,
            "injection_events": sum(
                count for lvl, count in risk_counts.items()
                if lvl in ("HIGH_RISK", "CRITICAL")
            ),
        }

    def export_events(self, path: str) -> None:
        """Export all in-memory events to a JSONL file."""
        output_path = Path(path)
        with output_path.open("w", encoding="utf-8") as f:
            for event in self._events:
                f.write(json.dumps(event) + "\n")
        print(f"Exported {len(self._events)} events to {output_path}")

    def clear_events(self) -> None:
        """Clear the in-memory event store."""
        self._events.clear()
