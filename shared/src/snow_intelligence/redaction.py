"""Conservative redaction before data leaves the controlled workload boundary."""

from __future__ import annotations

import re

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE), "[REDACTED_EMAIL]"),
    (re.compile(r"\b(?:\+?\d[\d .()\-]{7,}\d)\b"), "[REDACTED_PHONE]"),
    (re.compile(r"(?i)\b(?:password|passwd|api[_-]?key|token)\s*[:=]\s*\S+"), "[REDACTED_SECRET]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
)


def redact_text(value: str | None) -> str:
    """Redact common PII and secrets. Tenant DLP rules should extend this module."""
    if not value:
        return ""
    redacted = value
    for pattern, replacement in _PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted
