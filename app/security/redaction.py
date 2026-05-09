import re
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Iterable


@dataclass(frozen=True)
class SensitivePattern:
    """Compiled-sensitive-data pattern metadata."""

    category: str
    pattern: str
    flags: int = re.IGNORECASE
    generic: bool = False


DEFAULT_SENSITIVE_PATTERNS = [
    SensitivePattern("api_key", r'\bapi[\s_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9._-]{8,})["\']?'),
    SensitivePattern("api_key", r'\bapikey\s*[:=]\s*["\']?([a-zA-Z0-9._-]{8,})["\']?'),
    SensitivePattern("password", r'\bpassword\s*[:=]\s*["\']?([^"\'\s]{3,})["\']?'),
    SensitivePattern("password", r'\bpwd\s*[:=]\s*["\']?([^"\'\s]{3,})["\']?'),
    SensitivePattern("password", r'\bpass\s*[:=]\s*["\']?([^"\'\s]{3,})["\']?'),
    SensitivePattern("token", r'\b(?:access_)?token\s*[:=]\s*["\']?([a-zA-Z0-9._-]{10,})["\']?'),
    SensitivePattern("token", r'\bbearer_token\s*[:=]\s*["\']?([a-zA-Z0-9._-]{10,})["\']?'),
    SensitivePattern(
        "secret",
        r'\b(?:secret|secret_key|private_key)\s*[:=]\s*["\']?([a-zA-Z0-9._/+=-]{6,})["\']?',
    ),
    SensitivePattern(
        "private_key",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.IGNORECASE | re.DOTALL,
    ),
    SensitivePattern("anthropic_api_key", r"\bsk-ant-[a-zA-Z0-9_-]{8,}\b"),
    SensitivePattern("openai_api_key", r"\bsk-[a-zA-Z0-9_-]{8,}\b"),
    SensitivePattern("aws_access_key", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    SensitivePattern("github_token", r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    SensitivePattern("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    SensitivePattern("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    SensitivePattern("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    SensitivePattern("ssn", r"\b\d{3}-\d{2}-\d{4}\b"),
    SensitivePattern("ssn", r"\b\d{9}\b"),
    SensitivePattern("credit_card", r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
    SensitivePattern("url", r"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?"),
    SensitivePattern("url", r"ftp://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?"),
    SensitivePattern("secret", r"\bsecret\b", generic=True),
]


def _patterns_by_category(patterns: Iterable[SensitivePattern]) -> Dict[str, List[str]]:
    grouped: Dict[str, List[str]] = {}
    for pattern in patterns:
        grouped.setdefault(pattern.category, []).append(pattern.pattern)
    return grouped


def _spans_overlap(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def find_sensitive_data(text: str, include_generic: bool = True) -> List[Dict[str, Any]]:
    """Return normalized sensitive-data findings with overlapping matches deduplicated."""
    findings: List[Dict[str, Any]] = []
    occupied_spans: List[tuple[int, int]] = []

    for sensitive_pattern in DEFAULT_SENSITIVE_PATTERNS:
        if sensitive_pattern.generic and not include_generic:
            continue

        for match in re.finditer(
            sensitive_pattern.pattern,
            text,
            sensitive_pattern.flags,
        ):
            span = match.span()
            if any(_spans_overlap(span, occupied) for occupied in occupied_spans):
                continue

            matched_value = next((group for group in match.groups() if group), match.group(0))
            findings.append(
                {
                    "category": sensitive_pattern.category,
                    "match": matched_value,
                    "start": span[0],
                    "end": span[1],
                }
            )
            occupied_spans.append(span)

    return findings


def contains_sensitive_data(text: str, include_generic: bool = True) -> bool:
    """Return whether text contains sensitive data."""
    return bool(find_sensitive_data(text, include_generic=include_generic))


def count_sensitive_data(text: str, include_generic: bool = True) -> int:
    """Count normalized sensitive-data findings."""
    return len(find_sensitive_data(text, include_generic=include_generic))


class DataRedactor:
    """Comprehensive data redaction engine for sensitive information."""

    def __init__(self):
        self.sensitive_patterns = DEFAULT_SENSITIVE_PATTERNS
        self.redaction_patterns = _patterns_by_category(self.sensitive_patterns)

    def redact(self, text: str, custom_patterns: Optional[Dict[str, List[str]]] = None) -> str:
        """Redact sensitive information from text."""
        redacted_text = text

        # Use custom patterns if provided, otherwise use default
        patterns = custom_patterns if custom_patterns else self.redaction_patterns

        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                redacted_text = re.sub(
                    pattern,
                    f"[REDACTED_{category.upper()}]",
                    redacted_text,
                    flags=re.IGNORECASE,
                )

        return redacted_text

    def detect_sensitive_data(self, text: str) -> Dict[str, List[str]]:
        """Detect and return sensitive data found in text."""
        detected: Dict[str, List[str]] = {}

        for finding in find_sensitive_data(text):
            detected.setdefault(finding["category"], []).append(finding["match"])

        for category, matches in detected.items():
            detected[category] = sorted(set(matches))

        return detected

    def get_redaction_stats(self, original_text: str, redacted_text: str) -> Dict[str, Any]:
        """Get statistics about redaction process."""
        original_detected = self.detect_sensitive_data(original_text)
        redacted_detected = self.detect_sensitive_data(redacted_text)

        total_original = sum(len(matches) for matches in original_detected.values())
        total_redacted = sum(len(matches) for matches in redacted_detected.values())

        return {
            "original_sensitive_count": total_original,
            "redacted_sensitive_count": total_redacted,
            "redaction_effectiveness": (
                (total_original - total_redacted) / total_original if total_original > 0 else 0
            ),
            "categories_found": list(original_detected.keys()),
            "categories_remaining": list(redacted_detected.keys()),
        }


# Global redactor instance
_redactor = DataRedactor()


def redact(text: str, custom_patterns: Optional[Dict[str, List[str]]] = None) -> str:
    """Simple redaction function for backward compatibility."""
    return _redactor.redact(text, custom_patterns)


def detect_sensitive_data(text: str) -> Dict[str, List[str]]:
    """Detect sensitive data in text."""
    return _redactor.detect_sensitive_data(text)


def get_redaction_stats(original_text: str, redacted_text: str) -> Dict[str, Any]:
    """Get redaction statistics."""
    return _redactor.get_redaction_stats(original_text, redacted_text)
