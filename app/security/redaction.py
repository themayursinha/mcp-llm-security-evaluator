import re
from typing import List, Dict, Any, Optional


class DataRedactor:
    """Comprehensive data redaction engine for sensitive information."""

    def __init__(self):
        self.redaction_patterns = {
            "api_key": [
                r'api[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9_-]{10,})["\']?',
                r'apikey\s*[:=]\s*["\']?([a-zA-Z0-9_-]{10,})["\']?',
                r'api_key\s*[:=]\s*["\']?([a-zA-Z0-9_-]{10,})["\']?',
            ],
            "password": [
                r'password\s*[:=]\s*["\']?([^"\'\s]{3,})["\']?',
                r'pwd\s*[:=]\s*["\']?([^"\'\s]{3,})["\']?',
                r'pass\s*[:=]\s*["\']?([^"\'\s]{3,})["\']?',
            ],
            "token": [
                r'token\s*[:=]\s*["\']?([a-zA-Z0-9._-]{20,})["\']?',
                r'access_token\s*[:=]\s*["\']?([a-zA-Z0-9._-]{20,})["\']?',
                r'bearer_token\s*[:=]\s*["\']?([a-zA-Z0-9._-]{20,})["\']?',
            ],
            "secret": [
                r'secret\s*[:=]\s*["\']?([a-zA-Z0-9._-]{10,})["\']?',
                r'secret_key\s*[:=]\s*["\']?([a-zA-Z0-9._-]{10,})["\']?',
                r'private_key\s*[:=]\s*["\']?([a-zA-Z0-9._-]{20,})["\']?',
                r"\bsecret\b",  # Simple word match for "secret"
            ],
            "email": [r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"],
            "ssn": [r"\b\d{3}-\d{2}-\d{4}\b", r"\b\d{9}\b"],
            "credit_card": [r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"],
            "url": [
                r"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?",
                r"ftp://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?",
            ],
        }

    def redact(
        self, text: str, custom_patterns: Optional[Dict[str, List[str]]] = None
    ) -> str:
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
        detected = {}

        for category, pattern_list in self.redaction_patterns.items():
            matches = []
            for pattern in pattern_list:
                found = re.findall(pattern, text, re.IGNORECASE)
                matches.extend(found)
            if matches:
                detected[category] = list(set(matches))  # Remove duplicates

        return detected

    def get_redaction_stats(
        self, original_text: str, redacted_text: str
    ) -> Dict[str, Any]:
        """Get statistics about redaction process."""
        original_detected = self.detect_sensitive_data(original_text)
        redacted_detected = self.detect_sensitive_data(redacted_text)

        total_original = sum(len(matches) for matches in original_detected.values())
        total_redacted = sum(len(matches) for matches in redacted_detected.values())

        return {
            "original_sensitive_count": total_original,
            "redacted_sensitive_count": total_redacted,
            "redaction_effectiveness": (
                (total_original - total_redacted) / total_original
                if total_original > 0
                else 0
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
