from typing import Tuple, Optional
from app.config import Config


class ConfigValidator:
    """Validator for application configuration."""

    @staticmethod
    def validate(provider: str = "auto") -> Tuple[bool, Optional[str]]:
        """Validate configuration based on selected provider.

        Args:
            provider: LLM provider name (auto, openai, anthropic, mock)

        Returns:
            Tuple of (is_valid, error_message)
        """
        if provider == "openai" and not Config.OPENAI_API_KEY:
            return False, "OPENAI_API_KEY is required when using OpenAI provider"

        if provider == "anthropic" and not Config.ANTHROPIC_API_KEY:
            return False, "ANTHROPIC_API_KEY is required when using Anthropic provider"

        if provider == "auto":
            if not Config.OPENAI_API_KEY and not Config.ANTHROPIC_API_KEY:
                # This is OK - will fall back to mock
                pass

        if Config.REPORT_FORMAT not in ["json", "html", "both"]:
            return (
                False,
                f"REPORT_FORMAT must be 'json', 'html', or 'both', got '{Config.REPORT_FORMAT}'",
            )

        if not (0 <= Config.SECURITY_THRESHOLD <= 100):
            return (
                False,
                f"SECURITY_THRESHOLD must be between 0 and 100, got {Config.SECURITY_THRESHOLD}",
            )

        if Config.LOG_LEVEL not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            return (
                False,
                f"LOG_LEVEL must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL, got '{Config.LOG_LEVEL}'",
            )

        return True, None
