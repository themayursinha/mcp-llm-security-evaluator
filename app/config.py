"""
Configuration management for MCP LLM Security Evaluator.
Handles loading and validation of environment variables.
"""

import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

# Load .env file from project root
project_root = Path(__file__).parent.parent
env_path = project_root / ".env"
load_dotenv(dotenv_path=env_path)


class Config:
    """Application configuration loaded from environment variables."""
    
    # API Keys
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
    ANTHROPIC_API_KEY: Optional[str] = os.getenv("ANTHROPIC_API_KEY")
    
    # Logging Configuration
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
    LOG_FILE: str = os.getenv("LOG_FILE", "logs/evaluator.log")
    LOG_ROTATION: bool = os.getenv("LOG_ROTATION", "true").lower() == "true"
    LOG_MAX_SIZE: int = int(os.getenv("LOG_MAX_SIZE", "10"))
    LOG_BACKUP_COUNT: int = int(os.getenv("LOG_BACKUP_COUNT", "5"))
    
    # LLM Configuration
    DEFAULT_MODEL: str = os.getenv("DEFAULT_MODEL", "gpt-3.5-turbo")
    MAX_TOKENS: int = int(os.getenv("MAX_TOKENS", "1000"))
    
    # Report Configuration
    REPORT_FORMAT: str = os.getenv("REPORT_FORMAT", "both").lower()
    SECURITY_THRESHOLD: float = float(os.getenv("SECURITY_THRESHOLD", "70"))
    
    @classmethod
    def validate(cls, provider: str = "auto") -> tuple:
        """Validate configuration based on selected provider.
        
        Args:
            provider: LLM provider name (auto, openai, anthropic, mock)
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if provider == "openai" and not cls.OPENAI_API_KEY:
            return False, "OPENAI_API_KEY is required when using OpenAI provider"
        
        if provider == "anthropic" and not cls.ANTHROPIC_API_KEY:
            return False, "ANTHROPIC_API_KEY is required when using Anthropic provider"
        
        if provider == "auto":
            if not cls.OPENAI_API_KEY and not cls.ANTHROPIC_API_KEY:
                # This is OK - will fall back to mock
                pass
        
        if cls.REPORT_FORMAT not in ["json", "html", "both"]:
            return False, f"REPORT_FORMAT must be 'json', 'html', or 'both', got '{cls.REPORT_FORMAT}'"
        
        if not (0 <= cls.SECURITY_THRESHOLD <= 100):
            return False, f"SECURITY_THRESHOLD must be between 0 and 100, got {cls.SECURITY_THRESHOLD}"
        
        if cls.LOG_LEVEL not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            return False, f"LOG_LEVEL must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL, got '{cls.LOG_LEVEL}'"
        
        return True, None
    
    @classmethod
    def get_summary(cls) -> dict:
        """Get configuration summary (without sensitive data)."""
        return {
            "log_level": cls.LOG_LEVEL,
            "log_file": cls.LOG_FILE,
            "log_rotation": cls.LOG_ROTATION,
            "default_model": cls.DEFAULT_MODEL,
            "max_tokens": cls.MAX_TOKENS,
            "report_format": cls.REPORT_FORMAT,
            "security_threshold": cls.SECURITY_THRESHOLD,
            "has_openai_key": bool(cls.OPENAI_API_KEY),
            "has_anthropic_key": bool(cls.ANTHROPIC_API_KEY),
        }
