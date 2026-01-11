import logging
import os
from logging.handlers import RotatingFileHandler
from app.config import Config


def setup_logging():
    """Setup structured logging for the application."""
    log_level = getattr(logging, Config.LOG_LEVEL, logging.INFO)

    # Create logs directory if it doesn't exist
    log_file = Config.LOG_FILE
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)


# Filter patterns for redaction (consistent with the app's redactor)
SENSITIVE_PATTERNS = [
    r"(?i)api[_-]?key\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{10,}['\"]?",
    r"(?i)password\s*[:=]\s*['\"]?[^\"'\s]{3,}['\"]?",
    r"(?i)token\s*[:=]\s*['\"]?[a-zA-Z0-9._-]{20,}['\"]?",
    r"(?i)secret\s*[:=]\s*['\"]?[a-zA-Z0-9._-]{10,}['\"]?",
]


class RedactingFormatter(logging.Formatter):
    """Custom formatter that redacts sensitive patterns from log messages."""

    def format(self, record):
        import re

        message = super().format(record)
        for pattern in SENSITIVE_PATTERNS:
            message = re.sub(pattern, "[REDACTED]", message)
        return message


def setup_logging():
    """Setup structured logging for the application."""
    log_level = getattr(logging, Config.LOG_LEVEL, logging.INFO)

    # Create logs directory if it doesn't exist
    log_file = Config.LOG_FILE
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(log_level)

    # Formatting
    formatter = RedactingFormatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler with rotation
    if Config.LOG_ROTATION:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=Config.LOG_MAX_SIZE * 1024 * 1024,  # Convert MB to Bytes
            backupCount=Config.LOG_BACKUP_COUNT,
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    else:
        # Standard file handler without rotation
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logging.info(f"Logging initialized at level {Config.LOG_LEVEL}")
    return logger


def get_logger(name):
    """Get a named logger."""
    return logging.getLogger(name)
