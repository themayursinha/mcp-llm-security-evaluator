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

    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(log_level)

    # Formatting
    formatter = logging.Formatter(
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
