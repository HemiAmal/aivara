"""Centralized application logging configuration for AIVARA."""

import logging
import sys
from typing import Optional


class RedactingFilter(logging.Filter):
    """Ensure no raw secrets, private keys, or passwords appear in log output."""

    SENSITIVE_KEYWORDS = ("password", "private_key", "secret", "token", "auth")

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        msg_lower = message.lower()
        for kw in self.SENSITIVE_KEYWORDS:
            if kw in msg_lower and any(c in msg_lower for c in ("=", ":")):
                # Mask message to prevent accidental leakage in audit/dev logs
                record.msg = f"[SENSITIVE_FIELD_REDACTED: contains '{kw}']"
                record.args = ()
                break
        return True


def setup_logging(log_level: Optional[str] = None) -> None:
    """Initialize structured, sanitized logging."""
    from aivara.core.config import settings

    level_name = (log_level or settings.log_level).upper()
    level = getattr(logging, level_name, logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    handler.addFilter(RedactingFilter())

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Avoid duplicate handlers if setup_logging is called multiple times
    if not root_logger.handlers:
        root_logger.addHandler(handler)
    else:
        root_logger.handlers = [handler]

    # Silence overly noisy external loggers in normal mode
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a named application logger."""
    return logging.getLogger(name)
