import json
import logging
import re
import sys
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union

from app.config.settings import settings

# Async context variable for storing per-request correlation IDs
correlation_id_ctx: ContextVar[Optional[str]] = ContextVar("correlation_id_ctx", default=None)


def get_correlation_id() -> str:
    """Returns the active request's correlation ID or default string."""
    return correlation_id_ctx.get() or "no-correlation-id"


def set_correlation_id(id_str: str) -> None:
    """Sets the active request's correlation ID in contextvars."""
    correlation_id_ctx.set(id_str)


def sanitize_correlation_id(cid: Optional[str]) -> str:
    """
    Validates and sanitizes incoming correlation IDs.
    Permits alphanumeric strings and hyphens between 1 and 64 chars.
    Generates a fresh UUID if missing, invalid, or oversized.
    """
    if not cid or not isinstance(cid, str):
        return str(uuid.uuid4())

    cleaned = cid.strip()
    if re.match(r"^[a-zA-Z0-9\-]{1,64}$", cleaned):
        return cleaned

    return str(uuid.uuid4())


# Security redaction patterns to prevent leaking sensitive secrets in logs
REDACTION_PATTERNS = [
    (re.compile(r"whsec_[a-zA-Z0-9_-]{10,}", re.IGNORECASE), "whsec_[REDACTED_WEBHOOK_SECRET]"),
    (re.compile(r"trn_live_[a-zA-Z0-9_-]{10,}", re.IGNORECASE), "trn_live_[REDACTED_API_KEY]"),
    (re.compile(r"sk-[a-zA-Z0-9_-]{10,}", re.IGNORECASE), "sk-[REDACTED_API_KEY]"),
    (re.compile(r"Bearer\s+[a-zA-Z0-9._-]+", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"(postgresql\+asyncpg|postgresql|postgres|mysql|redis)://[^:\s]+:[^@\s]+@[^\s]+", re.IGNORECASE), r"\1://[REDACTED_CREDENTIALS]"),
    (re.compile(r"(password|secret|api_key|token)=['\"]?[^\s'\"]+['\"]?", re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"authorization:\s*[^\s,]+", re.IGNORECASE), "authorization: [REDACTED]"),
    (re.compile(r"cookie:\s*[^\s,]+", re.IGNORECASE), "cookie: [REDACTED]"),
]


def redact_sensitive_text(text: Any) -> Any:
    """
    Scans and redacts API keys, passwords, bearer tokens, DB credentials, and cookies.
    """
    if not isinstance(text, str):
        return text

    redacted = text
    for pattern, replacement in REDACTION_PATTERNS:
        redacted = pattern.sub(replacement, redacted)

    return redacted


class StructuredLogFilter(logging.Filter):
    """
    Logging filter that injects correlation_id into records and redacts sensitive strings.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        record.correlation_id = get_correlation_id()
        if isinstance(record.msg, str):
            record.msg = redact_sensitive_text(record.msg)
        return True


class JSONLogFormatter(logging.Formatter):
    """
    Machine-readable JSON log formatter capturing standard and extra record metadata.
    """
    def format(self, record: logging.LogRecord) -> str:
        log_data: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "correlation_id": getattr(record, "correlation_id", get_correlation_id()),
            "message": record.getMessage(),
        }

        # Include custom extra fields attached to log records
        for key, val in record.__dict__.items():
            if key not in {
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "correlation_id"
            }:
                log_data[key] = redact_sensitive_text(str(val)) if isinstance(val, str) else val

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


class TextLogFormatter(logging.Formatter):
    """
    Development human-readable text log formatter including correlation ID.
    """
    def __init__(self) -> None:
        super().__init__(fmt="%(asctime)s [%(levelname)s] [cid:%(correlation_id)s] %(name)s: %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        if not hasattr(record, "correlation_id"):
            record.correlation_id = get_correlation_id()
        return super().format(record)


def setup_logging() -> None:
    """
    Configures application-wide logging with StructuredLogFilter and configurable format.
    """
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    use_json = (getattr(settings, "LOG_FORMAT", "text").lower() == "json")

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)
    handler.addFilter(StructuredLogFilter())

    if use_json:
        handler.setFormatter(JSONLogFormatter())
    else:
        handler.setFormatter(TextLogFormatter())

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers = [handler]

    logger = logging.getLogger("trustinel")
    logger.setLevel(log_level)
    logger.info(f"Structured logging initialized with level: {settings.LOG_LEVEL}, format: {settings.LOG_FORMAT}")
