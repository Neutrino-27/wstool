"""Central logging: JSON-lines diagnostic log with automatic credential redaction.

Diagnostic logs go to a rotating file; user-facing console output is a separate
concern handled by the GUI.
"""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Mapping

REDACTED = "***REDACTED***"
SENSITIVE_KEYS = frozenset({"programpassword", "password", "passwd", "p_passwd",
                            "token", "authorization"})

_XML_SECRET_RE = re.compile(
    r"(<(?P<tag>programPassword|password)(?:\s[^>]*)?>)(.*?)(</(?P=tag)>)",
    re.DOTALL | re.IGNORECASE)


def redact_params(params: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a copy of params with sensitive values masked."""
    return {k: (REDACTED if str(k).lower() in SENSITIVE_KEYS else v)
            for k, v in params.items()}


def redact_xml(xml_text: str) -> str:
    """Mask the content of sensitive elements inside a raw XML string."""
    return _XML_SECRET_RE.sub(lambda m: m.group(1) + REDACTED + m.group(4), xml_text)


class RedactingFilter(logging.Filter):
    """Safety net: redacts structured fields and secret-looking XML in messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            record.fields = {
                k: (REDACTED if str(k).lower() in SENSITIVE_KEYS
                    else redact_xml(v) if isinstance(v, str) else v)
                for k, v in fields.items()}
        if isinstance(record.msg, str):
            record.msg = redact_xml(record.msg)
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        if record.exc_info:
            payload["exc_type"] = record.exc_info[0].__name__
        return json.dumps(payload, ensure_ascii=False, default=str)


def setup_logging(log_dir: str = "logs", level: str = "INFO") -> logging.Logger:
    """Configure the 'sfc_tool' logger (idempotent)."""
    logger = logging.getLogger("sfc_tool")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False
    if any(getattr(h, "_sfc_handler", False) for h in logger.handlers):
        return logger
    os.makedirs(log_dir, exist_ok=True)
    handler = RotatingFileHandler(os.path.join(log_dir, "sfc_tool.log"),
                                  maxBytes=5_000_000, backupCount=10,
                                  encoding="utf-8")
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactingFilter())
    handler._sfc_handler = True  # type: ignore[attr-defined]
    logger.addHandler(handler)
    return logger
