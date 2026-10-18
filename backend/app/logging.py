"""Structured JSON logging without a logging dependency."""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, sort_keys=True)


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not any(isinstance(h, logging.StreamHandler) and getattr(h, "_aegis", False) for h in root.handlers):
        handler = logging.StreamHandler(sys.stdout)
        handler._aegis = True  # type: ignore[attr-defined]
        handler.setFormatter(JsonFormatter())
        root.addHandler(handler)


def log(logger: logging.Logger, level: int, message: str, **fields: Any) -> None:
    logger.log(level, message, extra={"fields": fields})
