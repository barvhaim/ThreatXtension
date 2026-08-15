"""Central structured logging configuration for ThreatXtension."""

from __future__ import annotations

import logging
import os
import sys

LOG_LEVEL_ENV = "THREATXTENSION_LOG_LEVEL"
FALLBACK_LOG_LEVEL_ENV = "LOG_LEVEL"
DEFAULT_LEVEL = "INFO"
DEFAULT_FORMAT = (
    "%(asctime)s %(levelname)s %(name)s "
    "[%(module)s:%(funcName)s:%(lineno)d] %(message)s"
)
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"


def _resolve_level(value: str | int | None = None) -> int:
    """Resolve a log level from an explicit value or environment."""
    if isinstance(value, int):
        return value

    if value is None:
        raw = os.getenv(LOG_LEVEL_ENV) or os.getenv(FALLBACK_LOG_LEVEL_ENV) or DEFAULT_LEVEL
    else:
        raw = str(value)

    raw = raw.strip().upper()
    level = getattr(logging, raw, None)
    if isinstance(level, int):
        return level

    logging.getLogger(__name__).warning(
        "Unsupported log level %r; using %s", raw, DEFAULT_LEVEL
    )
    return getattr(logging, DEFAULT_LEVEL, logging.INFO)


def configure_logging(level: str | int | None = None) -> logging.Logger:
    """Configure the ThreatXtension logger with timestamped output.

    The level is read from ``THREATXTENSION_LOG_LEVEL`` (or ``LOG_LEVEL``)
    when no explicit value is supplied. Only the ``threatxtension`` logger
    is configured so application entry points can control their own output.
    """
    logger = logging.getLogger("threatxtension")
    logger.setLevel(_resolve_level(level))
    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(DEFAULT_FORMAT, datefmt=DATE_FORMAT))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a child logger under the structured ThreatXtension logger."""
    if not name:
        return logging.getLogger("threatxtension")
    if name == "threatxtension" or name.startswith("threatxtension."):
        return logging.getLogger(name)
    return logging.getLogger(f"threatxtension.{name.lstrip('.')}")
