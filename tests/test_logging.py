"""Tests for structured logging configuration."""

import importlib.util
import logging
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "src/threatxtension/logging.py"


def _load_logging_module() -> importlib.util.ModuleType:
    """Load the logging module without requiring the package to be installed."""
    spec = importlib.util.spec_from_file_location("threatxtension_logging", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_configure_logging_uses_env_level_and_format(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_logging_module()
    monkeypatch.setenv("THREATXTENSION_LOG_LEVEL", "warning")
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    logger = module.configure_logging()
    assert logger.name == "threatxtension"
    assert logger.level == logging.WARNING
    assert logger.handlers
    formatter = logger.handlers[0].formatter
    assert formatter is not None
    record = logging.LogRecord(
        "threatxtension", logging.WARNING, "threatxtension", 1, "hello", (), None
    )
    assert formatter.formatTime(record)
    formatted = formatter.format(record)
    assert "WARNING" in formatted
    assert "hello" in formatted
    assert module.get_logger("api.database").name == "threatxtension.api.database"
