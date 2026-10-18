from __future__ import annotations

import json
import logging

from backend.app.config import Settings
from backend.app.db import Database
from backend.app.logging import JsonFormatter


def test_default_settings_are_offline_and_bounded():
    settings = Settings.from_env()
    assert settings.llm_enabled is False
    assert settings.max_body_bytes > 0
    assert settings.max_text_chars > 0


def test_environment_settings_parse(monkeypatch):
    monkeypatch.setenv("AEGIS_LLM_ENABLED", "true")
    monkeypatch.setenv("AEGIS_LLM_BASE_URL", "https://llm.invalid")
    monkeypatch.setenv("AEGIS_LLM_API_KEY", "test-key")
    monkeypatch.setenv("AEGIS_LLM_MODEL", "test-model")
    monkeypatch.setenv("AEGIS_CORS_ORIGINS", "http://one,http://two")
    settings = Settings.from_env()
    assert settings.llm_configured is True
    assert settings.cors_origins == ("http://one", "http://two")


def test_partial_llm_configuration_stays_disabled():
    settings = Settings.from_env(llm_enabled=True, llm_base_url="", llm_api_key="", llm_model="")
    assert settings.llm_configured is False


def test_database_creates_sqlmodel_metadata(tmp_path):
    database = Database(f"sqlite:///{(tmp_path / 'db.sqlite').as_posix()}")
    database.create_all()
    assert database.engine is not None


def test_structured_formatter_is_json():
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "hello", (), None)
    record.fields = {"request_id": "abc", "count": 2}
    payload = json.loads(JsonFormatter().format(record))
    assert payload["message"] == "hello"
    assert payload["request_id"] == "abc"


def test_openai_compatible_env_names_configure_gpt6_provider(monkeypatch):
    for key in ("AEGIS_LLM_ENABLED", "AEGIS_LLM_BASE_URL", "AEGIS_LLM_API_KEY", "AEGIS_LLM_MODEL"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("LLM_BASE_URL", "https://llm.invalid/v1")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_MODEL", "GPT-6 Astra")
    settings = Settings.from_env()
    assert settings.llm_configured is True
    assert settings.llm_model == "GPT-6 Astra"
