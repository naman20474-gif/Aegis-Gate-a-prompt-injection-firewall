from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.config import Settings
from backend.app.main import create_app
from backend.app.schemas import LLMResponse


class FakeLLM:
    def __init__(self, label: str = "allow", confidence: float = 1.0):
        self.label = label
        self.confidence = confidence
        self.calls: list[str] = []

    def analyze(self, text: str, *, provenance=None) -> LLMResponse:
        self.calls.append(text)
        return LLMResponse(
            available=True, provider="fake", label=self.label, confidence=self.confidence, reason="test classification"
        )


@pytest.fixture
def fake_llm():
    return FakeLLM()


@pytest.fixture
def app(tmp_path: Path):
    settings = Settings.from_env(
        database_url=f"sqlite:///{(tmp_path / 'aegis-test.db').as_posix()}",
        policy_dir=Path("backend/policies"),
        max_body_bytes=4_096,
        max_text_chars=2_000,
    )
    return create_app(settings)


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client
