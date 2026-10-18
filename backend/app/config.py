"""Environment-backed application settings."""
from __future__ import annotations

import os
from dotenv import load_dotenv
from dataclasses import dataclass, field
from pathlib import Path

load_dotenv()


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(value: str | None, default: int) -> int:
    try:
        return int(value) if value is not None else default
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    """A small dependency-free settings object so startup also works offline."""

    environment: str = "development"
    database_url: str = "sqlite:///./backend/aegis_gate.db"
    policy_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parents[1] / "policies")
    cors_origins: tuple[str, ...] = ("http://localhost:5173",)
    max_body_bytes: int = 204_800
    max_text_chars: int = 204_800
    llm_enabled: bool = False
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_model: str = ""
    llm_timeout_seconds: float = 5.0
    llm_token_cap: int = 4096
    llm_max_tokens: int = 256
    serve_frontend: bool = False
    log_level: str = "INFO"

    @classmethod
    def from_env(cls, **overrides: object) -> "Settings":
        origins = os.getenv("AEGIS_CORS_ORIGINS", "http://localhost:5173")
        values: dict[str, object] = {
            "environment": os.getenv("AEGIS_ENV", "development"),
            "database_url": os.getenv("AEGIS_DB_URL", "sqlite:///./backend/aegis_gate.db"),
            "policy_dir": Path(os.getenv("AEGIS_POLICY_DIR", str(Path(__file__).resolve().parents[1] / "policies"))),
            "cors_origins": tuple(x.strip() for x in origins.split(",") if x.strip()),
            "max_body_bytes": _int(os.getenv("AEGIS_MAX_BODY_BYTES"), 204_800),
            "max_text_chars": _int(os.getenv("AEGIS_MAX_TEXT_CHARS"), 204_800),
            "llm_enabled": _bool(os.getenv("AEGIS_LLM_ENABLED", os.getenv("LLM_ENABLED")), False),
            "llm_base_url": os.getenv("AEGIS_LLM_BASE_URL", os.getenv("LLM_BASE_URL", "")),
            "llm_api_key": os.getenv("AEGIS_LLM_API_KEY", os.getenv("LLM_API_KEY", "")),
            "llm_model": os.getenv("AEGIS_LLM_MODEL", os.getenv("LLM_MODEL", "GPT-6 Astra")),
            "llm_timeout_seconds": float(os.getenv("AEGIS_LLM_TIMEOUT_SECONDS", os.getenv("LLM_TIMEOUT_SECONDS", "5"))),
            "llm_token_cap": _int(os.getenv("AEGIS_LLM_TOKEN_CAP", os.getenv("LLM_TOKEN_CAP")), 4096),
            "llm_max_tokens": _int(os.getenv("AEGIS_LLM_MAX_TOKENS", os.getenv("LLM_MAX_TOKENS")), 256),
            "serve_frontend": _bool(os.getenv("AEGIS_SERVE_FRONTEND"), False),
            "log_level": os.getenv("AEGIS_LOG_LEVEL", "INFO"),
        }
        values.update(overrides)
        if isinstance(values.get("policy_dir"), str):
            values["policy_dir"] = Path(values["policy_dir"])
        if isinstance(values.get("cors_origins"), list):
            values["cors_origins"] = tuple(values["cors_origins"])
        return cls(**values)

    @property
    def llm_configured(self) -> bool:
        return bool(self.llm_enabled and self.llm_base_url and self.llm_api_key and self.llm_model)
