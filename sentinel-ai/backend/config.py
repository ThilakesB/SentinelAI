"""
backend/config.py
=================
Single source of truth for all application configuration.
Loaded once at startup via get_settings() (lru_cached).

Usage:
    from backend.config import get_settings
    settings = get_settings()
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────────────────
    app_env: Literal["development", "production"] = "development"
    app_secret_key: str = Field(..., min_length=16)
    app_host: str = "127.0.0.1"
    app_port: int = 8000
    app_log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # ── JWT ──────────────────────────────────────────────────────────────────
    jwt_secret_key: str = Field(..., min_length=32)
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60

    # ── Database ─────────────────────────────────────────────────────────────
    database_url: str = Field(..., description="asyncpg-compatible PostgreSQL URL")
    database_pool_min_size: int = 2
    database_pool_max_size: int = 10

    local_db_path: Path = Path("./data/sentinel_local.db")

    # ── Threat Intelligence ──────────────────────────────────────────────────
    abuseipdb_api_key: str = ""
    abuseipdb_confidence_threshold: int = Field(75, ge=0, le=100)

    malwarebazaar_api_key: str = ""
    nvd_api_key: str = ""
    virustotal_api_key: str = ""  # Fallback only — strict TOS

    threat_intel_refresh_hours: int = Field(6, ge=1, le=24)
    malwarebazaar_sync_hour: int = Field(3, ge=0, le=23)
    nvd_sync_hour: int = Field(4, ge=0, le=23)

    # ── YARA ─────────────────────────────────────────────────────────────────
    yara_rules_dir: Path = Path("./rules")

    # ── ML Model ─────────────────────────────────────────────────────────────
    ml_models_dir: Path = Path("./models")
    ml_retrain_hour: int = Field(3, ge=0, le=23)
    ml_anomaly_suspicious_threshold: float = Field(-0.1, le=0.0)
    ml_anomaly_critical_threshold: float = Field(-0.3, le=0.0)

    # ── Monitoring ───────────────────────────────────────────────────────────
    monitoring_interval_sec: int = Field(5, ge=1, le=60)
    resource_baseline_window_min: int = Field(60, ge=10)

    # ── Response Engine ──────────────────────────────────────────────────────
    auto_kill_critical: bool = False   # Must be explicitly opted in
    auto_block_ip_critical: bool = True

    # ── Computed helpers ─────────────────────────────────────────────────────
    @field_validator("local_db_path", "yara_rules_dir", "ml_models_dir", mode="before")
    @classmethod
    def resolve_path(cls, v: str | Path) -> Path:
        return Path(v).resolve()

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def database_url_sync(self) -> str:
        """Return a sync psycopg2 URL for Alembic migrations."""
        return self.database_url.replace("postgresql+asyncpg://", "postgresql://")

    def ensure_dirs(self) -> None:
        """Create all required local directories on first run."""
        for d in (
            self.local_db_path.parent,
            self.yara_rules_dir,
            self.ml_models_dir,
            Path("./data"),
            Path("./logs"),
        ):
            d.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached Settings singleton. Call this everywhere."""
    s = Settings()  # type: ignore[call-arg]
    s.ensure_dirs()
    return s
