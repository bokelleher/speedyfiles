"""Application configuration loaded from environment / .env.

For production: set env vars (Docker, systemd EnvironmentFile, etc.).
For local dev: drop a `.env` next to the working directory.
Most runtime config (mail, storage choice, webhooks) lives in the DB and is
editable via the admin UI — these env values are the bootstrap layer only.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",                # relative to CWD; missing-file is OK
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # General
    app_name: str = "SpeedyFiles"
    public_base_url: str = "http://localhost:5300"
    debug: bool = False

    # Security
    session_secret: str  # required — generate with `openssl rand -hex 32`
    session_cookie_name: str = "speedyfiles_session"
    session_max_age_seconds: int = 7 * 24 * 3600

    # Database — SQLite by default; Postgres via DATABASE_URL=postgresql+asyncpg://...
    database_url: str = "sqlite+aiosqlite:///./data/app.db"

    # Storage
    storage_backend: Literal["local", "s3"] = "local"
    local_storage_root: Path = Path("./files")
    s3_bucket: str | None = None
    s3_region: str = "us-east-1"
    s3_prefix: str = "packages"

    # Mail bootstrap defaults — overridable in the admin UI / DB
    smtp_host: str = "127.0.0.1"
    smtp_port: int = 587
    mail_from_address: str = "noreply@example.com"
    mail_from_name: str = "SpeedyFiles"
    mail_envelope_helo: str | None = None

    # UDP sidecar (planned v0.2)
    udp_sidecar_enabled: bool = False
    udp_sidecar_host: str = "localhost"
    udp_sidecar_port: int = 7443

    # Logging
    log_dir: Path = Path("./logs")

    @property
    def packages_dir(self) -> Path:
        return self.local_storage_root / "packages"

    @property
    def tmp_dir(self) -> Path:
        return self.local_storage_root / "tmp"


settings = Settings()
