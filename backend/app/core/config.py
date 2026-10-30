"""
Application configuration — all settings loaded from environment variables.
Uses Pydantic BaseSettings for type-safe, validated configuration.
"""
from typing import List, Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # -------------------------------------------------------------------------
    # Application
    # -------------------------------------------------------------------------
    PROJECT_NAME: str = "AI DevSecOps Platform"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # -------------------------------------------------------------------------
    # Database
    # -------------------------------------------------------------------------
    DATABASE_URL: str = "sqlite+aiosqlite:///./devsecops.db"
    DATABASE_URL_SYNC: str = "sqlite:///./devsecops.db"

    # -------------------------------------------------------------------------
    # Redis / Celery
    # -------------------------------------------------------------------------
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"

    # -------------------------------------------------------------------------
    # Security / JWT
    # -------------------------------------------------------------------------
    SECRET_KEY: str = "INSECURE_PLACEHOLDER_CHANGE_IN_PRODUCTION"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # -------------------------------------------------------------------------
    # CORS
    # -------------------------------------------------------------------------
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost",
        "http://127.0.0.1",
    ]

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            import json
            return json.loads(v)
        return v

    # -------------------------------------------------------------------------
    # AI Provider
    # -------------------------------------------------------------------------
    AI_PROVIDER: str = "gemini"          # "gemini" or "openai"
    GEMINI_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None

    # -------------------------------------------------------------------------
    # GitHub Integration
    # -------------------------------------------------------------------------
    GITHUB_CLIENT_ID: Optional[str] = None
    GITHUB_CLIENT_SECRET: Optional[str] = None
    GITHUB_WEBHOOK_SECRET: Optional[str] = None

    # -------------------------------------------------------------------------
    # Scanner / Upload / DAST
    # -------------------------------------------------------------------------
    SCAN_UPLOAD_DIR: str = "./uploads"

    # Maximum ZIP upload size — set as a single authoritative byte value.
    # Default: 1 GiB = 1,073,741,824 bytes
    # Disk-space requirement: peak usage ≈ 3× this value
    #   (compressed ZIP on disk + extracted tree + temp working copy)
    # To override: set MAX_UPLOAD_SIZE_BYTES=<bytes> in .env
    MAX_UPLOAD_SIZE_BYTES: int = 1_073_741_824  # 1 GiB

    # Kept for backward-compat references; derived at runtime in property below.
    # Do NOT set this in .env — set MAX_UPLOAD_SIZE_BYTES instead.
    SCAN_MAX_FILE_SIZE_MB: int = 0  # computed property below

    ZAP_BASE_URL: str = "http://localhost:8080"
    ALLOW_LOCAL_TARGETS: bool = False  # Opt-in strictly for controlled local lab targets

    @property
    def effective_max_upload_mb(self) -> int:
        """Convenience accessor returning the upload limit in whole MiB."""
        return self.MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)

    # -------------------------------------------------------------------------
    # Seed admin
    # -------------------------------------------------------------------------
    FIRST_ADMIN_EMAIL: str = "admin@example.com"
    FIRST_ADMIN_PASSWORD: str = "changeme"


# Singleton — import this everywhere instead of re-instantiating
settings = Settings()
