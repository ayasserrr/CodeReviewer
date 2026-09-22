import os
from pathlib import Path
from typing import Optional

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from enums import Environment, LogLevel, LogRenderer

# The real OS environment decides which per-environment .env file to load.
# Defaults to "development" when APP_ENV isn't set on the machine/process.
_APP_ENV = os.getenv("APP_ENV", Environment.DEVELOPMENT.value)

# Project root = two levels up from this file (src/config/settings.py -> project root).
_DEFAULT_PROJECT_ROOT = Path(__file__).resolve().parents[2]

ENV_DEFAULTS: dict[Environment, dict[str, object]] = {
    Environment.DEVELOPMENT: {
        "DEBUG": True,
        "LOG_LEVEL": LogLevel.DEBUG,
        "LOG_RENDERER": LogRenderer.CONSOLE,
    },
    Environment.STAGING: {
        "DEBUG": False,
        "LOG_LEVEL": LogLevel.INFO,
        "LOG_RENDERER": LogRenderer.JSON,
    },
    Environment.PRODUCTION: {
        "DEBUG": False,
        "LOG_LEVEL": LogLevel.INFO,
        "LOG_RENDERER": LogRenderer.JSON,
    },
    Environment.TESTING: {
        "DEBUG": True,
        "LOG_LEVEL": LogLevel.DEBUG,
        "LOG_RENDERER": LogRenderer.CONSOLE,
    },
}


class Settings(BaseSettings):
    APP_NAME: str = Field(..., min_length=1, description="The name of the application")
    APP_ENV: Environment = Field(..., description="The environment in which the application is running")
    VERSION: str = Field(..., min_length=1, description="The version of the application")
    DEBUG: Optional[bool] = Field(None, description="Whether to run the application in debug mode")
    API_VERSION: str = Field("/api/v1", min_length=1, description="URL prefix for the versioned API")
    PROJECT_ROOT: Path = Field(
        default_factory=lambda: _DEFAULT_PROJECT_ROOT,
        description="The root directory of the project",
    )

    # ===========================
    # Logging Configuration
    # ===========================
    LOG_LEVEL: Optional[LogLevel] = Field(None, description="The logging level for the application")
    LOG_DIR: str = Field("storage/logs", min_length=1, description="The directory where log files are stored")
    LOG_RENDERER: Optional[LogRenderer] = Field(None, description="The renderer for the application logs")
    LOG_MAX_BYTES: int = Field(10 * 1024 * 1024, gt=0, description="The maximum size in bytes of each log file before rotation")
    LOG_BACKUP_COUNT: int = Field(10, ge=0, description="The number of backup log files to keep")

    # ===========================
    # Database (PostgreSQL) Configuration
    # ===========================
    POSTGRES_HOST: str = Field(..., min_length=1, description="The PostgreSQL server host")
    POSTGRES_PORT: int = Field(5432, gt=0, le=65535, description="The PostgreSQL server port")
    POSTGRES_DB: str = Field(..., min_length=1, description="The PostgreSQL database name")
    POSTGRES_USER: str = Field(..., min_length=1, description="The PostgreSQL username")
    POSTGRES_PASSWORD: SecretStr = Field(..., description="The PostgreSQL password")
    POSTGRES_POOL_SIZE: int = Field(5, gt=0, description="Base number of persistent DB connections")
    POSTGRES_MAX_OVERFLOW: int = Field(10, ge=0, description="Extra connections allowed above the pool size")

    # ===========================
    # JWT / Auth Configuration
    # ===========================
    JWT_SECRET_KEY: SecretStr = Field(..., description="Secret key used to sign and verify JWTs")
    JWT_ALGORITHM: str = Field("HS256", min_length=1, description="JWT signing algorithm")
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(30, gt=0, description="Access token lifetime, in minutes")
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = Field(30, gt=0, description="Refresh token lifetime, in days")

    # ===========================
    # Repository Ingestion Configuration
    # ===========================
    CLONED_REPOS_DIR: str = Field(
        "cloned_repos", min_length=1, description="Directory (relative to PROJECT_ROOT unless absolute) for cloned repositories"
    )
    GIT_CLONE_TIMEOUT_SECONDS: int = Field(300, gt=0, description="Hard timeout for git clone operations, in seconds")
    GITLAB_API_TIMEOUT_SECONDS: int = Field(15, gt=0, description="Timeout for GitLab API requests, in seconds")
    MIN_FREE_DISK_MB: int = Field(500, gt=0, description="Minimum free disk space (MB) required before starting a clone")

    model_config = SettingsConfigDict(
        env_file=(".env", f".env.{_APP_ENV}"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @field_validator("PROJECT_ROOT")
    @classmethod
    def validate_project_root(cls, value: Path) -> Path:
        path = value.expanduser().resolve()
        if not path.is_dir():
            raise ValueError(f"PROJECT_ROOT does not exist or is not a directory: {path}")
        return path

    @field_validator("API_VERSION")
    @classmethod
    def validate_api_version(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        if not value.startswith("/"):
            raise ValueError("API_VERSION must start with '/' (e.g. '/api/v1')")
        return value

    @field_validator("LOG_DIR")
    @classmethod
    def validate_log_dir(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("LOG_DIR must not be empty")
        return value

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def validate_jwt_secret_key(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters long")
        return value

    @model_validator(mode="after")
    def apply_environment_defaults(self) -> "Settings":
        """Fill in any field left unset by the environment using ENV_DEFAULTS."""
        defaults = ENV_DEFAULTS.get(self.APP_ENV, {})
        if self.DEBUG is None:
            self.DEBUG = defaults.get("DEBUG", False)
        if self.LOG_LEVEL is None:
            self.LOG_LEVEL = defaults.get("LOG_LEVEL", LogLevel.INFO)
        if self.LOG_RENDERER is None:
            self.LOG_RENDERER = defaults.get("LOG_RENDERER", LogRenderer.JSON)
        return self

    @property
    def log_file_dir(self) -> Path:
        """LOG_DIR resolved against PROJECT_ROOT when it's a relative path."""
        log_dir = Path(self.LOG_DIR)
        return log_dir if log_dir.is_absolute() else self.PROJECT_ROOT / log_dir

    @property
    def cloned_repos_path(self) -> Path:
        """CLONED_REPOS_DIR resolved against PROJECT_ROOT when it's a relative path."""
        repos_dir = Path(self.CLONED_REPOS_DIR)
        return repos_dir if repos_dir.is_absolute() else self.PROJECT_ROOT / repos_dir

    @property
    def database_url(self) -> str:
        """Async DSN (asyncpg) used by the application's SQLAlchemy engine."""
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD.get_secret_value()}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def database_url_sync(self) -> str:
        """Sync DSN (psycopg) used by Alembic migrations."""
        return (
            f"postgresql+psycopg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD.get_secret_value()}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )


def get_settings() -> Settings:
    return Settings()
