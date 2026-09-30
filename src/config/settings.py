import os
from pathlib import Path
from typing import Literal, Optional

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
    GITLAB_ALLOWED_HOSTS: str = Field(
        "",
        description="Comma-separated GitLab hosts reviews may clone from (e.g. 'gitlab.com,gitlab.corp.local'). "
        "Empty = any public host. Listed hosts may be private and use http.",
    )
    GITLAB_ALLOW_PRIVATE_HOSTS: bool = Field(
        False, description="Allow unlisted hosts that resolve to private/loopback/link-local addresses (SSRF guard)"
    )
    GITLAB_ALLOW_HTTP: bool = Field(False, description="Allow plain-http GitLab URLs for unlisted hosts (token sent unencrypted)")
    MIN_FREE_DISK_MB: int = Field(500, gt=0, description="Minimum free disk space (MB) required before starting a clone")

    # ===========================
    # Repository Discovery Configuration
    # ===========================
    DISCOVERY_ENGINE_VERSION: str = Field("1.1.0", min_length=1, description="Version of the discovery algorithm/heuristics")
    DISCOVERY_SCHEMA_VERSION: str = Field("1.0.0", min_length=1, description="Version of the RepositoryManifest schema")
    DISCOVERY_TRAVERSAL_TIMEOUT_SECONDS: float = Field(30.0, gt=0, description="Max wall-clock time for filesystem traversal")
    DISCOVERY_AST_PER_FILE_TIMEOUT_MS: int = Field(1000, gt=0, description="Max time to spend AST-parsing a single file")
    DISCOVERY_TOTAL_TIMEOUT_SECONDS: float = Field(120.0, gt=0, description="Max wall-clock time for the whole discovery run")
    DISCOVERY_MAX_AST_FILE_SIZE_MB: float = Field(2.0, gt=0, description="Skip AST parsing for source files larger than this")

    # ===========================
    # Static Analysis Configuration (Track A — structural tools)
    # ===========================
    ANALYSIS_TIMEOUT_SECONDS: int = Field(60, gt=0, description="Per-tool subprocess timeout for structural tools, in seconds")
    RUFF_CONFIG_PATH: Optional[str] = Field(
        default_factory=lambda: str(_DEFAULT_PROJECT_ROOT / "src" / "assets" / "ruff.toml"),
        description="Ruff config passed to every scanned repository; bundled at src/assets/ruff.toml "
        "(same bundled-asset pattern as gitleaks) so scans get a consistent ruleset regardless of "
        "whether the target repo ships its own config. Only passed to ruff when the file actually exists.",
    )
    PYRIGHT_CONFIG_PATH: Optional[str] = Field(
        default_factory=lambda: str(_DEFAULT_PROJECT_ROOT / "src" / "assets" / "pyrightconfig.json"),
        description="Pyright config (--project) passed to every scanned repository; bundled at "
        "src/assets/pyrightconfig.json so type-checking behavior (strictness, python version) is "
        "consistent regardless of whether the target repo ships its own config. Only passed when the "
        "file actually exists.",
    )
    SEMGREP_CONFIG: str = Field(
        default_factory=lambda: str(_DEFAULT_PROJECT_ROOT / "src" / "assets" / "semgrep"),
        description="Semgrep --config: defaults to the bundled, project-owned rules in src/assets/semgrep/ so scans "
        "run offline and deterministically. 'auto' or a registry pack (e.g. 'p/python') downloads rules from "
        "semgrep.dev on every run instead (needs network).",
    )
    RADON_COMPLEXITY_RANKS_TO_IGNORE: str = Field("A,B", description="Comma-separated radon CC ranks that never become findings")
    RADON_MI_RANKS_TO_IGNORE: str = Field("A", description="Comma-separated radon MI ranks that never become findings")
    LIZARD_CCN_THRESHOLD: int = Field(10, gt=0, description="Cyclomatic complexity below which lizard results are skipped")
    LIZARD_CCN_ERROR_THRESHOLD: int = Field(20, gt=0, description="Cyclomatic complexity above which a lizard finding is severity=error instead of warning")

    # ===========================
    # Security Engine Configuration (Track B — concurrent security tools)
    # ===========================
    SECURITY_TOOL_TIMEOUT: int = Field(300, gt=0, description="Per-tool subprocess timeout for security tools, in seconds")
    SECURITY_MAX_WORKERS: int = Field(4, gt=0, description="Max concurrent security-tool subprocesses")

    # ===========================
    # DependencyGraph Configuration (tree-sitter + grimp)
    # ===========================
    DEPENDENCY_GRAPH_ENGINE_VERSION: str = Field(
        "1.1.0", min_length=1, description="Version of the extraction/call-resolution heuristics"
    )
    DEPENDENCY_GRAPH_SCHEMA_VERSION: str = Field(
        "1.0.0", min_length=1, description="Version of the DependencyGraph schema"
    )
    GRIMP_TIMEOUT_SECONDS: int = Field(
        60, gt=0, description="Timeout for the isolated grimp import-graph subprocess, in seconds"
    )

    # ===========================
    # LLM Provider Configuration (used by the Deep Review agents)
    # ===========================
    GEMINI_API_KEY: Optional[SecretStr] = Field(None, description="Google Gemini API key")
    GEMINI_MODEL: str = Field("gemini-2.5-flash", min_length=1, description="Gemini model id")

    # ===========================
    # Deep Review Configuration (deepagents multi-agent code review)
    # ===========================
    DEEP_REVIEW_ENABLED: bool = Field(True, description="Run the deep-review node after the dependency graph")
    DEEP_REVIEW_INSPECT_ENV_FILES: bool = Field(
        True,
        description="Let the deterministic env map read committed .env files for key names, duplicate keys and "
        "value flags (weak/short/localhost). Values never leave the process; agents still cannot open .env files.",
    )
    DEEP_REVIEW_JUDGE_MODEL: Optional[str] = Field(
        "gemini-3.1-pro-preview",
        description="Stronger Gemini model for the judgment roles — verifier and synthesizer. Live runs showed "
        "Flash alone as verifier lets praise and false 'unused' findings through; the pro judge rejects them "
        "correctly. Set to an empty string to use GEMINI_MODEL for every role instead.",
    )
    DEEP_REVIEW_CONFIG_PATH: str = Field(
        default_factory=lambda: str(_DEFAULT_PROJECT_ROOT / "src" / "assets" / "review_config.toml"),
        description="Review categories + security KPIs; bundled at src/assets/review_config.toml",
    )
    DEEP_REVIEW_ENGINE_VERSION: str = Field(
        "1.11.0", min_length=1, description="Version of the review prompts/orchestration; part of the cache key"
    )
    DEEP_REVIEW_MAX_CONCURRENCY: int = Field(
        6, gt=0, description="Max review agents running at once (bounded by the provider's rate limits)"
    )
    DEEP_REVIEW_AGENT_TIMEOUT_SECONDS: int = Field(
        900, gt=0, description="Wall-clock cap per agent; findings recorded before the cap are kept"
    )
    MAX_CONCURRENT_PIPELINES: int = Field(
        2, gt=0, description="Reviews running at once in this process; further submissions wait in the queue (PENDING)"
    )
    PIPELINE_STALE_AFTER_SECONDS: int = Field(
        7200,
        gt=0,
        description="At startup, PENDING/RUNNING review rows older than this are marked FAILED — their background "
        "task died with a previous process. Keep it well above the longest real pipeline run.",
    )
    DEEP_REVIEW_SPECIALIST_MODEL_CALLS: int = Field(60, gt=0, description="Model-call budget per specialist agent")
    DEEP_REVIEW_EXPLORER_MODEL_CALLS: int = Field(20, gt=0, description="Model-call budget per code-explorer subagent")
    DEEP_REVIEW_VERIFIER_MODEL_CALLS: int = Field(30, gt=0, description="Model-call budget per verifier agent")
    DEEP_REVIEW_SYNTHESIZER_MODEL_CALLS: int = Field(25, gt=0, description="Model-call budget for the synthesizer")
    DEEP_REVIEW_TOOL_RESULT_TOKEN_LIMIT: int = Field(
        12000, gt=0, description="Tool results above this many tokens are offloaded to the agent's virtual filesystem"
    )
    DEEP_REVIEW_MAX_OUTPUT_TOKENS: int = Field(16000, gt=0, description="Max output tokens per model call")
    DEEP_REVIEW_FUNCTION_CALLING_MODE: Literal["VALIDATED", "AUTO"] = Field(
        "VALIDATED",
        description="Gemini function-calling mode. VALIDATED constrains tool calls to the declared schemas "
        "(removes MALFORMED_FUNCTION_CALL retries); AUTO is Gemini's unconstrained default.",
    )

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

    @model_validator(mode="after")
    def validate_production_safety(self) -> "Settings":
        """Refuse to boot production with debug behaviour (auto-reload, API docs, verbose errors)."""
        if self.APP_ENV == Environment.PRODUCTION and self.DEBUG:
            raise ValueError("DEBUG must be false when APP_ENV=production")
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
    def radon_complexity_ranks_to_ignore(self) -> frozenset[str]:
        """RADON_COMPLEXITY_RANKS_TO_IGNORE parsed into a set of rank letters."""
        return frozenset(r.strip() for r in self.RADON_COMPLEXITY_RANKS_TO_IGNORE.split(",") if r.strip())

    @property
    def radon_mi_ranks_to_ignore(self) -> frozenset[str]:
        """RADON_MI_RANKS_TO_IGNORE parsed into a set of rank letters."""
        return frozenset(r.strip() for r in self.RADON_MI_RANKS_TO_IGNORE.split(",") if r.strip())

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
