import logging
import sys
from pathlib import Path

import structlog
from concurrent_log_handler import ConcurrentRotatingFileHandler

from config import settings
from enums import Environment, LogRenderer


def get_log_file_path() -> Path:
    """
    Constructs the log file path based on the log directory and current environment.

    Returns:
        Path: The constructed log file path.
    """
    env_name = settings.APP_ENV.value
    log_dir = settings.log_file_dir
    log_dir.mkdir(parents=True, exist_ok=True)  # Ensure the log directory exists

    return log_dir / f"{env_name}-logs.jsonl"


def add_environment(logger: object, method_name: str, event_dict: structlog.typing.EventDict) -> structlog.typing.EventDict:
    """Stamps every log event with the running environment."""
    event_dict["environment"] = settings.APP_ENV.value
    return event_dict


def get_structlog_processors(include_file_info: bool = True) -> list[structlog.typing.Processor]:
    """
    Returns the shared list of structlog processors used to build every log event,
    regardless of which renderer (console/JSON) ultimately formats it.

    Args:
        include_file_info: Whether to include callsite information (file, line, function) in the logs.

    Returns:
        list[structlog.typing.Processor]: A list of structlog processors.
    """
    processors: list[structlog.typing.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        add_environment,
    ]

    if include_file_info:
        processors.append(
            structlog.processors.CallsiteParameterAdder(
                [
                    structlog.processors.CallsiteParameter.FILENAME,
                    structlog.processors.CallsiteParameter.FUNC_NAME,
                    structlog.processors.CallsiteParameter.LINENO,
                    structlog.processors.CallsiteParameter.PATHNAME,
                    structlog.processors.CallsiteParameter.MODULE,
                ]
            )
        )

    return processors


def setup_logging() -> None:
    """
    Sets up stdlib logging + structlog based on the application settings:
    a console handler rendered per LOG_RENDERER, and a concurrent-safe
    rotating JSON file handler, both fed by the same structlog processor chain.
    """
    log_level = settings.LOG_LEVEL.value

    include_file_info = settings.APP_ENV in (Environment.STAGING, Environment.PRODUCTION)
    shared_processors = get_structlog_processors(include_file_info=include_file_info)

    console_renderer = (
        structlog.processors.JSONRenderer()
        if settings.LOG_RENDERER == LogRenderer.JSON
        else structlog.dev.ConsoleRenderer(colors=True)
    )

    console_formatter = structlog.stdlib.ProcessorFormatter(
        processor=console_renderer,
        foreign_pre_chain=shared_processors,
    )
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(console_formatter)

    file_formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.processors.JSONRenderer(),
        foreign_pre_chain=shared_processors,
    )
    file_handler = ConcurrentRotatingFileHandler(
        filename=str(get_log_file_path()),
        maxBytes=settings.LOG_MAX_BYTES,
        backupCount=settings.LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(log_level)

    logging.basicConfig(
        format="%(message)s",
        level=log_level,
        handlers=[console_handler, file_handler],
        force=True,
    )

    # Configure structlog to hand every event off to stdlib logging, which then
    # dispatches it to the console/file handlers configured above.
    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


# Third-party loggers that are pure noise at DEBUG (per-request HTTP wire events, optional
# integrations probing for packages this app never installs — deepagents logs a full
# traceback for each missing langchain_aws / langchain_fireworks on every agent build).
# Their warnings and errors still come through.
_NOISY_LOGGERS = (
    "httpcore",
    "httpx",
    "hpack",
    "urllib3",
    "asyncio",
    "passlib",
    "multipart",
    "python_multipart",
    "watchfiles",
    "google_genai",
    "google.auth",
    "grpc",
    "deepagents",
    "langchain",
    "langsmith",
    "langgraph",
)


def quiet_third_party_loggers(level: int = logging.WARNING) -> None:
    """Raise the threshold of chatty third-party loggers; the app's own loggers keep LOG_LEVEL."""
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(level)


# Initialize logging
setup_logging()
quiet_third_party_loggers()


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a structlog logger bound to ``name`` — pass ``__name__`` from the calling module.

    Deliberately NOT a single shared singleton: with ``cache_logger_on_first_use=True``,
    structlog resolves and caches a logger's name lazily on its first actual log
    call. A single logger object imported everywhere (``logger = structlog.get_logger()``)
    would cache whichever module happened to log *first* in the process, and
    every other module's log lines would silently inherit that same wrong
    name for the rest of the process's life. Passing an explicit ``name``
    (``__name__``) sidesteps that entirely — each module gets its own
    correctly-named, independently-cached logger.
    """
    return structlog.get_logger(name)
