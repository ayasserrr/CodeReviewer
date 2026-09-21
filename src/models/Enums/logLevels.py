from enum import StrEnum


class LogLevel(StrEnum):
    """Enum representing different log levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
