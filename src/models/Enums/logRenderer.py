from enum import StrEnum


class LogRenderer(StrEnum):
    """Enum representing the available structlog output renderers."""

    CONSOLE = "console"
    JSON = "json"
