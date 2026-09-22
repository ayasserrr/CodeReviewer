from enum import StrEnum


class SourceType(StrEnum):
    """Enum representing where a repository was ingested from."""

    GITLAB = "gitlab"
