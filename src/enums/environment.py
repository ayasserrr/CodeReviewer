from enum import StrEnum


class Environment(StrEnum):
    """Enum representing different application environments."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"
