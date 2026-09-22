from enum import StrEnum


class ConfidenceLevel(StrEnum):
    """Confidence level for a deterministic framework-detection score."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
