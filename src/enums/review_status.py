from enum import StrEnum


class ReviewStatus(StrEnum):
    """Enum representing the lifecycle status of a review report."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
