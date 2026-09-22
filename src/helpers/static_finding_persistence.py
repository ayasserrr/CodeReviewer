"""Persistence for Static Analysis findings."""

from uuid import UUID

from data.repositories import StaticFindingRepository
from system import get_logger
from utils import StaticFinding

logger = get_logger(__name__)


async def save_static_findings(
    finding_repo: StaticFindingRepository, *, repository_id: UUID, head_sha: str, findings: list[StaticFinding]
) -> None:
    """Persist every finding from one Static Analysis run.

    Upserts on ``(repository_id, head_sha, finding_id)`` — re-running
    analysis at the same commit never creates duplicate rows. Each finding
    is saved with its ``tool``, so a downstream query can always answer
    "which tool found this" and "which tools ran" for a given commit.

    Args:
        finding_repo: Data-access layer for the ``static_findings`` table.
        repository_id: The repository these findings belong to.
        head_sha: The commit SHA the findings were produced at.
        findings: The content-hashed ``StaticFinding`` objects to persist.
    """
    if not findings:
        logger.info("static_findings_persist_skipped_empty", repository_id=str(repository_id), head_sha=head_sha)
        return

    rows = [
        {
            "repository_id": repository_id,
            "head_sha": head_sha,
            "finding_id": finding.id,
            "tool": finding.tool,
            "file": finding.file,
            "line": finding.line,
            "severity": finding.severity,
            "category": finding.category,
            "message": finding.message,
        }
        for finding in findings
    ]

    inserted = await finding_repo.bulk_upsert(rows)
    logger.info(
        "static_findings_persisted",
        repository_id=str(repository_id),
        head_sha=head_sha,
        findings_count=len(findings),
        inserted_count=inserted,
        skipped_as_duplicates=len(findings) - inserted,
    )
