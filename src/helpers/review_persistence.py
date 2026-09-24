"""Cache-key computation and ``review_reports`` persistence for the Deep Review node.

Same caching contract as Discovery and the DependencyGraph node: an identical
input (same repository, same commit, same review engine, same review config,
same model) reuses the stored report instead of re-running the agents. Unlike
those nodes the key includes ``repository_id`` — a report row belongs to one
user's repository, and the API only serves reports to their owner.
"""

import hashlib
from collections import Counter
from datetime import UTC, datetime
from uuid import UUID

from data.models import ReviewReport
from data.repositories import ReviewReportRepository
from enums import ReviewStatus
from system import get_logger
from utils import DeepReviewReport

logger = get_logger(__name__)


def compute_review_cache_key(
    *, repository_id: str, head_sha: str, engine_version: str, config_hash: str, provider: str, model: str
) -> str:
    """Deterministic key over everything that changes the review's output."""
    raw = f"{repository_id}:{head_sha}:{engine_version}:{config_hash}:{provider}:{model}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


async def get_cached_review(repo: ReviewReportRepository, cache_key: str) -> ReviewReport | None:
    """The newest COMPLETED report for ``cache_key``, or ``None``."""
    record = await repo.get_completed_by_cache_key(cache_key)
    if record is not None:
        logger.info("deep_review_cache_hit", cache_key=cache_key, review_report_id=str(record.id))
    return record


async def start_review(
    repo: ReviewReportRepository,
    *,
    repository_id: UUID,
    head_sha: str,
    branch: str,
    cache_key: str,
    engine_version: str,
    provider: str,
    model: str,
) -> ReviewReport:
    """Insert the RUNNING row up front so an in-flight review is visible."""
    return await repo.create(
        repository_id=repository_id,
        commit_sha=head_sha,
        branch=branch,
        status=ReviewStatus.RUNNING,
        cache_key=cache_key,
        engine_version=engine_version,
        provider=provider,
        model=model,
    )


def issues_summary(report: DeepReviewReport) -> dict:
    """Small, queryable roll-up stored in ``review_reports.issues_summary``."""
    return {
        "by_severity": dict(Counter(f.severity for f in report.findings)),
        "by_category": dict(Counter(f.category_id for f in report.findings)),
        "security_kpis": {k.kpi_id: k.status for k in report.kpi_assessments},
        "total": len(report.findings),
    }


async def complete_review(
    repo: ReviewReportRepository, review_report_id: UUID, report: DeepReviewReport, markdown: str
) -> None:
    await repo.update(
        review_report_id,
        status=ReviewStatus.COMPLETED,
        report_markdown=markdown,
        report_data=report.model_dump(mode="json"),
        issues_summary=issues_summary(report),
        completed_at=datetime.now(UTC),
    )


async def fail_review(repo: ReviewReportRepository, review_report_id: UUID, error: str) -> None:
    await repo.update(
        review_report_id,
        status=ReviewStatus.FAILED,
        error=error[:4000],
        completed_at=datetime.now(UTC),
    )
