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
from utils import DeepReviewError, DeepReviewReport

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
    """Insert the RUNNING row up front so an in-flight review is visible.

    Legacy/direct-invocation path: used when the caller (a script, a test,
    ``pipeline_graph.ainvoke()`` called without going through the ingestion
    API) didn't pre-create a row via ``queue_review``. The API path instead
    pre-creates a PENDING row before the pipeline even starts and
    ``mark_review_running`` transitions it in place.
    """
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


async def queue_review(repo: ReviewReportRepository, *, repository_id: UUID) -> ReviewReport:
    """Insert a PENDING row before the pipeline has even started.

    Called synchronously from the ingestion endpoint, before the request
    returns — ``commit_sha``/``branch`` aren't known yet (nothing has been
    cloned), so both stay ``None`` until ``mark_review_running`` fills them
    in once ``ingest_node`` has resolved a ``head_sha``.
    """
    return await repo.create(repository_id=repository_id, status=ReviewStatus.PENDING)


async def mark_review_running(
    repo: ReviewReportRepository,
    review_report_id: UUID,
    *,
    head_sha: str,
    branch: str,
    cache_key: str,
    engine_version: str,
    provider: str,
    model: str,
) -> ReviewReport:
    """Transition a pre-created (PENDING) row to RUNNING, filling in what's now known.

    Raises:
        DeepReviewError: If ``review_report_id`` doesn't exist — it was
            created moments earlier by the same request that queued this
            pipeline run, so a miss here means something deleted it out
            from under an in-flight run.
    """
    updated = await repo.update(
        review_report_id,
        status=ReviewStatus.RUNNING,
        commit_sha=head_sha,
        branch=branch,
        cache_key=cache_key,
        engine_version=engine_version,
        provider=provider,
        model=model,
    )
    if updated is None:
        raise DeepReviewError(f"review_report {review_report_id} not found")
    return updated


async def skip_review(repo: ReviewReportRepository, review_report_id: UUID, *, head_sha: str, branch: str) -> None:
    """Complete a pre-created row when ``DEEP_REVIEW_ENABLED`` is false.

    There's no ``ReviewStatus.SKIPPED`` — COMPLETED with no report data is
    the honest terminal state here: the pipeline (ingest through the
    dependency graph) succeeded, the deep-review agents specifically were
    turned off. Without this, a row pre-created by the ingestion endpoint
    would stay PENDING forever whenever the feature is disabled.
    """
    await repo.update(
        review_report_id,
        status=ReviewStatus.COMPLETED,
        commit_sha=head_sha,
        branch=branch,
        completed_at=datetime.now(UTC),
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
