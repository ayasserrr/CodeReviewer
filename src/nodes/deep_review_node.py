"""LangGraph node wrapping the Deep Review controller.

Thin by design — all orchestration lives in ``controllers.DeepReviewController``;
this adapts graph state in and out and owns the ``review_reports`` row
lifecycle. Database sessions are deliberately short: one to check the cache
and insert the RUNNING row, one to write the result. No connection is held
open for the minutes the agents run.

A review failure never fails the pipeline: ingestion, discovery, static
analysis and the dependency graph have already been persisted and are still
returned; the row is marked FAILED with the reason and ``review_status`` says
so.
"""

from typing import TYPE_CHECKING
from uuid import UUID

from config import settings
from controllers import DeepReviewController
from data import db_manager
from data.repositories import ReviewReportRepository
from helpers import (
    complete_review,
    compute_review_cache_key,
    fail_review,
    get_cached_review,
    model_identity,
    start_review,
)
from system import get_logger
from utils import DeepReviewReport

if TYPE_CHECKING:
    from graph import PipelineState

logger = get_logger(__name__)


async def deep_review_node(state: "PipelineState") -> dict:
    """Fifth node of the pipeline: multi-agent deep code review."""
    if not settings.DEEP_REVIEW_ENABLED:
        return {"review_report_id": None, "review_status": "skipped", "review_report": None}

    context = state["result"].context
    manifest = state["manifest"]
    repository_uuid = UUID(context.repository_id)
    repository_name = context.gitlab_url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")

    controller = DeepReviewController()
    review_config = controller.load_config()
    provider, model = model_identity(settings)
    cache_key = compute_review_cache_key(
        repository_id=context.repository_id,
        head_sha=context.head_sha,
        engine_version=settings.DEEP_REVIEW_ENGINE_VERSION,
        config_hash=review_config.config_hash,
        provider=provider,
        model=model,
    )

    async with db_manager.session() as db_session:
        repo = ReviewReportRepository(db_session)
        cached = await get_cached_review(repo, cache_key)
        if cached is not None and cached.report_data:
            return {
                "review_report_id": cached.id,
                "review_status": "completed",
                "review_report": DeepReviewReport.model_validate(cached.report_data),
            }
        record = await start_review(
            repo,
            repository_id=repository_uuid,
            head_sha=context.head_sha,
            branch=context.default_branch,
            cache_key=cache_key,
            engine_version=settings.DEEP_REVIEW_ENGINE_VERSION,
            provider=provider,
            model=model,
        )
        review_report_id = record.id

    try:
        report, markdown = await controller.review(
            repository_id=context.repository_id,
            repository_name=repository_name,
            repo_path=context.repo_path,
            head_sha=context.head_sha,
            cache_key=cache_key,
            manifest=manifest,
            static_findings=state.get("findings", []),
            tool_results=state.get("tool_results", {}),
            graph=state["dependency_graph"],
            review_config=review_config,
        )
    except Exception as exc:  # noqa: BLE001 -- recorded on the row; earlier phases' results still returned
        logger.exception("deep_review_failed", repository_id=context.repository_id)
        async with db_manager.session() as db_session:
            await fail_review(ReviewReportRepository(db_session), review_report_id, f"{type(exc).__name__}: {exc}")
        return {"review_report_id": review_report_id, "review_status": "failed", "review_report": None}

    async with db_manager.session() as db_session:
        await complete_review(ReviewReportRepository(db_session), review_report_id, report, markdown)
    return {"review_report_id": review_report_id, "review_status": "completed", "review_report": report}
