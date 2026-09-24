"""LangGraph node wrapping the Deep Review controller.

Thin by design — all orchestration lives in ``controllers.DeepReviewController``;
this adapts graph state in and out and owns the ``review_reports`` row
lifecycle. Database sessions are deliberately short: one to check the cache
and transition the row, one to write the result. No connection is held open
for the minutes the agents run.

Two ways this node can be entered, both supported:

- **Via the ingestion API** (the normal path): ``state["review_report_id"]``
  is already set — the endpoint inserted a PENDING row before returning 202
  and handed the pipeline to ``graph.runner.run_pipeline_background``. This
  node transitions that same row (PENDING -> RUNNING -> COMPLETED/FAILED)
  rather than creating a new one, since the client is already polling it.
- **Direct invocation** (scripts, tests, anything that calls
  ``pipeline_graph.ainvoke()`` without going through the API) — no
  pre-created row, so this node creates one itself, exactly as before.

A review failure never fails the pipeline: ingestion, discovery, static
analysis and the dependency graph have already been persisted and are still
returned; the row is marked FAILED with the reason and ``review_status`` says
so. A pipeline-level failure in an *earlier* node (ingest, discovery, ...)
never reaches this node at all — ``graph.runner.run_pipeline_background`` is
the catch-all for those, since they can't fail their own row (they don't
have one yet).
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
    mark_review_running,
    model_identity,
    skip_review,
    start_review,
)
from system import get_logger
from utils import DeepReviewReport

if TYPE_CHECKING:
    from graph import PipelineState

logger = get_logger(__name__)


async def deep_review_node(state: "PipelineState") -> dict:
    """Fifth node of the pipeline: multi-agent deep code review."""
    context = state["result"].context
    existing_review_report_id = state.get("review_report_id")

    if not settings.DEEP_REVIEW_ENABLED:
        if existing_review_report_id is not None:
            async with db_manager.session() as db_session:
                await skip_review(
                    ReviewReportRepository(db_session),
                    existing_review_report_id,
                    head_sha=context.head_sha,
                    branch=context.default_branch,
                )
        return {"review_report_id": existing_review_report_id, "review_status": "skipped", "review_report": None}

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
            report = DeepReviewReport.model_validate(cached.report_data)
            review_report_id = existing_review_report_id or cached.id
            if existing_review_report_id is not None and existing_review_report_id != cached.id:
                # The client is polling *our* pre-created row, not the row the
                # cache hit landed on — copy the result across so it isn't
                # left stuck PENDING while a different row holds the data. Fill in
                # the commit/branch/model metadata first — the pre-created row
                # has none, and a completed review without its commit is useless.
                await mark_review_running(
                    repo,
                    existing_review_report_id,
                    head_sha=context.head_sha,
                    branch=context.default_branch,
                    cache_key=cache_key,
                    engine_version=settings.DEEP_REVIEW_ENGINE_VERSION,
                    provider=provider,
                    model=model,
                )
                await complete_review(repo, existing_review_report_id, report, cached.report_markdown or "")
            return {"review_report_id": review_report_id, "review_status": "completed", "review_report": report}

        if existing_review_report_id is not None:
            record = await mark_review_running(
                repo,
                existing_review_report_id,
                head_sha=context.head_sha,
                branch=context.default_branch,
                cache_key=cache_key,
                engine_version=settings.DEEP_REVIEW_ENGINE_VERSION,
                provider=provider,
                model=model,
            )
        else:
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
    except Exception as exc:
        logger.exception("deep_review_failed", repository_id=context.repository_id)
        async with db_manager.session() as db_session:
            await fail_review(ReviewReportRepository(db_session), review_report_id, f"{type(exc).__name__}: {exc}")
        return {"review_report_id": review_report_id, "review_status": "failed", "review_report": None}

    async with db_manager.session() as db_session:
        await complete_review(ReviewReportRepository(db_session), review_report_id, report, markdown)
    return {"review_report_id": review_report_id, "review_status": "completed", "review_report": report}
