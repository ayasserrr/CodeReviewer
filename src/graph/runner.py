"""Runs the pipeline graph detached from the HTTP request that triggered it.

``POST /ingestion/repositories`` returns 202 as soon as the review row is
queued and hands the actual run to a FastAPI background task calling
``run_pipeline_background`` — by then the request (and its ``DbSession``) is
already gone, so this module never touches it; every node already opens its
own session via ``db_manager.session()``, and this function opens one more
of its own, only to record a pipeline-level failure.
"""

from uuid import UUID

from data import db_manager
from data.repositories import ReviewReportRepository
from graph.state import PipelineState
from graph.workflow import pipeline_graph
from helpers import fail_review
from system import get_logger

logger = get_logger(__name__)


async def run_pipeline_background(state: PipelineState, review_report_id: UUID) -> None:
    """Runs the full ``ingest -> ... -> deep_review`` pipeline for one queued request.

    Any exception anywhere in the pipeline — not just a deep-review
    failure, which ``deep_review_node`` already handles on its own row —
    is caught here and turns into a FAILED row instead of a silently lost
    background task. There is no request left to propagate an exception to,
    so this is the last line of defense: a failure in ingest, discovery,
    static analysis or the dependency graph (none of which touch
    ``review_reports`` themselves) would otherwise leave the row stuck at
    PENDING/RUNNING forever with no record of why.
    """
    try:
        await pipeline_graph.ainvoke(state)
    except Exception as exc:
        logger.exception("pipeline_background_run_failed", review_report_id=str(review_report_id))
        async with db_manager.session() as db_session:
            await fail_review(ReviewReportRepository(db_session), review_report_id, f"{type(exc).__name__}: {exc}")
