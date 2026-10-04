"""Live pipeline progress for UIs polling a ``review_reports`` row.

The pipeline runs in the background for minutes; a client polling
``GET /reviews/{id}`` should see *where* it is, not just ``running``. Two
kinds of events land on the row:

- **Stages** (``ingest`` -> ``discovery`` -> ``static_analysis`` ->
  ``dependency_graph`` -> ``deep_review``), recorded by the node wrapper in
  ``graph.workflow`` — the nodes themselves stay unaware of progress.
- **Agents** inside ``deep_review`` (each specialist, verifier and the
  synthesizer starting/finishing), reported by ``DeepReviewController``.

Shape of ``review_reports.progress``::

    {
      "stages": {"ingest": {"status": "completed", "started_at": ..., "finished_at": ...}, ...},
      "agents": {"specialist:security": {"status": "running", "started_at": ...}, ...}
    }

Progress is best-effort observability: a failed write is logged and
swallowed, never allowed to fail the pipeline it describes.
"""

import asyncio
import copy
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from data import db_manager
from data.repositories import ReviewReportRepository
from system import get_logger
from utils import AgentRunStats

logger = get_logger(__name__)

PIPELINE_STAGES: tuple[str, ...] = ("ingest", "discovery", "static_analysis", "dependency_graph", "deep_review")
"""Every stage in execution order — also the order a UI should display them in."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


class PipelineProgress:
    """Records progress events onto one ``review_reports`` row.

    Writes are serialized with a lock (the deep-review agents finish
    concurrently) and each opens its own short session, so no connection
    is held across the minutes a stage runs.
    """

    def __init__(self, review_report_id: UUID) -> None:
        self.review_report_id = review_report_id
        self._lock = asyncio.Lock()

    async def _apply(self, mutate, *, stage: str | None = None) -> None:
        try:
            async with self._lock, db_manager.session() as db_session:
                repo = ReviewReportRepository(db_session)
                row = await repo.get(self.review_report_id)
                if row is None:
                    return
                progress: dict[str, Any] = copy.deepcopy(row.progress or {})
                progress.setdefault("stages", {})
                progress.setdefault("agents", {})
                mutate(progress)
                # A fresh dict object, so SQLAlchemy sees the JSONB column as changed.
                await repo.update(self.review_report_id, progress=progress, stage=stage)
        except Exception:
            logger.warning("pipeline_progress_write_failed", review_report_id=str(self.review_report_id), exc_info=True)

    async def stage_started(self, stage: str) -> None:
        def mutate(progress: dict[str, Any]) -> None:
            progress["stages"][stage] = {"status": "running", "started_at": _now()}

        await self._apply(mutate, stage=stage)

    async def stage_finished(self, stage: str, status: str) -> None:
        """``status``: ``completed`` or ``failed``. The last stage completing marks the run ``done``."""

        def mutate(progress: dict[str, Any]) -> None:
            entry = progress["stages"].setdefault(stage, {"started_at": _now()})
            entry.update(status=status, finished_at=_now())

        final_stage = status == "failed" or stage == PIPELINE_STAGES[-1]
        await self._apply(mutate, stage=("failed" if status == "failed" else "done") if final_stage else stage)

    async def agent_started(self, agent: str) -> None:
        def mutate(progress: dict[str, Any]) -> None:
            progress["agents"][agent] = {"status": "running", "started_at": _now()}

        await self._apply(mutate)

    async def agent_finished(self, stats: AgentRunStats) -> None:
        def mutate(progress: dict[str, Any]) -> None:
            entry = progress["agents"].setdefault(stats.agent, {"started_at": _now()})
            entry.update(
                status=stats.status,
                finished_at=_now(),
                duration_seconds=round(stats.duration_seconds, 1),
                model_calls=stats.model_calls,
            )

        await self._apply(mutate)
