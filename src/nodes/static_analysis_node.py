"""LangGraph node wrapping the static analysis + security engine orchestration.

Thin by design — all the actual tool-running logic lives in
``services.static_analysis``; this just adapts graph state in and out.
Runs immediately after ``discovery`` and reads only what discovery already
produced (the ``RepositoryManifest``, for every tool's file list); it never
re-scans the filesystem itself.
"""

from typing import TYPE_CHECKING

from data import db_manager
from services import analyze

if TYPE_CHECKING:
    from graph import PipelineState


async def static_analysis_node(state: "PipelineState") -> dict:
    """Third node of the pipeline: run structural + security tools against the ingested clone."""
    context = state["result"].context
    manifest = state["manifest"]

    async with db_manager.session() as db_session:
        findings, tool_results = await analyze(context.repo_path, manifest, db_session)
    return {"findings": findings, "tool_results": tool_results}
