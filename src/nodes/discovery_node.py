"""LangGraph node wrapping the discovery controller.

Thin by design — all the actual discovery logic lives in
``controllers.DiscoveryController``; this just adapts graph state in and out.
Runs immediately after ``ingest`` and reads only what ingestion already
produced (``repo_path``, ``head_sha``) — it never calls GitLab again.
"""

from typing import TYPE_CHECKING
from uuid import UUID

from controllers import DiscoveryController
from data import db_manager

if TYPE_CHECKING:
    from graph import PipelineState


async def discovery_node(state: "PipelineState") -> dict:
    """Second node of the pipeline: build a versioned manifest from the ingested snapshot."""
    context = state["result"].context

    async with db_manager.session() as db_session:
        manifest = await DiscoveryController(db_session).discover(
            repository_id=UUID(context.repository_id),
            repo_path=context.repo_path,
            head_sha=context.head_sha,
        )
    return {"manifest": manifest}
