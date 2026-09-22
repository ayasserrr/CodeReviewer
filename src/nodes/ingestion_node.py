"""LangGraph node wrapping the ingestion controller.

Thin by design — all the actual ingestion logic lives in
``controllers.IngestionController``; this just adapts graph state in and out.

The ``PipelineState`` import is TYPE_CHECKING-only: ``graph.workflow`` needs
to import this module to register the node, so this module must not import
``graph`` back at runtime (that would be a real circular import, not just an
ordering quirk — this is the one edge in the dependency graph that has to
stay one-directional).
"""

from typing import TYPE_CHECKING

from controllers import IngestionController
from data import db_manager

if TYPE_CHECKING:
    from graph import PipelineState


async def ingest_node(state: "PipelineState") -> dict:
    """Entry point of the pipeline: ingest a GitLab repository into a local snapshot."""
    async with db_manager.session() as db_session:
        result = await IngestionController(db_session).ingest(
            gitlab_url=state["gitlab_url"],
            access_token=state["access_token"],
            repo_id=state.get("repo_id"),
            user_id=state["user_id"],
        )
    return {"result": result}
