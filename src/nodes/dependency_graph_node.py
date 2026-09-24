"""LangGraph node wrapping the DependencyGraph controller.

Thin by design — all the actual tree-sitter/grimp logic lives in
``controllers.DependencyGraphController``; this just adapts graph state in
and out. Runs immediately after ``static_analysis`` and reads only what
discovery already produced (the ``RepositoryManifest``, for the file list
and source roots); it never re-scans the filesystem itself.
"""

from typing import TYPE_CHECKING
from uuid import UUID

from controllers import DependencyGraphController
from data import db_manager

if TYPE_CHECKING:
    from graph import PipelineState


async def dependency_graph_node(state: "PipelineState") -> dict:
    """Fourth node of the pipeline: build the tree-sitter + grimp dependency graph."""
    context = state["result"].context
    manifest = state["manifest"]

    async with db_manager.session() as db_session:
        graph = await DependencyGraphController(db_session).build(
            repository_id=UUID(context.repository_id),
            repo_path=context.repo_path,
            head_sha=context.head_sha,
            manifest=manifest,
        )
    return {"dependency_graph": graph}
