"""Compiles the code-review pipeline graph.

Wires up ingestion, discovery, static analysis, the dependency graph and
the multi-agent deep review: ``ingest -> discovery -> static_analysis ->
dependency_graph -> deep_review -> END``. The deep review reads everything
the earlier phases put in state (clone, manifest, static findings, graph).

Every node is wrapped by ``_tracked``: when the run has a ``review_reports``
row (the API path), each stage's start/finish is recorded on it so a client
polling ``GET /reviews/{id}`` sees live progress. The nodes stay unaware.
"""

from collections.abc import Awaitable, Callable
from functools import wraps

from langgraph.graph import END, START, StateGraph

from graph.state import PipelineState
from helpers import PipelineProgress
from nodes import (
    deep_review_node,
    dependency_graph_node,
    discovery_node,
    ingest_node,
    static_analysis_node,
)

NodeFn = Callable[[PipelineState], Awaitable[dict]]


def _tracked(stage: str, node: NodeFn) -> NodeFn:
    """Record ``stage`` start/finish on the run's review row, if it has one."""

    @wraps(node)
    async def wrapper(state: PipelineState) -> dict:
        review_report_id = state.get("review_report_id")
        if review_report_id is None:
            return await node(state)
        progress = PipelineProgress(review_report_id)
        await progress.stage_started(stage)
        try:
            output = await node(state)
        except Exception:
            await progress.stage_finished(stage, "failed")
            raise
        # deep_review_node records its own failure on the row instead of raising.
        failed = output.get("review_status") == "failed"
        await progress.stage_finished(stage, "failed" if failed else "completed")
        return output

    return wrapper


def build_pipeline_graph():
    """Build and compile the code-review pipeline graph."""
    state_graph = StateGraph(PipelineState)
    state_graph.add_node("ingest", _tracked("ingest", ingest_node))
    state_graph.add_node("discovery", _tracked("discovery", discovery_node))
    state_graph.add_node("static_analysis", _tracked("static_analysis", static_analysis_node))
    state_graph.add_node("dependency_graph", _tracked("dependency_graph", dependency_graph_node))
    state_graph.add_node("deep_review", _tracked("deep_review", deep_review_node))
    state_graph.add_edge(START, "ingest")
    state_graph.add_edge("ingest", "discovery")
    state_graph.add_edge("discovery", "static_analysis")
    state_graph.add_edge("static_analysis", "dependency_graph")
    state_graph.add_edge("dependency_graph", "deep_review")
    state_graph.add_edge("deep_review", END)
    return state_graph.compile()


pipeline_graph = build_pipeline_graph()
