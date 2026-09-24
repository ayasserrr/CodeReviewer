"""Compiles the code-review pipeline graph.

Wires up ingestion, discovery, static analysis, the dependency graph and
the multi-agent deep review: ``ingest -> discovery -> static_analysis ->
dependency_graph -> deep_review -> END``. The deep review reads everything
the earlier phases put in state (clone, manifest, static findings, graph).
"""

from langgraph.graph import END, START, StateGraph

from graph.state import PipelineState
from nodes import (
    deep_review_node,
    dependency_graph_node,
    discovery_node,
    ingest_node,
    static_analysis_node,
)


def build_pipeline_graph():
    """Build and compile the code-review pipeline graph."""
    state_graph = StateGraph(PipelineState)
    state_graph.add_node("ingest", ingest_node)
    state_graph.add_node("discovery", discovery_node)
    state_graph.add_node("static_analysis", static_analysis_node)
    state_graph.add_node("dependency_graph", dependency_graph_node)
    state_graph.add_node("deep_review", deep_review_node)
    state_graph.add_edge(START, "ingest")
    state_graph.add_edge("ingest", "discovery")
    state_graph.add_edge("discovery", "static_analysis")
    state_graph.add_edge("static_analysis", "dependency_graph")
    state_graph.add_edge("dependency_graph", "deep_review")
    state_graph.add_edge("deep_review", END)
    return state_graph.compile()


pipeline_graph = build_pipeline_graph()
