"""Compiles the code-review pipeline graph.

Currently wires up ingestion, discovery, static analysis, and the
dependency graph: ``ingest -> discovery -> static_analysis ->
dependency_graph -> END``. Knowledge-base construction and review-generation
nodes get added here as their own ``add_node``/``add_edge`` calls once they
exist, hanging off ``dependency_graph`` and reading the graph it produces
from state.
"""

from langgraph.graph import END, START, StateGraph

from graph import PipelineState
from nodes import (
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
    state_graph.add_edge(START, "ingest")
    state_graph.add_edge("ingest", "discovery")
    state_graph.add_edge("discovery", "static_analysis")
    state_graph.add_edge("static_analysis", "dependency_graph")
    state_graph.add_edge("dependency_graph", END)
    return state_graph.compile()


pipeline_graph = build_pipeline_graph()
