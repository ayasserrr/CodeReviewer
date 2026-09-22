"""Compiles the code-review pipeline graph.

Currently wires up only the ingestion phase, with ``ingest`` as the entry
point. Discovery, static analysis, and review-generation nodes get added
here as their own ``add_node``/``add_edge`` calls once they exist — later
phases hang off ``ingest`` and read the ``RepositoryContext`` it produces
from state, without needing to call GitLab again.
"""

from langgraph.graph import END, START, StateGraph

from graph import PipelineState
from nodes import ingest_node


def build_pipeline_graph():
    """Build and compile the code-review pipeline graph."""
    state_graph = StateGraph(PipelineState)
    state_graph.add_node("ingest", ingest_node)
    state_graph.add_edge(START, "ingest")
    state_graph.add_edge("ingest", END)
    return state_graph.compile()


pipeline_graph = build_pipeline_graph()
