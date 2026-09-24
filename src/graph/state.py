"""Shared state threaded through the code-review pipeline graph.

Populated incrementally as each phase runs:
- ``ingest`` sets ``result`` (the ``RepositoryIngestionResult`` wrapping the
  ``RepositoryContext`` snapshot everything downstream operates on).
- ``discovery`` sets ``manifest`` (the versioned ``RepositoryManifest``).
- ``static_analysis`` sets ``findings`` (content-hashed ``StaticFinding``s
  from the structural + security tools) and ``tool_results`` (the raw
  per-tool status/error contract, kept for observability/debugging).
- ``dependency_graph`` sets ``dependency_graph`` (the tree-sitter + grimp
  ``DependencyGraph`` — functions, classes, containment, calls, imports).
- ``deep_review`` sets ``review_report_id``, ``review_status`` and, on
  success, ``review_report`` (the multi-agent ``DeepReviewReport``).

Later phases (knowledge base construction, review generation) add their
own keys here without needing to touch what earlier phases already set.
"""

from typing import Any, TypedDict
from uuid import UUID

from utils import (
    DeepReviewReport,
    DependencyGraph,
    RepositoryIngestionResult,
    RepositoryManifest,
    StaticFinding,
)


class PipelineState(TypedDict, total=False):
    """State for the full code-review pipeline graph.

    Attributes:
        gitlab_url: The repository's GitLab URL.
        access_token: GitLab access token, consumed only by ``ingest_node``
            and never written back into state or logged.
        repo_id: Optional existing repository UUID to re-ingest.
        user_id: The authenticated user this repository belongs to.
        result: The ingestion outcome, populated by ``ingest_node``.
        manifest: The discovery outcome, populated by ``discovery_node``.
        findings: Normalized findings, populated by ``static_analysis_node``.
        tool_results: Raw per-tool result contract, populated by ``static_analysis_node``.
        dependency_graph: The tree-sitter + grimp dependency graph, populated
            by ``dependency_graph_node``.
        review_report_id: The ``review_reports`` row for this run, populated by
            ``deep_review_node`` (absent when deep review is disabled).
        review_status: ``completed`` / ``failed`` / ``skipped``.
        review_report: The deep-review report, populated on success.
    """

    gitlab_url: str
    access_token: str
    repo_id: str | None
    user_id: UUID
    result: RepositoryIngestionResult
    manifest: RepositoryManifest
    findings: list[StaticFinding]
    tool_results: dict[str, dict[str, Any]]
    dependency_graph: DependencyGraph
    review_report_id: UUID | None
    review_status: str
    review_report: DeepReviewReport | None
