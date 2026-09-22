"""Shared state threaded through the code-review pipeline graph.

Populated incrementally as each phase runs:
- ``ingest`` sets ``result`` (the ``RepositoryIngestionResult`` wrapping the
  ``RepositoryContext`` snapshot everything downstream operates on).
- ``discovery`` sets ``manifest`` (the versioned ``RepositoryManifest``).

Later phases (static analysis, knowledge base construction, review
generation) add their own keys here without needing to touch what earlier
phases already set.
"""

from typing import Optional, TypedDict
from uuid import UUID

from utils import RepositoryIngestionResult, RepositoryManifest


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
    """

    gitlab_url: str
    access_token: str
    repo_id: Optional[str]
    user_id: UUID
    result: RepositoryIngestionResult
    manifest: RepositoryManifest
