"""Immutable data contracts produced by the ingestion controller.

Everything downstream of ingestion (file discovery, static analysis, the
knowledge graph, review generation, ...) operates entirely on a
``RepositoryContext`` and must never need to call GitLab again.
"""

from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from enums import SourceType


class RepositoryContext(BaseModel):
    """A validated, immutable snapshot of one ingested repository.

    Attributes:
        repo_path: Absolute path to the local clone.
        repository_id: Stable identifier — also the folder name under ``cloned_repos/``.
        source_type: Where this repository was ingested from.
        gitlab_url: Normalized clone URL (host + full project path, no credentials).
        head_sha: Full 40-character commit SHA checked out.
        default_branch: The branch that was resolved and checked out.
    """

    model_config = ConfigDict(frozen=True)

    repo_path: Path
    repository_id: str
    source_type: SourceType
    gitlab_url: str
    head_sha: str
    default_branch: str


class RepositoryIngestionResult(BaseModel):
    """The outcome of a single ingestion run.

    Attributes:
        context: The resulting immutable repository snapshot.
        duration_seconds: Wall-clock time the ingestion pipeline took.
        ingested_at: When ingestion completed, in UTC.
    """

    model_config = ConfigDict(frozen=True)

    context: RepositoryContext
    duration_seconds: float = Field(..., ge=0)
    ingested_at: datetime
