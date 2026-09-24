"""The DependencyGraph schema — the DependencyGraph node's versioned, cacheable output.

A plain, JSON-serializable Pydantic model, stored as-is in the
``dependency_graphs.graph_data`` JSONB column and reconstructed byte-for-byte
on a cache hit — the same approach ``utils.manifest.RepositoryManifest``
already uses.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class FunctionNode(BaseModel):
    """One function or method extracted via tree-sitter.

    Attributes:
        id: ``f"{file}::{qualname}"`` — stable across re-parses of unchanged source.
        name: The function's simple (unqualified) name.
        qualname: Dotted path from the module (e.g. ``"MyClass.my_method"``).
        file: Path relative to the repository root.
        start_line: 1-based starting line number.
        end_line: 1-based ending line number.
        start_byte: Starting byte offset in the file's source.
        end_byte: Ending byte offset in the file's source.
        is_async: Whether declared with ``async def``.
        decorators: Decorator names applied to this function, in source order.
        params: Parameter names, in declaration order.
        content_hash: ``sha256`` of the function's own byte span.
        loc: Line count of the function's byte span.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    qualname: str
    file: str
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    is_async: bool = False
    decorators: tuple[str, ...] = Field(default_factory=tuple)
    params: tuple[str, ...] = Field(default_factory=tuple)
    content_hash: str
    loc: int


class ClassNode(BaseModel):
    """One class extracted via tree-sitter.

    Attributes:
        id: ``f"{file}::{qualname}"`` — stable across re-parses of unchanged source.
        name: The class's simple (unqualified) name.
        qualname: Dotted path from the module (e.g. ``"Outer.Inner"``).
        file: Path relative to the repository root.
        start_line: 1-based starting line number.
        end_line: 1-based ending line number.
        start_byte: Starting byte offset in the file's source.
        end_byte: Ending byte offset in the file's source.
        method_count: Number of direct (non-nested-class) methods.
        content_hash: ``sha256`` of the class's own byte span.
        loc: Line count of the class's byte span.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    qualname: str
    file: str
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    method_count: int = 0
    content_hash: str
    loc: int


class ContainsEdge(BaseModel):
    """A lexical containment relationship: file->def, class->method, function->nested-function.

    Attributes:
        parent_id: The containing file path, or a ``FunctionNode``/``ClassNode`` id.
        child_id: The contained ``FunctionNode``/``ClassNode`` id.
    """

    model_config = ConfigDict(frozen=True)

    parent_id: str
    child_id: str


class CallEdge(BaseModel):
    """A resolved call relationship between two functions in this repository.

    Attributes:
        caller_id: The calling ``FunctionNode`` id.
        callee_id: The called ``FunctionNode`` id.
        line: 1-based line number of the call site.
        col: 0-based column number of the call site.
    """

    model_config = ConfigDict(frozen=True)

    caller_id: str
    callee_id: str
    line: int
    col: int


class ImportEdge(BaseModel):
    """A module-level import relationship discovered by grimp.

    Attributes:
        module: The importing module's dotted path.
        imported: The imported module's dotted path.
    """

    model_config = ConfigDict(frozen=True)

    module: str
    imported: str


class DependencyGraphStatistics(BaseModel):
    """Aggregate counters for one dependency-graph build.

    Attributes:
        files_parsed: Python files successfully parsed via tree-sitter.
        functions_found: Total ``FunctionNode``s extracted.
        classes_found: Total ``ClassNode``s extracted.
        calls_found: Total call sites captured before resolution.
        calls_resolved: Call sites that resolved to exactly one function (became a ``CallEdge``).
        calls_skipped_external: Call sites with zero repo-local candidates (external/library calls).
        calls_skipped_ambiguous: Call sites with more than one repo-local candidate.
        import_edges_found: Total ``ImportEdge``s discovered by grimp.
        duration_seconds: Wall-clock time the build took.
    """

    model_config = ConfigDict(frozen=True)

    files_parsed: int = 0
    functions_found: int = 0
    classes_found: int = 0
    calls_found: int = 0
    calls_resolved: int = 0
    calls_skipped_external: int = 0
    calls_skipped_ambiguous: int = 0
    import_edges_found: int = 0
    duration_seconds: float = 0.0


class DependencyGraphFailure(BaseModel):
    """One file that failed tree-sitter extraction.

    Attributes:
        file: Path relative to the repository root.
        error: ``f"{type(exc).__name__}: {exc}"``.
    """

    model_config = ConfigDict(frozen=True)

    file: str
    error: str


class DependencyGraph(BaseModel):
    """The full, versioned, cacheable output of the DependencyGraph phase.

    Attributes:
        schema_version: Version of this schema's shape.
        engine_version: Version of the extraction/resolution logic that produced this.
        repository_id: The ingested repository's stable identifier.
        head_sha: The commit SHA this graph describes.
        cache_key: ``hash(head_sha + engine_version + schema_version)``.
        generated_at: When this graph was produced, in UTC.
        functions: Every function/method extracted, across all parsed files.
        classes: Every class extracted, across all parsed files.
        contains_edges: Lexical containment relationships.
        call_edges: Resolved call relationships (flattened — every call in a
            function's body, regardless of nesting depth, that matched
            exactly one repo-local candidate).
        import_edges: Module-level import relationships from grimp.
        statistics: Aggregate counters for this build.
        failed_files: Files that raised during tree-sitter extraction.
    """

    model_config = ConfigDict(frozen=True)

    schema_version: str
    engine_version: str
    repository_id: str
    head_sha: str
    cache_key: str
    generated_at: datetime

    functions: tuple[FunctionNode, ...] = Field(default_factory=tuple)
    classes: tuple[ClassNode, ...] = Field(default_factory=tuple)
    contains_edges: tuple[ContainsEdge, ...] = Field(default_factory=tuple)
    call_edges: tuple[CallEdge, ...] = Field(default_factory=tuple)
    import_edges: tuple[ImportEdge, ...] = Field(default_factory=tuple)
    statistics: DependencyGraphStatistics = Field(default_factory=DependencyGraphStatistics)
    failed_files: tuple[DependencyGraphFailure, ...] = Field(default_factory=tuple)
