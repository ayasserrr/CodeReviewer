"""The RepositoryManifest schema — Discovery's versioned, cacheable output.

Everything downstream (Knowledge Base construction, Deep Review agents)
reads this manifest instead of re-scanning the repository. It's a plain,
JSON-serializable Pydantic model so it can be stored as-is in the
``repository_manifests.manifest_data`` JSONB column and reconstructed
byte-for-byte on a cache hit.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from enums import ConfidenceLevel, HttpMethod


class FileEntry(BaseModel):
    """One file discovered during traversal.

    Attributes:
        path: Path relative to the repository root (POSIX separators).
        language: Detected language name, or ``None`` if unrecognized.
        size_bytes: File size in bytes.
        lines: Line count, or ``None`` if the file wasn't read as text.
        parse_error: Whether AST parsing raised (e.g. a syntax error).
        parse_error_message: The exception message, if ``parse_error`` is true.
        skipped_due_to_size: True if the file exceeded ``DISCOVERY_MAX_AST_FILE_SIZE_MB``.
        ast_timeout: True if AST parsing exceeded the per-file timeout.
    """

    model_config = ConfigDict(frozen=True)

    path: str
    language: str | None
    size_bytes: int
    lines: int | None = None
    parse_error: bool = False
    parse_error_message: str | None = None
    skipped_due_to_size: bool = False
    ast_timeout: bool = False


class LanguageStat(BaseModel):
    """Aggregate statistics for one detected language.

    Attributes:
        language: Language name.
        file_count: Number of files of this language.
        total_bytes: Combined size of all files of this language.
        total_lines: Combined line count of all files of this language.
    """

    model_config = ConfigDict(frozen=True)

    language: str
    file_count: int
    total_bytes: int
    total_lines: int


class FrameworkEvidence(BaseModel):
    """The raw signals behind one framework's confidence score.

    Attributes:
        dependency_found: Evidence A — listed in a dependency manifest.
        dependency_source: Which file it was found in (e.g. ``pyproject.toml``).
        import_found: Evidence B — an explicit import statement was found.
        import_locations: Files where the import was found.
        pattern_found: Evidence C — an AST-level usage pattern was found
            (e.g. ``app = FastAPI()``, ``@app.route(...)``).
        pattern_locations: Files where the pattern was found.
    """

    model_config = ConfigDict(frozen=True)

    dependency_found: bool = False
    dependency_source: str | None = None
    import_found: bool = False
    import_locations: tuple[str, ...] = Field(default_factory=tuple)
    pattern_found: bool = False
    pattern_locations: tuple[str, ...] = Field(default_factory=tuple)


class FrameworkDetection(BaseModel):
    """One framework's deterministic detection result.

    Attributes:
        name: Framework name (e.g. ``"fastapi"``).
        score: Deterministic score — A=1, B=1, C=2; see ``helpers.framework_detector``.
        confidence: LOW (score 1), MEDIUM (score 2-3), or HIGH (score 4+).
        is_primary: True only at HIGH confidence — a confirmed primary framework.
        evidence: The raw signals the score was computed from.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    score: int = Field(..., ge=0)
    confidence: ConfidenceLevel
    is_primary: bool
    evidence: FrameworkEvidence


class Entrypoint(BaseModel):
    """A detected application entrypoint.

    Attributes:
        path: File path relative to the repository root.
        kind: How it was recognized (``"main_guard"``, ``"framework_app_instance"``,
            ``"manage_py"``, ``"wsgi"``, or ``"asgi"``).
        detail: Optional extra context (e.g. the variable name assigned).
    """

    model_config = ConfigDict(frozen=True)

    path: str
    kind: str
    detail: str | None = None


class Endpoint(BaseModel):
    """A detected HTTP endpoint, function-based or class-based.

    Attributes:
        method: HTTP method.
        path: Route path as declared in source (e.g. ``"/users/{id}"``).
        handler: Function or method name that handles the request.
        file: File path relative to the repository root.
        line: 1-based line number of the handler definition.
        framework: Which framework this route was detected for.
        is_class_based: True for class-based views (e.g. Flask ``MethodView``).
        class_name: The containing class name, if ``is_class_based``.
        duplicate: True if this exact ``(method, path)`` also appears elsewhere —
            callers should treat all entries sharing a ``(method, path)`` as needing
            disambiguation via ``file``/``line`` rather than assuming a single owner.
    """

    model_config = ConfigDict(frozen=True)

    method: HttpMethod
    path: str
    handler: str
    file: str
    line: int
    framework: str
    is_class_based: bool = False
    class_name: str | None = None
    duplicate: bool = False


class DependencyEntry(BaseModel):
    """One declared dependency.

    Attributes:
        name: Package name.
        version: Version specifier as declared, or ``None`` if unpinned.
        source_file: Which manifest file declared it.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    version: str | None
    source_file: str


class DiscoveryStatistics(BaseModel):
    """Aggregate counters and flags for one discovery run.

    Attributes:
        total_files_found: Files discovered during traversal.
        total_files_scanned: Files actually read/classified.
        total_files_ast_parsed: Files that went through AST parsing.
        total_files_skipped_due_to_size: Files skipped for exceeding the AST size cap.
        total_parse_errors: Files where AST parsing raised.
        total_bytes: Combined size of all scanned files.
        total_lines: Combined line count of all scanned files.
        duration_seconds: Wall-clock time the discovery run took.
        traversal_timed_out: True if the 5s traversal budget was exceeded.
        discovery_timed_out: True if the 15s total budget was exceeded
            (in which case the manifest reflects a partial, best-effort scan).
        source_roots: The source roots identified by the rapid surface scan.
    """

    model_config = ConfigDict(frozen=True)

    total_files_found: int = 0
    total_files_scanned: int = 0
    total_files_ast_parsed: int = 0
    total_files_skipped_due_to_size: int = 0
    total_parse_errors: int = 0
    total_bytes: int = 0
    total_lines: int = 0
    duration_seconds: float = 0.0
    traversal_timed_out: bool = False
    discovery_timed_out: bool = False
    source_roots: tuple[str, ...] = Field(default_factory=tuple)


class RepositoryManifest(BaseModel):
    """The full, versioned, cacheable output of the Discovery phase.

    Attributes:
        schema_version: Version of this schema's shape.
        discovery_engine_version: Version of the detection heuristics that produced this.
        repository_id: The ingested repository's stable identifier.
        head_sha: The commit SHA this manifest describes.
        cache_key: ``hash(head_sha + discovery_engine_version + schema_version)``.
        generated_at: When this manifest was produced, in UTC.
        files: Every file discovered, with per-file classification/parse status.
        languages: Aggregate stats per detected language.
        frameworks: Deterministic framework-detection results.
        entrypoints: Detected application entrypoints.
        endpoints: Detected HTTP endpoints.
        dependencies: Declared dependencies across all manifest files found.
        statistics: Aggregate counters and timeout/truncation flags.
        unreadable_directories: Directories that raised ``PermissionError``.
        env_file_exists: Whether a ``.env`` file exists at the repo root.
            Its contents are never read or stored — existence only.
    """

    model_config = ConfigDict(frozen=True)

    schema_version: str
    discovery_engine_version: str
    repository_id: str
    head_sha: str
    cache_key: str
    generated_at: datetime

    files: tuple[FileEntry, ...] = Field(default_factory=tuple)
    languages: tuple[LanguageStat, ...] = Field(default_factory=tuple)
    frameworks: tuple[FrameworkDetection, ...] = Field(default_factory=tuple)
    entrypoints: tuple[Entrypoint, ...] = Field(default_factory=tuple)
    endpoints: tuple[Endpoint, ...] = Field(default_factory=tuple)
    dependencies: tuple[DependencyEntry, ...] = Field(default_factory=tuple)
    statistics: DiscoveryStatistics = Field(default_factory=DiscoveryStatistics)
    unreadable_directories: tuple[str, ...] = Field(default_factory=tuple)
    env_file_exists: bool = False
