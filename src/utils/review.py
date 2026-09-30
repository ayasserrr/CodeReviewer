"""Schemas for the Deep Review node — its TOML config and its versioned report.

Two halves:

- ``ReviewConfig`` (+ ``ReviewCategory``, ``SecurityKpi``) mirrors
  ``src/assets/review_config.toml`` — what the review looks for.
- ``DeepReviewReport`` (+ ``ReviewFinding``, ``KpiAssessment``, ...) is the
  node's output: plain, JSON-serializable Pydantic, stored as-is in
  ``review_reports.report_data`` and rendered to markdown deterministically
  by ``helpers.review_report_renderer`` — the same "persist the model, not a
  rendering of it" approach ``RepositoryManifest`` and ``DependencyGraph`` use.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Severity = Literal["Critical", "High", "Medium", "Low"]
Confidence = Literal["low", "medium", "high"]
TriageVerdict = Literal["true_positive", "false_positive", "low_value"]
KpiStatus = Literal["open", "partially_open", "closed", "not_applicable", "not_verified"]
VerificationVerdict = Literal["confirmed", "rejected", "adjusted"]
# How reachable the defect is today — severity is calibrated against it.
Exposure = Literal["live", "conditional", "latent", "dead", "theoretical"]
EXPOSURE_LABELS: dict[str, str] = {
    "live": "live — reachable through the running system today",
    "conditional": "reachable, but only under specific conditions",
    "latent": "latent — present in the code, not reachable from any entry point today (one import/route away)",
    "dead": "dead — unused code nothing calls or plans to call",
    "theoretical": "theoretical — needs a future change to the architecture before it can happen",
}

SEVERITY_ORDER: tuple[str, ...] = ("Critical", "High", "Medium", "Low")
CONFIDENCE_ORDER: tuple[str, ...] = ("low", "medium", "high")


# ---------------------------------------------------------------------------
# Config (review_config.toml)
# ---------------------------------------------------------------------------


class ReviewSettings(BaseModel):
    """The ``[review]`` table."""

    model_config = ConfigDict(frozen=True)

    title_suffix: str = "Full Engineering Review"
    include_remediation: bool = False
    severity_levels: tuple[str, ...] = SEVERITY_ORDER
    verify_severities: tuple[Severity, ...] = ("Critical", "High", "Medium", "Low")
    max_findings_per_category: int = Field(30, gt=0)
    min_confidence: Confidence = "medium"


class ReviewCategory(BaseModel):
    """One ``[[categories]]`` entry — one specialist agent.

    Attributes:
        id: Stable identifier (also the specialist agent's name suffix).
        title: Report section title.
        code: Short prefix for finding ids (e.g. ``"SEC"`` -> ``SEC-3``).
        enabled: Disabled categories are skipped entirely.
        owns_security_kpis: The specialist that must assess every KPI.
        strong_model: Run this category's specialist on the judge model — for
            lanes whose value is deep multi-file tracing (the base model tends to
            stop at surface patterns there).
        effort: Relative run length (1-5). Heavier lanes are launched first, so the longest
            agents don't queue behind short ones for a free slot (longest-first scheduling).
        focus: Category-specific review checklist injected into its prompt.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(..., pattern=r"^[a-z][a-z0-9_]*$")
    title: str
    code: str = Field(..., pattern=r"^[A-Z]{2,6}$")
    enabled: bool = True
    owns_security_kpis: bool = False
    strong_model: bool = False
    effort: int = Field(2, ge=1, le=5)
    focus: str


class SecurityKpi(BaseModel):
    """One ``[[security_kpis]]`` entry — a mandatory security checklist item."""

    model_config = ConfigDict(frozen=True)

    id: str
    title: str
    description: str
    look_for: str


class ReviewConfig(BaseModel):
    """The whole parsed ``review_config.toml``.

    Attributes:
        review: Global report/verification settings.
        static_tool_owners: ``tool -> category id`` that triages that tool's findings.
        categories: Every category, in report-section order.
        security_kpis: The mandatory security checklist.
        config_hash: sha256 of the raw TOML bytes — part of the review cache key.
    """

    model_config = ConfigDict(frozen=True)

    review: ReviewSettings = Field(default_factory=ReviewSettings)
    static_tool_owners: dict[str, str] = Field(default_factory=dict)
    categories: tuple[ReviewCategory, ...]
    security_kpis: tuple[SecurityKpi, ...] = Field(default_factory=tuple)
    config_hash: str = ""

    @model_validator(mode="after")
    def _validate_references(self) -> "ReviewConfig":
        ids = [c.id for c in self.categories]
        if len(ids) != len(set(ids)):
            raise ValueError("review_config: duplicate category ids")
        codes = [c.code for c in self.categories]
        if len(codes) != len(set(codes)):
            raise ValueError("review_config: duplicate category codes")
        unknown = {owner for owner in self.static_tool_owners.values() if owner not in ids}
        if unknown:
            raise ValueError(f"review_config: static_analysis.owners reference unknown categories {sorted(unknown)}")
        kpi_ids = [k.id for k in self.security_kpis]
        if len(kpi_ids) != len(set(kpi_ids)):
            raise ValueError("review_config: duplicate security KPI ids")
        return self

    @property
    def enabled_categories(self) -> tuple[ReviewCategory, ...]:
        return tuple(c for c in self.categories if c.enabled)

    def category(self, category_id: str) -> ReviewCategory:
        for category in self.categories:
            if category.id == category_id:
                return category
        raise KeyError(category_id)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


class EvidenceRef(BaseModel):
    """One ``file:line`` citation, validated against the repository on record."""

    model_config = ConfigDict(frozen=True)

    file: str
    line_start: int = Field(..., ge=1)
    line_end: int | None = Field(None, ge=1)
    note: str | None = None

    @property
    def label(self) -> str:
        if self.line_end and self.line_end != self.line_start:
            return f"{self.file}:{self.line_start}-{self.line_end}"
        return f"{self.file}:{self.line_start}"


class Verification(BaseModel):
    """The independent verifier's judgment of one finding."""

    model_config = ConfigDict(frozen=True)

    verdict: VerificationVerdict
    original_severity: Severity
    note: str
    independent: bool = True  # False: only a deterministic severity cap was applied, no verifier ran


class ReviewFinding(BaseModel):
    """One issue found by a specialist agent.

    Attributes:
        id: ``f"{category.code}-{n}"`` — stable within one report.
        category_id: The owning category.
        severity: Final severity (after verification adjustments).
        confidence: The recording agent's confidence.
        title: One-line statement of the defect.
        description: Markdown body — what is wrong and the evidence, citing ``file:line``.
        impact: What happens because of it.
        remediation: Only populated when the config asks for it.
        evidence: Validated citations.
        kpi_ids: Security KPIs this finding substantiates.
        static_finding_ids: ``StaticFinding.id``s this finding confirms/aggregates.
        verification: The verifier's judgment, or ``None`` if not verified.
        duplicate_of: Set by the synthesizer when merged into another finding.
        exposure: How reachable the defect is today (live / conditional / latent / dead / theoretical).
    """

    model_config = ConfigDict(frozen=True)

    id: str
    category_id: str
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    impact: str
    remediation: str | None = None
    evidence: tuple[EvidenceRef, ...] = Field(default_factory=tuple)
    kpi_ids: tuple[str, ...] = Field(default_factory=tuple)
    static_finding_ids: tuple[str, ...] = Field(default_factory=tuple)
    verification: Verification | None = None
    duplicate_of: str | None = None
    exposure: Exposure = "live"

    @property
    def independently_verified(self) -> bool:
        return self.verification is not None and self.verification.independent


class KpiAssessment(BaseModel):
    """The security specialist's status for one mandatory security KPI."""

    model_config = ConfigDict(frozen=True)

    kpi_id: str
    title: str
    status: KpiStatus
    summary: str
    evidence: tuple[EvidenceRef, ...] = Field(default_factory=tuple)
    finding_ids: tuple[str, ...] = Field(default_factory=tuple)


class StaticTriage(BaseModel):
    """The owning specialist's verdict on one static-analysis finding."""

    model_config = ConfigDict(frozen=True)

    finding_id: str
    tool: str
    verdict: TriageVerdict
    reason: str
    triaged_by: str


class StaticToolSummary(BaseModel):
    """Per-tool triage counters for the report's static-analysis section."""

    model_config = ConfigDict(frozen=True)

    tool: str
    status: str
    error: str | None = None
    total: int = 0
    true_positive: int = 0
    false_positive: int = 0
    low_value: int = 0
    untriaged: int = 0


class PriorityItem(BaseModel):
    """One ranked entry in the report's "Priority order" section."""

    model_config = ConfigDict(frozen=True)

    title: str
    rationale: str
    finding_ids: tuple[str, ...] = Field(default_factory=tuple)


class RootCause(BaseModel):
    """One cross-cutting root cause tying several findings together."""

    model_config = ConfigDict(frozen=True)

    title: str
    explanation: str
    finding_ids: tuple[str, ...] = Field(default_factory=tuple)


class ExecutiveSummary(BaseModel):
    """What the synthesizer agent contributes on top of the findings."""

    model_config = ConfigDict(frozen=True)

    scope: str = ""
    verdict: str = ""
    priority_order: tuple[PriorityItem, ...] = Field(default_factory=tuple)
    cross_cutting: tuple[RootCause, ...] = Field(default_factory=tuple)
    verification_note: str = ""


class AgentRunStats(BaseModel):
    """Observability for one agent run (specialist, verifier or synthesizer)."""

    model_config = ConfigDict(frozen=True)

    agent: str
    status: Literal["completed", "incomplete", "timed_out", "failed", "skipped"]
    duration_seconds: float = 0.0
    model_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    subagent_calls: int = 0
    error: str | None = None
    # Repository files this agent opened with read_file (feeds ReviewCoverage; not persisted per agent).
    files_read: tuple[str, ...] = Field(default=(), exclude=True)


class ReviewCoverage(BaseModel):
    """Where every file of the repository went — computed, not model-generated.

    Answers "did the review really see everything?": what discovery found,
    what each static tool was given, which Python files are in the dependency
    graph (and which are not, by name), and how much of the source the agents
    actually opened.
    """

    model_config = ConfigDict(frozen=True)

    files_discovered: int = 0
    source_files: int = 0
    python_files: int = 0
    python_files_in_graph: int = 0
    python_not_in_graph: tuple[str, ...] = ()
    static_tools_run: tuple[str, ...] = ()
    static_tools_failed: tuple[str, ...] = ()
    static_python_files: int = 0
    static_code_files: int = 0
    source_files_opened_by_agents: int = 0
    unopened_source_dirs: tuple[str, ...] = ()
    traversal_timed_out: bool = False
    discovery_timed_out: bool = False
    unreadable_directories: tuple[str, ...] = ()
    system_docs: tuple[str, ...] = ()
    lane_scopes: tuple[str, ...] = ()  # "security: 41 of 42 scope files opened"


class ReviewStatistics(BaseModel):
    """Aggregate counters for one review run."""

    model_config = ConfigDict(frozen=True)

    duration_seconds: float = 0.0
    findings_recorded: int = 0
    findings_reported: int = 0
    findings_rejected_by_verifier: int = 0
    findings_rejected_invalid_evidence: int = 0
    findings_merged_as_duplicates: int = 0
    findings_dropped_low_confidence: int = 0
    static_findings_total: int = 0
    static_findings_triaged: int = 0
    static_false_positives: int = 0
    input_tokens: int = 0
    output_tokens: int = 0


class MergedFinding(BaseModel):
    """A finding folded into another as the same defect — kept so its lane can point to it."""

    model_config = ConfigDict(frozen=True)

    id: str
    category_id: str
    title: str
    primary_id: str


class InventorySection(BaseModel):
    """One deterministic inventory list (from static maps, not the model)."""

    model_config = ConfigDict(frozen=True)

    title: str
    note: str = ""
    rows: tuple[str, ...] = ()


class DeepReviewReport(BaseModel):
    """The full, versioned, cacheable output of the Deep Review node."""

    model_config = ConfigDict(frozen=True)

    engine_version: str
    repository_id: str
    repository_name: str
    head_sha: str
    cache_key: str
    provider: str
    model: str
    generated_at: datetime

    summary: ExecutiveSummary = Field(default_factory=ExecutiveSummary)
    categories: tuple[ReviewCategory, ...] = Field(default_factory=tuple)
    findings: tuple[ReviewFinding, ...] = Field(default_factory=tuple)
    rejected_findings: tuple[ReviewFinding, ...] = Field(default_factory=tuple)
    dismissed_leads: tuple[str, ...] = Field(default_factory=tuple)  # "lane — lead row — cited reason"
    open_leads: tuple[str, ...] = Field(default_factory=tuple)
    hypotheses: tuple[str, ...] = Field(default_factory=tuple)  # "lane — H-X-n: statement [outcome]"
    system_models: tuple[str, ...] = Field(default_factory=tuple)  # "lane: the agent's model of the system"
    own_investigation: int = 0  # findings not sitting on any static lead or tool hit  # "lane — lead: rows" left neither recorded nor dismissed
    merged_findings: tuple[MergedFinding, ...] = Field(default_factory=tuple)
    inventory: tuple[InventorySection, ...] = Field(default_factory=tuple)
    coverage: ReviewCoverage | None = None
    kpi_assessments: tuple[KpiAssessment, ...] = Field(default_factory=tuple)
    static_triage: tuple[StaticTriage, ...] = Field(default_factory=tuple)
    static_summary: tuple[StaticToolSummary, ...] = Field(default_factory=tuple)
    agent_runs: tuple[AgentRunStats, ...] = Field(default_factory=tuple)
    statistics: ReviewStatistics = Field(default_factory=ReviewStatistics)
