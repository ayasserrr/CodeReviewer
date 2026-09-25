"""The shared, in-process workspace every Deep Review agent works against.

One ``ReviewWorkspace`` per review run. It does two jobs:

1. **Read side (context engineering).** Everything earlier pipeline phases
   already computed — Discovery's manifest, the static-analysis findings, the
   tree-sitter/grimp dependency graph — is indexed once here and exposed to
   the agents as small, paginated, token-frugal query tools. Agents ask for
   exactly the slice they need ("who calls ``save_user``?", "bandit findings
   in ``app/api``") instead of having whole JSON blobs stuffed into their
   context, and never re-derive what a deterministic phase already knows.

2. **Write side (the collector).** Agents never hand back one giant final
   JSON answer. They *record* findings, static-finding triage verdicts, KPI
   assessments and verifications incrementally through validated tools.
   That means: a malformed call gets an immediate, specific error the agent
   can fix on its next turn; nothing is lost if an agent hits its call
   budget or wall-clock timeout mid-review; and no model-specific
   structured-output mode is needed (forced ``tool_choice`` is rejected by
   several current models).

Every citation is validated against the real clone on record — the file
must exist inside the repository, must not be a sensitive ``.env`` file,
and the cited lines must exist — so hallucinated ``file:line`` evidence is
bounced back to the agent instead of reaching the report.

Tools are plain synchronous functions (LangChain runs them in a worker
thread when the agent is async), so all collector mutations go through one
lock.
"""

import fnmatch
import re
import threading
from collections import Counter, defaultdict
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from langchain_core.tools import BaseTool, StructuredTool
from pydantic import BaseModel, Field

from helpers.fs_scanner import is_sensitive_env_file
from helpers.review_maps import ReviewMaps, classify_env_value
from utils import (
    DependencyGraph,
    EvidenceRef,
    ExecutiveSummary,
    KpiAssessment,
    PriorityItem,
    RepositoryManifest,
    ReviewCategory,
    ReviewConfig,
    ReviewFinding,
    RootCause,
    StaticFinding,
    StaticTriage,
    Verification,
)
from utils.review import SEVERITY_ORDER

REPO_MOUNT = "/"
"""The clone is mounted at the root of every agent's filesystem, so the paths
agents read, the paths the tools print and the paths cited in the report are
all the same repository-relative paths (agent state lives under ``/_review/``)."""

_MAX_TEXT = 6000
"""Hard cap on any single free-text field an agent records."""

_ZERO_CALLERS_NOTE = (
    "callers=0 does NOT mean unused: functions passed as values (route/graph/DI registrations, callbacks, "
    "decorators), module-level calls, re-exports and dynamic dispatch are not call edges. "
    "Run find_references before claiming anything is dead."
)


# ---------------------------------------------------------------------------
# Tool argument schemas
# ---------------------------------------------------------------------------


_MAX_MERGED_EVIDENCE = 25
# Hardening and hygiene classes: real, but a missing layer of defence rather than an exploit on its own.
_HARDENING_TITLE = re.compile(
    r"(?i)\b(cors|unpinned|pinn(ed|ing)|revision|security headers?|hsts|content-security-policy|csp|"
    r"swagger|openapi|lockfile|version constraints?)\b"
)
_EXPLOIT_TITLE = re.compile(r"(?i)\b(cve-\d+|rce|remote code|code execution|known vulnerab\w*)\b")


def _is_script_or_test(path: str, scripts: set[str], unreachable: set[str]) -> bool:
    """Tests, and scripts the running service never imports (a ``scripts/`` file the app calls is live code)."""
    parts = PurePosixPath(path).parts
    name = parts[-1]
    is_test = (
        any(p in ("tests", "test") for p in parts[:-1])
        or name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"
    )
    return is_test or path in scripts or ("scripts" in parts[:-1] and path in unreachable)
_LEAD_LINE_TOLERANCE = 15
# High-signal bundled semgrep rules the security lane must rule on one by one.
_SECURITY_LEAD_RULES: dict[str, str] = {
    "python-cors-wildcard-with-credentials": "CORS allows any origin with credentials",
    "python-sql-injection-built-query": "SQL built from strings reaching execute()",
    "python-sqlalchemy-text-built-query": "SQLAlchemy text() built from strings",
    "python-subprocess-shell-true": "subprocess with shell=True",
    "python-os-system-non-literal": "os.system with a non-literal command",
    "python-eval-exec-non-literal": "eval/exec of non-literal code",
    "python-unsafe-deserialization": "unsafe deserialization",
    "python-tls-verification-disabled": "TLS verification disabled",
    "python-jwt-verification-disabled": "JWT verification disabled",
    "python-exception-text-returned-to-client": "raw exception text returned to clients",
}
_TITLE_STOPWORDS = {
    "with", "from", "into", "that", "this", "missing", "lack", "lacks", "using", "used", "without", "the", "and",
    "for", "via", "not", "all", "any", "are", "absence", "absent", "leads", "lead", "allows", "allowed", "can",
    "issue", "issues", "potential", "possible", "multiple", "across", "due", "its", "has", "have", "been",
}

# Static-analysis rules (bundled semgrep ids and bandit test ids) that are leads for a security KPI.
_KPI_RULES: dict[str, tuple[str, ...]] = {
    "python-debug-enabled": ("KPI-03",),
    "python-streamlit-unsafe-html": ("KPI-03", "KPI-05"),
    "web-spreadsheet-export": ("KPI-04", "KPI-12"),
    "python-spreadsheet-export": ("KPI-04", "KPI-12"),
    "web-dangerously-set-inner-html": ("KPI-05",),
    "web-innerhtml-or-document-write": ("KPI-05",),
    "web-iframe-sandbox-escape": ("KPI-05",),
    "web-raw-html-markdown": ("KPI-05",),
    "python-markupsafe-markup-non-literal": ("KPI-05",),
    "python-jinja2-autoescape-disabled": ("KPI-05",),
    "python-static-files-mount": ("KPI-06",),
    "python-exception-text-returned-to-client": ("KPI-07",),
    "python-content-disposition-header": ("KPI-08",),
    "python-upload-filename-path-traversal": ("KPI-11",),
    "B201": ("KPI-03",),
}


class EvidenceInput(BaseModel):
    """One ``file:line`` citation supplied by an agent."""

    file: str = Field(..., description="Repository-relative path, e.g. 'app/main.py' (a leading '/' is accepted).")
    line_start: int = Field(..., ge=1, description="1-based first line of the cited code.")
    line_end: int | None = Field(None, ge=1, description="1-based last line, if the citation spans several lines.")
    note: str | None = Field(None, description="Optional short note on what this line shows.")


class _QueryStaticArgs(BaseModel):
    tool: str | None = Field(None, description="Filter by tool, e.g. 'bandit', 'ruff', 'pyright'.")
    rule: str | None = Field(None, description="Filter by rule/check id (exact), e.g. 'B105' or 'reportOptionalMemberAccess'.")
    file_glob: str | None = Field(None, description="fnmatch pattern on the repo-relative path, e.g. 'app/api/*'.")
    severity: str | None = Field(None, description="Filter by tool severity, e.g. 'high', 'error', 'critical'.")
    triage: Literal["any", "untriaged", "true_positive", "false_positive", "low_value"] = Field(
        "any", description="Filter by triage state."
    )
    offset: int = Field(0, ge=0)
    limit: int = Field(40, ge=1, le=200)


class _FindSymbolArgs(BaseModel):
    name: str = Field(..., description="Function/class name or dotted qualname fragment (case-insensitive substring).")
    limit: int = Field(20, ge=1, le=100)


class _ReferencesArgs(BaseModel):
    name: str = Field(..., description="Identifier to search for as a whole word, e.g. 'build_pipeline_graph'.")
    file_glob: str | None = Field(None, description="Optional fnmatch filter on repo-relative paths, e.g. 'src/*'.")
    limit: int = Field(60, ge=1, le=300)


class _CallRelationArgs(BaseModel):
    function: str = Field(..., description="A function id ('path.py::Class.method') or a bare name.")
    direction: Literal["callers", "callees", "both"] = "both"
    limit: int = Field(40, ge=1, le=200)


class _ImportArgs(BaseModel):
    module: str = Field(
        ...,
        description="Dotted module (prefix match, e.g. 'app.services') or repository file/directory path "
        "(e.g. 'backend/app/services/upload.py').",
    )
    direction: Literal["imports", "imported_by", "both"] = "both"
    limit: int = Field(60, ge=1, le=300)


class _EndpointArgs(BaseModel):
    path_contains: str | None = Field(None, description="Substring filter on the route path or handler file.")
    method: str | None = Field(None, description="HTTP method filter, e.g. 'POST'.")
    flagged_only: bool = Field(
        False, description="Only routes flagged CLIENT-ASSERTED IDENTITY / NO AUTH DEPENDENCY / AUTH ENTRY POINT."
    )
    offset: int = Field(0, ge=0)
    limit: int = Field(80, ge=1, le=300)


class _HotspotArgs(BaseModel):
    kind: Literal["fan_in", "fan_out", "size", "complexity"] = Field(
        "fan_in", description="fan_in = most-called functions; size = largest functions; complexity = static complexity findings."
    )
    limit: int = Field(20, ge=1, le=100)


class _RecordFindingArgs(BaseModel):
    title: str = Field(..., description="One-line statement of the defect (no remediation).")
    severity: Literal["Critical", "High", "Medium", "Low"]
    confidence: Literal["low", "medium", "high"] = Field(
        ..., description="How sure you are after reading the code. Findings below the configured minimum are dropped."
    )
    description: str = Field(
        ...,
        description="Markdown body: what is wrong and the concrete evidence, citing `file:line` inline. "
        "Bullets are fine. State facts you verified in code, not guesses.",
    )
    impact: str = Field(..., description="What concretely happens because of this (who can do what / what breaks).")
    evidence: list[EvidenceInput] = Field(..., min_length=1, description="Every file:line you rely on (at least one).")
    kpi_ids: list[str] = Field(default_factory=list, description="Security KPI ids this finding substantiates, e.g. ['KPI-06'].")
    static_finding_ids: list[str] = Field(
        default_factory=list, description="Ids of static-analysis findings this finding confirms or aggregates."
    )
    remediation: str | None = Field(None, description="Only if remediation is requested in your instructions.")


class _UpdateFindingArgs(BaseModel):
    finding_id: str
    severity: Literal["Critical", "High", "Medium", "Low"] | None = None
    confidence: Literal["low", "medium", "high"] | None = None
    title: str | None = None
    description: str | None = None
    impact: str | None = None
    evidence: list[EvidenceInput] | None = Field(None, description="Replaces the evidence list when given.")
    kpi_ids: list[str] | None = None
    static_finding_ids: list[str] | None = None


class _WithdrawArgs(BaseModel):
    finding_id: str
    reason: str


class _TriageArgs(BaseModel):
    finding_ids: list[str] = Field(..., min_length=1, max_length=500, description="Static finding ids to triage (batch them).")
    verdict: Literal["true_positive", "false_positive", "low_value"] = Field(
        ...,
        description="true_positive = real defect; false_positive = the tool is wrong here; "
        "low_value = technically correct but not worth anyone's time (style noise, test code).",
    )
    reason: str = Field(..., description="Why — cite the code fact that decides it.")


class _TriageRuleArgs(BaseModel):
    tool: str = Field(..., description="Tool name, e.g. 'ruff'.")
    rule: str = Field(..., description="Exact rule/check id, e.g. 'E501' or 'B008'.")
    verdict: Literal["true_positive", "false_positive", "low_value"]
    reason: str = Field(..., description="Why this verdict holds for the whole rule group — cite what you sampled.")
    file_glob: str | None = Field(None, description="Optionally restrict to paths matching this fnmatch pattern.")


class _KpiArgs(BaseModel):
    kpi_id: str
    status: Literal["open", "partially_open", "closed", "not_applicable", "not_verified"]
    summary: str = Field(..., description="1-4 sentences: the verdict and the decisive evidence, citing file:line.")
    evidence: list[EvidenceInput] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list, description="Your recorded findings that detail this KPI.")


class _VerifyArgs(BaseModel):
    finding_id: str
    verdict: Literal["confirmed", "rejected", "adjusted"] = Field(
        ...,
        description="confirmed = true as stated; rejected = not a real issue / evidence doesn't support it; "
        "adjusted = real but the severity is wrong (give adjusted_severity).",
    )
    note: str = Field(..., description="The decisive fact you checked, citing file:line.")
    adjusted_severity: Literal["Critical", "High", "Medium", "Low"] | None = None
    corrected_title: str | None = Field(
        None, description="Only when the title overstates or misnames the defect: the accurate one-line title."
    )
    corrected_impact: str | None = Field(
        None,
        description="Only when the defect is real but the stated impact is not what the code actually allows "
        "(e.g. claims file disclosure the parser cannot do): the accurate impact. Replaces the original.",
    )


class _ListFindingsArgs(BaseModel):
    category_id: str | None = None
    min_severity: Literal["Critical", "High", "Medium", "Low"] | None = None


class _GetFindingArgs(BaseModel):
    finding_id: str


class _DuplicateArgs(BaseModel):
    duplicate_id: str = Field(..., description="The finding to fold away.")
    primary_id: str = Field(..., description="The finding that stays (usually the better-evidenced one).")
    reason: str


class _PriorityInput(BaseModel):
    title: str = Field(..., description="Short theme, e.g. 'Integration & configuration'.")
    rationale: str = Field(..., description="One or two sentences: why this ranks here, naming the concrete problems.")
    finding_ids: list[str] = Field(default_factory=list)


class _RootCauseInput(BaseModel):
    title: str
    explanation: str = Field(..., description="How this single root cause produces the listed findings.")
    finding_ids: list[str] = Field(default_factory=list)


class _SummaryArgs(BaseModel):
    scope: str = Field(..., description="One paragraph: what was reviewed (components, stacks, deploy artifacts).")
    verdict: str = Field(..., description="One paragraph: production-readiness verdict and the main reasons.")
    priority_order: list[_PriorityInput] = Field(..., min_length=1, description="Ranked themes, most blocking first.")
    cross_cutting: list[_RootCauseInput] = Field(default_factory=list, description="3-6 root causes behind many findings.")
    verification_note: str = Field("", description="Which highest-severity items were confirmed directly in code.")


# ---------------------------------------------------------------------------
# Workspace
# ---------------------------------------------------------------------------


class ReviewWorkspace:
    """Indexes + collector for one review run.

    Args:
        repo_path: Absolute path to the local clone.
        manifest: Discovery's manifest.
        static_findings: Normalized findings from the static-analysis node.
        tool_results: Raw per-tool status contract from the static-analysis node.
        graph: The dependency graph node's output.
        config: The parsed review config.
        maps: Deterministic route/env/client-call/import maps (``helpers.review_maps``).
    """

    def __init__(
        self,
        *,
        repo_path: Path,
        manifest: RepositoryManifest,
        static_findings: list[StaticFinding],
        tool_results: dict[str, dict[str, Any]],
        graph: DependencyGraph,
        config: ReviewConfig,
        maps: ReviewMaps | None = None,
    ) -> None:
        self.repo_path = repo_path.resolve()
        self.maps = maps or ReviewMaps()
        self.manifest = manifest
        self.graph = graph
        self.config = config
        self.tool_results = tool_results

        # Static findings: first occurrence wins on the content-hash id.
        self.static_by_id: dict[str, StaticFinding] = {}
        for finding in static_findings:
            self.static_by_id.setdefault(finding.id, finding)

        # Dependency-graph indexes.
        self.functions = {f.id: f for f in graph.functions}
        self.classes = {c.id: c for c in graph.classes}
        self._callers: dict[str, list[tuple[str, int]]] = defaultdict(list)
        self._callees: dict[str, list[tuple[str, int]]] = defaultdict(list)
        for edge in graph.call_edges:
            self._callers[edge.callee_id].append((edge.caller_id, edge.line))
            self._callees[edge.caller_id].append((edge.callee_id, edge.line))
        self._imports: dict[str, set[str]] = defaultdict(set)
        self._imported_by: dict[str, set[str]] = defaultdict(set)
        for edge in graph.import_edges:
            self._imports[edge.module].add(edge.imported)
            self._imported_by[edge.imported].add(edge.module)

        self._line_counts: dict[str, int | None] = {}
        self._text_cache: dict[str, list[str]] = {}

        # Collector state.
        self._lock = threading.Lock()
        self.findings: dict[str, ReviewFinding] = {}
        self.withdrawn: dict[str, str] = {}
        self.invalid_evidence_bounces = 0
        self._counters: Counter[str] = Counter()
        self.triage: dict[str, StaticTriage] = {}
        self.kpis: dict[str, KpiAssessment] = {}
        self.verifications: dict[str, Verification] = {}
        self.rejected: dict[str, ReviewFinding] = {}
        self.duplicates: dict[str, str] = {}
        self.summary: ExecutiveSummary | None = None

    # ------------------------------------------------------------------
    # Evidence validation
    # ------------------------------------------------------------------

    def _normalize_path(self, raw: str) -> str:
        return raw.strip().replace("\\", "/").lstrip("/")

    def _line_count(self, rel_path: str) -> int | None:
        """Line count of a repo file, or ``None`` if it can't be cited."""
        if rel_path in self._line_counts:
            return self._line_counts[rel_path]
        count: int | None = None
        parts = PurePosixPath(rel_path).parts
        if rel_path and ".." not in parts and not is_sensitive_env_file(PurePosixPath(rel_path).name):
            candidate = (self.repo_path / rel_path).resolve()
            if candidate.is_file() and candidate.is_relative_to(self.repo_path):
                try:
                    with candidate.open("rb") as handle:
                        count = sum(1 for _ in handle)
                except OSError:
                    count = None
        self._line_counts[rel_path] = count
        return count

    def validate_evidence(self, evidence: list[EvidenceInput]) -> tuple[list[EvidenceRef], list[str]]:
        """Return ``(valid_refs, errors)`` for a list of agent citations."""
        refs: list[EvidenceRef] = []
        errors: list[str] = []
        for item in evidence:
            rel = self._normalize_path(item.file)
            total = self._line_count(rel)
            if total is None:
                errors.append(f"'{item.file}' is not a readable file in the repository")
                continue
            end = item.line_end if item.line_end and item.line_end >= item.line_start else None
            if item.line_start > max(total, 1) or (end is not None and end > max(total, 1)):
                errors.append(f"'{rel}' has {total} lines; cited {item.line_start}{f'-{end}' if end else ''}")
                continue
            note = item.note[:300] if item.note else None
            refs.append(EvidenceRef(file=rel, line_start=item.line_start, line_end=end, note=note))
        return refs, errors

    # ------------------------------------------------------------------
    # Read-side tools (shared by every agent)
    # ------------------------------------------------------------------

    def static_overview(self) -> str:
        """Per-tool status, counts, severities and top rules of the static-analysis pass."""
        by_tool: dict[str, list[StaticFinding]] = defaultdict(list)
        for finding in self.static_by_id.values():
            by_tool[finding.tool].append(finding)
        lines = ["tool | status | owner | findings | by severity | top rules (count)"]
        for tool in sorted(set(self.tool_results) | set(by_tool)):
            findings = by_tool.get(tool, [])
            result = self.tool_results.get(tool, {})
            status = result.get("status", "unknown")
            if result.get("error"):
                status += f" ({str(result['error'])[:80]})"
            severities = Counter(f.severity for f in findings)
            rules = Counter(f.category for f in findings).most_common(8)
            triaged = sum(1 for f in findings if f.id in self.triage)
            lines.append(
                f"{tool} | {status} | {self.config.static_tool_owners.get(tool, '-')} | "
                f"{len(findings)} (triaged {triaged}) | "
                + ", ".join(f"{k}={v}" for k, v in severities.most_common())
                + " | "
                + ", ".join(f"{rule}({count})" for rule, count in rules)
            )
        return "\n".join(lines)

    def query_static_findings(
        self,
        tool: str | None = None,
        rule: str | None = None,
        file_glob: str | None = None,
        severity: str | None = None,
        triage: str = "any",
        offset: int = 0,
        limit: int = 40,
    ) -> str:
        """Paginated, filtered static-analysis findings (one compact line each)."""
        matches = []
        for finding in self.static_by_id.values():
            if tool and finding.tool != tool:
                continue
            if rule and finding.category != rule:
                continue
            if severity and finding.severity.lower() != severity.lower():
                continue
            if file_glob and not fnmatch.fnmatch(finding.file, self._normalize_path(file_glob)):
                continue
            state = self.triage[finding.id].verdict if finding.id in self.triage else "untriaged"
            if triage != "any" and state != triage:
                continue
            matches.append((finding, state))
        matches.sort(key=lambda item: (item[0].tool, item[0].file, item[0].line or 0))
        page = matches[offset : offset + limit]
        if not page:
            return f"No static findings match (total matching: {len(matches)})."
        lines = [f"{len(matches)} matching; showing {offset}-{offset + len(page) - 1}", "id | tool | severity | rule | location | triage | message"]
        for finding, state in page:
            location = f"{finding.file}:{finding.line}" if finding.line else finding.file
            message = " ".join(finding.message.split())[:220]
            lines.append(f"{finding.id} | {finding.tool} | {finding.severity} | {finding.category} | {location} | {state} | {message}")
        if offset + len(page) < len(matches):
            lines.append(f"... more: call again with offset={offset + len(page)}")
        return "\n".join(lines)

    def find_symbol(self, name: str, limit: int = 20) -> str:
        """Locate functions/classes by name or qualname fragment."""
        needle = name.lower().strip()
        rows = []
        for fn in self.functions.values():
            if needle in fn.qualname.lower():
                flags = ("async " if fn.is_async else "") + (f"@{','.join(fn.decorators)} " if fn.decorators else "")
                rows.append(
                    f"function | {fn.id} | {fn.file}:{fn.start_line}-{fn.end_line} | {flags}({', '.join(fn.params)}) "
                    f"| loc={fn.loc} | callers={len(self._callers.get(fn.id, []))}"
                )
        for cls in self.classes.values():
            if needle in cls.qualname.lower():
                rows.append(f"class | {cls.id} | {cls.file}:{cls.start_line}-{cls.end_line} | methods={cls.method_count} | loc={cls.loc}")
        if not rows:
            return f"No function or class matching '{name}' in the dependency graph (only Python is indexed)."
        return "\n".join([f"{len(rows)} match(es)", *rows[:limit], f"({_ZERO_CALLERS_NOTE})"])

    def _file_lines(self, rel_path: str) -> list[str]:
        if rel_path not in self._text_cache:
            try:
                self._text_cache[rel_path] = (self.repo_path / rel_path).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                self._text_cache[rel_path] = []
        return self._text_cache[rel_path]

    def find_references(self, name: str, file_glob: str | None = None, limit: int = 60) -> str:
        """Every whole-word occurrence of an identifier across the scanned source files."""
        ident = name.strip().split(".")[-1]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", ident):
            return "Give a plain identifier (letters, digits, underscore)."
        pattern = re.compile(rf"\b{re.escape(ident)}\b")
        glob = self._normalize_path(file_glob) if file_glob else None
        hits: list[str] = []
        files_hit: set[str] = set()
        for entry in self.manifest.files:
            if entry.language is None or (glob and not fnmatch.fnmatch(entry.path, glob)):
                continue
            for number, line in enumerate(self._file_lines(entry.path), start=1):
                if pattern.search(line):
                    files_hit.add(entry.path)
                    hits.append(f"{entry.path}:{number}: {line.strip()[:200]}")
        if not hits:
            return f"No whole-word references to '{ident}' in scanned source files."
        header = f"{len(hits)} reference(s) to '{ident}' in {len(files_hit)} file(s) (definition lines included)"
        more = [f"... {len(hits) - limit} more"] if len(hits) > limit else []
        return "\n".join([header, *hits[:limit], *more])

    def _resolve_function_ids(self, function: str) -> list[str]:
        if function in self.functions:
            return [function]
        needle = function.lower()
        return [fid for fid, fn in self.functions.items() if fn.name.lower() == needle or fn.qualname.lower() == needle]

    def call_relations(self, function: str, direction: str = "both", limit: int = 40) -> str:
        """Resolved callers and/or callees (with call-site lines) of a function."""
        ids = self._resolve_function_ids(function)
        if not ids:
            return f"No function '{function}' in the dependency graph. Use find_symbol first."
        out: list[str] = []
        for fid in ids[:5]:
            out.append(f"## {fid}")
            if direction in ("callers", "both"):
                callers = self._callers.get(fid, [])
                out.append(f"callers ({len(callers)}):")
                out.extend(f"  {caller} @ line {line}" for caller, line in callers[:limit])
            if direction in ("callees", "both"):
                callees = self._callees.get(fid, [])
                out.append(f"callees ({len(callees)}):")
                out.extend(f"  {callee} @ line {line}" for callee, line in callees[:limit])
        out.append(f"Note: only calls resolving to exactly one repo-local function are edges. {_ZERO_CALLERS_NOTE}")
        return "\n".join(out)

    def module_imports(self, module: str, direction: str = "both", limit: int = 60) -> str:
        """Import edges for a dotted module prefix (grimp) or a file/directory path (static resolver)."""
        out = []
        modules = sorted({m for m in (*self._imports, *self._imported_by) if m == module or m.startswith(module + ".")})
        for mod in modules[:20]:
            if direction in ("imports", "both"):
                out.append(f"{mod} imports: {', '.join(sorted(self._imports.get(mod, set()))[:limit]) or '-'}")
            if direction in ("imported_by", "both"):
                out.append(f"{mod} imported by: {', '.join(sorted(self._imported_by.get(mod, set()))[:limit]) or '-'}")
        if not out and self.maps.import_edges:
            needle = module.strip("/").removesuffix(".py").replace(".", "/") if "/" not in module else module.strip("/")
            files = sorted(f for f in self.maps.import_edges if needle in f)
            reverse = self.maps.imported_by()
            for path in files[:20]:
                if direction in ("imports", "both"):
                    out.append(f"{path} imports: {', '.join(sorted(self.maps.import_edges.get(path, ()))[:limit]) or '-'}")
                if direction in ("imported_by", "both"):
                    out.append(f"{path} imported by: {', '.join(sorted(reverse.get(path, ()))[:limit]) or '- (nothing)'}")
            if len(files) > 20:
                out.append(f"... {len(files) - 20} more files match '{module}' — narrow the query")
        return "\n".join(out) or (
            f"No module or file matching '{module}' in the import graph. Try a repository path (e.g. 'app/services')."
        )

    def list_endpoints(
        self,
        path_contains: str | None = None,
        method: str | None = None,
        flagged_only: bool = False,
        offset: int = 0,
        limit: int = 80,
    ) -> str:
        """HTTP routes with their auth dependencies and identity inputs (route map), else Discovery's list."""
        if self.maps.routes:
            rows = [
                r
                for r in self.maps.routes
                if (not path_contains or path_contains in r.path or path_contains in r.file)
                and (not method or r.method == method.upper())
                and (not flagged_only or r.flags)
            ]
            page = rows[offset : offset + limit]
            lines = [f"{len(rows)} route(s) (auth = strongest check in the dependency closure)"]
            for r in page:
                lines.append(
                    f"{r.method} {r.path} -> {r.handler} ({r.file}:{r.line}) | auth: {r.auth_label} | "
                    f"identity: {', '.join(r.identity_inputs) or '-'} | flags: {', '.join(r.flags) or '-'} | "
                    f"deps: {', '.join(r.dependencies) or '-'}"
                )
            if self.maps.mounts and offset == 0 and not flagged_only:
                lines.append("Mounted sub-apps (no FastAPI dependencies apply): " + "; ".join(
                    f"{m.path} -> {m.target} ({m.file}:{m.line})" for m in self.maps.mounts))
            return "\n".join(lines)
        rows = [
            e
            for e in self.manifest.endpoints
            if (not path_contains or path_contains in e.path) and (not method or str(e.method).upper() == method.upper())
        ]
        if not rows:
            return "No endpoints detected (Discovery detects Python web frameworks only; grep for others)."
        page = rows[offset : offset + limit]
        lines = [f"{len(rows)} endpoint(s)"]
        for e in page:
            dup = " [DUPLICATE]" if e.duplicate else ""
            lines.append(f"{e.method} {e.path} -> {e.handler} ({e.file}:{e.line}) [{e.framework}]{dup}")
        return "\n".join(lines)

    def hotspots(self, kind: str = "fan_in", limit: int = 20) -> str:
        """Ranked hot spots: most-called, most-calling, largest, or most complex code."""
        if kind == "fan_in":
            ranked = sorted(self._callers.items(), key=lambda kv: len(kv[1]), reverse=True)[:limit]
            return "\n".join(f"{len(callers)} callers | {fid}" for fid, callers in ranked) or "No resolved calls."
        if kind == "fan_out":
            ranked = sorted(self._callees.items(), key=lambda kv: len(kv[1]), reverse=True)[:limit]
            return "\n".join(f"{len(callees)} callees | {fid}" for fid, callees in ranked) or "No resolved calls."
        if kind == "size":
            ranked = sorted(self.functions.values(), key=lambda f: f.loc, reverse=True)[:limit]
            return "\n".join(f"{f.loc} loc | {f.id} | {f.file}:{f.start_line}" for f in ranked) or "No functions indexed."
        complexity = [f for f in self.static_by_id.values() if f.tool in ("radon", "lizard")]
        complexity.sort(key=lambda f: (f.severity != "error", f.file, f.line or 0))
        return "\n".join(f"{f.tool} | {f.severity} | {f.file}:{f.line} | {f.message[:160]}" for f in complexity[:limit]) or (
            "No complexity findings."
        )

    # ------------------------------------------------------------------
    # Write-side: specialists
    # ------------------------------------------------------------------

    def _next_id(self, category: ReviewCategory) -> str:
        self._counters[category.id] += 1
        return f"{category.code}-{self._counters[category.id]}"

    def _check_links(self, kpi_ids: list[str], static_ids: list[str]) -> list[str]:
        errors = []
        known_kpis = {k.id for k in self.config.security_kpis}
        errors += [f"unknown KPI id '{k}'" for k in kpi_ids if k not in known_kpis]
        errors += [f"unknown static finding id '{s}'" for s in static_ids if s not in self.static_by_id]
        return errors

    def record_finding(self, category: ReviewCategory, args: _RecordFindingArgs) -> str:
        refs, errors = self.validate_evidence(args.evidence)
        errors += self._check_links(args.kpi_ids, args.static_finding_ids)
        if errors or not refs:
            with self._lock:
                self.invalid_evidence_bounces += 1
            return "NOT RECORDED — fix and retry: " + "; ".join(errors or ["no valid evidence"])
        with self._lock:
            active = [f for f in self.findings.values() if f.category_id == category.id]
            if len(active) >= self.config.review.max_findings_per_category:
                return (
                    f"NOT RECORDED — category cap of {self.config.review.max_findings_per_category} findings reached. "
                    "Merge related issues into an existing finding (update_finding) or withdraw weaker ones."
                )
            finding_id = self._next_id(category)
            self.findings[finding_id] = ReviewFinding(
                id=finding_id,
                category_id=category.id,
                severity=args.severity,
                confidence=args.confidence,
                title=args.title.strip()[:300],
                description=args.description.strip()[:_MAX_TEXT],
                impact=args.impact.strip()[:_MAX_TEXT],
                remediation=(args.remediation or "").strip()[:_MAX_TEXT] or None
                if self.config.review.include_remediation
                else None,
                evidence=tuple(refs),
                kpi_ids=tuple(dict.fromkeys(args.kpi_ids)),
                static_finding_ids=tuple(dict.fromkeys(args.static_finding_ids)),
            )
        note = ""
        if args.severity in ("Critical", "High") and self._all_unreachable(refs):
            note = (
                " NOTE: every cited file is unreachable from the application roots (reachability.md) — if this is "
                "a runtime vulnerability, it is latent: say so and calibrate the severity (update_finding)."
            )
        return f"Recorded {finding_id} ({args.severity}) with {len(refs)} validated citation(s).{note}"

    def _all_unreachable(self, refs) -> bool:
        unreachable = set(self.maps.unreachable)
        files = {ref.file for ref in refs if ref.file.endswith(".py")}
        return bool(files) and files <= unreachable

    def update_finding(self, category: ReviewCategory, args: _UpdateFindingArgs) -> str:
        with self._lock:
            finding = self.findings.get(args.finding_id)
        if finding is None or finding.category_id != category.id:
            return f"Unknown finding '{args.finding_id}' in your category."
        changes: dict[str, Any] = {}
        errors: list[str] = []
        if args.evidence is not None:
            refs, errors = self.validate_evidence(args.evidence)
            if refs and not errors:
                changes["evidence"] = tuple(refs)
        errors += self._check_links(args.kpi_ids or [], args.static_finding_ids or [])
        if errors:
            return "NOT UPDATED — fix and retry: " + "; ".join(errors)
        for field in ("severity", "confidence"):
            if getattr(args, field) is not None:
                changes[field] = getattr(args, field)
        for field in ("title", "description", "impact"):
            if getattr(args, field):
                changes[field] = getattr(args, field).strip()[:_MAX_TEXT]
        if args.kpi_ids is not None:
            changes["kpi_ids"] = tuple(dict.fromkeys(args.kpi_ids))
        if args.static_finding_ids is not None:
            changes["static_finding_ids"] = tuple(dict.fromkeys(args.static_finding_ids))
        with self._lock:
            self.findings[args.finding_id] = finding.model_copy(update=changes)
        return f"Updated {args.finding_id}: {', '.join(changes) or 'no changes'}."

    def withdraw_finding(self, category: ReviewCategory, args: _WithdrawArgs) -> str:
        with self._lock:
            finding = self.findings.get(args.finding_id)
            if finding is None or finding.category_id != category.id:
                return f"Unknown finding '{args.finding_id}' in your category."
            del self.findings[args.finding_id]
            self.withdrawn[args.finding_id] = args.reason
        return f"Withdrew {args.finding_id}."

    def list_my_findings(self, category: ReviewCategory) -> str:
        with self._lock:
            mine = [f for f in self.findings.values() if f.category_id == category.id]
            assessed = set(self.kpis)
            triaged = sum(1 for t in self.triage.values() if t.triaged_by == category.id)
        lines = [f"{len(mine)} finding(s) recorded; {triaged} static finding(s) triaged."]
        lines += [f"{f.id} | {f.severity} | {f.confidence} | {f.title}" for f in mine]
        if category.owns_security_kpis:
            missing = [k.id for k in self.config.security_kpis if k.id not in assessed]
            lines.append(f"KPIs assessed: {len(assessed)}/{len(self.config.security_kpis)}; missing: {', '.join(missing) or 'none'}")
        owned = [t for t, owner in self.config.static_tool_owners.items() if owner == category.id]
        if owned:
            untriaged = sum(1 for f in self.static_by_id.values() if f.tool in owned and f.id not in self.triage)
            lines.append(f"Untriaged static findings from your tools ({', '.join(owned)}): {untriaged}")
        return "\n".join(lines)

    def triage_static(self, category: ReviewCategory, args: _TriageArgs) -> str:
        owned = {t for t, owner in self.config.static_tool_owners.items() if owner == category.id}
        accepted, foreign, unknown = 0, [], []
        with self._lock:
            for fid in dict.fromkeys(args.finding_ids):
                finding = self.static_by_id.get(fid)
                if finding is None:
                    unknown.append(fid)
                elif finding.tool not in owned:
                    foreign.append(fid)
                else:
                    self.triage[fid] = StaticTriage(
                        finding_id=fid,
                        tool=finding.tool,
                        verdict=args.verdict,
                        reason=args.reason.strip()[:600],
                        triaged_by=category.id,
                    )
                    accepted += 1
        parts = [f"Triaged {accepted} as {args.verdict}."]
        if foreign:
            parts.append(f"Ignored {len(foreign)} owned by another category (you triage only: {', '.join(sorted(owned)) or 'none'}).")
        if unknown:
            parts.append(f"Unknown ids: {', '.join(unknown[:10])}.")
        return " ".join(parts)

    def triage_rule(self, category: ReviewCategory, args: _TriageRuleArgs) -> str:
        """Apply one verdict to every still-untriaged finding of a (tool, rule) group."""
        glob = self._normalize_path(args.file_glob) if args.file_glob else None
        ids = [
            f.id
            for f in self.static_by_id.values()
            if f.tool == args.tool
            and f.category == args.rule
            and f.id not in self.triage
            and (not glob or fnmatch.fnmatch(f.file, glob))
        ]
        if not ids:
            return f"No untriaged {args.tool} findings for rule '{args.rule}'{f' under {glob}' if glob else ''}."
        return self.triage_static(category, _TriageArgs(finding_ids=ids, verdict=args.verdict, reason=args.reason))

    def kpi_leads(self) -> dict[str, list[str]]:
        """Deterministic leads per security KPI: static-rule hits and map rows that bear on it.

        A lead is not a verdict — it is a place the KPI assessor must look at
        before it may call a KPI closed or not applicable.
        """
        leads: dict[str, list[str]] = defaultdict(list)
        for finding in self.static_by_id.values():
            rule = finding.category.rsplit(".", 1)[-1]
            for kpi_id in _KPI_RULES.get(rule, ()):
                leads[kpi_id].append(f"{finding.file}:{finding.line} ({finding.tool} {rule})")
        for mount in self.maps.mounts:
            leads["KPI-06"].append(f"{mount.file}:{mount.line} (mounted sub-app {mount.path} -> {mount.target[:60]})")
        for route in self.maps.routes:
            if route.is_auth_entry:
                leads["KPI-01"].append(f"{route.file}:{route.line} (auth entry point {route.method} {route.path})")
        for read in self.maps.env_reads:
            if read.default and any(
                flag in ("points at localhost/loopback", "contains a private IP address", "points at a dev/staging/test host")
                for flag in classify_env_value(read.key, read.default.strip("'\""))
            ):
                leads["KPI-10"].append(f"{read.file}:{read.line} ({read.key} defaults to a local/dev/private host)")
        return {kpi: list(dict.fromkeys(items)) for kpi, items in leads.items()}

    def lane_leads(self, category_id: str) -> list[tuple[str, frozenset[str], list[str]]]:
        """Deterministic must-check leads for one category: ``(label, files, rows)`` groups.

        Built from the maps and the static rules. A lead group is "addressed"
        when a finding of that category cites at least one of its files — the
        completion check nudges the specialist once about unaddressed groups.
        """
        groups: list[tuple[str, frozenset[str], list[str]]] = []

        def add(label: str, rows: list[tuple[str, str]]) -> None:
            if rows:
                groups.append((label, frozenset(f for f, _ in rows), [r for _, r in rows]))

        def static_rows(*rules: str) -> list[tuple[str, str]]:
            # Keyed "file:line": a static lead is addressed only by a finding citing near
            # that line, not by any finding in the same (often large) file.
            return [
                (f"{f.file}:{f.line}" if f.line else f.file, f"{f.file}:{f.line} ({f.category.rsplit('.', 1)[-1]})")
                for f in self.static_by_id.values()
                if f.category.rsplit(".", 1)[-1] in rules
            ]

        routes = self.maps.routes
        if category_id == "security":
            add("Routes taking a user identity from the request with no token verification (CLIENT-ASSERTED IDENTITY)",
                [(r.file, f"{r.method} {r.path} ({r.file}:{r.line}; {', '.join(r.identity_inputs)})")
                 for r in routes if "CLIENT-ASSERTED IDENTITY" in r.flags])
            add("Mounted sub-apps that FastAPI dependencies do not protect",
                [(m.file, f"{m.path} -> {m.target[:60]} ({m.file}:{m.line})") for m in self.maps.mounts])
            add("Upload filenames reaching filesystem paths (semgrep)", static_rows("python-upload-filename-path-traversal"))
            for rule, label in _SECURITY_LEAD_RULES.items():
                add(f"{label} (semgrep {rule})", static_rows(rule))
            add("Queries that receive the caller's identity but never use it (possible global data exposure)",
                [(f"{x.file}:{x.line}", f"{x.function} ({x.file}:{x.line}) ignores {x.identity}")
                 for x in self.maps.identity_unused])
            add("Objects addressed by an id in the path with no verified user (IDOR / enumeration)",
                [(r.file, f"{r.method} {r.path} ({r.file}:{r.line}; {r.auth_label})")
                 for r in routes if re.search(r"\{[^}]*(id|thread|key|name)[^}]*\}", r.path, re.IGNORECASE)
                 and not r.user_token_verified and not r.is_auth_entry])
        elif category_id == "auth":
            add("Auth entry points (rate limiting, enumeration, OTP/reset flows)",
                [(r.file, f"{r.method} {r.path} ({r.file}:{r.line})") for r in routes if r.is_auth_entry])
            add("Insecure secret defaults (semgrep)", static_rows("python-insecure-secret-default"))
        elif category_id == "inputs":
            add("Upload handlers (FILE UPLOAD routes)",
                [(r.file, f"{r.method} {r.path} ({r.file}:{r.line})") for r in routes if r.accepts_upload])
        elif category_id == "frontend":
            add("Pages rendered without an auth guard (the page must fetch before redirecting)",
                [(f"{x.file}:{x.line}", f"{x.path} -> <{x.component}> ({x.file}:{x.line})") for x in self.maps.unguarded_routes])
            add("Frontend security hits (semgrep web rules)", [
                (f.file, f"{f.file}:{f.line} ({f.category.rsplit('.', 1)[-1]})")
                for f in self.static_by_id.values() if f.category.rsplit(".", 1)[-1].startswith("web-")
            ])
        elif category_id == "integration":
            add("Environment keys with divergent inline defaults",
                [(r.file, f"{key}: {r.default} @ {r.file}:{r.line}")
                 for key, reads in self.maps.env_divergent_defaults().items() for r in reads])
            add("Frontend calls with no backend route", [(c.file, f"{c.path} ({c.file}:{c.line})")
                                                         for c in self.maps.unmatched_client_calls()])
        elif category_id == "performance":
            add("Blocking calls inside async functions (semgrep)", static_rows("python-blocking-call-in-async-def"))
            add("Process-local state (singletons, caches, flags, semaphores: one process only, lost on restart)",
                [(f"{x.file}:{x.line}", f"{x.name} ({x.file}:{x.line}): {x.kind}") for x in self.maps.process_state])
            add("Local on-disk vector stores (semgrep)", static_rows("python-local-vector-store"))
            add("Model / embedding calls inside loops (semgrep)", static_rows("python-model-call-in-loop"))
            add("Whole-collection recomputation (rerank / rescore / reindex / all items; check if it runs per event)",
                static_rows("python-whole-collection-recompute"))
            add("Collection endpoints with no pagination input",
                [(r.file, f"{r.method} {r.path} -> {r.handler} ({r.file}:{r.line})")
                 for r in routes if r.is_unpaginated_listing])
        elif category_id == "correctness":
            entry_points = [(r.file, r.handler, f"{r.method} {r.path} ({r.file}:{r.line})") for r in routes if r.accepts_upload]
            entry_points += [
                (job.file, job.function, f"background job {job.function} ({job.file}:{job.line}, started at {job.started_at})")
                for job in self.maps.background_jobs if job.file
            ]
            if entry_points:
                files: set[str] = set()
                for file, function, _ in entry_points:
                    files |= self._reachable_files(file, function, depth=2)
                groups.append((
                    "Core pipelines to trace end to end (upload handlers and background jobs; their callees are in scope)",
                    frozenset(files),
                    [row for _, _, row in entry_points],
                ))
            add("Values rewritten during extraction (semgrep)", static_rows("python-silent-value-substitution"))
            add("Random identifiers (semgrep)", static_rows("python-random-identifier"))
            add("Work claims / locks / in-progress flags (semgrep)", static_rows("python-claim-flag-or-lock"))
            add("Document text lowercased at extraction (semgrep)", static_rows("python-lowercased-extracted-text"))
        elif category_id == "llm":
            add("LangGraph graphs compiled without a checkpointer (semgrep)",
                static_rows("python-langgraph-compile-without-checkpointer"))
            add("Model calls inside loops (semgrep)", static_rows("python-model-call-in-loop"))
            add("Document text lowercased before embedding / prompting (semgrep)",
                static_rows("python-lowercased-extracted-text"))
        elif category_id == "maintainability":
            by_dir: dict[str, list[str]] = defaultdict(list)
            for path in self.maps.unreachable:
                by_dir[str(PurePosixPath(path).parent)].append(path)
            add("Backend routes no frontend code calls (dead or external-only endpoints)",
                [(r.file, f"{r.method} {r.path} -> {r.handler} ({r.file}:{r.line})")
                 for r in self.maps.routes_without_client()])
            if by_dir:
                groups.append((
                    "Modules no application root imports (dead-code candidates, by directory)",
                    frozenset(self.maps.unreachable),
                    [f"{d}/ ({len(paths)} modules)" for d, paths in sorted(by_dir.items(), key=lambda kv: -len(kv[1]))],
                ))
        elif category_id == "secrets":
            add(".env files with flagged keys (weak/short/localhost/browser-exposed/duplicates)",
                [(f.file, f"{f.file}: " + "; ".join(f"{k} {flag}" for k, flag in f.flags[:6])
                  + (f"; duplicates: {', '.join(k for k, _ in f.duplicates)}" if f.duplicates else ""))
                 for f in self.maps.env_files if f.flags or f.duplicates])
            add("Insecure secret defaults (semgrep)", static_rows("python-insecure-secret-default"))
        for label, _ in self._absence_leads(category_id):
            groups.append((label, frozenset(), ["confirm the absence (the static search found nothing) and record it"]))
        return groups

    def _reachable_files(self, file: str, function: str, depth: int) -> set[str]:
        """``file`` plus the files of functions reachable from ``function`` within ``depth`` calls."""
        files = {file}
        frontier = [fid for fid, fn in self.functions.items() if fn.file == file and fn.name == function]
        for _ in range(depth):
            nxt = []
            for fid in frontier:
                for callee, _line in self._callees.get(fid, ()):
                    node = self.functions.get(callee)
                    if node is not None and node.file not in files:
                        files.add(node.file)
                    nxt.append(callee)
            frontier = nxt
        return files

    def _absence_leads(self, category_id: str) -> list[tuple[str, str]]:
        return [
            (f"Baseline with no trace anywhere in the code: {b.label}", b.mention)
            for b in self.maps.absent_baselines
            if b.lane == category_id
        ]

    def untriaged_groups(self, category_id: str, threshold: float = 0.25) -> list[tuple[str, str, int]]:
        """``(tool, rule, count)`` of untriaged static findings this category owns — empty when coverage is fine."""
        owned = {t for t, owner in self.config.static_tool_owners.items() if owner == category_id}
        mine = [f for f in self.static_by_id.values() if f.tool in owned]
        if not mine:
            return []
        pending = [f for f in mine if f.id not in self.triage]
        if len(pending) <= threshold * len(mine):
            return []
        groups = Counter((f.tool, f.category) for f in pending)
        return [(tool, rule, count) for (tool, rule), count in groups.most_common()]

    def unaddressed_leads(self, category_id: str) -> list[tuple[str, list[str]]]:
        mine = [f for f in self.findings.values() if f.category_id == category_id]
        spans: dict[str, list[tuple[int, int]]] = defaultdict(list)
        for f in mine:
            for ref in f.evidence:
                spans[ref.file].append((ref.line_start, ref.line_end or ref.line_start))

        def addressed(key: str) -> bool:
            file, sep, line = key.rpartition(":")
            if sep and line.isdigit():
                n = int(line)
                return any(lo - _LEAD_LINE_TOLERANCE <= n <= hi + _LEAD_LINE_TOLERANCE for lo, hi in spans.get(file, ()))
            return key in spans

        missing = [
            (label, rows)
            for label, keys, rows in self.lane_leads(category_id)
            if keys and not any(addressed(key) for key in keys)
        ]
        for label, mention in self._absence_leads(category_id):
            if not any(re.search(mention, f"{f.title} {f.description}") for f in mine):
                missing.append((label, ["confirm the absence (the static search found nothing) and record it"]))
        return missing

    def assess_kpi(self, args: _KpiArgs) -> str:
        kpi = next((k for k in self.config.security_kpis if k.id == args.kpi_id), None)
        if kpi is None:
            return f"Unknown KPI '{args.kpi_id}'. Valid: {', '.join(k.id for k in self.config.security_kpis)}"
        refs, errors = self.validate_evidence(args.evidence)
        if errors:
            return "NOT RECORDED — fix and retry: " + "; ".join(errors)
        if args.status in ("open", "partially_open", "closed") and not refs:
            return "NOT RECORDED — open/partially_open/closed need at least one file:line citation."
        leads = self.kpi_leads().get(kpi.id, [])
        if leads and args.status == "not_applicable":
            return (
                f"NOT RECORDED — {kpi.id} cannot be not_applicable: the capability exists at "
                + "; ".join(leads[:8])
                + ". Read those locations and assess open / partially_open / closed."
            )
        if leads and args.status == "closed":
            lead_files = {lead.split(":", 1)[0] for lead in leads}
            if not lead_files & {ref.file for ref in refs}:
                return (
                    f"NOT RECORDED — closing {kpi.id} requires citing the lead locations you checked: "
                    + "; ".join(leads[:8])
                    + ". If any of them is unsafe the KPI is open."
                )
        with self._lock:
            unknown = [fid for fid in args.finding_ids if fid not in self.findings]
            self.kpis[kpi.id] = KpiAssessment(
                kpi_id=kpi.id,
                title=kpi.title,
                status=args.status,
                summary=args.summary.strip()[:2000],
                evidence=tuple(refs),
                finding_ids=tuple(fid for fid in args.finding_ids if fid in self.findings),
            )
        suffix = f" (ignored unknown finding ids: {', '.join(unknown)})" if unknown else ""
        return f"Assessed {kpi.id} as {args.status}.{suffix}"

    # ------------------------------------------------------------------
    # Write-side: verifiers
    # ------------------------------------------------------------------

    def findings_to_verify(self, category_id: str) -> list[ReviewFinding]:
        verify = set(self.config.review.verify_severities)
        with self._lock:
            return [
                f
                for f in self.findings.values()
                if f.category_id == category_id and f.severity in verify and f.id not in self.verifications
            ]

    def render_finding(self, finding: ReviewFinding) -> str:
        evidence = "\n".join(f"- {e.label}" + (f" — {e.note}" if e.note else "") for e in finding.evidence)
        extras = []
        if finding.kpi_ids:
            extras.append(f"KPIs: {', '.join(finding.kpi_ids)}")
        if finding.static_finding_ids:
            extras.append(f"static findings: {', '.join(finding.static_finding_ids)}")
        unreachable = sorted({e.file for e in finding.evidence} & set(self.maps.unreachable))
        if unreachable:
            extras.append(
                "REACHABILITY: " + ", ".join(unreachable) + " — not imported by any application root "
                "(reachability.md); a runtime exploit through only these files is latent, not live. "
                "Confirm with find_references, then calibrate severity"
            )
        return (
            f"### {finding.id} [{finding.severity}, confidence {finding.confidence}] {finding.title}\n"
            f"{finding.description}\n\n**Impact:** {finding.impact}\n\n**Evidence:**\n{evidence}\n"
            + (f"{'; '.join(extras)}\n" if extras else "")
        )

    def submit_verification(self, category_id: str, args: _VerifyArgs) -> str:
        with self._lock:
            finding = self.findings.get(args.finding_id)
            if finding is None or finding.category_id != category_id:
                return f"Unknown finding '{args.finding_id}' for this verification batch."
            if args.verdict == "adjusted" and not args.adjusted_severity:
                return "NOT RECORDED — 'adjusted' requires adjusted_severity."
            verification = Verification(verdict=args.verdict, original_severity=finding.severity, note=args.note.strip()[:1500])
            self.verifications[finding.id] = verification
            if args.verdict == "rejected":
                self.rejected[finding.id] = finding.model_copy(update={"verification": verification})
                del self.findings[finding.id]
            else:
                update: dict[str, Any] = {
                    "verification": verification,
                    "severity": args.adjusted_severity if args.verdict == "adjusted" else finding.severity,
                }
                if args.corrected_title and args.corrected_title.strip():
                    update["title"] = args.corrected_title.strip()[:300]
                if args.corrected_impact and args.corrected_impact.strip():
                    update["impact"] = args.corrected_impact.strip()[:3000]
                self.findings[finding.id] = finding.model_copy(update=update)
        return f"{args.finding_id}: {args.verdict}."

    # ------------------------------------------------------------------
    # Write-side: synthesizer
    # ------------------------------------------------------------------

    def list_findings(self, category_id: str | None = None, min_severity: str | None = None) -> str:
        cutoff = SEVERITY_ORDER.index(min_severity) if min_severity else len(SEVERITY_ORDER) - 1
        with self._lock:
            rows = [
                f
                for f in self.findings.values()
                if f.id not in self.duplicates
                and (not category_id or f.category_id == category_id)
                and SEVERITY_ORDER.index(f.severity) <= cutoff
            ]
        rows.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), f.category_id, f.id))
        if not rows:
            return "No findings match."
        lines = [f"{len(rows)} finding(s)", "id | severity | verified | title | first evidence"]
        for f in rows:
            verified = f.verification.verdict if f.verification else "unverified"
            lines.append(f"{f.id} | {f.severity} | {verified} | {f.title} | {f.evidence[0].label if f.evidence else '-'}")
        return "\n".join(lines)

    @staticmethod
    def _title_terms(title: str) -> set[str]:
        return set(re.findall(r"[a-z][a-z0-9_]{2,}", title.lower())) - _TITLE_STOPWORDS

    @staticmethod
    def _locations_overlap(a: ReviewFinding, b: ReviewFinding, tolerance: int = 5) -> bool:
        for ea in a.evidence:
            for eb in b.evidence:
                if ea.file != eb.file:
                    continue
                a_end, b_end = ea.line_end or ea.line_start, eb.line_end or eb.line_start
                if ea.line_start - tolerance <= b_end and eb.line_start - tolerance <= a_end:
                    return True
        return False

    def _same_defect(self, a: ReviewFinding, b: ReviewFinding) -> bool:
        terms_a, terms_b = self._title_terms(a.title), self._title_terms(b.title)
        if not terms_a or not terms_b:
            return False
        overlap = len(terms_a & terms_b) / len(terms_a | terms_b)
        if self._locations_overlap(a, b):
            return overlap >= 0.15
        shares_file = bool({e.file for e in a.evidence} & {e.file for e in b.evidence})
        return shares_file and overlap >= 0.34

    def apply_severity_caps(self) -> int:
        """Deterministic severity ceilings the model is not trusted to apply on its own.

        - every cited Python file is unreachable from the application roots -> latent, at most High;
        - every cited file is a standalone script or a test -> at most Medium;
        - the finding reports an absent production baseline (rate limiting, metrics, ...) -> at most High.
        The cap and its reason are appended to the verification note, so the report shows why.
        """
        unreachable = set(self.maps.unreachable)
        scripts = set(self.maps.orphan_scripts)
        baselines = [b for b in self.maps.absent_baselines]
        capped = 0
        with self._lock:
            for fid, finding in list(self.findings.items()):
                files = {ref.file for ref in finding.evidence}
                py_files = {f for f in files if f.endswith(".py")}
                ceiling, reason = None, ""
                if py_files and py_files == files and all(_is_script_or_test(f, scripts, unreachable) for f in files):
                    ceiling, reason = "Medium", "only standalone scripts/tests are affected, not the running service"
                elif py_files and py_files <= unreachable and py_files == files:
                    ceiling, reason = "High", "latent — the cited code is not imported by any application entry point"
                elif any(re.search(b.mention, finding.title) for b in baselines):
                    ceiling, reason = "High", "missing production baseline"
                elif _HARDENING_TITLE.search(finding.title) and not _EXPLOIT_TITLE.search(finding.title):
                    ceiling, reason = "High", "configuration hardening / supply-chain hygiene, not a direct exploit"
                if ceiling is None or SEVERITY_ORDER.index(finding.severity) >= SEVERITY_ORDER.index(ceiling):
                    continue
                note = f"Severity capped {finding.severity} → {ceiling}: {reason}."
                verification = (
                    finding.verification.model_copy(update={"note": f"{finding.verification.note} {note}".strip()})
                    if finding.verification
                    else Verification(verdict="adjusted", original_severity=finding.severity, note=note)
                )
                self.findings[fid] = finding.model_copy(update={"severity": ceiling, "verification": verification})
                capped += 1
        return capped

    def auto_fold_duplicates(self) -> int:
        """Fold findings that are the same defect recorded twice (overlapping citations + same key terms).

        Deterministic, before synthesis: lanes overlap by design (security and auth both
        see rate limiting; security and inputs both see upload validation), and the
        synthesizer does not reliably catch every pair. The more severe / better
        evidenced finding stays primary and absorbs the other's locations.
        """
        with self._lock:
            live = [f for f in self.findings.values() if f.id not in self.duplicates]
        rank = {
            f.id: (SEVERITY_ORDER.index(f.severity), -len(f.evidence), f.verification is None, f.id) for f in live
        }
        live.sort(key=lambda f: rank[f.id])
        folded = 0
        for i, primary in enumerate(live):
            if primary.id in self.duplicates:
                continue
            for other in live[i + 1 :]:
                if other.id in self.duplicates:
                    continue
                current = self.findings[primary.id]
                if self._same_defect(current, other):
                    self.mark_duplicate(
                        _DuplicateArgs(duplicate_id=other.id, primary_id=primary.id, reason="auto: same defect")
                    )
                    folded += 1
        return folded

    def auto_triage_cited(self) -> int:
        """Untriaged static findings that sit inside a live finding's cited lines are true positives."""
        spans: dict[str, list[tuple[int, int, str]]] = defaultdict(list)
        with self._lock:
            for finding in self.findings.values():
                if finding.id in self.duplicates:
                    continue
                for ref in finding.evidence:
                    spans[ref.file].append((ref.line_start - 1, (ref.line_end or ref.line_start) + 1, finding.id))
            count = 0
            for static in self.static_by_id.values():
                if static.id in self.triage or static.line is None:
                    continue
                hit = next((fid for lo, hi, fid in spans.get(static.file, ()) if lo <= static.line <= hi), None)
                if hit is not None:
                    self.triage[static.id] = StaticTriage(
                        finding_id=static.id, tool=static.tool, verdict="true_positive",
                        reason=f"cited by reported finding {hit}", triaged_by="citation",
                    )
                    count += 1
        return count

    def duplicate_candidates(self) -> str:
        """Pairs of findings from different categories that cite the same file:line or share a KPI."""
        with self._lock:
            live = [f for f in self.findings.values() if f.id not in self.duplicates]
        by_location: dict[str, set[str]] = defaultdict(set)
        by_kpi: dict[str, set[str]] = defaultdict(set)
        for f in live:
            for ref in f.evidence:
                by_location[f"{ref.file}:{ref.line_start}"].add(f.id)
            for kpi in f.kpi_ids:
                by_kpi[kpi].add(f.id)
        category = {f.id: f.category_id for f in live}
        pairs: dict[tuple[str, str], list[str]] = defaultdict(list)
        for reason, groups in (("same citation", by_location), ("same KPI", by_kpi)):
            for key, ids in groups.items():
                ordered = sorted(ids)
                for i, a in enumerate(ordered):
                    for b in ordered[i + 1 :]:
                        if category[a] != category[b] or reason == "same KPI":
                            pairs[(a, b)].append(f"{reason} {key}")
        words = {f.id: self._title_terms(f.title) for f in live}
        for i, a in enumerate(live):
            for b in live[i + 1 :]:
                if not words[a.id] or not words[b.id]:
                    continue
                overlap = len(words[a.id] & words[b.id]) / len(words[a.id] | words[b.id])
                same_lane = a.category_id == b.category_id
                if overlap >= (0.5 if same_lane else 0.3):
                    key = tuple(sorted((a.id, b.id)))
                    label = "same pattern in one category" if same_lane else "similar titles across categories"
                    pairs[key].append(f"{label} (title overlap {overlap:.0%})")
        if not pairs:
            return "No cross-category overlaps found."
        titles = {f.id: f.title for f in live}
        lines = ["Candidate duplicates (overlap is a hint, not proof — read both and merge only the SAME defect):"]
        for (a, b), reasons in sorted(pairs.items(), key=lambda kv: -len(kv[1])):
            lines.append(f"- {a} \"{titles[a][:90]}\" <> {b} \"{titles[b][:90]}\" ({'; '.join(reasons[:3])})")
        return "\n".join(lines[:120])

    def get_finding(self, finding_id: str) -> str:
        with self._lock:
            finding = self.findings.get(finding_id)
        return self.render_finding(finding) if finding else f"Unknown finding '{finding_id}'."

    def mark_duplicate(self, args: _DuplicateArgs) -> str:
        with self._lock:
            if args.duplicate_id == args.primary_id:
                return "A finding cannot duplicate itself."
            if args.duplicate_id not in self.findings or args.primary_id not in self.findings:
                return "Both ids must be existing findings."
            primary = args.primary_id
            while primary in self.duplicates:  # follow chains to the root
                primary = self.duplicates[primary]
            if primary == args.duplicate_id:
                return "That would create a cycle."
            self.duplicates[args.duplicate_id] = primary
            # The primary absorbs the folded finding's locations and links, and keeps the
            # higher severity: one pattern found in many files becomes one finding.
            kept, folded = self.findings[primary], self.findings[args.duplicate_id]
            evidence = {ref.label: ref for ref in (*kept.evidence, *folded.evidence)}
            severity = min(kept.severity, folded.severity, key=SEVERITY_ORDER.index)
            self.findings[primary] = kept.model_copy(
                update={
                    "evidence": tuple(list(evidence.values())[:_MAX_MERGED_EVIDENCE]),
                    "kpi_ids": tuple(dict.fromkeys((*kept.kpi_ids, *folded.kpi_ids))),
                    "static_finding_ids": tuple(dict.fromkeys((*kept.static_finding_ids, *folded.static_finding_ids))),
                    "severity": severity,
                }
            )
        return f"{args.duplicate_id} folded into {primary} (locations merged)."

    def submit_summary(self, args: _SummaryArgs) -> str:
        known = set(self.findings)
        def _clean(ids: list[str]) -> tuple[str, ...]:
            return tuple(self.duplicates.get(i, i) for i in dict.fromkeys(ids) if i in known)

        with self._lock:
            self.summary = ExecutiveSummary(
                scope=args.scope.strip()[:3000],
                verdict=args.verdict.strip()[:4000],
                priority_order=tuple(
                    PriorityItem(title=p.title.strip()[:200], rationale=p.rationale.strip()[:1500], finding_ids=_clean(p.finding_ids))
                    for p in args.priority_order
                ),
                cross_cutting=tuple(
                    RootCause(title=r.title.strip()[:200], explanation=r.explanation.strip()[:2000], finding_ids=_clean(r.finding_ids))
                    for r in args.cross_cutting
                ),
                verification_note=args.verification_note.strip()[:2000],
            )
        return "Executive summary recorded. You are done — reply with one short sentence."

    # ------------------------------------------------------------------
    # Tool factories
    # ------------------------------------------------------------------

    def query_tools(self) -> list[BaseTool]:
        """Read-only tools every agent (and the code-explorer subagent) gets."""
        return [
            _tool(self.static_overview, "static_analysis_overview",
                  "Summary of the static-analysis pass: per tool status, finding counts, severities, top rules, owner category."),
            _tool(self.query_static_findings, "query_static_findings",
                  "List static-analysis findings (paginated, filterable by tool/rule/file glob/severity/triage state).",
                  _QueryStaticArgs),
            _tool(self.find_symbol, "find_symbol",
                  "Locate Python functions/classes by name in the dependency graph: file:line span, params, decorators, caller count.",
                  _FindSymbolArgs),
            _tool(self.find_references, "find_references",
                  "Whole-word search for an identifier across every scanned source file (fast, exhaustive). "
                  "Mandatory before any 'unused/dead' claim.", _ReferencesArgs),
            _tool(self.call_relations, "get_call_relations",
                  "Callers and callees of a Python function (resolved call graph with call-site lines). Use to trace reachability.",
                  _CallRelationArgs),
            _tool(self.module_imports, "get_module_imports",
                  "Import graph: what a module/file imports and who imports it (accepts dotted modules or repository "
                  "paths). Use for layering and reachability questions.",
                  _ImportArgs),
            _tool(self.list_endpoints, "list_endpoints",
                  "HTTP routes with full paths, the auth dependencies that actually apply (app/router/route, transitive), "
                  "identity inputs taken from the request, and flags. Filter with flagged_only=true for the risky ones.",
                  _EndpointArgs),
            _tool(self.hotspots, "get_hotspots",
                  "Ranked hot spots: most-called functions (fan_in), most-calling (fan_out), largest (size), most complex (complexity).",
                  _HotspotArgs),
        ]

    def specialist_tools(self, category: ReviewCategory, *, kpi_assessor: bool = False) -> list[BaseTool]:
        """Query tools + the recording tools bound to one category.

        The KPI assessor (a second agent on the KPI-owning category) gets
        ``assess_security_kpi`` instead of the static-triage tools.
        """
        tools = [
            *self.query_tools(),
            _tool(lambda **kw: self.record_finding(category, _RecordFindingArgs(**kw)), "record_finding",
                  "Record one verified finding for your category. Validates every file:line citation against the repository.",
                  _RecordFindingArgs),
            _tool(lambda **kw: self.update_finding(category, _UpdateFindingArgs(**kw)), "update_finding",
                  "Amend one of your recorded findings (only the fields you pass change).", _UpdateFindingArgs),
            _tool(lambda **kw: self.withdraw_finding(category, _WithdrawArgs(**kw)), "withdraw_finding",
                  "Withdraw one of your findings that turned out to be wrong.", _WithdrawArgs),
            _tool(lambda: self.list_my_findings(category), "list_my_findings",
                  "Recap of what you have recorded so far (findings, triage progress, KPI coverage)."),
        ]
        if kpi_assessor:
            tools.append(
                _tool(lambda **kw: self.assess_kpi(_KpiArgs(**kw)), "assess_security_kpi",
                      "Record the status of one mandatory security KPI with evidence. Every KPI must be assessed.", _KpiArgs)
            )
            return tools
        tools += [
            _tool(lambda **kw: self.triage_static(category, _TriageArgs(**kw)), "triage_static_findings",
                  "Give a verdict on static-analysis findings from the tools your category owns. Batch ids that share a verdict.",
                  _TriageArgs),
            _tool(lambda **kw: self.triage_rule(category, _TriageRuleArgs(**kw)), "triage_static_rule",
                  "Apply one verdict to ALL untriaged findings of one (tool, rule) group — after sampling a few instances "
                  "with query_static_findings and reading the code. The fast way through large lint rule groups.",
                  _TriageRuleArgs),
        ]
        return tools

    def verifier_tools(self, category_id: str) -> list[BaseTool]:
        return [
            *self.query_tools(),
            _tool(lambda **kw: self.submit_verification(category_id, _VerifyArgs(**kw)), "submit_verification",
                  "Record your independent verdict on one finding.", _VerifyArgs),
        ]

    def synthesizer_tools(self) -> list[BaseTool]:
        return [
            self.query_tools()[0],
            _tool(self.list_findings, "list_findings", "Compact list of all current findings (filterable).", _ListFindingsArgs),
            _tool(self.get_finding, "get_finding", "Full text of one finding.", _GetFindingArgs),
            _tool(self.duplicate_candidates, "find_duplicate_candidates",
                  "Pairs of findings from different categories that cite the same file:line or the same KPI — "
                  "the usual shape of one defect reported twice. Start deduplication here."),
            _tool(lambda **kw: self.mark_duplicate(_DuplicateArgs(**kw)), "mark_duplicate",
                  "Fold a finding that reports the same underlying defect as another (e.g. from two categories) into it.",
                  _DuplicateArgs),
            _tool(lambda **kw: self.submit_summary(_SummaryArgs(**kw)), "submit_executive_summary",
                  "Record the report's scope, verdict, priority order, cross-cutting root causes and verification note. Call once, last.",
                  _SummaryArgs),
        ]


def _tool(func: Callable[..., str], name: str, description: str, args_schema: type[BaseModel] | None = None) -> BaseTool:
    """Wrap a workspace method as a LangChain tool with an explicit schema."""
    if args_schema is None:
        return StructuredTool.from_function(func=lambda: func(), name=name, description=description)
    return StructuredTool.from_function(func=func, name=name, description=description, args_schema=args_schema)


__all__ = ["REPO_MOUNT", "EvidenceInput", "ReviewWorkspace"]
