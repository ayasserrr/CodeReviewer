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
from helpers.review_signals import is_test_file
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
# Lint-rule restatements in a maintainability finding title: ruff/flake8-style codes or the tool names.
_LINT_TITLE = re.compile(r"\b(?:RUF|SIM|UP|PL[A-Z]?|[FEWBCN])\d{3,4}\b|\b(?:ruff|radon|lizard|vulture)\b|cyclomatic complexity", re.IGNORECASE)
_DEAD_MODULE_TITLE = re.compile(
    r"(dead|unreachable|unused|orphan\w*|not imported)\b.*\b(modules?|files?|packages?|director\w*|code)\b"
    r"|\b(modules?|files?|packages?)\b.*\b(dead|unreachable|unused|orphan\w*|not imported)",
    re.IGNORECASE,
)
_DOC_CLAIM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+\S")
SYSTEM_DOC_NAME = "agents.md"
_SYSTEM_DOC_FILE_CHARS = 40_000
_SYSTEM_DOC_TOTAL_CHARS = 80_000
# ruff codes that only describe layout: pycodestyle whitespace/indent/blank-line/line-length and isort.
_FORMATTING_RULE = re.compile(r"^(W29\d|W391|E1\d\d|E2\d\d|E3\d\d|E501|I00\d)$")
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
_AUTHISH_PATH = re.compile(r"(?i)(auth|security|jwt|token|otp|session|password|login)")
_LEAD_LINE_TOLERANCE = 15
_SCOPE_REASON = re.compile(r"(?i)(brief|checklist|baseline|prompt|instructions?|review scope|lead list)s?\b[^.]{0,40}"
                           r"\b(does not|doesn't|do not|never) (list|include|mention|require|cover)")
_SEVERE_STATIC = {"critical", "high"}  # security tools only; pyright/radon use "error" for ordinary hits
_PERSISTED_STATE = re.compile(r"(?i)\block(ed)?\b|\bflag\b|in[_ -]?progress|background work|\bjob\b|\blease\b|semaphore")
_CLEANUP_ONLY = re.compile(r"(?i)\bfinally\b|\bexcept\b|context manager|\bwith\b block|cleaned up|clears? the|releases?")
# A named recovery MECHANISM, not a scenario word: "safe even on crashes" is exactly the wrong claim.
_PROCESS_DEATH = re.compile(r"(?i)stale|\bttl\b|expir|startup|on start|heartbeat|\bowner|\blease\b|timeout|"
                            r"not persisted|in[- ]memory only|reset (on|at|when)|reaper|watchdog|advisory lock|"
                            r"transaction[- ]scoped|rolled back")


def _cleanup_only_reason(claim: str, note: str) -> str | None:
    """A lock/flag/job that survives the process is not made safe by cleanup code: ``finally`` and
    ``except`` do not run when the process is killed, restarted or redeployed mid-job."""
    if _PERSISTED_STATE.search(claim) and _CLEANUP_ONLY.search(note) and not _PROCESS_DEATH.search(note):
        return ("NOT RECORDED — the reason relies on cleanup code (finally/except/release), which does not run when "
                "the process is killed, restarted or redeployed mid-job. Say what happens to this lock/flag/job "
                "then — is it persisted (DB row, file, cache key) and what clears it: an expiry/TTL, a startup reset, "
                "a heartbeat or owner check? If nothing does, it is a finding: record it.")
    return None
_NON_REASON = re.compile(
    r"(?i)\b(budget|out of time|no time|time ran|ran out|partially|not (fully )?(investigated|checked|traced|reviewed)|"
    r"did not (check|trace|review)|covered (by|in|under) (finding|another)|see finding|already (recorded|reported|covered)|"
    r"will (check|review) later|skipp?ed)\b"
)
_ANCHOR_TERMS = frozenset({
    "cors", "csrf", "xss", "jwt", "ssrf", "xxe", "idor", "csp", "hsts", "otp", "sqli", "injection", "traversal",
    "deserialization", "clickjacking", "openapi", "swagger", "mktemp", "pickle", "yaml", "iframe", "sandbox",
})
_MIN_HYPOTHESES = 6
_GENERIC_NOTE_WORDS = frozenset({"code", "file", "function", "line", "this", "that", "with", "because", "safe",
                                 "defect", "issue", "application", "system", "data", "value", "check", "used"})
_EACH_ROW_MAX_KEYS = 25
_ROW_SYMBOL = re.compile(r"^`?([A-Za-z_][A-Za-z0-9_]{3,})`?\s*\(")
"""Lead groups up to this many distinct locations are tracked row by row, not as a whole."""
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
    "python-mass-assignment": "client payload copied field-by-field onto stored objects (privileged fields settable?)",
    "python-open-redirect": "redirect target taken from the request",
    "python-assert-as-guard": "assert used as an access/validation check (removed under -O)",
    "python-archive-extract-all": "archive extracted without member-path checks (zip slip)",
    "web-postmessage-any-origin": "postMessage to any origin / message listener without origin check",
    "web-redirect-from-url-param": "browser navigation target read from the URL",
}
# Rules whose judgement belongs to another lane (security still triages every semgrep hit).
_LANE_RULE_LEADS: dict[str, dict[str, str]] = {
    "auth": {
        "python-cookie-missing-flags": "cookies set without HttpOnly/Secure",
        "python-jwt-decode-without-algorithms": "jwt.decode without an algorithms allow-list",
        "python-secret-compared-with-equality": "secrets/tokens compared with == (timing, plaintext storage)",
    },
    "observability": {"python-secret-written-to-log": "credentials or tokens written to logs"},
    "inputs": {"python-archive-extract-all": "archives extracted without member count/size/path limits"},
    "correctness": {
        "python-exception-swallowed": "broad exceptions swallowed without logging (failure looks like success)",
        "python-mutable-default-argument": "mutable default arguments shared across calls",
        "python-module-level-db-session": "one database session/connection shared by the whole process",
        "python-float-for-money": "money handled as float",
    },
}
_TITLE_STOPWORDS = {
    "with", "from", "into", "that", "this", "missing", "lack", "lacks", "using", "used", "without", "the", "and",
    "for", "via", "not", "all", "any", "are", "absence", "absent", "leads", "lead", "allows", "allowed", "can",
    "issue", "issues", "potential", "possible", "multiple", "across", "due", "its", "has", "have", "been",
    # Generic nouns every lane uses: sharing them says nothing about sharing a defect.
    "api", "endpoint", "endpoints", "route", "routes", "application", "app", "code", "service", "services",
    "file", "files", "data", "insecure", "unsafe", "vulnerability", "vulnerable",
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
    "python-technology-disclosure-header": ("KPI-03", "KPI-10"),
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
    exposure: Literal["live", "conditional", "latent", "dead", "theoretical"] = Field(
        "live",
        description="How reachable the defect is TODAY: live = reachable through the running system; "
        "conditional = reachable only under specific conditions (a config, a role, a race); latent = the code "
        "exists but no entry point reaches it (one import/route away); dead = unused code nothing calls; "
        "theoretical = needs a future architectural change. Calibrate severity to it.",
    )
    violates_documented_rule: str | None = Field(
        None,
        description="When the repository's AGENTS.md documents the behaviour this finding contradicts: that "
        "rule's path:line, e.g. 'AGENTS.md:17'. It is added to the evidence as the documented intent.",
    )


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
    exposure: Literal["live", "conditional", "latent", "dead", "theoretical"] | None = None


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


class _HypothesisInput(BaseModel):
    statement: str = Field(..., description="A concrete suspected defect in THIS repository (what, where, why it would fail).")
    files: list[str] = Field(..., min_length=1, description="Repository files the hypothesis is about.")


class _HypothesesArgs(BaseModel):
    system_model: str = Field(
        ...,
        description="3-8 sentences: how this system works from your lane's point of view (components, data flow, "
        "trust boundaries, what could hurt most) — learned from the code and AGENTS.md, not from the leads.",
    )
    hypotheses: list[_HypothesisInput] = Field(
        ..., min_length=1, description="Repository-specific suspicions to investigate (at least 6)."
    )


class _ResolveHypothesisArgs(BaseModel):
    hypothesis_id: str
    outcome: Literal["confirmed", "ruled_out"]
    finding_id: str | None = Field(None, description="For confirmed: the finding you recorded for it.")
    note: str = Field("", description="For ruled_out: what makes it safe, citing the repository path:line.")


class _UpholdArgs(BaseModel):
    ref: str = Field(..., description="The item id (H-... or D-...).")
    note: str = Field(..., description="The code you checked that makes it safe, citing repository path:line.")


class _OverturnArgs(BaseModel):
    ref: str = Field(..., description="The item id (H-... or D-...) whose 'safe' conclusion is wrong.")
    why_wrong: str = Field(..., description="Why the specialist's reasoning does not hold, citing the code.")
    title: str
    severity: Literal["Critical", "High", "Medium", "Low"]
    description: str
    impact: str
    evidence: list[EvidenceInput] = Field(..., min_length=1)
    exposure: Literal["live", "conditional", "latent", "dead", "theoretical"] = "live"


class _DismissLeadArgs(BaseModel):
    lead: str = Field(
        ...,
        description="Text identifying the lead: a distinctive part of one row (e.g. its file:line) closes that row; "
        "a group label closes the whole group.",
    )
    reason: str = Field(
        "",
        description="Why it is not a defect, citing the repository `path:line` that shows it (the guard, caller, "
        "config or test). Shown in the report. Not needed with finding_id.",
    )
    finding_id: str | None = Field(
        None,
        description="When one of your findings already covers this lead: its id. The lead's location is added to "
        "that finding's evidence instead of being dismissed.",
    )


class _VerifyArgs(BaseModel):
    finding_id: str
    verdict: Literal["confirmed", "rejected", "adjusted"] = Field(
        ...,
        description="confirmed = true as stated; rejected = not a real issue / evidence doesn't support it; "
        "adjusted = real but the severity is wrong (give adjusted_severity).",
    )
    note: str = Field(
        ...,
        description="The decisive fact you checked, citing file:line. A rejection must cite the repository code "
        "that disproves the claim.",
    )
    adjusted_severity: Literal["Critical", "High", "Medium", "Low"] | None = None
    corrected_title: str | None = Field(
        None, description="Only when the title overstates or misnames the defect: the accurate one-line title."
    )
    corrected_exposure: Literal["live", "conditional", "latent", "dead", "theoretical"] | None = Field(
        None, description="Only when the recorded exposure (live/conditional/latent/dead/theoretical) is wrong."
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
        self.system_docs = self._load_system_docs()

        # Collector state.
        self._lock = threading.Lock()
        self.findings: dict[str, ReviewFinding] = {}
        self.withdrawn: dict[str, str] = {}
        # Lead rows a specialist dismissed with a cited reason: (category_id, row) -> reason.
        self.dismissed_leads: dict[tuple[str, str], str] = {}
        self._lead_rows: dict[tuple[str, str], list[tuple[str, str]]] = {}
        self._scopes: dict[str, list[str]] | None = None
        # Per lane: the agent's own system model and repo-specific hypotheses (id -> record).
        self.system_models: dict[str, str] = {}
        self.negative_audit: dict[str, str] = {}  # ref -> "upheld: ..." / "overturned -> FID"
        self.hypotheses: dict[str, dict[str, Any]] = {}
        self.invalid_evidence_bounces = 0
        self._counters: Counter[str] = Counter()
        self.triage: dict[str, StaticTriage] = {}
        self.kpis: dict[str, KpiAssessment] = {}
        self.verifications: dict[str, Verification] = {}
        self.rejected: dict[str, ReviewFinding] = {}
        self.duplicates: dict[str, str] = {}
        self.summary: ExecutiveSummary | None = None

    def _documented_rule_ref(self, raw: str) -> tuple[list[EvidenceRef], list[str]]:
        """``AGENTS.md:17`` -> an evidence ref on that line, noted as the documented intent."""
        match = re.fullmatch(r"\s*(.+?):(\d+)(?:-(\d+))?\s*", raw)
        if not match or PurePosixPath(self._normalize_path(match.group(1))).name.lower() != SYSTEM_DOC_NAME:
            return [], [f"violates_documented_rule must be an AGENTS.md path:line (got {raw!r})"]
        start, end = int(match.group(2)), int(match.group(3)) if match.group(3) else None
        refs, errors = self.validate_evidence(
            [EvidenceInput(file=match.group(1), line_start=start, line_end=end, note="documented intent (AGENTS.md)")]
        )
        return refs, errors

    def _check_dead_module_claim(self, title: str, refs: list[EvidenceRef]) -> list[str]:
        """A finding that calls whole modules dead may only cite modules the import map finds unreachable."""
        if not self.maps.unreachable or not _DEAD_MODULE_TITLE.search(title):
            return []
        unreachable = set(self.maps.unreachable)
        live = sorted({r.file for r in refs if r.file.endswith(".py") and r.file not in unreachable})
        if not live:
            return []
        return [
            "these modules ARE imported by the application (reachable), so they are not dead: "
            + ", ".join(live[:10])
            + " — cite only modules listed in /_review/context/reachability.md"
        ]

    def _load_system_docs(self) -> tuple[tuple[str, str], ...]:
        """Developer-written system descriptions (``AGENTS.md``, any case, any folder; shallowest first).

        The repository's own account of its intended logic: agents review the code against it.
        """
        paths = sorted(
            (f.path for f in self.manifest.files if PurePosixPath(f.path).name.lower() == SYSTEM_DOC_NAME),
            key=lambda path: (path.count("/"), path),
        )
        docs: list[tuple[str, str]] = []
        budget = _SYSTEM_DOC_TOTAL_CHARS
        for path in paths:
            if budget <= 0:
                break
            try:
                text = (self.repo_path / path).read_text(encoding="utf-8-sig", errors="replace")
            except OSError:
                continue
            text = text[: min(_SYSTEM_DOC_FILE_CHARS, budget)]
            budget -= len(text)
            docs.append((path, text))
        return tuple(docs)

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
        if category.id == "maintainability" and _LINT_TITLE.search(args.title):
            return (
                "NOT RECORDED — this restates lint output. Lint rule groups belong in the static-analysis triage "
                "(triage_static_rule), not in findings. Record the underlying defect only if it has a real cost here "
                "(e.g. dead code sized in lines, a duplicated implementation that diverged)."
            )
        refs, errors = self.validate_evidence(args.evidence)
        if args.violates_documented_rule:
            doc_refs, doc_errors = self._documented_rule_ref(args.violates_documented_rule)
            refs += [r for r in doc_refs if r not in refs]
            errors += doc_errors
        errors += self._check_links(args.kpi_ids, args.static_finding_ids)
        errors += self._check_dead_module_claim(args.title, refs)
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
                exposure=args.exposure,
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
        for field in ("severity", "confidence", "exposure"):
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
                self._lead_rows[(category_id, label)] = list(rows)

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
            if self.system_docs:
                # Every bullet / numbered line is a checkable claim about the system; headings as fallback.
                claims = [
                    f"{path}:{n} {line.strip()[:160]}"
                    for path, text in self.system_docs
                    for n, line in enumerate(text.splitlines(), start=1)
                    if _DOC_CLAIM.match(line)
                ]
                headings = claims or [
                    f"{path}:{n} {line.lstrip('#').strip()}"
                    for path, text in self.system_docs
                    for n, line in enumerate(text.splitlines(), start=1)
                    if line.startswith("#") and line.lstrip("#").strip()
                ]
                groups.append((
                    (
                        "Rules the developers documented in AGENTS.md — check each against the code; record every "
                        "divergence with violates_documented_rule='<path>:<line>' of the rule it breaks"
                    ),
                    frozenset(path for path, _ in self.system_docs),
                    headings[:40] or [path for path, _ in self.system_docs],
                ))
            add("Random identifiers (semgrep)", static_rows("python-random-identifier"))
            add("Work claims / locks / in-progress flags (semgrep)", static_rows("python-claim-flag-or-lock"))
        elif category_id == "llm":
            add("LangGraph graphs compiled without a checkpointer (semgrep)",
                static_rows("python-langgraph-compile-without-checkpointer"))
            add("Model calls inside loops (semgrep)", static_rows("python-model-call-in-loop"))
        elif category_id == "maintainability":
            by_dir: dict[str, list[str]] = defaultdict(list)
            for path in self.maps.unreachable:
                by_dir[str(PurePosixPath(path).parent)].append(path)
            add("Backend routes no frontend code calls — an API route is NOT dead just because this frontend skips it; "
                "record at most ONE grouped finding, only for routes nothing else uses (scripts, other services, docs)",
                [(r.file, f"{r.method} {r.path} -> {r.handler} ({r.file}:{r.line})"
                  + (f" — DOCUMENTED in {self.maps.documented_routes[r.path]}: an external contract unless the "
                     "docs are stale" if r.path in self.maps.documented_routes else ""))
                 for r in self.maps.routes_without_client()])
            if by_dir:
                lines = {f.path: f.lines or 0 for f in self.manifest.files}
                sized = sorted(
                    ((d, len(paths), sum(lines.get(x, 0) for x in paths)) for d, paths in by_dir.items()),
                    key=lambda row: -row[2],
                )
                total = sum(n for _, _, n in sized)
                groups.append((
                    (
                        f"Modules no application root imports — {len(self.maps.unreachable)} modules, ~{total:,} "
                        "lines of dead-code candidates. Confirm, then record ONE grouped dead-code finding sized "
                        "in lines (not one per folder)"
                    ),
                    frozenset(self.maps.unreachable),
                    [f"{d}/ ({n} modules, {loc:,} lines)" for d, n, loc in sized],
                ))
            clones: Counter[str] = Counter()
            for f in self.static_by_id.values():
                if f.tool == "jscpd":
                    match = re.search(r"\((\d+) lines", f.message)
                    clones[f.file] += int(match.group(1)) if match else 0
            add("Largest duplicated code (jscpd): parallel implementations to name, e.g. near-identical orchestrators",
                [(path, f"{path}: {n:,} duplicated lines") for path, n in clones.most_common(12) if n >= 30])
        elif category_id == "secrets":
            add(".env files with flagged keys (weak/short/localhost/browser-exposed/duplicates)",
                [(f.file, f"{f.file}: " + "; ".join(f"{k} {flag}" for k, flag in f.flags[:6])
                  + (f"; duplicates: {', '.join(k for k, _ in f.duplicates)}" if f.duplicates else ""))
                 for f in self.maps.env_files if f.flags or f.duplicates])
            add("Insecure secret defaults (semgrep)", static_rows("python-insecure-secret-default"))
        for rule, label in _LANE_RULE_LEADS.get(category_id, {}).items():
            add(f"{label} (semgrep {rule})", static_rows(rule))
        self._signal_leads(category_id, add)
        for label, _ in self._absence_leads(category_id):
            groups.append((label, frozenset(), ["confirm the absence (the static search found nothing) and record it"]))
        return groups

    def _signal_leads(self, category_id: str, add) -> None:
        """Leads from runtime_signals.md: behaviour of the running system no linter reports."""
        sig = self.maps.signals

        def rows(signals) -> list[tuple[str, str]]:
            return [(f"{x.file}:{x.line}" if x.line else x.file, x.row if x.line else f"{x.text} ({x.file})") for x in signals]

        # Keyed by file (not file:line) and closed only by a finding NAMING the function: a defect deep
        # inside a long function is still about that function.
        if category_id == "correctness":
            add("Hotspots — functions that combine several kinds of side effect. For each, walk every failure "
                "path: a step failing after an earlier one committed, two concurrent calls, a retry, a crash "
                "mid-way. Where is state left inconsistent, a lock or record stuck, work duplicated or lost?",
                [(x.file, x.row) for x in sig.hotspots])
        if category_id == "security":
            add("Route handlers with the most powerful side effects — who can call each (authn AND authz: is any "
                "logged-in user allowed?), what caller input reaches the file, network, subprocess or database "
                "effect, and is it constrained? For outbound messaging: who may send to whom, with what content "
                "(an open relay or phishing from the organisation's own sender)?",
                [(x.file, x.row) for x in sig.hotspots if "route handler" in x.text])
        if category_id in ("integration", "auth"):
            add("Credentials accepted in the query string (proxy/server logs, browser history, referrers)",
                rows(sig.query_credentials))
        if category_id == "secrets":
            add("Secrets / personal data shipped with the code or baked into the image — not committed to git is not "
                "enough when the build context or delivered tree carries them", rows(sig.packaged_artifacts))
            add("Deploy manifests: env keys set twice (last writer wins) or pointing at local/dev targets",
                rows([x for x in sig.deploy_env if "privileged" not in x.text and "count = 1" not in x.text]))
        if category_id == "security":
            add("Containers deployed privileged", rows([x for x in sig.deploy_env if "privileged" in x.text]))
            add("Third-party services that receive application data — which personal data goes to each, is it "
                "minimized, documented and covered by the users' consent (one grouped finding)",
                rows(sig.data_processors))
        if category_id == "auth":
            add("Naive datetimes in token / OTP / session code (expiry and iat computed without a timezone)",
                rows([x for x in sig.naive_datetimes if _AUTHISH_PATH.search(x.file)]))
        if category_id == "integration":
            add("Keys set to contradictory targets in different .env files (dev vs prod, local vs remote)",
                [(f, f"{key} — {f}: {flags}") for key, per_file in self.maps.env_contradictions() for f, flags in per_file])
        if category_id == "llm":
            add("Chat / agent routes — trace what ONE request sends to the model: is history persisted or resent, "
                "is there a per-user/session token or cost budget, are model and tool errors caught",
                [(r.file, f"{r.method} {r.path} -> {r.handler} ({r.file}:{r.line})")
                 for r in self.maps.routes if re.search(r"(?i)chat|agent|assistant|ask|conversation", r.path)])
            add("Agent loops re-sending a growing message list (input tokens grow with every round)", rows(sig.agent_loops))
            add("Tool outputs handed to the model whole (no size bound)", rows(sig.unbounded_tool_output))
            add("Files that call a model but never read token usage (cost is invisible)", rows(sig.usage_never_read))
            add("Model / embedding clients built at import time (network at import, per-worker copies)",
                rows(sig.model_clients_at_import))
        elif category_id == "performance":
            add("Sync model / embedding work reached from async code — each call freezes every request on the worker",
                rows(sig.blocking_in_async))
            add("Unbounded reads: whole tables / whole directories loaded per request (record ONE grouped finding "
                "together with the unpaginated endpoints)", rows(sig.unbounded_reads))
            add("All-or-nothing startup: heavy init with no error handling, provider clients built at import time",
                rows(sig.startup_fragility))
            add("Whole-file JSON rewrites per event (O(events x file size) disk I/O)", rows(sig.whole_file_rewrites))
            add("Deployment pinned to one instance (the process-local state above is why)",
                rows([x for x in sig.deploy_env if "count = 1" in x.text]))
        elif category_id == "observability":
            if sig.print_live:
                total = sum(n for _, n in sig.print_live)
                add(f"print() used as logging in LIVE modules ({total} calls in {len(sig.print_live)} files) — cite these, "
                    "not scripts", [(f, f"{f}: {n} print() calls") for f, n in sig.print_live[:15]])
            add("Health endpoints that check no dependency (report healthy while the database/model is down)",
                rows(sig.static_health))
            add("Background jobs — where does a failure end up (log line only, in-memory/TTL state, or a durable "
                "record that survives a restart)?",
                [(f"{j.file}:{j.line}", f"{j.function} ({j.file}:{j.line}) started at {j.started_at}")
                 for j in self.maps.background_jobs if j.file and j.file not in set(self.maps.unreachable)])
        elif category_id == "testing":
            add("CI / deploy pipelines with no test, lint or scan step (build -> deploy with no gate)",
                [(p.file, f"{p.file}: stages {', '.join(p.stages) or 'unnamed'}") for p in sig.ci_without_checks])
            add("Frontend calls with no backend route — broken contracts a contract/integration test would have caught",
                [(c.file, f"{c.path} ({c.file}:{c.line})") for c in self.maps.unmatched_client_calls()])
            add("Tests that cannot fail (no assertion) and credentials hard-coded in test/automation scripts",
                rows(sig.weak_tests))
            add("Deployment pipeline hygiene (sudo, curl | sh, secrets echoed, :latest images, --privileged)",
                rows(sig.pipeline_hygiene))
            if not sig.route_tests:
                critical = [r for r in self.maps.routes if r.is_auth_entry or r.accepts_upload
                            or "CLIENT-ASSERTED IDENTITY" in r.flags]
                add("Critical routes no test exercises — name them in the missing-tests finding (auth, authorization, "
                    "uploads) rather than saying 'no tests' in general",
                    [(r.file, f"{r.method} {r.path} ({r.file}:{r.line})") for r in critical][:40])
        elif category_id == "dependencies":
            add("Libraries doing the same job", [(src, f"{fam}: {', '.join(pkgs)} ({src})") for fam, pkgs, src in sig.duplicate_libraries])
            add("Declared dependencies nothing live imports (dead weight / attack surface)",
                [(x.file, f"{x.text} ({x.file})") for x in sig.unused_dependencies])
            add("Supply chain: missing lockfiles, unpinned base images", rows(sig.supply_chain))
        elif category_id == "inputs":
            add("External commands run with no timeout (a hostile document hangs the worker)", rows(sig.subprocess_no_timeout))
        elif category_id == "maintainability":
            add("Executor nesting / single-worker thread pools (concurrency that is hard to reason about)",
                rows(sig.executor_nesting))
            add("Layers that import each other both ways (layering violation: core logic depends on the app layer)",
                [(ex.split(" -> ", 1)[0], f"{a} <-> {b}: {ex}") for a, b, examples in sig.layer_cycles for ex in examples])
        if category_id == "correctness":
            add("Naive datetimes outside auth code (date math against aware values, wrong 'now' across timezones)",
                rows([x for x in sig.naive_datetimes if not _AUTHISH_PATH.search(x.file)][:15]))
        if category_id in ("maintainability", "correctness") and sig.parallel_implementations:
            label = (
                "Parallel implementations of one operation — name which one production uses and how the copies differ"
                if category_id == "maintainability"
                else "Parallel implementations of one operation — check whether the copies now process the same data "
                "differently (a correctness bug)"
            )
            add(label, [(x.file, f"{name}: {x.row}") for name, sites in sig.parallel_implementations[:12] for x in sites])

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
        leads = [
            (f"Baseline with no trace anywhere in the code: {b.label}", b.mention)
            for b in self.maps.absent_baselines
            if b.lane == category_id
        ]
        sig = self.maps.signals
        leads += [
            (f"Control with no trace anywhere in the live code: {label}", mention)
            for lane, label, mention in sig.absent_controls if lane == category_id
        ]
        if category_id == "dependencies" and any("no lockfile" in x.text or "no package-lock" in x.text
                                                 for x in sig.supply_chain):
            leads.append((
                (
                    "Control with no trace anywhere in the live code: a dependency lockfile (transitive versions "
                    "float between builds)"
                ),
                r"(?i)lock\s?-?file|lockfile|lock file|package-lock|poetry\.lock",
            ))
        if category_id == "testing" and sig.ci_pipelines and not any(p.runs_scans for p in sig.ci_pipelines):
            leads.append((
                "No CI/deploy pipeline runs a security or dependency scan (bandit/semgrep/pip-audit/npm audit/trivy/...)",
                r"(?i)scan|security (test|check)|dependency (audit|check)|sast",
            ))
        if category_id == "testing" and self.maps.routes and not sig.route_tests:
            leads.append((
                (
                    f"No test drives the HTTP API ({len(sig.test_files)} test files, none uses TestClient/httpx/supertest): "
                    "auth, authorization, uploads and the frontend/backend contract are untested"
                ),
                r"(?i)(integration|route|api|endpoint|contract|auth).{0,60}test|test.{0,60}(integration|route|api|endpoint|contract)",
            ))
        return leads

    def untriaged_groups(self, category_id: str, threshold: float = 0.25) -> list[tuple[str, str, int]]:
        """``(tool, rule, count)`` of untriaged static findings this category owns — empty when coverage is fine."""
        owned = {t for t, owner in self.config.static_tool_owners.items() if owner == category_id}
        mine = [f for f in self.static_by_id.values() if f.tool in owned]
        if not mine:
            return []
        pending = [f for f in mine if f.id not in self.triage]
        # A severe hit is never covered by the "most of it is triaged" allowance.
        severe = [f for f in pending if f.severity in _SEVERE_STATIC]
        if len(pending) <= threshold * len(mine):
            pending = severe
        if not pending:
            return []
        groups = Counter((f.tool, f.category) for f in pending)
        return [(tool, rule, count) for (tool, rule), count in groups.most_common()]

    def unrecorded_true_positives(self, category_id: str) -> list[str]:
        """Severe static hits the lane marked real that no finding (in any lane) reports.

        A triage verdict alone never reaches the report's findings — a confirmed CVE or
        injection sink that only lives in the triage table is a lost defect."""
        owned = {t for t, owner in self.config.static_tool_owners.items() if owner == category_id}
        texts = [" ".join([f.title, f.description, f.impact or ""]).lower() for f in self.findings.values()]
        spans: dict[str, list[tuple[int, int]]] = defaultdict(list)
        for f in self.findings.values():
            for ref in f.evidence:
                spans[ref.file].append((ref.line_start, ref.line_end or ref.line_start))
        rows = []
        for sf in self.static_by_id.values():
            if (sf.tool not in owned or sf.severity not in _SEVERE_STATIC
                    or getattr(self.triage.get(sf.id), "verdict", None) != "true_positive"):
                continue
            rule = sf.category.lower()
            package = sf.message.split()[0].lower() if sf.line is None and sf.message else ""
            cited = sf.line is not None and any(
                lo - _LEAD_LINE_TOLERANCE <= sf.line <= hi + _LEAD_LINE_TOLERANCE for lo, hi in spans.get(sf.file, ()))
            named = any(rule in t or (len(package) > 2 and re.search(rf"\b{re.escape(package)}\b", t)) for t in texts)
            if not (cited or named):
                where = f"{sf.file}:{sf.line}" if sf.line else sf.file
                rows.append(f"{sf.id} [{sf.tool} {sf.category}, {sf.severity}] {where} — {sf.message[:140]}")
        return rows

    def unaddressed_leads(self, category_id: str, *, any_lane: bool = False) -> list[tuple[str, list[str]]]:
        """Lead groups (or rows) no finding cites. ``any_lane``: a finding from ANY lane counts
        (used for the report — a lead another lane recorded is covered, just not by its owner)."""
        mine = [f for f in self.findings.values() if any_lane or f.category_id == category_id]
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

        dismissed = {row for (cat, row) in self.dismissed_leads if cat == category_id}
        missing: list[tuple[str, list[str]]] = []
        for label, keys, rows in self.lane_leads(category_id):
            if not keys or label in dismissed:
                continue
            pairs = self._lead_rows.get((category_id, label)) or [(k, r) for k, r in zip(sorted(keys), rows, strict=False)]
            if len(keys) <= _EACH_ROW_MAX_KEYS:
                # Small groups are checked row by row: citing one row no longer hides the others
                # (observed: one subprocess cited, another in the same group silently dropped).
                texts = " ".join(
                    f"{f.title} {f.description} " + " ".join(e.note or "" for e in f.evidence) for f in mine
                )

                def named(row: str, texts: str = texts) -> bool:
                    # A row about a named symbol ("session_cache (file:22): ...") is covered only when a
                    # finding names it — a citation near it in a big grouped finding is not enough.
                    ident = _ROW_SYMBOL.match(row)
                    return ident is None or ident.group(1) in texts

                open_rows = [row for key, row in pairs if not (addressed(key) and named(row)) and row not in dismissed]
                if open_rows:
                    missing.append((label, open_rows))
            elif not any(addressed(key) for key in keys) and not any(row in dismissed for _, row in pairs):
                missing.append((label, rows))
        for label, mention in self._absence_leads(category_id):
            if label in dismissed:
                continue
            # A missing control needs a finding of its own: its title must name it (a passing
            # mention in another finding's text used to close it — observed with the token budget).
            strict = label.startswith("Control with no trace")
            if not any(re.search(mention, f.title if strict else f"{f.title} {f.description}") for f in mine):
                missing.append((label, ["confirm the absence (the static search found nothing) and record it"]))
        return missing

    # ------------------------------------------------------------------
    # Lead dismissals and file scopes
    # ------------------------------------------------------------------

    def dismiss_lead(self, category: ReviewCategory, args: "_DismissLeadArgs") -> str:
        """Close lead rows: attach them to the finding that covers them, or dismiss them with a cited reason."""
        if args.finding_id:
            return self._attach_lead(category, args)
        if _NON_REASON.search(args.reason):
            return (
                "NOT RECORDED — lack of time/budget, 'partially investigated' or 'covered elsewhere' is not a reason a "
                "row is not a defect. If a finding covers it, call dismiss_lead again with finding_id=<that finding> "
                "(the row is added to its evidence). Otherwise open the code and either record it or cite what makes "
                "it safe."
            )
        if not self._cites_repository(args.reason):
            return (
                "NOT RECORDED — a dismissal must cite the repository code that shows the row is not a defect "
                "(a `path:line` in the reason: the guard, the caller, the config that handles it). If you cannot "
                "cite one, the row is a finding: record it."
            )
        needle = args.lead.strip().lower()
        if (refused := _cleanup_only_reason(args.lead, args.reason)) is not None:
            return refused
        if len(needle) < 4:
            return "NOT RECORDED — pass a distinctive part of the lead row (e.g. its file:line) or the group label."
        self.lane_leads(category.id)  # refresh the row index
        candidates: list[str] = []
        for (cat, label), pairs in self._lead_rows.items():
            if cat != category.id:
                continue
            if needle in label.lower():
                candidates.append(label)
            candidates += [row for _, row in pairs if needle in row.lower()]
        candidates += [label for label, _ in self._absence_leads(category.id) if needle in label.lower()]
        if not candidates:
            return f"No lead of your lane matches '{args.lead}'. Use text from a row or label exactly as listed."
        with self._lock:
            for row in dict.fromkeys(candidates):
                self.dismissed_leads[(category.id, row)] = args.reason.strip()[:600]
        return f"Dismissed {len(set(candidates))} lead row(s)."

    def _attach_lead(self, category: ReviewCategory, args: "_DismissLeadArgs") -> str:
        """Add the matching lead rows' locations to one of the lane's findings (addresses them properly)."""
        with self._lock:
            finding = self.findings.get(args.finding_id or "")
        if finding is None or finding.category_id != category.id:
            return f"Unknown finding '{args.finding_id}' in your category."
        needle = args.lead.strip().lower()
        self.lane_leads(category.id)
        keys = [
            key for (cat, label), pairs in self._lead_rows.items() if cat == category.id
            for key, row in pairs if needle in row.lower() or needle in label.lower()
        ]
        refs = []
        for key in dict.fromkeys(keys):
            file, sep, line = key.rpartition(":")
            evidence = EvidenceInput(file=file, line_start=int(line)) if sep and line.isdigit() and int(line) > 0 \
                else EvidenceInput(file=key, line_start=1)
            valid, _ = self.validate_evidence([evidence])
            refs += valid
        if not refs:
            return f"No lead row of your lane matches '{args.lead}' with a citable location."
        with self._lock:
            known = {(e.file, e.line_start) for e in finding.evidence}
            added = tuple(r for r in refs if (r.file, r.line_start) not in known)
            self.findings[finding.id] = finding.model_copy(update={"evidence": finding.evidence + added})
        return f"Attached {len(added)} lead location(s) to {finding.id} as evidence."

    def record_hypotheses(self, category: ReviewCategory, args: _HypothesesArgs) -> str:
        if len(args.system_model.strip()) < 120:
            return "NOT RECORDED — describe the system model in 3-8 sentences (components, data flow, trust boundaries)."
        known = {f.path for f in self.manifest.files}
        errors, accepted = [], []
        for n, item in enumerate(args.hypotheses, start=1):
            files = [self._normalize_path(f) for f in item.files]
            missing = [f for f in files if f not in known]
            if len(item.statement.strip()) < 30:
                errors.append(f"hypothesis {n}: state the suspected defect concretely")
            elif missing:
                errors.append(f"hypothesis {n}: not repository files: {', '.join(missing)}")
            else:
                accepted.append((item.statement.strip()[:500], tuple(files)))
        existing = [h for h in self.hypotheses.values() if h["lane"] == category.id]
        if len(existing) + len(accepted) < _MIN_HYPOTHESES and not errors:
            return (
                f"NOT RECORDED — at least {_MIN_HYPOTHESES} repository-specific hypotheses are needed "
                f"(you have {len(existing) + len(accepted)}). Derive them from the code you read, not from the leads."
            )
        with self._lock:
            self.system_models[category.id] = args.system_model.strip()[:2000]
            ids = []
            for statement, files in accepted:
                hid = f"H-{category.code}-{len([h for h in self.hypotheses.values() if h['lane'] == category.id]) + 1}"
                self.hypotheses[hid] = {"lane": category.id, "statement": statement, "files": files,
                                        "outcome": None, "finding_id": None, "note": ""}
                ids.append(hid)
        suffix = f" Not recorded: {'; '.join(errors)}." if errors else ""
        return f"Recorded {', '.join(ids) or 'no'} hypotheses.{suffix} Investigate each and resolve it with resolve_hypothesis."

    def resolve_hypothesis(self, category: ReviewCategory, args: _ResolveHypothesisArgs) -> str:
        with self._lock:
            record = self.hypotheses.get(args.hypothesis_id)
        if record is None or record["lane"] != category.id:
            return f"Unknown hypothesis '{args.hypothesis_id}' in your lane."
        if args.outcome == "confirmed":
            finding = self.findings.get(args.finding_id or "")
            if finding is None or finding.category_id != category.id:
                return "NOT RECORDED — confirmed needs the id of the finding you recorded for it."
        elif not self._cites_repository(args.note) or _NON_REASON.search(args.note):
            return "NOT RECORDED — ruled_out needs the code that shows it is safe (a repository path:line in the note)."
        elif (refused := _cleanup_only_reason(record["statement"], args.note)) is not None:
            return refused
        elif not self._note_matches(args.note, record["statement"], record["files"]):
            return (
                f"NOT RECORDED — this note does not address {args.hypothesis_id} ('{record['statement'][:100]}'). "
                "Re-check which hypothesis you are closing and cite the code that decides it."
            )
        with self._lock:
            record.update(outcome=args.outcome, finding_id=args.finding_id, note=args.note.strip()[:600])
        return f"{args.hypothesis_id}: {args.outcome}."

    def _note_matches(self, note: str, statement: str, files) -> bool:
        """A note closes a hypothesis/lead only if it talks about it (shares its files or key words)."""
        note_l = (note or "").lower()
        if any(PurePosixPath(f).name.lower() in note_l for f in files):
            return True
        words = set(re.findall(r"[a-z][a-z0-9_]{3,}", statement.lower())) - _TITLE_STOPWORDS - _GENERIC_NOTE_WORDS
        return len(words & set(re.findall(r"[a-z][a-z0-9_]{3,}", note_l))) >= 2

    # ------------------------------------------------------------------
    # Audit of negative conclusions (dismissed leads, ruled-out hypotheses)
    # ------------------------------------------------------------------

    def negatives_to_audit(self, category_id: str, limit: int = 12) -> list[dict[str, str]]:
        """The lane's "this is safe" conclusions, for a second agent to check like any finding.

        A wrong dismissal is as costly as a false finding and used to go unchecked (observed: a
        stuck-lock lead dismissed because the release sat in a background task's finally block —
        exactly the bug)."""
        items: list[dict[str, str]] = []
        for hid, h in self.hypotheses.items():
            if h["lane"] == category_id and h["outcome"] == "ruled_out" and hid not in self.negative_audit:
                items.append({"ref": hid, "kind": "ruled-out hypothesis", "claim": h["statement"], "reason": h["note"]})
        for n, ((lane, row), reason) in enumerate(sorted(self.dismissed_leads.items()), start=1):
            ref = f"D-{self.config.category(lane).code}-{n}" if lane == category_id else ""
            if ref and ref not in self.negative_audit:
                items.append({"ref": ref, "kind": "dismissed lead", "claim": row, "reason": reason})
        return items[:limit]

    def uphold_negative(self, category_id: str, args: "_UpholdArgs") -> str:
        item = next((i for i in self.negatives_to_audit(category_id, limit=999) if i["ref"] == args.ref), None)
        if item is None:
            return f"Unknown or already judged item '{args.ref}'."
        if not self._cites_repository(args.note):
            return "NOT RECORDED — upholding needs the code you checked (a repository path:line in the note)."
        if (refused := _cleanup_only_reason(item["claim"], args.note)) is not None:
            return refused
        with self._lock:
            self.negative_audit[args.ref] = f"upheld: {args.note.strip()[:300]}"
        return f"{args.ref}: upheld."

    def overturn_negative(self, category: ReviewCategory, args: "_OverturnArgs") -> str:
        item = next((i for i in self.negatives_to_audit(category.id, limit=999) if i["ref"] == args.ref), None)
        if item is None:
            return f"Unknown or already judged item '{args.ref}'."
        record = _RecordFindingArgs(
            title=args.title, severity=args.severity, confidence="high", description=args.description,
            impact=args.impact, evidence=args.evidence, exposure=args.exposure,
        )
        out = self.record_finding(category, record)
        if not out.startswith("Recorded "):
            return out
        fid = out.split()[1]
        with self._lock:
            finding = self.findings[fid]
            self.findings[fid] = finding.model_copy(update={"verification": Verification(
                verdict="confirmed", original_severity=finding.severity,
                note=f"Found by the verifier: the specialist's {item['kind']} was wrong — {args.why_wrong.strip()[:600]}",
            )})
            self.verifications[fid] = self.findings[fid].verification
            self.negative_audit[args.ref] = f"overturned -> {fid}"
            if args.ref in self.hypotheses:
                self.hypotheses[args.ref].update(outcome="confirmed", finding_id=fid,
                                                 note=f"ruling overturned by the verifier: {args.why_wrong[:200]}")
            else:
                # Kept (not deleted) so the other D- refs stay stable while the audit runs.
                for key in [k for k in self.dismissed_leads if k[0] == category.id and k[1] == item["claim"]]:
                    self.dismissed_leads[key] = f"dismissal overturned by the verifier → {fid}"
        return f"{args.ref}: overturned; recorded {fid} (verified)."

    def open_hypotheses(self, category_id: str) -> list[str]:
        return [f"{hid}: {h['statement'][:160]}" for hid, h in self.hypotheses.items()
                if h["lane"] == category_id and h["outcome"] is None]

    def hypothesis_rows(self) -> list[str]:
        rows = []
        for hid, h in self.hypotheses.items():
            if h["outcome"] == "confirmed":
                result = f"confirmed → {h['finding_id']}"
            elif h["outcome"] == "ruled_out":
                audit = self.negative_audit.get(hid, "")
                result = f"ruled out — {h['note']}" + ("; verifier upheld" if audit.startswith("upheld") else "")
            else:
                result = "not resolved"
            rows.append(f"{h['lane']} — {hid}: {h['statement']} [{result}]")
        return rows

    def lead_backed(self, finding: ReviewFinding) -> bool:
        """True when the finding sits on a static lead or a static-tool hit (vs. the agent's own investigation)."""
        if finding.static_finding_ids:
            return True
        cited = {(e.file, e.line_start) for e in finding.evidence}
        cited_files = {e.file for e in finding.evidence}
        for pairs in self._lead_rows.values():
            for key, _row in pairs:
                file, sep, line = key.rpartition(":")
                if sep and line.isdigit():
                    if any(f == file and abs(n - int(line)) <= _LEAD_LINE_TOLERANCE for f, n in cited):
                        return True
                elif key in cited_files:
                    return True
        for sf in self.static_by_id.values():
            if any(sf.file == f and sf.line and abs(sf.line - n) <= 2 for f, n in cited):
                return True
        return False

    def render_system_overview(self) -> str:
        """A factual map of THIS system for the agents' first step (building their own system model)."""
        maps, sig = self.maps, self.maps.signals
        files = self.manifest.files
        comps: dict[str, Counter] = defaultdict(Counter)
        for f in files:
            parts = PurePosixPath(f.path).parts
            top = "/".join(parts[:2]) if len(parts) > 2 else parts[0] if len(parts) > 1 else "."
            comps[top][f.language or "other"] += 1
        lines = ["# System overview (static facts — build your own model of the system from these and the code)", ""]
        lines.append("## Components (folder: files by language)")
        for top, langs in sorted(comps.items(), key=lambda kv: -sum(kv[1].values()))[:20]:
            lines.append(f"- {top}: " + ", ".join(f"{n} {lang}" for lang, n in langs.most_common(4)))
        runtimes = self.declared_runtimes()
        lines += ["", "## Declared runtime versions (judge syntax and semantics against THESE, not older releases): "
                  + ("; ".join(runtimes) or "none declared")]
        lines += ["", f"## Application entry points: {', '.join(maps.app_roots) or 'none detected'}"]
        groups: dict[str, list] = defaultdict(list)
        for r in maps.routes:
            segs = [x for x in r.path.strip("/").split("/") if x and not x.startswith("{")]
            groups["/" + "/".join(segs[:3])].append(r)
        if groups:
            lines += ["", f"## API surface ({len(maps.routes)} routes, grouped; auth = strongest check applied)"]
            for prefix, routes in sorted(groups.items()):
                auth = Counter(r.auth_label for r in routes)
                flags = Counter(f for r in routes for f in r.flags)
                lines.append(f"- {prefix}: {len(routes)} routes; auth " + ", ".join(f"{k} x{v}" for k, v in auth.items())
                             + ("; flags " + ", ".join(f"{k} x{v}" for k, v in flags.items()) if flags else ""))
        stores = sorted({pkg.lower() for pkg in re.findall(
            r"(?i)\b(sqlalchemy|psycopg2?|asyncpg|sqlite3|redis|pymongo|motor|chromadb|qdrant|faiss|elasticsearch|"
            r"boto3|minio|celery|kafka|pika)\b", " ".join(py for py in self._python_sources()))})
        lines += ["", f"## Data stores and infrastructure libraries in live code: {', '.join(stores) or 'none detected'}"]
        lines.append("## External services that receive data: "
                     + ("; ".join(x.text.split(' —')[0] for x in sig.data_processors) or "none detected"))
        lines.append(f"## Background work ({len(maps.background_jobs)}): "
                     + "; ".join(f"{j.function} ({j.file}:{j.line})" for j in maps.background_jobs if j.file)[:1500])
        lines.append(f"## Process-local state: {len(maps.process_state)} items (architecture.md)")
        web = [f.path for f in files if f.path.endswith((".tsx", ".jsx", ".vue", ".svelte"))]
        lines.append(f"## Browser client: {len(web)} component files; {len(maps.client_calls)} API call paths "
                     f"({len(maps.unmatched_client_calls())} with no backend route)")
        lines.append(f"## Tests: {len(sig.test_files)} files ({len(sig.route_tests)} drive the API); CI/deploy pipelines: "
                     + (", ".join(p.file for p in sig.ci_pipelines) or "none"))
        docs = ", ".join(path for path, _ in self.system_docs)
        lines.append(f"## Developer-written system description (AGENTS.md): {docs or 'none — infer the intent from the code'}")
        lines.append(f"## Dead-code candidates: {len(maps.unreachable)} modules no entry point imports (reachability.md)")
        return "\n".join(lines)

    def declared_runtimes(self) -> list[str]:
        """Interpreter / runtime versions the project declares (pyproject, .python-version, Dockerfiles, package.json)."""
        found: list[str] = []
        patterns = (
            (r"(?im)^\s*requires-python\s*=\s*[\"']([^\"']+)", "requires-python {}"),
            (r"(?im)^\s*python_requires\s*=\s*[\"']([^\"']+)", "python_requires {}"),
            (r"(?im)^\s*FROM\s+(?:[\w./-]+/)?python:([\w.${}:-]+)", "Docker python:{}"),
            (r"(?im)^\s*ARG\s+PYTHON_VERSION\s*=\s*([\w.]+)", "Docker PYTHON_VERSION={}"),
            (r'"node"\s*:\s*"([^"]+)"', "node {}"),
            (r"(?im)^\s*FROM\s+(?:[\w./-]+/)?node:([\w.-]+)", "Docker node:{}"),
        )
        for entry in self.manifest.files:
            name = PurePosixPath(entry.path).name.lower()
            if name in (".python-version", ".nvmrc", ".tool-versions"):
                try:
                    text = (self.repo_path / entry.path).read_text(encoding="utf-8", errors="replace").strip()
                    found.append(f"{entry.path}: {text.splitlines()[0][:40] if text else '?'}")
                except OSError:
                    pass
                continue
            if not (name in ("pyproject.toml", "setup.cfg", "setup.py", "package.json") or name.startswith("dockerfile")):
                continue
            try:
                text = (self.repo_path / entry.path).read_text(encoding="utf-8", errors="replace")[:100_000]
            except OSError:
                continue
            for rx, fmt in patterns:
                for value in re.findall(rx, text)[:2]:
                    found.append(f"{entry.path}: " + fmt.format(value.strip()))
        return list(dict.fromkeys(found))[:12]

    def _python_sources(self):
        dead = set(self.maps.unreachable)
        for f in self.manifest.files:
            if f.language == "Python" and f.path not in dead and not is_test_file(f.path):
                try:
                    yield (self.repo_path / f.path).read_text(encoding="utf-8", errors="replace")[:50_000]
                except OSError:
                    continue

    def lane_scopes(self) -> dict[str, list[str]]:
        """Which repository files each lane must open itself (directly or through its code-explorers).

        Every live source file lands in at least one lane: a file no rule claims goes to
        correctness (backend) or frontend (browser code). Dead modules are left to the
        maintainability lane's reachability evidence — reading them adds nothing.
        """
        if self._scopes is not None:
            return self._scopes
        maps, sig = self.maps, self.maps.signals
        dead = set(maps.unreachable)
        code_langs_excluded = {"Markdown", "JSON", "YAML", "TOML"}
        entries = {f.path: f for f in self.manifest.files}

        def is_live_code(path: str) -> bool:
            f = entries.get(path)
            return bool(
                f and f.language and f.language not in code_langs_excluded and path not in dead
                and not is_test_file(path) and not f.skipped_due_to_size
                and ((f.lines or 0) >= 5 if f.lines is not None else f.size_bytes >= 120)
                and not path.endswith((".min.js", ".d.ts"))
            )

        live = sorted(p for p in entries if is_live_code(p))
        web = [p for p in live if p.endswith((".ts", ".tsx", ".js", ".jsx", ".vue", ".svelte", ".mjs"))]
        backend = [p for p in live if p not in set(web)]

        # A top-level folder holding several code packages is a project container
        # ("my-service/{app,src}"): its name says nothing about each file.
        children: dict[str, set[str]] = defaultdict(set)
        for p in live:
            parts = PurePosixPath(p).parts
            if len(parts) > 2:
                children[parts[0]].add(parts[1])
        containers = {top for top, subs in children.items() if len(subs) >= 2}

        def rel(path: str) -> str:
            parts = PurePosixPath(path).parts
            return "/".join(parts[1:]) if len(parts) > 1 and parts[0] in containers else path

        def match(rx: str, pool=live) -> set[str]:
            return {p for p in pool if re.search(rx, "/" + rel(p), re.IGNORECASE)}

        deploy = {p for p in entries if re.search(
            r"(?i)(^|/)(dockerfile[^/]*|jenkinsfile[^/]*|docker-compose[^/]*|compose\.ya?ml|\.gitlab-ci\.yml)$|/jenkins/|"
            r"\.nomad$|\.github/workflows/|(^|/)k8s/|(^|/)helm/", p)}
        # Operational scripts run against real environments (migrations, bootstrap, cron): the
        # deploy-facing lanes must read them, not only the catch-all lane.
        ops = {p for p in entries if not is_test_file(p) and "node_modules" not in p and re.search(
            r"(?i)(\.(sh|bash|sql)$|(^|/)(makefile|procfile|alembic\.ini|entrypoint[^/]*)$|(^|/)(migrations?|alembic)/)",
            p) and (entries[p].size_bytes or 0) > 0}
        manifests = {p for p in entries if re.search(
            r"(?i)(^|/)(requirements[^/]*\.(txt|in)|pyproject\.toml|package\.json|pipfile|setup\.(py|cfg))$", p)
            and "node_modules" not in p}
        templates = {p for p in entries if is_sensitive_env_file(PurePosixPath(p).name) is False
                     and re.search(r"(?i)(^|/)\.env[^/]*(example|sample|template|dist)", p)}
        route_files = {r.file for r in maps.routes} & set(live)
        upload_files: set[str] = set()
        for r in maps.routes:
            if r.accepts_upload:
                upload_files |= self._reachable_files(r.file, r.handler, depth=2)
        env_files = {r.file for r in maps.env_reads} & set(live)
        model_files = {x.file for x in sig.usage_never_read + sig.model_clients_at_import + sig.blocking_in_async
                       + sig.agent_loops + sig.unbounded_tool_output}
        job_files = {j.file for j in maps.background_jobs if j.file}
        scopes: dict[str, set[str]] = {
            "security": route_files | match(r"(auth|security|deps|middleware|permission|guard|export|html|iframe)"),
            "auth": match(r"(auth|security|jwt|token|session|login|user|otp|password|deps)"),
            "integration": env_files | match(r"(config|settings|client|/api/|http|proxy|vite\.config|(^|/)main\.(py|tsx?))")
            | deploy | ops,
            "frontend": set(web),
            "observability": set(maps.app_roots) | {f for f, _ in sig.print_live} | job_files
            | {x.file for x in sig.static_health},
            "testing": set(sig.test_files) | deploy | ops,
            "secrets": env_files | templates | deploy | match(r"(^|/)scripts?/"),
            "performance": {x.file for x in maps.process_state} | {x.file for x in sig.blocking_in_async} | job_files
            | {x.file for x in sig.unbounded_reads} | {x.file for x in sig.startup_fragility}
            | {r.file for r in maps.routes if r.is_unpaginated_listing},
            "llm": model_files | match(r"(llm|agent|prompt|chat|rag|embed|vector|model|inference|transcri)"),
            "inputs": upload_files | match(r"(upload|import|extract|pars|ocr|pdf|docx|media|audio|image|file|webhook)"),
            "correctness": upload_files | job_files | match(r"(service|screen|scor|pipeline|extract|process|crud|repositor)",
                                                             backend),
            "maintainability": {x.file for _, sites in sig.parallel_implementations for x in sites}
            | {ex.split(" -> ", 1)[0] for _, _, examples in sig.layer_cycles for ex in examples},
            "dependencies": manifests | {p for p in deploy if "dockerfile" in p.lower()},
        }
        claimed = set().union(*scopes.values())
        for path in live:
            if path not in claimed:
                scopes["frontend" if path in set(web) else "correctness"].add(path)
        live_or_config = set(live) | deploy | manifests | templates | set(sig.test_files) | ops
        self._scopes = {lane: sorted(p for p in paths if p in live_or_config) for lane, paths in scopes.items()}
        return self._scopes

    def unopened_scope(self, category_id: str, opened: set[str]) -> list[str]:
        opened = {p.lstrip("/") for p in opened}
        return [p for p in self.lane_scopes().get(category_id, []) if p not in opened]

    def render_scopes(self) -> str:
        lines = ["# File scope per lane (every live source file is in at least one lane's scope)",
                 "Open every file of your lane — yourself or through code-explorer sweeps (their reads count).", ""]
        for lane, paths in self.lane_scopes().items():
            lines.append(f"## {lane} ({len(paths)} files)")
            lines += [f"- {p}" for p in paths] or ["- none"]
            lines.append("")
        return "\n".join(lines)

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

    def _cites_repository(self, text: str) -> bool:
        known = {f.path for f in self.manifest.files}
        for path in re.findall(r"([\w./\-]+\.[A-Za-z0-9]+):\d+", text or ""):
            path = path.lstrip("/")
            if path in known or any(k.endswith("/" + path) for k in known):
                return True
        return False

    def _verdict_mismatch(self, finding: ReviewFinding, note: str) -> str | None:
        """Refuse a verdict whose note is about different code than the finding (ids mixed up in a batch).

        Observed: a verifier checking several findings recorded "rejected — password hashing is
        fine (utils.py:19)" on the finding about unpaginated coupon lists.
        """
        cited = {m.lstrip("/") for m in re.findall(r"([\w./\-]+\.[A-Za-z0-9]+):\d+", note or "")}
        own = {e.file for e in finding.evidence}
        note_words = set(re.findall(r"[a-z][a-z0-9_]{2,}", (note or "").lower()))
        if not cited:
            # No citation to compare: the note must at least talk about this finding (its title or files).
            finding_words = self._title_terms(finding.title) | {
                w for e in finding.evidence for w in re.findall(r"[a-z][a-z0-9_]{2,}", PurePosixPath(e.file).stem.lower())
            } | set(re.findall(r"[a-z][a-z0-9_]{3,}", finding.description.lower())[:80])
            if len((note or "").split()) >= 8 and not (finding_words & note_words):
                return (
                    f"NOT RECORDED — this note does not mention anything from {finding.id} "
                    f"('{finding.title[:100]}'). Re-check which finding you are judging and cite its code."
                )
            return None
        if any(c == f or f.endswith("/" + c) or c.endswith("/" + f) for c in cited for f in own):
            return None
        terms = self._title_terms(finding.title)
        if terms & set(re.findall(r"[a-z][a-z0-9_]{2,}", (note or "").lower())):
            return None
        other = next((f for f in self.findings.values() if f.id != finding.id and f.category_id == finding.category_id
                      and any(c == e.file or e.file.endswith("/" + c) for c in cited for e in f.evidence)), None)
        hint = f" It matches {other.id} ('{other.title[:80]}') — did you mean that id?" if other else ""
        return (
            f"NOT RECORDED — this note cites {', '.join(sorted(cited))}, but {finding.id} is about "
            f"'{finding.title[:100]}' ({', '.join(sorted(own)) or 'no files'}).{hint} Re-check which finding you are judging."
        )

    def submit_verification(self, category_id: str, args: _VerifyArgs) -> str:
        with self._lock:
            finding = self.findings.get(args.finding_id)
            if finding is None or finding.category_id != category_id:
                return f"Unknown finding '{args.finding_id}' for this verification batch."
            if args.verdict == "adjusted" and not args.adjusted_severity:
                return "NOT RECORDED — 'adjusted' requires adjusted_severity."
            mismatch = self._verdict_mismatch(finding, args.note)
            if mismatch:
                return mismatch
            if args.verdict == "rejected" and not self._cites_repository(args.note):
                return (
                    "NOT RECORDED — a rejection must cite the code that disproves the claim (a repository "
                    "`path:line` in the note, e.g. the guard, caller or config you found). If you could not find "
                    "such code, the claim stands: confirm it, or adjust its severity/title/impact."
                )
            if args.verdict == "rejected" and _SCOPE_REASON.search(args.note):
                return (
                    "NOT RECORDED — whether a checklist, brief or baseline lists this is not a reason it is not a "
                    "defect. Reject only on what the code does; otherwise confirm or adjust."
                )
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
                if args.corrected_exposure:
                    update["exposure"] = args.corrected_exposure
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
        if overlap >= 0.7:
            # Near-identical titles from two lanes citing different sides of one defect
            # (e.g. the bundled API key seen in session.ts and in .env.example).
            return True
        if self._locations_overlap(a, b):
            # Same place + the same specific defect keyword (cors, csrf, xss, jwt, ...) is one defect even
            # when the titles are worded apart ("Overly permissive CORS" vs "CORS allows credentialed ...").
            return overlap >= 0.15 or bool(terms_a & terms_b & _ANCHOR_TERMS)
        shares_file = bool({e.file for e in a.evidence} & {e.file for e in b.evidence})
        return shares_file and overlap >= 0.34

    def apply_severity_caps(self) -> int:
        """Deterministic severity ceilings the model is not trusted to apply on its own.

        - every cited Python file, or the first-cited (defect) location, is unreachable from the
          application roots -> latent, at most High;
        - every cited file is a standalone script or a test -> at most Medium;
        - the finding reports an absent production baseline (rate limiting, metrics, ...) -> at most High;
        - exposure dead / theoretical -> at most Medium (and a finding located in unreachable code is
          re-labelled latent whatever exposure the agent gave it).
        The cap and its reason are appended to the verification note, so the report shows why.
        """
        unreachable = set(self.maps.unreachable)
        scripts = set(self.maps.orphan_scripts)
        baselines = [b for b in self.maps.absent_baselines]
        capped = 0
        with self._lock:
            for fid, finding in list(self.findings.items()):
                files = {ref.file for ref in finding.evidence}
                primary = finding.evidence[0].file if finding.evidence else None
                py_files = {f for f in files if f.endswith(".py")}
                in_dead_code = bool(py_files and py_files <= unreachable and py_files == files) or (
                    primary is not None and primary in unreachable
                )
                if in_dead_code and finding.exposure in ("live", "conditional"):
                    # The defect's location is not reachable from any entry point: whatever the
                    # agent wrote, it is not live today.
                    finding = finding.model_copy(update={"exposure": "latent"})
                    self.findings[fid] = finding
                ceiling, reason = None, ""
                if finding.exposure in ("dead", "theoretical"):
                    ceiling, reason = "Medium", f"exposure is {finding.exposure} — nothing reaches it today"
                elif (finding.category_id != "testing" and py_files and py_files == files
                        and all(_is_script_or_test(f, scripts, unreachable) for f in files)):
                    # Testing findings cite the test files BECAUSE the service lacks tests: the
                    # affected thing is the running service, not the scripts it cites.
                    ceiling, reason = "Medium", "only standalone scripts/tests are affected, not the running service"
                elif py_files and py_files <= unreachable and py_files == files:
                    ceiling, reason = "High", "latent — the cited code is not imported by any application entry point"
                elif primary and primary in unreachable:
                    # The defect's own location is dead code; citing the live route it *would* sit
                    # behind does not make it reachable (observed: a dead text-to-SQL module rated
                    # Critical because the finding also cited the live chat router).
                    ceiling, reason = "High", f"latent — {primary} (the defect's location) is not imported by any application entry point"
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
                    else Verification(verdict="adjusted", original_severity=finding.severity, note=note, independent=False)
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

    def auto_triage_formatting(self) -> int:
        """Pure-formatting lint groups (whitespace, blank lines, line length, import order) are low value.

        They are never defects, and on a real repository they number in the thousands
        (observed: 1,209 ruff W293 alone) — triaging them by hand only burns the owning
        agent's budget. Their counts stay visible in the report's static-analysis table.
        """
        count = 0
        with self._lock:
            for static in self.static_by_id.values():
                if static.id in self.triage or static.tool != "ruff" or not _FORMATTING_RULE.match(static.category):
                    continue
                self.triage[static.id] = StaticTriage(
                    finding_id=static.id, tool=static.tool, verdict="low_value",
                    reason="formatting only (whitespace, blank lines, line length, import order) — not a defect",
                    triaged_by="formatting",
                )
                count += 1
        return count

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
            _tool(lambda **kw: self.record_hypotheses(category, _HypothesesArgs(**kw)), "record_hypotheses",
                  "FIRST STEP: record your model of this system and at least 6 repository-specific hypotheses "
                  "(suspected defects with the files involved), derived from reading the code.", _HypothesesArgs),
            _tool(lambda **kw: self.resolve_hypothesis(category, _ResolveHypothesisArgs(**kw)), "resolve_hypothesis",
                  "Close one hypothesis: confirmed (with the finding id) or ruled_out (citing the code that makes "
                  "it safe). Every hypothesis ends one of these two ways; the report lists them.",
                  _ResolveHypothesisArgs),
            _tool(lambda **kw: self.dismiss_lead(category, _DismissLeadArgs(**kw)), "dismiss_lead",
                  "Close a mandatory lead row (or a whole group). With finding_id: the row is covered by that finding "
                  "and its location is added to the finding's evidence. Without: the row is NOT a defect, and the "
                  "reason cites the code that shows it (listed in the report). Budget/time is never a reason.",
                  _DismissLeadArgs),
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

    def negative_audit_tools(self, category: ReviewCategory) -> list[BaseTool]:
        return [
            *self.query_tools(),
            _tool(lambda **kw: self.uphold_negative(category.id, _UpholdArgs(**kw)), "uphold",
                  "The specialist was right: the item is not a defect. Cite the code you checked.", _UpholdArgs),
            _tool(lambda **kw: self.overturn_negative(category, _OverturnArgs(**kw)), "overturn",
                  "The specialist was wrong: record the defect as a finding (it is marked verified by you).",
                  _OverturnArgs),
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
