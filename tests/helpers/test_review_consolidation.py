"""Deterministic duplicate folding and citation-based static triage (pairs taken from a real run)."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from config import settings
from helpers.review_config_loader import load_review_config
from helpers.review_workspace import EvidenceInput, ReviewWorkspace, _RecordFindingArgs
from utils import (
    DependencyGraph,
    DiscoveryStatistics,
    FileEntry,
    RepositoryManifest,
    StaticFinding,
)

FILES = {
    "app/main.py": 120,
    "app/routers/auth.py": 60,
    "app/routers/candidate_actions.py": 60,
    "app/services/internal_vacancy_service.py": 160,
    "app/services/cv_operations_service.py": 800,
    "src/utils/extract_docx_txt.py": 30,
}


@pytest.fixture
def workspace(tmp_path: Path) -> ReviewWorkspace:
    for rel, lines in FILES.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x = 1\n" * lines)
    manifest = RepositoryManifest(
        schema_version="1", discovery_engine_version="1", repository_id="r", head_sha="a" * 40, cache_key="k",
        generated_at=datetime.now(UTC), statistics=DiscoveryStatistics(source_roots=(".",)),
        files=tuple(FileEntry(path=p, language="Python", size_bytes=1, lines=n) for p, n in FILES.items()),
    )
    graph = DependencyGraph(schema_version="1", engine_version="1", repository_id="r", head_sha="a" * 40,
                            cache_key="k", generated_at=datetime.now(UTC))
    static = [StaticFinding.from_normalized("semgrep", {"file": "app/main.py", "line": 50, "severity": "error",
                                                        "category": "python-cors-wildcard-with-credentials",
                                                        "message": "cors"}),
              StaticFinding.from_normalized("ruff", {"file": "app/main.py", "line": 110, "severity": "warning",
                                                     "category": "E501", "message": "long"})]
    return ReviewWorkspace(repo_path=tmp_path, manifest=manifest, static_findings=static, tool_results={},
                           graph=graph, config=load_review_config(settings.DEEP_REVIEW_CONFIG_PATH))


def record(ws: ReviewWorkspace, category: str, title: str, severity: str, *cites: tuple[str, int, int]) -> str:
    out = ws.record_finding(ws.config.category(category), _RecordFindingArgs(
        title=title, severity=severity, confidence="high", description="d", impact="i",
        evidence=[EvidenceInput(file=f, line_start=a, line_end=b) for f, a, b in cites]))
    return out.split()[1]


def test_real_duplicate_pairs_fold_and_distinct_baselines_do_not(workspace):
    ws = workspace
    cors_int = record(ws, "integration", "Overly permissive CORS policy allows requests from any origin", "Medium",
                      ("app/main.py", 44, 49))
    cors_sec = record(ws, "security", "CORS misconfiguration: wildcard origin with credentials allowed", "High",
                      ("app/main.py", 48, 53))
    cors_sec2 = record(ws, "security", "Insecure CORS configuration: wildcard origin with credentials allowed", "High",
                       ("app/main.py", 50, 50))
    pt_sec = record(ws, "security", "Path Traversal vulnerability in file upload handlers", "High",
                    ("app/services/cv_operations_service.py", 779, 782),
                    ("app/services/internal_vacancy_service.py", 140, 142))
    pt_bug = record(ws, "correctness", "Unsanitized filename in file upload leads to path traversal vulnerability",
                    "High", ("app/services/internal_vacancy_service.py", 141, 141))
    rl_sec = record(ws, "security", "No rate limiting on authentication endpoints", "High",
                    ("app/routers/auth.py", 30, 30), ("app/main.py", 40, 60))
    rl_auth = record(ws, "auth", "Absence of rate limiting on any route", "High", ("app/main.py", 1, 1))
    ex_sec = record(ws, "security", "Raw exception messages exposed in API responses", "Medium",
                    ("app/routers/candidate_actions.py", 29, 32))
    ex_obs = record(ws, "observability", "Insufficient Error Handling and Information Disclosure via Raw Exception Text",
                    "High", ("app/routers/candidate_actions.py", 30, 30))
    metrics = record(ws, "observability", "Absence of Application Metrics", "High", ("app/main.py", 1, 1))
    logs = record(ws, "observability", "Absence of Structured (JSON) Logging Configuration", "Medium", ("app/main.py", 1, 1))
    ids = record(ws, "observability", "Absence of Request/Correlation ID Propagation", "Medium", ("app/main.py", 1, 1))
    xxe = record(ws, "security", "XML External Entity (XXE) vulnerability via entity expansion", "High",
                 ("src/utils/extract_docx_txt.py", 15, 15))
    parser = record(ws, "inputs", "Parser abuse and resource exhaustion vulnerabilities in file processing", "High",
                    ("src/utils/extract_docx_txt.py", 15, 15))

    ws.auto_fold_duplicates()

    live = {fid for fid in ws.findings if fid not in ws.duplicates}
    assert cors_sec in live and {cors_int, cors_sec2} <= set(ws.duplicates)
    assert len({pt_sec, pt_bug} & live) == 1
    assert len({rl_sec, rl_auth} & live) == 1
    assert ex_obs in live and ex_sec in ws.duplicates  # the higher-severity one stays
    assert {metrics, logs, ids, xxe, parser} <= live
    merged = ws.findings[cors_sec]
    assert {(e.file, e.line_start) for e in merged.evidence} >= {("app/main.py", 44), ("app/main.py", 50)}


def test_static_findings_inside_cited_lines_become_true_positives(workspace):
    ws = workspace
    record(ws, "security", "CORS wildcard with credentials", "High", ("app/main.py", 48, 53))
    assert ws.auto_triage_cited() == 1
    triaged = next(iter(ws.triage.values()))
    assert triaged.verdict == "true_positive" and triaged.reason.startswith("cited by reported finding SEC-")


def test_static_lead_is_addressed_only_by_a_citation_near_its_line(workspace):
    from utils import StaticFinding

    ws = workspace
    lock = StaticFinding.from_normalized("semgrep", {
        "file": "app/services/cv_operations_service.py", "line": 700, "severity": "info",
        "category": "src.assets.semgrep.python-claim-flag-or-lock", "message": "claim"})
    ws.static_by_id[lock.id] = lock
    label = "Work claims / locks / in-progress flags (semgrep)"
    record(ws, "correctness", "Random IDs collide", "High", ("app/services/cv_operations_service.py", 100, 105))
    assert label in [name for name, _ in ws.unaddressed_leads("correctness")]
    record(ws, "correctness", "Screening lock is never released on failure", "High",
           ("app/services/cv_operations_service.py", 690, 695))
    assert label not in [name for name, _ in ws.unaddressed_leads("correctness")]


def test_severity_caps_for_latent_script_and_baseline_findings(workspace):
    from helpers.review_maps import BASELINES

    ws = workspace
    ws.maps.unreachable = ["app/services/internal_vacancy_service.py", "src/utils/extract_docx_txt.py"]
    ws.maps.orphan_scripts = ["src/utils/extract_docx_txt.py"]
    ws.maps.absent_baselines = [b for b in BASELINES if b.id == "rate_limiting"]
    latent = record(ws, "security", "SQL injection via LLM-generated SQL", "Critical",
                    ("app/services/internal_vacancy_service.py", 10, 12))
    script = record(ws, "observability", "Seed script prints admin passwords", "High",
                    ("src/utils/extract_docx_txt.py", 5, 5))
    baseline = record(ws, "auth", "No rate limiting on any route", "Critical", ("app/main.py", 1, 1))
    live = record(ws, "security", "Client-asserted identity bypass", "Critical", ("app/routers/auth.py", 30, 30))
    assert ws.apply_severity_caps() == 3
    assert ws.findings[latent].severity == "High" and "latent" in ws.findings[latent].verification.note
    assert ws.findings[script].severity == "Medium"
    assert ws.findings[baseline].severity == "High"
    assert ws.findings[live].severity == "Critical" and ws.findings[live].verification is None


def test_hardening_findings_are_capped_but_known_exploits_are_not(workspace):
    ws = workspace
    ws.maps.absent_baselines = []
    cors = record(ws, "security", "CORS wildcard origin with credentials allowed", "Critical", ("app/main.py", 20, 22))
    pins = record(ws, "dependencies", "Unsafe Hugging Face model downloads without revision pinning", "Critical",
                  ("app/main.py", 40, 40))
    cve = record(ws, "dependencies", "Unpinned torch with known vulnerability CVE-2025-32434 (RCE)", "Critical",
                 ("app/main.py", 50, 50))
    assert ws.apply_severity_caps() == 2
    assert ws.findings[cors].severity == "High" and "hardening" in ws.findings[cors].verification.note
    assert ws.findings[pins].severity == "High"
    assert ws.findings[cve].severity == "Critical"


def test_untriaged_groups_only_when_coverage_is_low(workspace):
    from helpers.review_workspace import _TriageRuleArgs

    ws = workspace
    assert ws.untriaged_groups("maintainability") == [("ruff", "E501", 1)]
    ws.triage_rule(ws.config.category("maintainability"),
                   _TriageRuleArgs(tool="ruff", rule="E501", verdict="low_value", reason="style"))
    assert ws.untriaged_groups("maintainability") == []
