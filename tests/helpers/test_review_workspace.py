"""Unit tests for ReviewWorkspace — the Deep Review agents' query + recording tools."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from config import settings
from helpers.review_config_loader import load_review_config
from helpers.review_workspace import (
    EvidenceInput,
    ReviewWorkspace,
    _DuplicateArgs,
    _KpiArgs,
    _RecordFindingArgs,
    _SummaryArgs,
    _TriageArgs,
    _TriageRuleArgs,
    _VerifyArgs,
)
from utils import (
    CallEdge,
    DependencyGraph,
    DiscoveryStatistics,
    FileEntry,
    FunctionNode,
    RepositoryManifest,
    StaticFinding,
)


def _fn(file: str, qualname: str, start: int, end: int) -> FunctionNode:
    return FunctionNode(
        id=f"{file}::{qualname}", name=qualname.split(".")[-1], qualname=qualname, file=file,
        start_line=start, end_line=end, start_byte=0, end_byte=1, content_hash="h", loc=end - start + 1,
    )


def _static(tool: str, rule: str, file: str, line: int, message: str = "msg") -> StaticFinding:
    return StaticFinding.from_normalized(
        tool, {"file": file, "line": line, "severity": "warning", "category": rule, "message": message}
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text(
        "from app.service import helper\n\n\ndef handler():\n    return helper()\n\n\nregistry = [handler]\n"
    )
    (tmp_path / "app" / "service.py").write_text("def helper():\n    return 1\n")
    (tmp_path / ".env").write_text("SECRET=real\n")
    return tmp_path


@pytest.fixture
def workspace(repo: Path) -> ReviewWorkspace:
    manifest = RepositoryManifest(
        schema_version="1", discovery_engine_version="1", repository_id="r", head_sha="a" * 40, cache_key="k",
        generated_at=datetime.now(UTC), statistics=DiscoveryStatistics(source_roots=(".",)),
        files=(
            FileEntry(path="app/main.py", language="Python", size_bytes=1, lines=8),
            FileEntry(path="app/service.py", language="Python", size_bytes=1, lines=2),
        ),
    )
    handler, helper = _fn("app/main.py", "handler", 4, 5), _fn("app/service.py", "helper", 1, 2)
    graph = DependencyGraph(
        schema_version="1", engine_version="1", repository_id="r", head_sha="a" * 40, cache_key="k",
        generated_at=datetime.now(UTC), functions=(handler, helper),
        call_edges=(CallEdge(caller_id=handler.id, callee_id=helper.id, line=5, col=11),),
    )
    static = [
        _static("ruff", "E501", "app/main.py", 1),
        _static("ruff", "E501", "app/service.py", 1),
        _static("bandit", "B105", "app/main.py", 4),
    ]
    tool_results = {"ruff": {"status": "success"}, "bandit": {"status": "success"}}
    config = load_review_config(settings.DEEP_REVIEW_CONFIG_PATH)
    return ReviewWorkspace(
        repo_path=repo, manifest=manifest, static_findings=static, tool_results=tool_results, graph=graph, config=config
    )


def _finding(**overrides) -> _RecordFindingArgs:
    data = {
        "title": "Handler trusts input",
        "severity": "High",
        "confidence": "high",
        "description": "`app/main.py:4` does X.",
        "impact": "Y happens.",
        "evidence": [EvidenceInput(file="app/main.py", line_start=4, line_end=5)],
    }
    data.update(overrides)
    return _RecordFindingArgs(**data)


class TestEvidenceValidation:
    def test_valid_citation_with_leading_slash(self, workspace):
        refs, errors = workspace.validate_evidence([EvidenceInput(file="/app/main.py", line_start=2)])
        assert errors == []
        assert refs[0].file == "app/main.py"
        assert refs[0].label == "app/main.py:2"

    def test_line_out_of_range_is_rejected(self, workspace):
        _, errors = workspace.validate_evidence([EvidenceInput(file="app/service.py", line_start=50)])
        assert "has 2 lines" in errors[0]

    @pytest.mark.parametrize("path", ["missing.py", "../outside.py", ".env", "app"])
    def test_uncitable_paths_are_rejected(self, workspace, path):
        refs, errors = workspace.validate_evidence([EvidenceInput(file=path, line_start=1)])
        assert refs == [] and errors


class TestRecording:
    def test_record_assigns_category_prefixed_ids(self, workspace):
        security = workspace.config.category("security")
        assert "Recorded SEC-1" in workspace.record_finding(security, _finding())
        assert "Recorded SEC-2" in workspace.record_finding(security, _finding(title="Another"))
        assert set(workspace.findings) == {"SEC-1", "SEC-2"}

    def test_invalid_evidence_is_bounced_not_recorded(self, workspace):
        security = workspace.config.category("security")
        result = workspace.record_finding(security, _finding(evidence=[EvidenceInput(file="nope.py", line_start=1)]))
        assert result.startswith("NOT RECORDED")
        assert workspace.findings == {}
        assert workspace.invalid_evidence_bounces == 1

    def test_unknown_links_are_rejected(self, workspace):
        security = workspace.config.category("security")
        result = workspace.record_finding(security, _finding(kpi_ids=["KPI-99"], static_finding_ids=["nope"]))
        assert "unknown KPI id" in result and "unknown static finding id" in result

    def test_category_cap(self, workspace):
        security = workspace.config.category("security")
        review = workspace.config.review.model_copy(update={"max_findings_per_category": 1})
        workspace.config = workspace.config.model_copy(update={"review": review})
        workspace.record_finding(security, _finding())
        assert "cap" in workspace.record_finding(security, _finding(title="Two"))

    def test_update_and_withdraw_only_own_category(self, workspace):
        security, auth = workspace.config.category("security"), workspace.config.category("auth")
        workspace.record_finding(security, _finding())
        from helpers.review_workspace import _UpdateFindingArgs, _WithdrawArgs

        assert "Unknown finding" in workspace.update_finding(auth, _UpdateFindingArgs(finding_id="SEC-1", severity="Low"))
        assert "Updated SEC-1" in workspace.update_finding(security, _UpdateFindingArgs(finding_id="SEC-1", severity="Low"))
        assert workspace.findings["SEC-1"].severity == "Low"
        assert "Withdrew" in workspace.withdraw_finding(security, _WithdrawArgs(finding_id="SEC-1", reason="wrong"))
        assert workspace.findings == {}


class TestStaticTriage:
    def test_owner_can_triage_and_others_cannot(self, workspace):
        ruff_ids = [f.id for f in workspace.static_by_id.values() if f.tool == "ruff"]
        security = workspace.config.category("security")
        result = workspace.triage_static(
            security, _TriageArgs(finding_ids=ruff_ids, verdict="false_positive", reason="r")
        )
        assert "Ignored 2 owned by another category" in result
        maintainability = workspace.config.category("maintainability")
        workspace.triage_static(maintainability, _TriageArgs(finding_ids=ruff_ids, verdict="low_value", reason="style"))
        assert all(workspace.triage[i].verdict == "low_value" for i in ruff_ids)

    def test_triage_rule_covers_whole_untriaged_group(self, workspace):
        maintainability = workspace.config.category("maintainability")
        result = workspace.triage_rule(
            maintainability, _TriageRuleArgs(tool="ruff", rule="E501", verdict="low_value", reason="long lines")
        )
        assert "Triaged 2" in result
        assert "No untriaged" in workspace.triage_rule(
            maintainability, _TriageRuleArgs(tool="ruff", rule="E501", verdict="low_value", reason="again")
        )

    def test_query_filters_by_triage_state(self, workspace):
        assert "3 matching" in workspace.query_static_findings()
        assert "1 matching" in workspace.query_static_findings(tool="bandit")
        assert "No static findings" in workspace.query_static_findings(triage="false_positive")


class TestGraphQueries:
    def test_find_symbol_and_call_relations(self, workspace):
        assert "app/service.py:1-2" in workspace.find_symbol("helper")
        relations = workspace.call_relations("helper", direction="callers")
        assert "app/main.py::handler @ line 5" in relations
        assert "does NOT mean unused" in relations

    def test_find_references_sees_value_uses(self, workspace):
        refs = workspace.find_references("handler")
        assert "app/main.py:4" in refs and "app/main.py:8" in refs  # definition + registration as a value

    def test_find_references_rejects_non_identifiers(self, workspace):
        assert "plain identifier" in workspace.find_references("a b")


class TestVerificationAndSynthesis:
    def test_reject_moves_finding_out(self, workspace):
        security = workspace.config.category("security")
        workspace.record_finding(security, _finding())
        refused = workspace.submit_verification("security", _VerifyArgs(finding_id="SEC-1", verdict="rejected", note="guarded"))
        assert refused.startswith("NOT RECORDED") and "SEC-1" in workspace.findings
        workspace.submit_verification(
            "security", _VerifyArgs(finding_id="SEC-1", verdict="rejected", note="guarded by the dependency at app/main.py:3")
        )
        assert "SEC-1" not in workspace.findings
        assert workspace.rejected["SEC-1"].verification.verdict == "rejected"

    def test_adjust_requires_and_applies_severity(self, workspace):
        security = workspace.config.category("security")
        workspace.record_finding(security, _finding())
        assert "requires adjusted_severity" in workspace.submit_verification(
            "security", _VerifyArgs(finding_id="SEC-1", verdict="adjusted", note="n")
        )
        workspace.submit_verification(
            "security", _VerifyArgs(finding_id="SEC-1", verdict="adjusted", note="n", adjusted_severity="Low")
        )
        assert workspace.findings["SEC-1"].severity == "Low"
        assert workspace.findings["SEC-1"].verification.original_severity == "High"
        assert workspace.findings_to_verify("security") == []

    def test_verifier_can_correct_an_overstated_title_and_impact(self, workspace):
        security = workspace.config.category("security")
        workspace.record_finding(security, _finding(title="XXE reads local files", impact="Arbitrary file read."))
        workspace.submit_verification(
            "security",
            _VerifyArgs(
                finding_id="SEC-1", verdict="adjusted", note="stdlib parser", adjusted_severity="Medium",
                corrected_title="Entity expansion on uploaded DOCX", corrected_impact="Memory exhaustion only.",
            ),
        )
        finding = workspace.findings["SEC-1"]
        assert (finding.severity, finding.title, finding.impact) == (
            "Medium", "Entity expansion on uploaded DOCX", "Memory exhaustion only.",
        )

    def test_duplicate_candidates_pair_findings_citing_the_same_line_across_categories(self, workspace):
        workspace.record_finding(workspace.config.category("security"), _finding(title="Default JWT secret"))
        workspace.record_finding(workspace.config.category("secrets"), _finding(title="Hard-coded SECRET_KEY default"))
        workspace.record_finding(
            workspace.config.category("performance"),
            _finding(title="Unrelated", evidence=[EvidenceInput(file="app/service.py", line_start=1)]),
        )
        out = workspace.duplicate_candidates()
        assert "SEC-1" in out and "ENV-1" in out and "same citation app/main.py:4" in out
        assert "PERF-1" not in out

    def test_duplicates_and_summary_ids_resolve_to_primary(self, workspace):
        security = workspace.config.category("security")
        workspace.record_finding(security, _finding())
        workspace.record_finding(security, _finding(title="Same thing"))
        assert "cycle" not in workspace.mark_duplicate(_DuplicateArgs(duplicate_id="SEC-2", primary_id="SEC-1", reason="same"))
        assert "cycle" in workspace.mark_duplicate(_DuplicateArgs(duplicate_id="SEC-1", primary_id="SEC-2", reason="x"))
        workspace.submit_summary(
            _SummaryArgs(
                scope="s", verdict="v",
                priority_order=[{"title": "t", "rationale": "r", "finding_ids": ["SEC-2", "SEC-1", "BOGUS"]}],
            )
        )
        assert workspace.summary.priority_order[0].finding_ids == ("SEC-1", "SEC-1")

    def test_kpi_assessment_requires_evidence_when_open(self, workspace):
        assert "at least one" in workspace.assess_kpi(_KpiArgs(kpi_id="KPI-01", status="open", summary="s"))
        assert "Unknown KPI" in workspace.assess_kpi(_KpiArgs(kpi_id="KPI-99", status="closed", summary="s"))
        workspace.assess_kpi(
            _KpiArgs(kpi_id="KPI-04", status="not_applicable", summary="no spreadsheet exports anywhere")
        )
        assert workspace.kpis["KPI-04"].status == "not_applicable"


class TestToolBinding:
    def test_kpi_tool_only_for_kpi_assessor(self, workspace):
        security = workspace.config.category("security")
        focus = {t.name for t in workspace.specialist_tools(security)}
        kpis = {t.name for t in workspace.specialist_tools(security, kpi_assessor=True)}
        assert "assess_security_kpi" not in focus and "triage_static_rule" in focus
        assert "assess_security_kpi" in kpis and "triage_static_rule" not in kpis

    def test_tool_invocation_round_trip(self, workspace):
        security = workspace.config.category("security")
        record = next(t for t in workspace.specialist_tools(security) if t.name == "record_finding")
        result = record.invoke(
            {
                "title": "t", "severity": "Medium", "confidence": "high", "description": "d", "impact": "i",
                "evidence": [{"file": "app/service.py", "line_start": 1}],
            }
        )
        assert result.startswith("Recorded SEC-1")


class TestMapsIntegration:
    @pytest.fixture
    def mapped(self, workspace, repo):
        from helpers.review_maps import build_review_maps

        (repo / "app" / "main.py").write_text(
            "from fastapi import FastAPI, Header\nfrom app.service import helper\napp = FastAPI()\n"
            "@app.get('/items')\nasync def items(x_user_email: str = Header(..., alias='x-user-email')):\n"
            "    return helper()\n"
        )
        workspace.maps = build_review_maps(repo, workspace.manifest)
        return workspace

    def test_list_endpoints_shows_auth_and_identity(self, mapped):
        out = mapped.list_endpoints(flagged_only=True)
        assert "GET /items -> items (app/main.py:5)" in out
        assert "header:x-user-email" in out and "CLIENT-ASSERTED IDENTITY" in out and "NO AUTH DEPENDENCY" in out

    def test_kpi_with_leads_cannot_be_not_applicable_or_closed_blindly(self, mapped):
        mapped.static_by_id["x"] = _static("semgrep", "src.assets.semgrep.python-exception-text-returned-to-client",
                                           "app/service.py", 1)
        leads = mapped.kpi_leads()
        assert leads["KPI-07"] == ["app/service.py:1 (semgrep python-exception-text-returned-to-client)"]
        na = mapped.assess_kpi(_KpiArgs(kpi_id="KPI-07", status="not_applicable", summary="none"))
        assert na.startswith("NOT RECORDED") and "app/service.py:1" in na
        blind = mapped.assess_kpi(_KpiArgs(kpi_id="KPI-07", status="closed", summary="ok",
                                           evidence=[EvidenceInput(file="app/main.py", line_start=1)]))
        assert blind.startswith("NOT RECORDED")
        checked = mapped.assess_kpi(_KpiArgs(kpi_id="KPI-07", status="closed", summary="generic message",
                                             evidence=[EvidenceInput(file="app/service.py", line_start=1)]))
        assert checked == "Assessed KPI-07 as closed."
        assert "Assessed KPI-09" in mapped.assess_kpi(_KpiArgs(kpi_id="KPI-09", status="not_applicable", summary="n/a"))

    def test_unreachable_evidence_is_flagged_to_recorder_and_verifier(self, mapped, repo):
        (repo / "app" / "legacy.py").write_text("def old():\n    return 1\n")
        mapped.maps.unreachable = ["app/legacy.py"]
        legacy = _finding(evidence=[EvidenceInput(file="app/legacy.py", line_start=1)])
        assert "latent" in mapped.record_finding(mapped.config.category("security"), legacy)
        assert "REACHABILITY: app/legacy.py" in mapped.render_finding(mapped.findings["SEC-1"])
        live = mapped.record_finding(mapped.config.category("security"), _finding())
        assert "latent" not in live
        assert "REACHABILITY" not in mapped.render_finding(mapped.findings["SEC-2"])

    def test_lane_leads_and_unaddressed_groups(self, mapped):
        leads = mapped.lane_leads("security")
        assert leads[0][0].startswith("Routes taking a user identity") and leads[0][1] == frozenset({"app/main.py"})
        assert [label for label, _ in mapped.unaddressed_leads("security")] == [
            leads[0][0], "Baseline with no trace anywhere in the code: HTTP security headers (HSTS, CSP, X-Content-Type-Options, ...)",
        ]
        mapped.record_finding(mapped.config.category("security"), _finding(title="Header identity"))
        mapped.record_finding(mapped.config.category("security"), _finding(title="No security headers (HSTS, CSP)"))
        assert mapped.unaddressed_leads("security") == []
        assert mapped.lane_leads("llm") == []

    def test_absent_baselines_are_leads_addressed_by_mention(self, mapped):
        assert [b.id for b in mapped.maps.absent_baselines if b.lane == "observability"] == [
            "request_ids", "metrics", "structured_logging",
        ]
        labels = [label for label, _ in mapped.unaddressed_leads("observability")]
        assert any("request/correlation IDs" in label for label in labels)
        mapped.record_finding(
            mapped.config.category("observability"),
            _finding(title="No correlation IDs", description="`app/main.py:4` has no request-id middleware."),
        )
        labels = [label for label, _ in mapped.unaddressed_leads("observability")]
        assert not any("request/correlation IDs" in label for label in labels)
        assert any("metrics" in label for label in labels)

    def test_folding_a_duplicate_merges_locations_and_keeps_higher_severity(self, workspace):
        perf = workspace.config.category("performance")
        workspace.record_finding(perf, _finding(title="Sync I/O in async A", severity="Medium"))
        workspace.record_finding(perf, _finding(title="Sync I/O in async B", severity="High",
                                                evidence=[EvidenceInput(file="app/service.py", line_start=1)]))
        assert "same pattern in one category" in workspace.duplicate_candidates()
        workspace.mark_duplicate(_DuplicateArgs(duplicate_id="PERF-2", primary_id="PERF-1", reason="same pattern"))
        merged = workspace.findings["PERF-1"]
        assert merged.severity == "High"
        assert {e.file for e in merged.evidence} == {"app/main.py", "app/service.py"}

    def test_module_imports_accepts_repository_paths(self, mapped):
        assert "app/service.py imported by: app/main.py" in mapped.module_imports("app/service.py", "imported_by")
        assert "app/main.py imports: app/service.py" in mapped.module_imports("app.main", "imports")
