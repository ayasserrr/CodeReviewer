"""End-to-end test of DeepReviewController with a scripted fake chat model.

The real deepagents graphs, middleware stack, filesystem sandbox and
workspace tools all run; only the LLM is replaced by a deterministic script
that picks its next move from the agent's system prompt (which role it is)
and how many turns it has taken. That exercises the whole orchestration —
parallel specialists, the KPI assessor, pipelined verification, synthesis,
assembly and markdown rendering — without network access or an API key.
"""

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch
from uuid import uuid4

import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, SystemMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from config import settings
from controllers.deep_review_controller import DeepReviewController
from utils import DependencyGraph, DiscoveryStatistics, FileEntry, RepositoryManifest, StaticFinding


class ScriptedChatModel(BaseChatModel):
    """Answers each turn via ``script(system_prompt, turn_index)``."""

    script: Callable[[str, int], AIMessage]

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **kwargs: Any) -> "ScriptedChatModel":
        return self

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs) -> ChatResult:
        system = next((m.text for m in messages if isinstance(m, SystemMessage)), "")
        turn = sum(1 for m in messages if isinstance(m, AIMessage))
        message = self.script(system, turn)
        message.usage_metadata = {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}
        return ChatResult(generations=[ChatGeneration(message=message)])


def _call(name: str, **args: Any) -> dict:
    return {"name": name, "args": args, "id": f"call_{uuid4().hex[:8]}", "type": "tool_call"}


def _script(system: str, turn: int) -> AIMessage:
    done = AIMessage(content="Done.")
    if "mandatory security KPI checklist (SEC)" in system:
        if turn == 0:
            return AIMessage(
                content="",
                tool_calls=[
                    _call(
                        "assess_security_kpi", kpi_id="KPI-02", status="open",
                        summary="Docs always on.", evidence=[{"file": "app/main.py", "line_start": 1}],
                    )
                ],
            )
        return done
    if "# Your assignment: Security & Authorization (SEC)" in system:
        if turn == 0:
            return AIMessage(
                content="",
                tool_calls=[
                    _call("write_plan", plan="- [ ] check handler"),
                    _call(
                        "record_finding", title="Handler returns secrets", severity="High", confidence="high",
                        description="`app/main.py:4` returns the secret.", impact="Anyone can read it.",
                        evidence=[{"file": "app/main.py", "line_start": 4, "line_end": 5}],
                    ),
                    _call(
                        "record_finding", title="Speculative issue", severity="Medium", confidence="high",
                        description="Not real.", impact="None.", evidence=[{"file": "app/main.py", "line_start": 1}],
                    ),
                ],
            )
        return done
    if "Dead Code, Duplication & Architecture (MNT)" in system:
        if turn == 0:
            return AIMessage(
                content="",
                tool_calls=[_call("triage_static_rule", tool="ruff", rule="E501", verdict="false_positive", reason="URLs")],
            )
        return done
    if "independent verification (Security & Authorization)" in system:
        if turn == 0:
            return AIMessage(
                content="",
                tool_calls=[
                    _call("submit_verification", finding_id="SEC-1", verdict="confirmed", note="Read app/main.py:4."),
                    _call("submit_verification", finding_id="SEC-2", verdict="rejected", note="Guarded upstream."),
                ],
            )
        return done
    if "lead reviewer" in system:
        if turn == 0:
            return AIMessage(
                content="",
                tool_calls=[
                    _call(
                        "submit_executive_summary", scope="A tiny FastAPI app.", verdict="Not production-ready.",
                        priority_order=[{"title": "Secrets", "rationale": "Leaks.", "finding_ids": ["SEC-1"]}],
                        cross_cutting=[{"title": "No auth", "explanation": "Root cause.", "finding_ids": ["SEC-1"]}],
                        verification_note="SEC-1 confirmed in code.",
                    )
                ],
            )
        return done
    return AIMessage(content="Nothing to report in this category.")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("from fastapi import FastAPI\n\napp = FastAPI()\ndef h():\n    return SECRET\n")
    return tmp_path


def _inputs(repo: Path):
    manifest = RepositoryManifest(
        schema_version="1", discovery_engine_version="1", repository_id=str(uuid4()), head_sha="a" * 40,
        cache_key="k", generated_at=datetime.now(UTC), statistics=DiscoveryStatistics(source_roots=(".",)),
        files=(FileEntry(path="app/main.py", language="Python", size_bytes=10, lines=5),),
    )
    graph = DependencyGraph(
        schema_version="1", engine_version="1", repository_id=manifest.repository_id, head_sha="a" * 40,
        cache_key="k", generated_at=datetime.now(UTC),
    )
    static = [
        StaticFinding.from_normalized(
            "ruff", {"file": "app/main.py", "line": 1, "severity": "warning", "category": "E501", "message": "long"}
        )
    ]
    return manifest, graph, static


@pytest.fixture
def scripted_models():
    def factory(_settings, _role):
        return ScriptedChatModel(script=_script)

    with (
        patch("helpers.review_agents.build_chat_model", side_effect=factory),
        patch("controllers.deep_review_controller.build_chat_model", side_effect=factory),
    ):
        yield


async def test_full_review_with_scripted_agents(repo: Path, scripted_models, monkeypatch):
    monkeypatch.setattr(settings, "DEEP_REVIEW_MAX_CONCURRENCY", 4)
    manifest, graph, static = _inputs(repo)

    report, markdown = await DeepReviewController().review(
        repository_id=manifest.repository_id, repository_name="demo", repo_path=repo, head_sha="a" * 40,
        cache_key="ck", manifest=manifest, static_findings=static, tool_results={"ruff": {"status": "success"}},
        graph=graph,
    )

    # Findings: SEC-1 confirmed and kept, SEC-2 rejected by the verifier.
    assert [f.id for f in report.findings] == ["SEC-1"]
    assert report.findings[0].verification.verdict == "confirmed"
    assert [f.id for f in report.rejected_findings] == ["SEC-2"]

    # KPI checklist: the assessed KPI keeps its status, every other KPI is explicitly not_verified.
    kpis = {k.kpi_id: k.status for k in report.kpi_assessments}
    assert kpis["KPI-02"] == "open"
    assert len(kpis) == 12 and list(kpis.values()).count("not_verified") == 11

    # Static triage done by the owning category, counted in the per-tool summary.
    ruff = next(s for s in report.static_summary if s.tool == "ruff")
    assert (ruff.total, ruff.false_positive, ruff.untriaged) == (1, 1, 0)

    # Every category ran (plus the KPI assessor), verification only where findings existed.
    agents = {r.agent: r.status for r in report.agent_runs}
    assert agents["specialist:security-kpis"] == "completed"
    assert agents["verifier:security"] == "completed" and "verifier:auth" not in agents
    assert agents["synthesizer"] == "completed"
    assert all(status == "completed" for status in agents.values())

    # Rendered report structure.
    assert markdown.startswith("# demo — Full Engineering Review")
    assert "## 0. Priority order" in markdown and "1. **Secrets** - Leaks. (section 2.1)." in markdown
    assert "## 0.1 Security issues that must be explicitly avoided before production" in markdown
    assert "### [High] 2.1 Handler returns secrets" in markdown
    assert "*Evidence:* `app/main.py:4-5`" in markdown
    assert "| ruff | success | 1 | 0 | 1 | 0 | 0 |" in markdown
    assert "Cross-cutting summary" in markdown
    assert report.statistics.findings_rejected_by_verifier == 1


async def test_failed_agent_degrades_to_coverage_warning(repo: Path, monkeypatch):
    monkeypatch.setattr(settings, "DEEP_REVIEW_MAX_CONCURRENCY", 4)
    manifest, graph, static = _inputs(repo)

    def exploding_script(system: str, turn: int) -> AIMessage:
        if "Security & Authorization (SEC)" in system and "KPI" not in system.split("# Your assignment")[-1]:
            raise RuntimeError("provider exploded")
        return AIMessage(content="Nothing.")

    def factory(_settings, _role):
        return ScriptedChatModel(script=exploding_script)

    with (
        patch("helpers.review_agents.build_chat_model", side_effect=factory),
        patch("controllers.deep_review_controller.build_chat_model", side_effect=factory),
        patch("helpers.review_agents.ModelRetryMiddleware") as no_retry,
    ):
        from langchain.agents.middleware import AgentMiddleware

        no_retry.side_effect = lambda **_: type("NoRetry", (AgentMiddleware,), {})()
        report, markdown = await DeepReviewController().review(
            repository_id=manifest.repository_id, repository_name="demo", repo_path=repo, head_sha="a" * 40,
            cache_key="ck", manifest=manifest, static_findings=static, tool_results={}, graph=graph,
        )

    runs = {r.agent: r for r in report.agent_runs}
    assert runs["specialist:security"].status == "failed"
    assert "provider exploded" in runs["specialist:security"].error
    assert runs["synthesizer"].status == "skipped"  # no findings at all
    assert "Coverage warning" in markdown and "specialist:security" in markdown
