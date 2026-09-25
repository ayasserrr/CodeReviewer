"""Tests for the review config loader, the agents' filesystem sandbox and the
review middleware — everything in the Deep Review harness that doesn't need a model."""

from pathlib import Path

import pytest
from deepagents.middleware.filesystem import _check_fs_permission
from langchain_core.messages import AIMessage, HumanMessage

from config import settings
from helpers.review_agents import (
    _BudgetNudgeMiddleware,
    _EmptyTurnRetryMiddleware,
    _plan_tool,
    _UsageCounter,
    build_backend,
    build_chat_model,
    build_permissions,
    model_identity,
    run_agent,
)
from helpers.review_config_loader import load_review_config, parse_review_config
from utils import DeepReviewError, InvalidInputError


class TestReviewConfig:
    def test_bundled_config_is_valid(self):
        config = load_review_config(settings.DEEP_REVIEW_CONFIG_PATH)
        assert len(config.security_kpis) == 12
        assert [k.id for k in config.security_kpis][:2] == ["KPI-01", "KPI-02"]
        assert sum(c.owns_security_kpis for c in config.categories) == 1
        assert set(config.static_tool_owners) >= {"ruff", "pyright", "bandit", "semgrep", "gitleaks", "pip_audit"}
        assert len(config.config_hash) == 64

    def test_hash_changes_with_content(self):
        base = b'[[categories]]\nid = "a"\ntitle = "A"\ncode = "AA"\nfocus = "x"\n'
        assert parse_review_config(base).config_hash != parse_review_config(base + b"\n").config_hash

    @pytest.mark.parametrize(
        "raw, message",
        [
            (b"not = [valid", "invalid TOML"),
            (b'[[categories]]\nid = "a"\ntitle = "A"\ncode = "AA"\nfocus = "x"\n' * 2, "duplicate category ids"),
            (
                b'[static_analysis.owners]\nruff = "nope"\n[[categories]]\nid = "a"\ntitle = "A"\ncode = "AA"\nfocus = "x"\n',
                "unknown categories",
            ),
        ],
    )
    def test_invalid_configs_raise(self, raw, message):
        with pytest.raises(InvalidInputError, match=message):
            parse_review_config(raw)


class TestSandbox:
    @pytest.mark.parametrize(
        "path, expected",
        [
            ("/app/main.py", "allow"),
            ("/.env.example", "allow"),
            ("/_review/context/repo_brief.md", "allow"),
            ("/.env", "deny"),
            ("/deploy/.env.production", "deny"),
            ("/.github/workflows/.env", "deny"),
            ("/.git/config", "deny"),
            ("/web/node_modules/pkg/index.js", "deny"),
            ("/.venv/lib/site.py", "deny"),
        ],
    )
    def test_read_permissions(self, path, expected):
        assert _check_fs_permission(build_permissions(), "read", path) == expected

    def test_nothing_is_writable(self):
        rules = build_permissions()
        assert _check_fs_permission(rules, "write", "/app/main.py") == "deny"
        assert _check_fs_permission(rules, "write", "/_review/context/repo_brief.md") == "deny"

    def test_repo_is_the_filesystem_root(self, tmp_path: Path):
        (tmp_path / "app").mkdir()
        (tmp_path / "app" / "main.py").write_text("print(1)\n")
        result = build_backend(tmp_path).read("/app/main.py")
        assert result.error is None and "print(1)" in result.file_data["content"]


class TestModels:
    def test_missing_key_raises(self, monkeypatch):
        monkeypatch.setattr(settings, "GEMINI_API_KEY", None)
        with pytest.raises(DeepReviewError, match="GEMINI_API_KEY"):
            build_chat_model(settings, "specialist")

    def test_judge_model_only_changes_judgment_roles(self, monkeypatch):
        monkeypatch.setattr(settings, "GEMINI_MODEL", "gemini-2.5-flash")
        monkeypatch.setattr(settings, "DEEP_REVIEW_JUDGE_MODEL", None)
        assert model_identity(settings) == ("gemini", "gemini-2.5-flash")
        monkeypatch.setattr(settings, "DEEP_REVIEW_JUDGE_MODEL", "gemini-pro-x")
        assert model_identity(settings) == ("gemini", "gemini-2.5-flash + judge gemini-pro-x")


class _Response:
    def __init__(self, message: AIMessage) -> None:
        self.result = [message]


class _Request:
    def __init__(self, calls_used: int) -> None:
        self.state = {"run_model_call_count": calls_used}
        self.messages = [HumanMessage("go")]

    def override(self, **kwargs):
        new = _Request(self.state["run_model_call_count"])
        new.messages = kwargs.get("messages", self.messages)
        new.model = kwargs.get("model", getattr(self, "model", None))
        return new


class TestMiddleware:
    def test_empty_turn_is_retried_until_valid(self):
        replies = iter(
            [
                AIMessage(content="", response_metadata={"finish_reason": "MALFORMED_FUNCTION_CALL"}),
                AIMessage(content=""),
                AIMessage(content="", tool_calls=[{"name": "ls", "args": {}, "id": "1"}]),
            ]
        )
        calls = []

        def handler(request):
            calls.append(request)
            return _Response(next(replies))

        response = _EmptyTurnRetryMiddleware(max_retries=3).wrap_model_call(_Request(0), handler)
        assert len(calls) == 3
        assert response.result[0].tool_calls

    def test_last_retry_falls_back_to_the_judge_model(self):
        judge = object()
        calls = []

        def handler(request):
            calls.append(request)
            if getattr(request, "model", None) is judge:
                return _Response(AIMessage(content="", tool_calls=[{"name": "ls", "args": {}, "id": "1"}]))
            return _Response(AIMessage(content=""))

        middleware = _EmptyTurnRetryMiddleware(max_retries=3, fallback_model=judge)
        response = middleware.wrap_model_call(_Request(0), handler)
        assert [getattr(c, "model", None) is judge for c in calls] == [False, False, False, True]
        assert response.result[0].tool_calls

    def test_text_answer_is_not_retried(self):
        calls = []

        def handler(request):
            calls.append(request)
            return _Response(AIMessage(content="final summary"))

        _EmptyTurnRetryMiddleware().wrap_model_call(_Request(0), handler)
        assert len(calls) == 1

    def test_budget_nudge_only_near_the_limit(self):
        seen = []
        nudge = _BudgetNudgeMiddleware(limit=20, remaining_threshold=6)
        nudge.wrap_model_call(_Request(5), lambda r: seen.append(r.messages) or _Response(AIMessage("x")))
        nudge.wrap_model_call(_Request(16), lambda r: seen.append(r.messages) or _Response(AIMessage("x")))
        assert len(seen[0]) == 1
        assert "4 model turns left" in seen[1][-1].content

    def test_plan_tool_counts_progress(self):
        assert "1/3 steps done" in _plan_tool().invoke({"plan": "- [x] a\n- [ ] b\n- [ ] c"})


class TestUsageCounterSubagentDelegation:
    """The `task` tool is deepagents' fixed name for dispatching to a subagent
    (see deepagents.middleware.subagents) -- every call is one delegation to
    this agent's code-explorer."""

    def test_counts_only_task_tool_calls(self):
        counter = _UsageCounter()
        counter.on_tool_start({"name": "task"}, "investigate uploads")
        counter.on_tool_start({"name": "read_file"}, "app/main.py")
        counter.on_tool_start({"name": "grep"}, "TODO")
        counter.on_tool_start({"name": "task"}, "investigate auth")

        assert counter.subagent_calls == 2

    def test_zero_when_never_delegated(self):
        counter = _UsageCounter()
        counter.on_tool_start({"name": "read_file"}, "app/main.py")
        assert counter.subagent_calls == 0


class TestRunAgentSubagentStats:
    async def test_subagent_call_count_surfaces_in_stats_and_is_not_lost_on_timeout(self):
        class _DelegatingAgent:
            async def ainvoke(self, state, config):
                for callback in config["callbacks"]:
                    callback.on_tool_start({"name": "task"}, "sweep 1")
                    callback.on_tool_start({"name": "task"}, "sweep 2")
                return {}

        stats = await run_agent(_DelegatingAgent(), name="specialist:test", kickoff="go", files={}, timeout_seconds=5)

        assert stats.status == "completed"
        assert stats.subagent_calls == 2

    async def test_zero_subagent_calls_when_agent_never_delegates(self):
        class _NonDelegatingAgent:
            async def ainvoke(self, state, config):
                return {}

        stats = await run_agent(
            _NonDelegatingAgent(), name="specialist:test", kickoff="go", files={}, timeout_seconds=5
        )

        assert stats.subagent_calls == 0


class _FakeAgent:
    """Returns scripted final message lists, one per ``ainvoke``, recording what it was given."""

    def __init__(self, finals: list[AIMessage]) -> None:
        self.finals = finals
        self.inputs: list[dict] = []

    async def ainvoke(self, state, config=None):
        self.inputs.append(state)
        return {"messages": [*state["messages"], self.finals[len(self.inputs) - 1]], "files": state["files"]}


class TestRunAgentResume:
    async def test_empty_final_turn_is_resumed_with_history(self):
        from helpers.review_agents import run_agent

        agent = _FakeAgent([AIMessage(content=""), AIMessage(content="Done.")])
        stats = await run_agent(agent, name="specialist:x", kickoff="go", files={}, timeout_seconds=30)

        assert stats.status == "completed"
        assert len(agent.inputs) == 2
        resumed = agent.inputs[1]["messages"]
        assert resumed[0].content == "go" and "previous reply was empty" in resumed[-1].content

    async def test_still_empty_after_resumes_is_incomplete_not_completed(self):
        from helpers.review_agents import run_agent

        agent = _FakeAgent([AIMessage(content="")] * 3)
        stats = await run_agent(agent, name="specialist:x", kickoff="go", files={}, timeout_seconds=30)

        assert stats.status == "incomplete"
        assert "empty model turn" in stats.error
        assert len(agent.inputs) == 3

    def test_thinking_is_capped_below_the_output_budget(self, monkeypatch):
        from pydantic import SecretStr

        monkeypatch.setattr(settings, "GEMINI_API_KEY", SecretStr("test-key"))
        model = build_chat_model(settings, "specialist")
        assert 0 < model.thinking_budget < settings.DEEP_REVIEW_MAX_OUTPUT_TOKENS

    async def test_completion_check_resumes_once_with_its_message(self):
        from helpers.review_agents import run_agent

        agent = _FakeAgent([AIMessage(content="All done."), AIMessage(content="Recorded 3 findings.")])
        checks = []

        def nothing_recorded():
            checks.append(1)
            return "You recorded nothing — continue."

        stats = await run_agent(
            agent, name="specialist:x", kickoff="go", files={}, timeout_seconds=30, completion_check=nothing_recorded
        )
        assert stats.status == "completed"
        assert len(agent.inputs) == 2 and len(checks) == 1
        assert agent.inputs[1]["messages"][-1].content == "You recorded nothing — continue."

    async def test_satisfied_completion_check_does_not_resume(self):
        from helpers.review_agents import run_agent

        agent = _FakeAgent([AIMessage(content="Done.")])
        stats = await run_agent(
            agent, name="specialist:x", kickoff="go", files={}, timeout_seconds=30, completion_check=lambda: None
        )
        assert stats.status == "completed" and len(agent.inputs) == 1
