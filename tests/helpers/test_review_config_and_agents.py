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
                AIMessage(content="", response_metadata={"finish_reason": "MAX_TOKENS"}),
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
            return _Response(AIMessage(content="", response_metadata={"finish_reason": "MALFORMED_FUNCTION_CALL"}))

        middleware = _EmptyTurnRetryMiddleware(max_retries=3, fallback_model=judge)
        response = middleware.wrap_model_call(_Request(0), handler)
        assert [getattr(c, "model", None) is judge for c in calls] == [False, False, False, True]
        assert response.result[0].tool_calls

    def test_silent_normal_end_is_not_retried(self):
        """A thinking model that is done often ends with thoughts only (STOP, no text): not a failure."""
        calls = []

        def handler(request):
            calls.append(request)
            return _Response(AIMessage(content="", response_metadata={"finish_reason": "STOP"}))

        _EmptyTurnRetryMiddleware().wrap_model_call(_Request(0), handler)
        assert len(calls) == 1

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
        # Resumed once; re-checked after the resume, and an unchanged answer ends the loop.
        assert len(agent.inputs) == 2 and len(checks) == 2
        assert agent.inputs[1]["messages"][-1].content.startswith("You recorded nothing — continue.")
        assert "model turns for this" in agent.inputs[1]["messages"][-1].content  # time/budget left is stated

    async def test_silent_end_with_work_done_completes_without_resume(self):
        from helpers.review_agents import run_agent

        agent = _FakeAgent([AIMessage(content="", response_metadata={"finish_reason": "STOP"})])
        stats = await run_agent(
            agent, name="verifier:x", kickoff="go", files={}, timeout_seconds=30, completion_check=lambda: None
        )
        assert stats.status == "completed" and len(agent.inputs) == 1

    async def test_silent_end_with_work_missing_is_resumed_with_the_check(self):
        from helpers.review_agents import run_agent

        agent = _FakeAgent([AIMessage(content=""), AIMessage(content="Verified.")])
        pending = ["BUG-1"]
        stats = await run_agent(
            agent, name="verifier:x", kickoff="go", files={}, timeout_seconds=30,
            completion_check=lambda: f"No verdict yet: {pending[0]}" if pending else None,
        )
        assert stats.status == "completed" and len(agent.inputs) == 2
        assert "No verdict yet: BUG-1" in agent.inputs[1]["messages"][-1].content

    async def test_completion_check_resends_while_progress_is_made_and_stops_when_stuck(self):
        from helpers.review_agents import run_agent

        agent = _FakeAgent([AIMessage(content="", response_metadata={"finish_reason": "STOP"})] * 6)
        pending = ["SEC-1", "SEC-2", "SEC-3"]

        def check():
            return f"No verdict yet: {', '.join(pending)}" if pending else None

        def ainvoke_side_effect():
            if len(agent.inputs) in (2, 3):
                pending.pop()  # the agent verifies one finding on each of the first two resumes

        original = agent.ainvoke

        async def tracking(state, config=None):
            result = await original(state, config=config)
            ainvoke_side_effect()
            return result

        agent.ainvoke = tracking
        stats = await run_agent(agent, name="verifier:x", kickoff="go", files={}, timeout_seconds=30,
                                completion_check=check)
        assert stats.status == "completed"
        # 1 initial + resumes while the pending list shrinks; the round that changes nothing ends it.
        assert len(agent.inputs) == 4

    async def test_satisfied_completion_check_does_not_resume(self):
        from helpers.review_agents import run_agent

        agent = _FakeAgent([AIMessage(content="Done.")])
        stats = await run_agent(
            agent, name="specialist:x", kickoff="go", files={}, timeout_seconds=30, completion_check=lambda: None
        )
        assert stats.status == "completed" and len(agent.inputs) == 1


class TestToolResultCap:
    def _call(self, content: str):
        from langchain_core.messages import ToolMessage

        from helpers.review_agents import _ToolResultCapMiddleware

        return _ToolResultCapMiddleware().wrap_tool_call(None, lambda _: ToolMessage(content=content, tool_call_id="1"))

    def test_small_text_passes_through(self):
        assert self._call("def f():\n    return 1\n").content == "def f():\n    return 1\n"

    def test_oversized_text_is_truncated_with_paging_hint(self):
        out = self._call("x" * 200_000).content
        assert len(out) < 50_000 and "output truncated: 200,000 characters" in out

    def test_binary_garbage_is_replaced(self):
        out = self._call("\x89PNG\r\n\x1a\n" + "\x00�\x01" * 5000).content
        assert out.startswith("[binary or non-text content omitted")


def test_strong_lane_specialist_runs_on_the_judge_model(monkeypatch, tmp_path):
    from config import settings as cfg
    from helpers import review_agents
    from helpers.review_config_loader import load_review_config

    assert load_review_config(cfg.DEEP_REVIEW_CONFIG_PATH).category("correctness").strong_model
    roles = []
    monkeypatch.setattr(review_agents, "build_chat_model", lambda settings, role: roles.append(role) or object())
    monkeypatch.setattr(review_agents, "create_deep_agent", lambda **kwargs: kwargs)
    for strong in (False, True):
        review_agents.build_agent(
            settings=cfg, repo_path=tmp_path, role="specialist", name="s", system_prompt="p",
            tools=[], explorer_tools=[], model_calls=5, strong=strong,
        )
    assert "specialist" in roles and "verifier" in roles


def test_run_budget_is_shared_across_resumes_and_warns_on_time():
    import time as _time

    from langchain_core.messages import HumanMessage

    from helpers.review_agents import _RUN_BUDGET, _BudgetNudgeMiddleware, _RunBudget

    budget = _RunBudget(limit=3, deadline=_time.monotonic() + 1000, timeout=1000)
    token = _RUN_BUDGET.set(budget)
    try:
        mw = _BudgetNudgeMiddleware(limit=3)
        assert [mw.before_model({}, None) for _ in range(3)] == [None, None, None]
        # A resumed invocation shares the same counter: the 4th call ends the run.
        assert mw.before_model({}, None)["jump_to"] == "end"
        # The code-explorer never consumes (or is ended by) its parent's budget.
        assert _BudgetNudgeMiddleware(limit=20, shared=False).before_model({}, None) is None

        class _Req:
            def __init__(self):
                self.messages = [HumanMessage(content="hi")]
                self.state = {}

            def override(self, messages):
                self.messages = messages
                return self
        budget.limit, budget.used = 100, 0
        assert len(mw._nudge(_Req()).messages) == 1  # plenty of calls and time: no notice
        budget.deadline = _time.monotonic() + 60  # 6% of the timeout left
        assert "minute" in mw._nudge(_Req()).messages[-1].content
    finally:
        _RUN_BUDGET.reset(token)


def test_gemini_tools_are_bound_in_validated_mode(monkeypatch):
    from langchain_core.tools import tool
    from pydantic import SecretStr

    from config import settings as real
    from helpers.review_agents import build_chat_model

    @tool
    def ping(x: str) -> str:
        """Echo."""
        return x

    monkeypatch.setattr(real, "GEMINI_API_KEY", SecretStr("test-key"))
    bound = build_chat_model(real, "specialist").bind_tools([ping])
    assert bound.kwargs["tool_config"]["function_calling_config"]["mode"] == "VALIDATED"

    monkeypatch.setattr(real, "DEEP_REVIEW_FUNCTION_CALLING_MODE", "AUTO")
    assert not build_chat_model(real, "specialist").bind_tools([ping]).kwargs.get("tool_config")
