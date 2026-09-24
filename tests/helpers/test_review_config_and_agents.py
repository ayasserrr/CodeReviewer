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
    build_backend,
    build_chat_model,
    build_permissions,
    model_identity,
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
        monkeypatch.setattr(settings, "DEEP_REVIEW_PROVIDER", "gemini")
        monkeypatch.setattr(settings, "GEMINI_API_KEY", None)
        with pytest.raises(DeepReviewError, match="GEMINI_API_KEY"):
            build_chat_model(settings, "specialist")

    def test_judge_model_only_changes_judgment_roles(self, monkeypatch):
        monkeypatch.setattr(settings, "DEEP_REVIEW_PROVIDER", "gemini")
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
        new.messages = kwargs["messages"]
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
