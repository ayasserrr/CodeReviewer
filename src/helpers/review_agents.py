"""Builds and runs the deepagents that perform the Deep Review.

Three agent kinds, all ``deepagents.create_deep_agent`` graphs:

- **specialist** (one per enabled review category, run concurrently) — owns one
  report section; has the read-only repo filesystem, the dependency-graph and
  static-analysis query tools, the category-bound recording tools, planning
  (``write_plan``) and a ``general-purpose`` *code-explorer* subagent it can fan
  work out to via the ``task`` tool (isolated context, parallel).
- **verifier** (one per category that produced findings) — the skeptic pass that
  re-reads the evidence and confirms / adjusts / rejects each finding.
- **synthesizer** (one) — de-duplicates across categories and writes the
  executive layer (scope, verdict, priority order, root causes).

deepagents features used, and why:

- ``CompositeBackend``: the clone is the root ``/`` (a ``FilesystemBackend``
  with ``virtual_mode=True``, which blocks ``..``/absolute escapes), so the
  paths agents read are exactly the repo-relative paths they cite;
  ``/_review/`` routes to ephemeral ``StateBackend`` state holding the
  context pack and — via ``artifacts_root`` — evicted tool results and
  summarized history.
- ``FilesystemPermission`` rules: nothing is writable through the file
  tools; real ``.env`` files, VCS internals and vendored/build directories
  are unreadable (mirrors Discovery's ``IGNORED_DIR_NAMES`` and sensitive-env rule).
- ``FilesystemMiddleware`` restricted to ``ls/read_file/glob/grep`` with
  large-result eviction (big tool outputs are written to the virtual FS and
  replaced by a pointer, keeping the context window lean).
- The built-in summarization middleware (history offloaded to the backend
  and summarized near the context limit), prompt-caching middleware
  (Gemini caches implicitly), ``PatchToolCallsMiddleware`` and the ``task``
  subagent tool.
- On top: a ``write_plan`` planning tool (see ``_plan_tool`` for why not
  LangChain's ``write_todos``), ``ContextEditingMiddleware`` (clears stale
  tool outputs once the context grows, so every turn stays small and fast —
  file contents can always be re-read), ``ModelCallLimitMiddleware`` (hard
  per-agent budget, graceful ``end``), ``_BudgetNudgeMiddleware`` (tells the
  agent when its budget is nearly spent so it records what it has instead of
  being cut off mid-investigation), ``ModelRetryMiddleware`` (backoff on
  transient provider errors / 429s) and ``_EmptyTurnRetryMiddleware``
  (re-asks turns that come back with neither text nor a tool call).
"""

import asyncio
import time
from pathlib import Path
from typing import Any, Literal

from deepagents import FilesystemMiddleware, FilesystemPermission, SubAgent, create_deep_agent
from deepagents.backends import CompositeBackend, FilesystemBackend, StateBackend
from langchain.agents.middleware import (
    AgentMiddleware,
    ClearToolUsesEdit,
    ContextEditingMiddleware,
    ModelCallLimitMiddleware,
    ModelRequest,
    ModelRetryMiddleware,
)
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, LLMResult
from langchain_core.tools import BaseTool, StructuredTool
from pydantic import BaseModel, Field

from config import Settings
from helpers.fs_scanner import IGNORED_DIR_NAMES
from helpers.review_context import AGENT_ROOT
from helpers.review_prompts import EXPLORER_PROMPT
from system import get_logger
from utils import AgentRunStats, DeepReviewError

logger = get_logger(__name__)

Role = Literal["specialist", "explorer", "verifier", "synthesizer"]

_READ_ONLY_FS_TOOLS = ["ls", "read_file", "glob", "grep"]

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


_PROVIDER = "gemini"


def _model_id(settings: Settings, role: Role) -> str:
    if role in ("verifier", "synthesizer") and settings.DEEP_REVIEW_JUDGE_MODEL:
        return settings.DEEP_REVIEW_JUDGE_MODEL
    return settings.GEMINI_MODEL


def model_identity(settings: Settings) -> tuple[str, str]:
    """``(provider, model label)`` the review runs on — part of the cache key."""
    model = _model_id(settings, "specialist")
    judge = _model_id(settings, "verifier")
    return _PROVIDER, model if judge == model else f"{model} + judge {judge}"


def build_chat_model(settings: Settings, role: Role) -> BaseChatModel:
    """Construct the chat model for one agent role.

    Deep-reasoning roles (specialist, verifier, synthesizer) think at full
    depth; the code-explorer subagent does read-heavy fetch-and-summarize
    work, so it thinks less and answers faster. ``DEEP_REVIEW_JUDGE_MODEL``,
    when set, upgrades only the verifier and synthesizer.

    Raises:
        DeepReviewError: If ``GEMINI_API_KEY`` is not configured.
    """
    deep = role != "explorer"
    model_id = _model_id(settings, role)
    if settings.GEMINI_API_KEY is None:
        raise DeepReviewError("GEMINI_API_KEY is not set")
    from langchain_google_genai import ChatGoogleGenerativeAI

    return ChatGoogleGenerativeAI(
        model=model_id,
        google_api_key=settings.GEMINI_API_KEY.get_secret_value(),
        max_output_tokens=settings.DEEP_REVIEW_MAX_OUTPUT_TOKENS,
        # -1 = dynamic thinking (the model decides per turn); the explorer gets
        # a small fixed budget because its job is retrieval, not judgment.
        thinking_budget=-1 if deep else 1024,
        max_retries=6,
        timeout=300,
    )


# ---------------------------------------------------------------------------
# Filesystem
# ---------------------------------------------------------------------------


def build_backend(repo_path: Path) -> CompositeBackend:
    """``/`` -> the clone on disk; ``/_review/`` -> agent state (context pack + offloaded artifacts)."""
    return CompositeBackend(
        default=FilesystemBackend(root_dir=repo_path, virtual_mode=True),
        routes={AGENT_ROOT: StateBackend()},
        artifacts_root=AGENT_ROOT,
    )


def _with_dot_dir_variants(pattern: str) -> list[str]:
    """wcmatch's ``**`` skips dot-directories, so also match under up to two of them."""
    head, _, tail = pattern.partition("/**/")
    return [pattern, f"{head}/**/.*/**/{tail}", f"{head}/**/.*/**/.*/**/{tail}"]


def build_permissions() -> list[FilesystemPermission]:
    """First match wins: nothing writable, no secrets, no vendored/VCS noise."""
    sensitive: list[str] = []
    for pattern in ("/**/.env", "/**/.env.*"):
        sensitive += _with_dot_dir_variants(pattern)
    noise: list[str] = []
    # .grimp_cache: written into the clone by the dependency-graph node's import scan.
    for name in sorted(IGNORED_DIR_NAMES | {".grimp_cache"}):
        noise += _with_dot_dir_variants(f"/**/{name}/**")
    templates = ["/**/.env.example", "/**/.env.sample", "/**/.env.template"]
    return [
        FilesystemPermission(operations=["write"], paths=["/**"], mode="deny"),
        FilesystemPermission(operations=["read"], paths=templates, mode="allow"),
        FilesystemPermission(operations=["read"], paths=sensitive + noise, mode="deny"),
    ]


def _filesystem_middleware(backend: CompositeBackend, settings: Settings) -> FilesystemMiddleware:
    return FilesystemMiddleware(
        backend=backend,
        tools=_READ_ONLY_FS_TOOLS,
        tool_token_limit_before_evict=settings.DEEP_REVIEW_TOOL_RESULT_TOKEN_LIMIT,
        grep_max_count=300,
        _permissions=build_permissions(),
    )


class _EmptyTurnRetryMiddleware(AgentMiddleware):
    """Re-issue model turns that return neither text nor a tool call.

    Gemini intermittently answers with ``finish_reason=MALFORMED_FUNCTION_CALL``
    and an empty message. An agent loop treats an AIMessage without tool calls
    as "done", so without this a specialist can silently end on its first
    turn with nothing reviewed. The request is simply retried (sampling is
    non-deterministic, so the retry almost always produces a valid call).
    """

    def __init__(self, max_retries: int = 3) -> None:
        super().__init__()
        self.max_retries = max_retries

    @staticmethod
    def _is_empty(response: Any) -> bool:
        result = getattr(response, "result", None)
        if result is None:
            result = getattr(getattr(response, "model_response", None), "result", None) or []
        message = next((m for m in reversed(result) if isinstance(m, AIMessage)), None)
        if message is None or message.tool_calls:
            return False
        malformed = message.response_metadata.get("finish_reason") == "MALFORMED_FUNCTION_CALL"
        return malformed or not (message.text or "").strip()

    def wrap_model_call(self, request: ModelRequest, handler):
        response = handler(request)
        for attempt in range(self.max_retries):
            if not self._is_empty(response):
                break
            logger.warning("deep_review_empty_model_turn_retry", attempt=attempt + 1)
            response = handler(request)
        return response

    async def awrap_model_call(self, request: ModelRequest, handler):
        response = await handler(request)
        for attempt in range(self.max_retries):
            if not self._is_empty(response):
                break
            logger.warning("deep_review_empty_model_turn_retry", attempt=attempt + 1)
            response = await handler(request)
        return response


class _BudgetNudgeMiddleware(AgentMiddleware):
    """Warn the agent (transiently, not persisted) when its model-call budget is nearly spent.

    Reads the run counter ``ModelCallLimitMiddleware`` keeps in state. The
    reminder is appended to this request only, so the conversation prefix —
    and with it the provider's prompt cache — is untouched.
    """

    def __init__(self, limit: int, remaining_threshold: int = 6) -> None:
        super().__init__()
        self.limit = limit
        self.remaining_threshold = remaining_threshold

    def _nudge(self, request: ModelRequest) -> ModelRequest:
        used = int(request.state.get("run_model_call_count", 0) or 0)
        remaining = self.limit - used
        if remaining > self.remaining_threshold:
            return request
        reminder = HumanMessage(
            content=(
                f"[Budget notice] You have {max(remaining, 0)} model turns left. Stop exploring now: record every "
                "verified finding / verdict / KPI assessment you still hold (use parallel tool calls), then reply "
                "with your short final summary."
            )
        )
        return request.override(messages=[*request.messages, reminder])

    def wrap_model_call(self, request: ModelRequest, handler):
        return handler(self._nudge(request))

    async def awrap_model_call(self, request: ModelRequest, handler):
        return await handler(self._nudge(request))


# Recording tools' results are tiny and carry ids the agent must remember.
_NEVER_CLEAR_TOOLS = (
    "write_plan",
    "record_finding",
    "update_finding",
    "withdraw_finding",
    "list_my_findings",
    "assess_security_kpi",
    "submit_verification",
    "mark_duplicate",
)


def _harness_middleware(model_calls: int) -> list:
    return [
        ContextEditingMiddleware(
            edits=[
                ClearToolUsesEdit(
                    trigger=60_000,
                    clear_at_least=20_000,  # clear in chunks so the cached prefix stays stable between edits
                    keep=10,
                    exclude_tools=_NEVER_CLEAR_TOOLS,
                    placeholder="[older tool output cleared to save context — re-run the tool if you need it again]",
                )
            ]
        ),
        ModelCallLimitMiddleware(run_limit=model_calls, exit_behavior="end"),
        _BudgetNudgeMiddleware(model_calls),
        ModelRetryMiddleware(max_retries=3, initial_delay=2.0, backoff_factor=2.0, max_delay=60.0),
        _EmptyTurnRetryMiddleware(),
    ]


class _PlanArgs(BaseModel):
    plan: str = Field(
        ...,
        description="Your review plan as a markdown checklist, one step per line: '- [ ] step' / '- [x] done'. "
        "Always send the full updated checklist.",
    )


def _plan_tool() -> BaseTool:
    """A per-agent planning scratchpad.

    Plays the role of ``write_todos`` (plan up front, tick steps off, re-plan)
    with a flat string schema: LangChain's ``write_todos`` (a list of
    ``{content, status}`` objects plus a very long description) makes Gemini
    2.5 emit ``MALFORMED_FUNCTION_CALL`` on most attempts, while this shape
    is reliable on every provider. The plan lives in the conversation, so it
    survives summarization like any other tool call.
    """

    def write_plan(plan: str) -> str:
        lines = [line for line in plan.splitlines() if line.strip().startswith(("- [", "* ["))]
        done = sum(1 for line in lines if line.strip()[3:4].lower() == "x")
        return f"Plan saved: {done}/{len(lines)} steps done. Keep it updated as you progress."

    return StructuredTool.from_function(
        func=write_plan,
        name="write_plan",
        description="Save or update your review plan (markdown checklist). Plan first, then tick steps off as you go.",
        args_schema=_PlanArgs,
    )


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------


def _explorer_subagent(settings: Settings, backend: CompositeBackend, tools: list) -> SubAgent:
    return {
        # Named "general-purpose" so it replaces deepagents' default subagent
        # (which would otherwise inherit write-capable defaults).
        "name": "general-purpose",
        "description": (
            "Read-only code explorer with isolated context. Give it ONE focused, read-heavy "
            "investigation (e.g. 'find every place uploaded files are written to disk and how the "
            "path is built'). It returns a concise answer with path:line citations. Launch several "
            "in parallel for independent sweeps."
        ),
        "system_prompt": EXPLORER_PROMPT,
        "model": build_chat_model(settings, "explorer"),
        "tools": tools,
        "middleware": [
            _filesystem_middleware(backend, settings),
            *_harness_middleware(settings.DEEP_REVIEW_EXPLORER_MODEL_CALLS),
        ],
    }


def build_agent(
    *,
    settings: Settings,
    repo_path: Path,
    role: Literal["specialist", "verifier", "synthesizer"],
    name: str,
    system_prompt: str,
    tools: list,
    explorer_tools: list,
    model_calls: int,
):
    """One configured deep agent (see module docstring for the stack)."""
    backend = build_backend(repo_path)
    middleware = [_filesystem_middleware(backend, settings), *_harness_middleware(model_calls)]
    return create_deep_agent(
        model=build_chat_model(settings, role),
        tools=[_plan_tool(), *tools] if role == "specialist" else tools,
        system_prompt=system_prompt,
        middleware=middleware,
        subagents=[_explorer_subagent(settings, backend, explorer_tools)],
        backend=backend,
        permissions=build_permissions(),
        name=name,
    )


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------


class _UsageCounter(BaseCallbackHandler):
    """Counts model calls and tokens across an agent run, subagents included."""

    def __init__(self) -> None:
        self.calls = 0
        self.input_tokens = 0
        self.output_tokens = 0

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        self.calls += 1
        for generations in response.generations:
            for generation in generations:
                message = getattr(generation, "message", None) if isinstance(generation, ChatGeneration) else None
                usage = getattr(message, "usage_metadata", None) or {}
                self.input_tokens += int(usage.get("input_tokens", 0) or 0)
                self.output_tokens += int(usage.get("output_tokens", 0) or 0)


async def run_agent(
    agent,
    *,
    name: str,
    kickoff: str,
    files: dict[str, dict],
    timeout_seconds: int,
) -> AgentRunStats:
    """Run one agent to completion under a wall-clock cap; never raises.

    Whatever the agent recorded through the workspace tools before a timeout
    or failure is kept — the collector lives outside the agent.
    """
    usage = _UsageCounter()
    start = time.monotonic()
    status: Literal["completed", "timed_out", "failed"] = "completed"
    error: str | None = None
    logger.info("deep_review_agent_started", agent=name)
    try:
        await asyncio.wait_for(
            agent.ainvoke(
                {"messages": [HumanMessage(content=kickoff)], "files": files},
                config={"callbacks": [usage], "recursion_limit": 1000, "run_name": name},
            ),
            timeout=timeout_seconds,
        )
    except TimeoutError:
        status, error = "timed_out", f"exceeded {timeout_seconds}s"
    except Exception as exc:  # noqa: BLE001 -- one agent's failure must never abort the review
        status, error = "failed", f"{type(exc).__name__}: {exc}"[:500]
    duration = time.monotonic() - start
    log = logger.info if status == "completed" else logger.warning
    log(
        "deep_review_agent_finished",
        agent=name,
        status=status,
        error=error,
        duration_seconds=round(duration, 2),
        model_calls=usage.calls,
        input_tokens=usage.input_tokens,
        output_tokens=usage.output_tokens,
    )
    return AgentRunStats(
        agent=name,
        status=status,
        duration_seconds=duration,
        model_calls=usage.calls,
        input_tokens=usage.input_tokens,
        output_tokens=usage.output_tokens,
        error=error,
    )
