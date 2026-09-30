"""Core Deep Review orchestration — a multi-agent code review built on deepagents.

Runs after the dependency graph and consumes everything earlier phases
produced (the clone, Discovery's manifest, the static-analysis findings and
the dependency graph). The flow, optimized for wall-clock time and accuracy:

1. **Context pack (deterministic, no LLM).** Index the manifest, static
   findings and graph into a ``ReviewWorkspace``; build the shared repository
   brief and the ``/_review/context/`` files.
2. **Specialists, in parallel.** One deep agent per enabled category in
   ``review_config.toml`` (bounded by ``DEEP_REVIEW_MAX_CONCURRENCY``), plus
   a dedicated security-KPI assessor. Each reads the code, triages the
   static-analysis findings its category owns (removing false positives), and
   records findings the tools can't see.
3. **Verification, pipelined.** As soon as a category's specialist finishes,
   an independent verifier agent re-checks that category's high-severity
   findings — it does not wait for the other specialists, so verification
   overlaps with the slower categories instead of adding a whole phase.
4. **Synthesis.** One agent de-duplicates across categories and writes the
   executive layer (scope, verdict, priority order, root causes).
5. **Assembly + rendering (deterministic).** Findings below the confidence
   floor are dropped, duplicates folded, unassessed KPIs marked not verified,
   and the markdown report rendered from the structured data.

No single agent failure fails the review: a failed/timed-out specialist
leaves a coverage warning on its section and everything it had already
recorded is kept. Only configuration errors (missing API key, invalid
config) raise ``DeepReviewError``.
"""

import asyncio
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from deepagents.backends.utils import create_file_data

from controllers import BaseController
from helpers import (
    PipelineProgress,
    ReviewWorkspace,
    build_agent,
    build_chat_model,
    build_context_files,
    build_inventory,
    build_repo_brief,
    build_review_maps,
    kpi_prompt,
    load_review_config,
    model_identity,
    render_report,
    run_agent,
    specialist_prompt,
    synthesizer_prompt,
    verifier_prompt,
)
from helpers.review_agents import current_lane_reads
from helpers.review_context import CONTEXT_MOUNT
from system import get_logger
from utils import (
    AgentRunStats,
    DeepReviewError,
    DeepReviewReport,
    DependencyGraph,
    ExecutiveSummary,
    InvalidInputError,
    KpiAssessment,
    MergedFinding,
    RepositoryManifest,
    ReviewCategory,
    ReviewConfig,
    ReviewCoverage,
    ReviewStatistics,
    StaticFinding,
    StaticToolSummary,
)
from utils.review import CONFIDENCE_ORDER

logger = get_logger(__name__)


_NON_SOURCE = frozenset({"Markdown", "JSON", "YAML", "TOML"})
"""Languages that are data/docs rather than code (mirrors static analysis' code-file filter)."""


def _coverage(workspace: ReviewWorkspace, runs: list[AgentRunStats]) -> ReviewCoverage:
    """Account for every file: discovered -> static tools -> dependency graph -> opened by an agent."""
    manifest, graph = workspace.manifest, workspace.graph
    source = [f.path for f in manifest.files if f.language is not None and f.language not in _NON_SOURCE]
    python = [f for f in manifest.files if f.language == "Python"]
    not_in_graph = sorted(
        f"{f.path} ({reason})"
        for f in python
        for reason in [
            "syntax error" if f.parse_error else "over the size limit" if f.skipped_due_to_size
            else "parse timeout" if f.ast_timeout else None
        ]
        if reason
    ) + sorted(f"{failure.file} (graph extraction failed)" for failure in graph.failed_files)
    opened = set().union(*(set(r.files_read) for r in runs)) if runs else set()
    unopened: Counter[str] = Counter()
    per_dir: Counter[str] = Counter()
    for path in source:
        parts = path.split("/")
        directory = "/".join(parts[:2]) if len(parts) > 2 else (parts[0] if len(parts) == 2 else ".")
        per_dir[directory] += 1
        if path not in opened:
            unopened[directory] += 1
    statuses = {tool: str(result.get("status")) for tool, result in workspace.tool_results.items()}
    stats = manifest.statistics
    return ReviewCoverage(
        files_discovered=len(manifest.files),
        source_files=len(source),
        python_files=len(python),
        python_files_in_graph=graph.statistics.files_parsed,
        python_not_in_graph=tuple(not_in_graph[:50]),
        static_tools_run=tuple(sorted(t for t, st in statuses.items() if st == "success")),
        static_tools_failed=tuple(sorted(f"{t} ({st})" for t, st in statuses.items() if st != "success")),
        static_python_files=len(python),
        static_code_files=len(source),
        source_files_opened_by_agents=len(opened & set(source)),
        unopened_source_dirs=tuple(
            f"{d}/ — {n} of {per_dir[d]} source files not opened" for d, n in unopened.most_common(12)
        ),
        traversal_timed_out=stats.traversal_timed_out,
        discovery_timed_out=stats.discovery_timed_out,
        unreadable_directories=tuple(manifest.unreadable_directories),
        system_docs=tuple(path for path, _ in workspace.system_docs),
        lane_scopes=tuple(_scope_rows(workspace, runs)),
    )


def _scope_rows(workspace: ReviewWorkspace, runs: list[AgentRunStats]) -> list[str]:
    """Per lane: how many files of its scope the lane itself (with its explorers) opened."""
    rows = []
    for lane, scope in workspace.lane_scopes().items():
        if not scope:
            continue
        opened: set[str] = set()
        for run in runs:
            if run.agent == f"specialist:{lane}" or run.agent.startswith(f"specialist:{lane}-"):
                opened |= set(run.files_read)
        done = len(set(scope) & opened)
        rows.append(f"{lane}: {done} of {len(scope)} scope files opened")
    return rows


_VERIFY_BATCH = 8
"""Findings per verifier run."""


def _unverified_nudge(workspace: ReviewWorkspace, category_id: str, ids: set[str] | None = None) -> str | None:
    """Completion check for a verifier: every finding it was given needs a verdict."""
    pending = [f for f in workspace.findings_to_verify(category_id) if ids is None or f.id in ids]
    if not pending:
        return None
    return (
        "These findings still have no verdict: " + ", ".join(f.id for f in pending)
        + ". Call submit_verification once for each (confirmed / adjusted / rejected)."
    )


def _format_lead_group(label: str, rows: list[str], limit: int = 15) -> str:
    more = f"\n  - ... {len(rows) - limit} more" if len(rows) > limit else ""
    return f"- {label}:\n" + "\n".join(f"  - {row}" for row in rows[:limit]) + more


class DeepReviewController(BaseController):
    """Runs one end-to-end deep review. Pure orchestration — no database access."""

    def load_config(self) -> ReviewConfig:
        """Load the review config, surfacing problems as ``DeepReviewError``."""
        try:
            return load_review_config(self.config.DEEP_REVIEW_CONFIG_PATH)
        except (OSError, InvalidInputError) as exc:
            raise DeepReviewError(f"Cannot load review config: {exc}") from exc

    async def review(
        self,
        *,
        repository_id: str,
        repository_name: str,
        repo_path: Path,
        head_sha: str,
        cache_key: str,
        manifest: RepositoryManifest,
        static_findings: list[StaticFinding],
        tool_results: dict[str, dict[str, Any]],
        graph: DependencyGraph,
        review_config: ReviewConfig | None = None,
        progress: PipelineProgress | None = None,
    ) -> tuple[DeepReviewReport, str]:
        """Run the review and return ``(report, markdown)``.

        ``progress``, when given, receives an event as each agent starts and
        finishes, so a client polling the review row sees live agent status.

        Raises:
            DeepReviewError: On configuration problems only.
        """
        start = time.monotonic()
        self._progress = progress
        config = review_config or self.load_config()
        provider, model = model_identity(self.config)
        build_chat_model(self.config, "specialist")  # fail fast on a missing API key

        maps = await asyncio.to_thread(
            build_review_maps, repo_path, manifest, inspect_env_files=self.config.DEEP_REVIEW_INSPECT_ENV_FILES
        )
        workspace = ReviewWorkspace(
            repo_path=repo_path,
            manifest=manifest,
            static_findings=static_findings,
            tool_results=tool_results,
            graph=graph,
            config=config,
            maps=maps,
        )
        formatting = workspace.auto_triage_formatting()
        brief = build_repo_brief(workspace, repository_name)
        files = build_context_files(workspace, brief)
        files[f"{CONTEXT_MOUNT}scopes.md"] = create_file_data(workspace.render_scopes())
        files[f"{CONTEXT_MOUNT}system_overview.md"] = create_file_data(workspace.render_system_overview())
        # Report order stays the config's; launch order is longest-first.
        categories = sorted(config.enabled_categories, key=lambda c: -c.effort)

        logger.info(
            "deep_review_started",
            repository_id=repository_id,
            head_sha=head_sha,
            provider=provider,
            model=model,
            categories=[c.id for c in categories],
            static_findings=len(workspace.static_by_id),
            formatting_findings_auto_triaged=formatting,
            max_concurrency=self.config.DEEP_REVIEW_MAX_CONCURRENCY,
        )

        semaphore = asyncio.Semaphore(self.config.DEEP_REVIEW_MAX_CONCURRENCY)
        runs: list[AgentRunStats] = []

        await asyncio.gather(
            *(self._category_pipeline(c, config, workspace, brief, files, repo_path, semaphore, runs) for c in categories)
        )

        # Deterministic clean-up before synthesis: the same defect recorded by two lanes
        # is folded, and static findings a verified finding cites count as triaged.
        capped = workspace.apply_severity_caps()
        folded = workspace.auto_fold_duplicates()
        cited = workspace.auto_triage_cited()
        logger.info("deep_review_consolidated", severity_capped=capped, folded_duplicates=folded, static_findings_triaged_by_citation=cited)

        if workspace.findings:
            runs.append(await self._run_synthesizer(workspace, brief, files, repo_path))
        else:
            runs.append(AgentRunStats(agent="synthesizer", status="skipped"))

        report = self._assemble(
            workspace=workspace,
            config=config,
            runs=runs,
            repository_id=repository_id,
            repository_name=repository_name,
            head_sha=head_sha,
            cache_key=cache_key,
            provider=provider,
            model=model,
            duration=time.monotonic() - start,
        )
        markdown = render_report(report)

        logger.info(
            "deep_review_completed",
            repository_id=repository_id,
            duration_seconds=round(report.statistics.duration_seconds, 1),
            findings=len(report.findings),
            by_severity=dict(Counter(f.severity for f in report.findings)),
            rejected=report.statistics.findings_rejected_by_verifier,
            static_false_positives=report.statistics.static_false_positives,
            input_tokens=report.statistics.input_tokens,
            output_tokens=report.statistics.output_tokens,
            incomplete_agents=[r.agent for r in runs if r.status not in ("completed", "skipped")],
        )
        return report, markdown

    # ------------------------------------------------------------------
    # Agent phases
    # ------------------------------------------------------------------

    async def _category_pipeline(
        self,
        category: ReviewCategory,
        config: ReviewConfig,
        workspace: ReviewWorkspace,
        brief: str,
        files: dict[str, dict],
        repo_path: Path,
        semaphore: asyncio.Semaphore,
        runs: list[AgentRunStats],
    ) -> None:
        """Specialist(s), then (immediately) the category's verifier — independent of other categories.

        The KPI-owning category runs two agents concurrently — the category
        specialist and a dedicated KPI assessor — so the 12-item checklist
        doesn't make security the long pole of the whole review.
        """
        kickoff = (
            f"Begin the {category.title} review of this repository. Work in this order:\n"
            "1. UNDERSTAND: read /_review/context/system_overview.md, agents_md.md if present, and the entry points "
            "and core modules that matter for your lane. Work out how THIS system works: its purpose, main flows, data, "
            "trust boundaries and where failure would hurt most.\n"
            "2. HYPOTHESIZE: call record_hypotheses with your system model and at least 4 suspicions specific to this "
            "repository — things an expert would check here because of how this system is built, not generic "
            "categories and not copies of the leads below.\n"
            "3. INVESTIGATE: prove or disprove each hypothesis in the code (resolve_hypothesis), sweep your file "
            "scope, and follow anything else you notice — your own findings beyond the leads are the most valuable "
            "part of the review.\n"
            "4. CLOSE THE LEADS: the static leads below are a safety net; each ends as a finding, attached to one, "
            "or dismissed with the code that proves it safe."
        )
        scope = workspace.lane_scopes().get(category.id, [])
        if scope:
            kickoff += (
                f"\n\nYour file scope: {len(scope)} files (listed under '{category.id}' in /_review/context/scopes.md). "
                "Open every one of them for your lane's concerns before you finish — read the small ones yourself in "
                "parallel batches, and hand the rest to code-explorer sweeps (several `task` calls in ONE turn, 8-12 "
                "files each, each asked to report every defect relevant to your lane with file:line). Their reads count "
                "toward your scope."
            )
        leads = workspace.lane_leads(category.id)
        if leads:
            kickoff += (
                "\n\nMandatory leads for your lane, found statically. Each group must end either as a recorded "
                "finding (grouping rows that share a root cause) or as a deliberate dismissal you can justify:\n"
                + "\n".join(_format_lead_group(label, rows) for label, _, rows in leads)
            )
        def nothing_recorded() -> str | None:
            recorded = any(f.category_id == category.id for f in workspace.findings.values())
            if not recorded and not any(fid.startswith(f"{category.code}-") for fid in workspace.withdrawn):
                return (
                    f"You are stopping with NO findings recorded for {category.title}. Unless you have verified that "
                    "this category genuinely does not apply to this repository, go back to your checklist and the "
                    "relevant /_review/context/ tables, verify the issues you found, and record them with "
                    "record_finding now. If it truly does not apply, reply with one sentence saying why."
                )
            parts = []
            scope_files = workspace.lane_scopes().get(category.id, [])
            if scope_files and not any(h["lane"] == category.id for h in workspace.hypotheses.values()):
                parts.append(
                    "You have not recorded your system model and hypotheses. Call record_hypotheses now: how this "
                    "system works for your lane, and at least 4 repository-specific suspicions with their files. Then "
                    "investigate each."
                )
            open_h = workspace.open_hypotheses(category.id)
            if open_h:
                parts.append(
                    "These hypotheses are not resolved yet — prove or disprove each in the code and call "
                    "resolve_hypothesis (confirmed with the finding id, or ruled_out citing the code):\n"
                    + "\n".join(f"- {h}" for h in open_h)
                )
            missing = workspace.unaddressed_leads(category.id)
            if missing:
                parts.append(
                    "These mandatory leads are still open. Each row ends as a finding that cites it (group rows that "
                    "share a root cause into one finding) or as dismiss_lead with the code that shows it is not a "
                    "defect:\n"
                    + "\n".join(_format_lead_group(label, rows) for label, rows in missing)
                )
            unopened = workspace.unopened_scope(category.id, current_lane_reads())
            if unopened:
                total = len(workspace.lane_scopes().get(category.id, []))
                sweeps = [unopened[i : i + 10] for i in range(0, min(len(unopened), 40), 10)]
                calls = "\n".join(
                    f'{n}. task(subagent_type="general-purpose", description="{category.title} review. Read each of '
                    f'these files in full and report every defect relevant to {category.title} with file:line and the '
                    f'mechanism, or \'none\' per file: {", ".join(chunk)}")'
                    for n, chunk in enumerate(sweeps, start=1)
                )
                parts.append(
                    f"You have opened {total - len(unopened)} of the {total} files in your scope; {len(unopened)} are "
                    f"still unopened. Issue these {len(sweeps)} sweeps together in ONE turn (they run in parallel), "
                    "then verify the key lines of what they report and record the real defects:\n" + calls
                )
            untriaged = workspace.untriaged_groups(category.id)
            if untriaged:
                parts.append(
                    "Static findings you own are still untriaged. Sample 2-3 instances per group with "
                    "query_static_findings, then give each group one verdict with triage_static_rule:\n"
                    + "\n".join(f"- {tool} {rule}: {count} untriaged" for tool, rule, count in untriaged[:15])
                )
            return ("Before you finish:\n\n" + "\n\n".join(parts)) if parts else None

        def kpis_unassessed() -> str | None:
            missing = [k.id for k in config.security_kpis if k.id not in workspace.kpis]
            if not missing:
                return None
            return f"These KPIs are not assessed yet: {', '.join(missing)}. Assess each with assess_security_kpi now."

        parts = [
            (
                f"specialist:{category.id}",
                specialist_prompt(config, category, brief),
                workspace.specialist_tools(category),
                nothing_recorded,
                category.strong_model,
            ),
        ]
        if category.owns_security_kpis and config.security_kpis:
            parts.append(
                (
                    f"specialist:{category.id}-kpis",
                    kpi_prompt(config, category, brief, workspace.kpi_leads()),
                    workspace.specialist_tools(category, kpi_assessor=True),
                    kpis_unassessed,
                    False,
                )
            )

        # Heavier lanes (larger scopes, deeper tracing) get proportionally more wall-clock time.
        lane_timeout = int(self.config.DEEP_REVIEW_AGENT_TIMEOUT_SECONDS * (0.9 + 0.1 * category.effort))

        async def run_part(name: str, prompt: str, tools: list, completion_check, strong: bool) -> None:
            async with semaphore:
                runs.append(
                    await self._run(
                        name,
                        timeout_seconds=lane_timeout,
                        role="specialist",
                        repo_path=repo_path,
                        system_prompt=prompt,
                        tools=tools,
                        explorer_tools=workspace.query_tools(),
                        model_calls=self.config.DEEP_REVIEW_SPECIALIST_MODEL_CALLS,
                        kickoff=kickoff,
                        files=files,
                        completion_check=completion_check,
                        strong=strong,
                    )
                )

        await asyncio.gather(*(run_part(*part) for part in parts))

        pending = workspace.findings_to_verify(category.id)
        if not pending:
            return
        # One verifier per batch: a lane with many findings used to hand one verifier more than it
        # could re-check before its time cap. Critical/High go to the judge model; Medium/Low to the
        # faster base model, which keeps the judge's (slower, rate-limited) capacity for what matters.
        severe = [f for f in pending if f.severity in ("Critical", "High")]
        minor = [f for f in pending if f.severity not in ("Critical", "High")]
        batches = [(severe[i : i + _VERIFY_BATCH], False) for i in range(0, len(severe), _VERIFY_BATCH)]
        batches += [(minor[i : i + _VERIFY_BATCH], True) for i in range(0, len(minor), _VERIFY_BATCH)]

        async def verify(label: str, batch: list, light: bool) -> None:
            ids = {f.id for f in batch}
            kickoff = "Verify each of these findings:\n\n" + "\n\n".join(workspace.render_finding(f) for f in batch)
            async with semaphore:
                runs.append(
                    await self._run(
                        f"verifier:{category.id}{label}",
                        role="verifier",
                        repo_path=repo_path,
                        system_prompt=verifier_prompt(category, brief),
                        tools=workspace.verifier_tools(category.id),
                        explorer_tools=workspace.query_tools(),
                        model_calls=self.config.DEEP_REVIEW_VERIFIER_MODEL_CALLS,
                        kickoff=kickoff,
                        files=files,
                        completion_check=lambda: _unverified_nudge(workspace, category.id, ids),
                        light=light,
                    )
                )

        await asyncio.gather(*(
            verify(f"-{i + 1}" if len(batches) > 1 else "", batch, light) for i, (batch, light) in enumerate(batches)
        ))
        # Whatever a batch could not finish (provider slowness, time cap) gets one more pass on the
        # base model with a fresh clock; anything still open is reported as not independently verified.
        leftover = workspace.findings_to_verify(category.id)
        if leftover:
            logger.info("deep_review_verification_retry", category=category.id, findings=len(leftover))
            await asyncio.gather(*(
                verify(f"-retry{'-' + str(i + 1) if len(leftover) > _VERIFY_BATCH else ''}",
                       leftover[i : i + _VERIFY_BATCH], True)
                for i in range(0, len(leftover), _VERIFY_BATCH)
            ))

    async def _run_synthesizer(
        self, workspace: ReviewWorkspace, brief: str, files: dict[str, dict], repo_path: Path
    ) -> AgentRunStats:
        counts = Counter(f.severity for f in workspace.findings.values())
        kickoff = (
            f"All specialists and verifiers are done. {len(workspace.findings)} findings are live "
            f"({', '.join(f'{v} {k}' for k, v in counts.most_common())}); "
            f"{len(workspace.rejected)} were rejected by verifiers. Produce the executive summary."
        )
        return await self._run(
            "synthesizer",
            role="synthesizer",
            repo_path=repo_path,
            system_prompt=synthesizer_prompt(brief),
            tools=workspace.synthesizer_tools(),
            explorer_tools=workspace.query_tools(),
            model_calls=self.config.DEEP_REVIEW_SYNTHESIZER_MODEL_CALLS,
            kickoff=kickoff,
            files=files,
            completion_check=lambda: None if workspace.summary is not None else (
                "The executive summary is not recorded yet. Call submit_executive_summary now "
                "(scope, verdict, priority order, cross-cutting root causes, verification note)."
            ),
        )

    async def _run(
        self,
        name: str,
        *,
        role: str,
        repo_path: Path,
        system_prompt: str,
        tools: list,
        explorer_tools: list,
        model_calls: int,
        kickoff: str,
        files: dict[str, dict],
        completion_check=None,
        strong: bool = False,
        timeout_seconds: int | None = None,
        light: bool = False,
    ) -> AgentRunStats:
        progress = getattr(self, "_progress", None)
        if progress is not None:
            await progress.agent_started(name)
        stats = await self._build_and_run(
            name,
            role=role,
            repo_path=repo_path,
            system_prompt=system_prompt,
            tools=tools,
            explorer_tools=explorer_tools,
            model_calls=model_calls,
            kickoff=kickoff,
            files=files,
            completion_check=completion_check,
            strong=strong,
            timeout_seconds=timeout_seconds,
            light=light,
        )
        if progress is not None:
            await progress.agent_finished(stats)
        return stats

    async def _build_and_run(
        self,
        name: str,
        *,
        role: str,
        repo_path: Path,
        system_prompt: str,
        tools: list,
        explorer_tools: list,
        model_calls: int,
        kickoff: str,
        files: dict[str, dict],
        completion_check=None,
        strong: bool = False,
        timeout_seconds: int | None = None,
        light: bool = False,
    ) -> AgentRunStats:
        try:
            agent = build_agent(
                settings=self.config,
                repo_path=repo_path,
                role=role,  # type: ignore[arg-type]
                name=name.replace(":", "-"),
                system_prompt=system_prompt,
                tools=tools,
                explorer_tools=explorer_tools,
                model_calls=model_calls,
                strong=strong,
                light=light,
            )
        except DeepReviewError:
            raise
        except Exception as exc:  # noqa: BLE001 -- a build failure degrades to one failed agent
            logger.error("deep_review_agent_build_failed", agent=name, error=str(exc))
            return AgentRunStats(agent=name, status="failed", error=f"build: {type(exc).__name__}: {exc}"[:500])
        return await run_agent(
            agent,
            name=name,
            kickoff=kickoff,
            files=files,
            timeout_seconds=timeout_seconds or self.config.DEEP_REVIEW_AGENT_TIMEOUT_SECONDS,
            completion_check=completion_check,
            model_calls=model_calls,
        )

    # ------------------------------------------------------------------
    # Assembly
    # ------------------------------------------------------------------

    def _assemble(
        self,
        *,
        workspace: ReviewWorkspace,
        config: ReviewConfig,
        runs: list[AgentRunStats],
        repository_id: str,
        repository_name: str,
        head_sha: str,
        cache_key: str,
        provider: str,
        model: str,
        duration: float,
    ) -> DeepReviewReport:
        floor = CONFIDENCE_ORDER.index(config.review.min_confidence)
        recorded = len(workspace.findings) + len(workspace.rejected)
        live = [f for f in workspace.findings.values() if f.id not in workspace.duplicates]
        low_confidence = [f for f in live if CONFIDENCE_ORDER.index(f.confidence) < floor]
        findings = [
            f.model_copy(update={"duplicate_of": None})
            for f in live
            if CONFIDENCE_ORDER.index(f.confidence) >= floor
        ]
        reported_ids = {f.id for f in findings}

        kpis: list[KpiAssessment] = []
        if any(c.owns_security_kpis for c in config.enabled_categories):
            for kpi in config.security_kpis:
                assessed = workspace.kpis.get(kpi.id)
                if assessed is None:
                    kpis.append(
                        KpiAssessment(
                            kpi_id=kpi.id,
                            title=kpi.title,
                            status="not_verified",
                            summary="Not assessed by the security review (agent budget or time ran out).",
                        )
                    )
                else:
                    kpis.append(
                        assessed.model_copy(
                            update={"finding_ids": tuple(i for i in assessed.finding_ids if i in reported_ids)}
                        )
                    )

        static_summary = []
        by_tool: dict[str, list[StaticFinding]] = {}
        for finding in workspace.static_by_id.values():
            by_tool.setdefault(finding.tool, []).append(finding)
        for tool in sorted(set(workspace.tool_results) | set(by_tool)):
            verdicts = Counter(
                workspace.triage[f.id].verdict if f.id in workspace.triage else "untriaged" for f in by_tool.get(tool, [])
            )
            static_summary.append(
                StaticToolSummary(
                    tool=tool,
                    status=str(workspace.tool_results.get(tool, {}).get("status", "unknown")),
                    error=(str(workspace.tool_results.get(tool, {}).get("error") or "").strip()[:300] or None),
                    total=len(by_tool.get(tool, [])),
                    true_positive=verdicts["true_positive"],
                    false_positive=verdicts["false_positive"],
                    low_value=verdicts["low_value"],
                    untriaged=verdicts["untriaged"],
                )
            )

        summary = workspace.summary or ExecutiveSummary()
        summary = summary.model_copy(
            update={
                "priority_order": tuple(
                    p.model_copy(update={"finding_ids": tuple(i for i in p.finding_ids if i in reported_ids)})
                    for p in summary.priority_order
                ),
                "cross_cutting": tuple(
                    r.model_copy(update={"finding_ids": tuple(i for i in r.finding_ids if i in reported_ids)})
                    for r in summary.cross_cutting
                ),
            }
        )

        statistics = ReviewStatistics(
            duration_seconds=duration,
            findings_recorded=recorded,
            findings_reported=len(findings),
            findings_rejected_by_verifier=len(workspace.rejected),
            findings_rejected_invalid_evidence=workspace.invalid_evidence_bounces,
            findings_merged_as_duplicates=len(workspace.duplicates),
            findings_dropped_low_confidence=len(low_confidence),
            static_findings_total=len(workspace.static_by_id),
            static_findings_triaged=len(workspace.triage),
            static_false_positives=sum(1 for t in workspace.triage.values() if t.verdict == "false_positive"),
            input_tokens=sum(r.input_tokens for r in runs),
            output_tokens=sum(r.output_tokens for r in runs),
        )

        merged = []
        for dup_id, primary in workspace.duplicates.items():
            while primary in workspace.duplicates:
                primary = workspace.duplicates[primary]
            folded = workspace.findings.get(dup_id)
            if folded is not None and primary in reported_ids:
                merged.append(MergedFinding(id=dup_id, category_id=folded.category_id, title=folded.title, primary_id=primary))

        return DeepReviewReport(
            engine_version=self.config.DEEP_REVIEW_ENGINE_VERSION,
            repository_id=repository_id,
            repository_name=repository_name,
            head_sha=head_sha,
            cache_key=cache_key,
            provider=provider,
            model=model,
            generated_at=datetime.now(UTC),
            summary=summary,
            categories=config.enabled_categories,
            findings=tuple(findings),
            rejected_findings=tuple(workspace.rejected.values()),
            hypotheses=tuple(workspace.hypothesis_rows()),
            system_models=tuple(f"{lane}: {text}" for lane, text in workspace.system_models.items()),
            own_investigation=sum(1 for f in findings if not workspace.lead_backed(f)),
            open_leads=tuple(
                f"{category.id} — {label}: " + "; ".join(rows[:6]) + (f" (+{len(rows) - 6} more)" if len(rows) > 6 else "")
                for category in config.enabled_categories
                for label, rows in workspace.unaddressed_leads(category.id, any_lane=True)
            ),
            dismissed_leads=tuple(
                f"{lane} — {row} — {reason}" for (lane, row), reason in sorted(workspace.dismissed_leads.items())
            ),
            merged_findings=tuple(sorted(merged, key=lambda m: m.id)),
            inventory=build_inventory(workspace.maps, line_counts={f.path: f.lines or 0 for f in workspace.manifest.files}),
            coverage=_coverage(workspace, runs),
            kpi_assessments=tuple(kpis),
            static_triage=tuple(workspace.triage.values()),
            static_summary=tuple(static_summary),
            agent_runs=tuple(sorted(runs, key=lambda r: r.agent)),
            statistics=statistics,
        )
