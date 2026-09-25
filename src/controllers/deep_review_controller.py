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

from controllers import BaseController
from helpers import (
    PipelineProgress,
    ReviewWorkspace,
    build_agent,
    build_chat_model,
    build_context_files,
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
from system import get_logger
from utils import (
    AgentRunStats,
    DeepReviewError,
    DeepReviewReport,
    DependencyGraph,
    ExecutiveSummary,
    InvalidInputError,
    KpiAssessment,
    RepositoryManifest,
    ReviewCategory,
    ReviewConfig,
    ReviewStatistics,
    StaticFinding,
    StaticToolSummary,
)
from utils.review import CONFIDENCE_ORDER

logger = get_logger(__name__)


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
        brief = build_repo_brief(workspace, repository_name)
        files = build_context_files(workspace, brief)
        categories = config.enabled_categories

        logger.info(
            "deep_review_started",
            repository_id=repository_id,
            head_sha=head_sha,
            provider=provider,
            model=model,
            categories=[c.id for c in categories],
            static_findings=len(workspace.static_by_id),
            max_concurrency=self.config.DEEP_REVIEW_MAX_CONCURRENCY,
        )

        semaphore = asyncio.Semaphore(self.config.DEEP_REVIEW_MAX_CONCURRENCY)
        runs: list[AgentRunStats] = []

        await asyncio.gather(
            *(self._category_pipeline(c, config, workspace, brief, files, repo_path, semaphore, runs) for c in categories)
        )

        # Deterministic clean-up before synthesis: the same defect recorded by two lanes
        # is folded, and static findings a verified finding cites count as triaged.
        folded = workspace.auto_fold_duplicates()
        cited = workspace.auto_triage_cited()
        logger.info("deep_review_consolidated", folded_duplicates=folded, static_findings_triaged_by_citation=cited)

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
            f"Begin the {category.title} review of this repository. The repository brief is in your instructions; "
            "/_review/context/ holds the full lists. Plan with write_plan, then work through it."
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
            if recorded or any(fid.startswith(f"{category.code}-") for fid in workspace.withdrawn):
                missing = workspace.unaddressed_leads(category.id)
                if not missing:
                    return None
                return (
                    "Before you finish: none of your findings cites these mandatory lead groups. Check each one and "
                    "record what is real (or reply why a group is not a defect):\n"
                    + "\n".join(_format_lead_group(label, rows) for label, rows in missing)
                )
            return (
                f"You are stopping with NO findings recorded for {category.title}. Unless you have verified that "
                "this category genuinely does not apply to this repository, go back to your checklist and the "
                "relevant /_review/context/ tables, verify the issues you found, and record them with "
                "record_finding now. If it truly does not apply, reply with one sentence saying why."
            )

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

        async def run_part(name: str, prompt: str, tools: list, completion_check, strong: bool) -> None:
            async with semaphore:
                runs.append(
                    await self._run(
                        name,
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
        verify_kickoff = "Verify each of these findings:\n\n" + "\n\n".join(workspace.render_finding(f) for f in pending)
        async with semaphore:
            runs.append(
                await self._run(
                    f"verifier:{category.id}",
                    role="verifier",
                    repo_path=repo_path,
                    system_prompt=verifier_prompt(category, brief),
                    tools=workspace.verifier_tools(category.id),
                    explorer_tools=workspace.query_tools(),
                    model_calls=self.config.DEEP_REVIEW_VERIFIER_MODEL_CALLS,
                    kickoff=verify_kickoff,
                    files=files,
                )
            )

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
            timeout_seconds=self.config.DEEP_REVIEW_AGENT_TIMEOUT_SECONDS,
            completion_check=completion_check,
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
            kpi_assessments=tuple(kpis),
            static_triage=tuple(workspace.triage.values()),
            static_summary=tuple(static_summary),
            agent_runs=tuple(sorted(runs, key=lambda r: r.agent)),
            statistics=statistics,
        )
