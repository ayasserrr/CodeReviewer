"""Deterministic markdown rendering of a ``DeepReviewReport``.

The LLM agents produce *structured* findings; this module lays them out in
the report format (priority order, security KPI checklist, one numbered
section per category, static-analysis triage, cross-cutting summary,
verification note). Rendering in code instead of asking a model to write the
final document means: no findings silently dropped or reworded, stable
section numbering for cross-references, zero extra tokens, and the markdown
can always be regenerated from the stored ``report_data``.
"""

from collections import Counter, defaultdict

from utils import EXPOSURE_LABELS, DeepReviewReport, ReviewFinding
from utils.review import SEVERITY_ORDER

_KPI_STATUS_LABEL = {
    "open": "Confirmed open",
    "partially_open": "Partially open",
    "closed": "Closed",
    "not_applicable": "Not applicable",
    "not_verified": "Not verified",
}


def section_numbers(report: DeepReviewReport) -> tuple[dict[str, int], dict[str, str]]:
    """``(category_id -> section number, finding_id -> "section.index")``."""
    category_numbers = {category.id: index for index, category in enumerate(report.categories, start=1)}
    finding_numbers: dict[str, str] = {}
    for category_id, findings in _findings_by_category(report).items():
        for index, finding in enumerate(findings, start=1):
            finding_numbers[finding.id] = f"{category_numbers[category_id]}.{index}"
    return category_numbers, finding_numbers


def _findings_by_category(report: DeepReviewReport) -> dict[str, list[ReviewFinding]]:
    grouped: dict[str, list[ReviewFinding]] = defaultdict(list)
    known = {c.id for c in report.categories}
    for finding in report.findings:
        if finding.category_id in known:
            grouped[finding.category_id].append(finding)
    for findings in grouped.values():
        findings.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), int(f.id.rsplit("-", 1)[-1])))
    return grouped


def _refs(finding_ids: tuple[str, ...], finding_numbers: dict[str, str]) -> str:
    sections = [finding_numbers[i] for i in finding_ids if i in finding_numbers]
    if not sections:
        return ""
    ordered = sorted(dict.fromkeys(sections), key=lambda s: tuple(int(p) for p in s.split(".")))
    return " (" + ("section " if len(ordered) == 1 else "sections ") + ", ".join(ordered) + ")"


def _evidence_line(finding: ReviewFinding) -> str:
    labels = ", ".join(f"`{e.label}`" for e in finding.evidence[:12])
    more = f" (+{len(finding.evidence) - 12} more)" if len(finding.evidence) > 12 else ""
    return f"*Evidence:* {labels}{more}"


def _exposure_line(finding: ReviewFinding) -> str | None:
    if finding.exposure == "live":
        return None
    return f"*Exposure:* {EXPOSURE_LABELS.get(finding.exposure, finding.exposure)}."


def _verification_line(finding: ReviewFinding) -> str:
    if finding.verification is None:
        return "*Verification:* not independently verified."
    v = finding.verification
    if not v.independent:
        return f"*Verification:* not independently verified. {v.note}"
    if v.verdict == "adjusted" and v.original_severity != finding.severity:
        return f"*Verification:* severity adjusted {v.original_severity} → {finding.severity} — {v.note}"
    return f"*Verification:* confirmed — {v.note}"


def render_report(report: DeepReviewReport) -> str:
    """Render the full markdown report."""
    category_numbers, finding_numbers = section_numbers(report)
    by_category = _findings_by_category(report)
    summary = report.summary
    run_status = {run.agent: run for run in report.agent_runs}
    out: list[str] = []

    # ---- header -----------------------------------------------------------
    out.append(f"# {report.repository_name} — Full Engineering Review")
    out.append("")
    scope = summary.scope or f"Repository `{report.repository_name}`."
    out.append(
        f"**Scope:** {scope} Evidence is cited by `file:line`. This is a findings-only document: "
        "it states what is wrong, the evidence, and the impact. It does **not** prescribe remediation."
        if not any(f.remediation for f in report.findings)
        else f"**Scope:** {scope} Evidence is cited by `file:line`."
    )
    out.append("")
    out.append(
        f"**Commit:** `{report.head_sha}` · **Generated:** {report.generated_at:%Y-%m-%d %H:%M} UTC · "
        f"**Review engine:** {report.engine_version} ({report.provider} `{report.model}`)"
    )
    out.append("")
    out.append(f"**Severity levels used below:** {', '.join(SEVERITY_ORDER)}.")
    out.append("")
    out.append(
        "**Exposure** (stated on every finding that is not live): live — reachable today; conditional — only "
        "under specific conditions; latent — in the code but no entry point reaches it; dead — unused code; "
        "theoretical — needs a future architectural change. Severity is calibrated to exposure."
    )
    out.append("")
    counts = Counter(f.severity for f in report.findings)
    out.append(
        "**Findings:** "
        + ", ".join(f"{counts.get(level, 0)} {level}" for level in SEVERITY_ORDER)
        + f" — {len(report.findings)} total after independent verification "
        f"({report.statistics.findings_rejected_by_verifier} rejected as unsupported, "
        f"{report.statistics.findings_merged_as_duplicates} merged as duplicates)."
    )
    unverified = Counter(
        f.severity for f in report.findings if not f.independently_verified and f.severity in ("Critical", "High")
    )
    if unverified:
        out.append("")
        out.append(
            "**Not independently verified:** "
            + ", ".join(f"{n} {sev}" for sev, n in sorted(unverified.items(), key=lambda kv: SEVERITY_ORDER.index(kv[0])))
            + " — marked *unverified* below; treat them as the specialist's claim until a reviewer confirms them."
        )
    out.append("")
    if summary.verdict:
        out.append(f"**Verdict:** {summary.verdict}")
        out.append("")
    out.append("---")
    out.append("")

    # ---- 0. priority order ------------------------------------------------
    if summary.priority_order:
        out.append("## 0. Priority order (what actually blocks this codebase, ranked)")
        out.append("")
        for index, item in enumerate(summary.priority_order, start=1):
            out.append(f"{index}. **{item.title}** - {item.rationale}{_refs(item.finding_ids, finding_numbers)}.")
        out.append("")
        out.append("---")
        out.append("")

    # ---- 0.1 security KPI checklist ---------------------------------------
    if report.kpi_assessments or any(c.owns_security_kpis for c in report.categories):
        out.append("## 0.1 Security issues that must be explicitly avoided before production")
        out.append("")
        out.append(
            "This checklist is the mandatory security KPI list (release blockers). Each item was assessed "
            "individually against the code; the file-level evidence is cited inline and detailed in the "
            "referenced sections."
        )
        out.append("")
        if not report.kpi_assessments:
            out.append("_The security specialist did not complete the KPI checklist; treat every item as not verified._")
            out.append("")
        for index, kpi in enumerate(report.kpi_assessments, start=1):
            evidence = ", ".join(f"`{e.label}`" for e in kpi.evidence[:6])
            evidence = f" ({evidence})" if evidence else ""
            out.append(
                f"{index}. **{kpi.title}** - {_KPI_STATUS_LABEL[kpi.status]}. {kpi.summary}{evidence}"
                f"{_refs(kpi.finding_ids, finding_numbers)}"
            )
        out.append("")
        out.append("---")
        out.append("")

    # ---- category sections ------------------------------------------------
    for category in report.categories:
        number = category_numbers[category.id]
        out.append(f"## {number}. {category.title}")
        out.append("")
        for agent in (f"specialist:{category.id}", f"specialist:{category.id}-kpis"):
            run = run_status.get(agent)
            if run is not None and run.status != "completed":
                out.append(
                    f"> **Coverage warning:** agent `{agent}` did not complete ({run.status}"
                    f"{': ' + run.error if run.error else ''}). Findings below are what was verified before it stopped."
                )
                out.append("")
        findings = by_category.get(category.id, [])
        if not findings:
            merged_here = [m for m in report.merged_findings if m.category_id == category.id]
            if merged_here:
                out.append("This lane's findings were merged into related findings reported elsewhere:")
                out.append("")
                for m in merged_here:
                    target = finding_numbers.get(m.primary_id)
                    out.append(f"- {m.title} → see {target}" if target else f"- {m.title} → merged into {m.primary_id}")
            else:
                out.append("No findings in this category.")
            out.append("")
        for finding in findings:
            tag = finding.severity if finding.independently_verified else f"{finding.severity} · unverified"
            out.append(f"### [{tag}] {finding_numbers[finding.id]} {finding.title}")
            out.append("")
            out.append(finding.description)
            out.append("")
            out.append(f"**Impact:** {finding.impact}")
            out.append("")
            if finding.remediation:
                out.append(f"**Remediation:** {finding.remediation}")
                out.append("")
            out.append(_evidence_line(finding))
            exposure = _exposure_line(finding)
            if exposure:
                out.append("")
                out.append(exposure)
            out.append("")
            out.append(_verification_line(finding))
            out.append("")
        merged_elsewhere = [
            m for m in report.merged_findings
            if m.category_id == category.id and findings and finding_numbers.get(m.primary_id, "").split(".")[0] != str(number)
        ]
        if merged_elsewhere:
            out.append("*Also found by this lane and merged into related findings:* " + "; ".join(
                f"{m.title} → {finding_numbers.get(m.primary_id, m.primary_id)}" for m in merged_elsewhere))
            out.append("")
        out.append("---")
        out.append("")

    # ---- static analysis triage -------------------------------------------
    next_number = len(report.categories) + 1
    out.append(f"## {next_number}. Static analysis triage")
    out.append("")
    out.append(
        "Every static-analysis finding was routed to exactly one specialist, who judged it against the code. "
        "True positives that matter are folded into the sections above."
    )
    out.append("")
    out.append("| Tool | Status | Findings | True positive | False positive | Low value | Not triaged |")
    out.append("|---|---|---:|---:|---:|---:|---:|")
    for tool in report.static_summary:
        out.append(
            f"| {tool.tool} | {tool.status} | {tool.total} | {tool.true_positive} | {tool.false_positive} | "
            f"{tool.low_value} | {tool.untriaged} |"
        )
    out.append("")
    failed = [tool for tool in report.static_summary if tool.status != "success"]
    if failed:
        out.append("**Tools that did not run:** " + "; ".join(
            f"`{tool.tool}` ({tool.status}: {(tool.error or 'no detail').replace('|', '/')})" for tool in failed
        ))
        out.append("")
    dismissed: dict[tuple[str, str], list[str]] = defaultdict(list)
    for triage in report.static_triage:
        if triage.verdict == "false_positive":
            dismissed[(triage.tool, triage.reason)].append(triage.finding_id)
    if dismissed:
        out.append("**Dismissed as false positives:**")
        out.append("")
        for (tool, reason), ids in sorted(dismissed.items(), key=lambda kv: -len(kv[1]))[:25]:
            out.append(f"- `{tool}` x{len(ids)} — {reason}")
        out.append("")
    out.append("---")
    out.append("")

    # ---- cross-cutting summary --------------------------------------------
    if summary.cross_cutting:
        next_number += 1
        out.append(f"## {next_number}. Cross-cutting summary (the same root causes, seen from many angles)")
        out.append("")
        for index, cause in enumerate(summary.cross_cutting, start=1):
            out.append(f"{index}. **{cause.title}** {cause.explanation}{_refs(cause.finding_ids, finding_numbers)}")
        out.append("")
        out.append("---")
        out.append("")

    # ---- coverage (every file accounted for) ------------------------------
    cov = report.coverage
    if cov is not None:
        out.append("## Review coverage (computed, not model-generated)")
        out.append("")
        out.append("| Stage | Covered |")
        out.append("|---|---|")
        out.append(f"| Discovery | {cov.files_discovered} files found ({cov.source_files} source files) — every folder "
                   "walked except dependency/build/VCS/cache directories |")
        tools = ", ".join(cov.static_tools_run) or "none"
        out.append(f"| Static analysis | {cov.static_python_files} Python files to the Python tools, "
                   f"{cov.static_code_files} source files to the cross-language tools; ran: {tools} |")
        graph_gap = cov.python_files - cov.python_files_in_graph
        out.append(f"| Dependency graph | {cov.python_files_in_graph} of {cov.python_files} Python files parsed"
                   f"{f' ({graph_gap} not parsed, listed below)' if graph_gap > 0 and cov.python_not_in_graph else ''} |")
        docs = ", ".join(f"`{d}`" for d in cov.system_docs)
        out.append(f"| System description | {'AGENTS.md used as the intended logic: ' + docs if docs else 'no AGENTS.md in the repository'} |")
        pct = round(100 * cov.source_files_opened_by_agents / cov.source_files) if cov.source_files else 0
        out.append(f"| Agents | {cov.source_files_opened_by_agents} of {cov.source_files} source files opened directly "
                   f"({pct}%); the rest were covered through static analysis, the dependency graph, grep and the maps |")
        if cov.lane_scopes:
            out.append("| Lane file scopes | " + "; ".join(cov.lane_scopes) + " |")
        out.append("")
        warnings = []
        if cov.traversal_timed_out:
            warnings.append("the filesystem walk hit its time budget — files beyond that point were not discovered")
        if cov.discovery_timed_out:
            warnings.append("discovery hit its time budget — every file is still listed, but late files were not AST-parsed")
        if cov.static_tools_failed:
            warnings.append("static tools that did not run: " + ", ".join(cov.static_tools_failed))
        if cov.unreadable_directories:
            warnings.append("unreadable directories: " + ", ".join(f"`{d}`" for d in cov.unreadable_directories[:10]))
        for warning in warnings:
            out.append(f"> **Coverage warning:** {warning}.")
            out.append("")
        if cov.python_not_in_graph:
            out.append("*Python files not in the dependency graph:* " + "; ".join(f"`{f}`" for f in cov.python_not_in_graph))
            out.append("")
        if cov.unopened_source_dirs:
            out.append("*Least-opened areas (reviewed via tools only):* " + "; ".join(cov.unopened_source_dirs))
            out.append("")
        out.append("---")
        out.append("")

    # ---- deterministic inventory ------------------------------------------
    if report.inventory:
        out.append("## Appendix A. Inventory (static, complete — not model-generated)")
        out.append("")
        out.append(
            "Exhaustive lists computed from the code itself (routes, imports, environment reads, frontend calls). "
            "They back the findings above and list every instance, including ones the findings group together."
        )
        out.append("")
        for item in report.inventory:
            out.append(f"**{item.title}** ({len([r for r in item.rows if not r.startswith('... ')])}"
                       f"{'+' if any(r.startswith('... ') for r in item.rows) else ''})")
            if item.note:
                out.append(f"*{item.note}*")
            out.append("")
            out.extend(f"- {row}" for row in item.rows)
            out.append("")
        out.append("---")
        out.append("")

    # ---- rejected claims (auditable) ----------------------------------------
    if report.rejected_findings:
        out.append("## Appendix B. Claims rejected by independent verification")
        out.append("")
        out.append("Recorded by a specialist, then disproved against the code by a second agent. Listed so the "
                   "rejection itself can be audited.")
        out.append("")
        for finding in sorted(report.rejected_findings, key=lambda f: (f.category_id, f.id)):
            reason = finding.verification.note if finding.verification else ""
            out.append(f"- **{finding.title}** ({finding.category_id}, {finding.severity}) — {reason[:400]}")
        out.append("")
        out.append("---")
        out.append("")

    if report.dismissed_leads:
        out.append("## Appendix C. Mandatory leads dismissed by the specialists")
        out.append("")
        out.append("Statically detected leads a specialist judged not to be defects, each with the code it cited.")
        out.append("")
        out.extend(f"- {row[:500]}" for row in report.dismissed_leads)
        out.append("")
        out.append("---")
        out.append("")

    # ---- coverage & verification note -------------------------------------
    stats = report.statistics
    out.append(
        f"*Review coverage: {len(report.categories)} specialist categories reviewed in parallel; "
        f"{stats.findings_recorded} findings recorded, {stats.findings_reported} reported "
        f"({stats.findings_rejected_by_verifier} rejected by independent verification, "
        f"{stats.findings_rejected_invalid_evidence} bounced for invalid citations, "
        f"{stats.findings_dropped_low_confidence} dropped as low-confidence); "
        f"{stats.static_findings_triaged}/{stats.static_findings_total} static findings triaged "
        f"({stats.static_false_positives} false positives); {stats.duration_seconds / 60:.1f} min wall-clock, "
        f"{stats.input_tokens + stats.output_tokens:,} tokens.*"
    )
    incomplete = [run for run in report.agent_runs if run.status not in ("completed", "skipped")]
    if incomplete:
        out.append("")
        out.append(
            "*Incomplete agents: "
            + "; ".join(f"{run.agent} ({run.status})" for run in incomplete)
            + ".*"
        )
    if summary.verification_note:
        out.append("")
        out.append(f"*Verification note: {summary.verification_note}*")
    out.append("")
    return "\n".join(out)
