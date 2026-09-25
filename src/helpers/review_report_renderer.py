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

from utils import DeepReviewReport, ReviewFinding
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


def _verification_line(finding: ReviewFinding) -> str:
    if finding.verification is None:
        return "*Verification:* not independently verified."
    v = finding.verification
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
    counts = Counter(f.severity for f in report.findings)
    out.append(
        "**Findings:** "
        + ", ".join(f"{counts.get(level, 0)} {level}" for level in SEVERITY_ORDER)
        + f" — {len(report.findings)} total after independent verification "
        f"({report.statistics.findings_rejected_by_verifier} rejected as unsupported, "
        f"{report.statistics.findings_merged_as_duplicates} merged as duplicates)."
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
            out.append(f"### [{finding.severity}] {finding_numbers[finding.id]} {finding.title}")
            out.append("")
            out.append(finding.description)
            out.append("")
            out.append(f"**Impact:** {finding.impact}")
            out.append("")
            if finding.remediation:
                out.append(f"**Remediation:** {finding.remediation}")
                out.append("")
            out.append(_evidence_line(finding))
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
