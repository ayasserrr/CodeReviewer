import { useMemo, useState } from "react";

import type { DeepReviewReport, Finding, ReviewDetail, Severity, StaticToolSummary } from "../api/types";
import { formatDuration, formatNumber, KPI_STATUS, SEVERITIES, SEVERITY_COLOR } from "../lib/format";
import { Markdown } from "./Markdown";
import { Badge, EmptyState, Icon, KpiBadge, SeverityBadge, SeverityBar, StatTile } from "./ui";

type Tab = "overview" | "findings" | "kpis" | "static" | "report";

/** "SEC-3" -> "2.1", matching the numbering in the markdown report. */
function useSectionNumbers(report: DeepReviewReport) {
  return useMemo(() => {
    const byFinding = new Map<string, string>();
    report.categories.forEach((category, ci) => {
      report.findings
        .filter((f) => f.category_id === category.id)
        .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || idNum(a.id) - idNum(b.id))
        .forEach((f, fi) => byFinding.set(f.id, `${ci + 1}.${fi + 1}`));
    });
    return byFinding;
  }, [report]);
}

const idNum = (id: string) => Number(id.split("-").pop()) || 0;

export function ReportView({ review }: { review: ReviewDetail }) {
  const report = review.report_data;
  const [tab, setTab] = useState<Tab>("overview");
  const [focusFinding, setFocusFinding] = useState<string | null>(null);
  if (!report) {
    return (
      <div className="card">
        <EmptyState title="No deep-review report">The pipeline finished without the AI review (it may be disabled).</EmptyState>
      </div>
    );
  }

  const openFinding = (id: string) => {
    setFocusFinding(id);
    setTab("findings");
  };
  const openKpis = report.kpi_assessments.filter((k) => k.status === "open" || k.status === "partially_open").length;

  return (
    <div className="stack" style={{ gap: 18 }}>
      <div className="tabs" role="tablist">
        {([
          ["overview", "Overview", null],
          ["findings", "Findings", report.findings.length],
          ["kpis", "Security KPIs", report.kpi_assessments.length ? `${openKpis} open` : null],
          ["static", "Static analysis", report.statistics.static_findings_total],
          ["report", "Full report", null],
        ] as [Tab, string, number | string | null][]).map(([id, label, count]) => (
          <button key={id} role="tab" aria-selected={tab === id} className={`tab${tab === id ? " active" : ""}`} onClick={() => setTab(id)}>
            {label}
            {count != null && <span className="count">{count}</span>}
          </button>
        ))}
      </div>

      {tab === "overview" && <Overview report={report} onOpenFinding={openFinding} />}
      {tab === "findings" && <Findings report={report} focus={focusFinding} />}
      {tab === "kpis" && <Kpis report={report} onOpenFinding={openFinding} />}
      {tab === "static" && <StaticAnalysis report={report} />}
      {tab === "report" && <FullReport review={review} />}
    </div>
  );
}

// ---- Overview ----------------------------------------------------------------

function Overview({ report, onOpenFinding }: { report: DeepReviewReport; onOpenFinding: (id: string) => void }) {
  const numbers = useSectionNumbers(report);
  const counts = useMemo(() => {
    const c: Partial<Record<Severity, number>> = {};
    for (const f of report.findings) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [report]);
  const byCategory = report.categories
    .map((cat) => ({ cat, findings: report.findings.filter((f) => f.category_id === cat.id) }))
    .filter((x) => x.findings.length)
    .sort((a, b) => b.findings.length - a.findings.length);
  const maxCat = Math.max(1, ...byCategory.map((x) => x.findings.length));
  const s = report.statistics;
  const blockers = (counts.Critical ?? 0) + (counts.High ?? 0);

  return (
    <div className="stack" style={{ gap: 16 }}>
      <div className="grid-4">
        <StatTile accent label="Findings" value={report.findings.length}
          sub={`${s.findings_rejected_by_verifier} rejected by verification`} />
        <StatTile label="Critical + High" value={<span style={{ color: blockers ? "var(--sev-critical)" : undefined }}>{blockers}</span>}
          sub="need attention before release" />
        <StatTile label="Static findings triaged" value={`${s.static_findings_triaged}/${s.static_findings_total}`}
          sub={`${s.static_false_positives} false positives removed`} />
        <StatTile label="Review time" value={formatDuration(s.duration_seconds)}
          sub={`${formatNumber(s.input_tokens + s.output_tokens)} tokens`} />
      </div>

      {report.summary.verdict && (
        <div className="card card-pad stack" style={{ borderLeft: "3px solid var(--accent)" }}>
          <span className="stat-label">Verdict</span>
          <p style={{ fontSize: 15, color: "var(--text-strong)", lineHeight: 1.6 }}>{report.summary.verdict}</p>
          {report.summary.scope && <p className="muted small">{report.summary.scope}</p>}
        </div>
      )}

      <div className="grid-2">
        <div className="card">
          <div className="card-header"><h2>Severity</h2></div>
          <div className="card-body"><SeverityBar counts={counts} height={12} /></div>
        </div>
        <div className="card">
          <div className="card-header"><h2>Findings by category</h2></div>
          <div className="card-body stack" style={{ gap: 9 }}>
            {byCategory.length ? byCategory.map(({ cat, findings }) => (
              <div key={cat.id} title={`${cat.title}: ${findings.length}`} style={{ display: "grid", gridTemplateColumns: "150px 1fr 26px", gap: 10, alignItems: "center" }}>
                <span className="small muted-2 truncate">{cat.title.split(/[,&:]/)[0].trim()}</span>
                <div style={{ display: "flex", gap: 2, height: 8 }}>
                  {SEVERITIES.map((sev) => {
                    const n = findings.filter((f) => f.severity === sev).length;
                    return n ? <div key={sev} title={`${n} ${sev}`} style={{ width: `${(n / maxCat) * 100}%`, background: SEVERITY_COLOR[sev], borderRadius: 2 }} /> : null;
                  })}
                </div>
                <span className="small strong num">{findings.length}</span>
              </div>
            )) : <span className="muted small">No findings</span>}
          </div>
        </div>
      </div>

      {report.summary.priority_order.length > 0 && (
        <div className="card">
          <div className="card-header"><h2>Priority order</h2><span className="hint">What blocks this codebase, ranked</span></div>
          <ol style={{ margin: 0, padding: "6px 20px 12px", listStyle: "none", display: "grid" }}>
            {report.summary.priority_order.map((item, i) => (
              <li key={i} style={{ display: "grid", gridTemplateColumns: "28px 1fr", gap: 12, padding: "12px 0", borderBottom: i < report.summary.priority_order.length - 1 ? "1px solid var(--border-soft)" : 0 }}>
                <span style={{ width: 26, height: 26, borderRadius: 7, background: i === 0 ? "var(--accent)" : "var(--surface-3)", color: "#fff", display: "grid", placeItems: "center", fontWeight: 700, fontSize: 12.5 }}>{i + 1}</span>
                <div className="stack" style={{ gap: 6 }}>
                  <span className="strong">{item.title}</span>
                  <span className="muted-2 small">{item.rationale}</span>
                  <FindingLinks ids={item.finding_ids} numbers={numbers} onOpen={onOpenFinding} />
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}

      {report.summary.cross_cutting.length > 0 && (
        <div className="card">
          <div className="card-header"><h2>Root causes</h2><span className="hint">The same problems, seen from many angles</span></div>
          <div className="card-body grid-2">
            {report.summary.cross_cutting.map((c, i) => (
              <div key={i} className="stack" style={{ gap: 6, padding: 14, background: "var(--surface-2)", borderRadius: 8, border: "1px solid var(--border-soft)" }}>
                <span className="strong">{c.title}</span>
                <span className="muted-2 small">{c.explanation}</span>
                <FindingLinks ids={c.finding_ids} numbers={numbers} onOpen={onOpenFinding} />
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function FindingLinks({ ids, numbers, onOpen }: { ids: string[]; numbers: Map<string, string>; onOpen: (id: string) => void }) {
  const unique = [...new Set(ids)].filter((id) => numbers.has(id));
  if (!unique.length) return null;
  return (
    <div className="row" style={{ gap: 6 }}>
      {unique.map((id) => (
        <button key={id} className="chip" style={{ height: 24, fontSize: 12 }} onClick={() => onOpen(id)}>§ {numbers.get(id)}</button>
      ))}
    </div>
  );
}

// ---- Findings ------------------------------------------------------------------

function Findings({ report, focus }: { report: DeepReviewReport; focus: string | null }) {
  const numbers = useSectionNumbers(report);
  const [severities, setSeverities] = useState<Set<Severity>>(new Set(SEVERITIES));
  const [category, setCategory] = useState("all");
  const [query, setQuery] = useState("");

  const q = query.trim().toLowerCase();
  const visible = report.findings.filter(
    (f) =>
      severities.has(f.severity) &&
      (category === "all" || f.category_id === category) &&
      (!q || `${f.title} ${f.description} ${f.evidence.map((e) => e.file).join(" ")}`.toLowerCase().includes(q)),
  );
  const toggle = (s: Severity) =>
    setSeverities((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });

  return (
    <div className="stack" style={{ gap: 14 }}>
      <div className="row" style={{ gap: 8 }}>
        {SEVERITIES.map((s) => {
          const n = report.findings.filter((f) => f.severity === s).length;
          return (
            <button key={s} className={`chip${severities.has(s) ? " on" : ""}`} onClick={() => toggle(s)} aria-pressed={severities.has(s)}>
              <span className="dot" style={{ color: SEVERITY_COLOR[s] }} />
              {s} <span className="muted">{n}</span>
            </button>
          );
        })}
        <span className="spacer" />
        <select className="select" style={{ width: 230, height: 32 }} value={category} onChange={(e) => setCategory(e.target.value)} aria-label="Category">
          <option value="all">All categories</option>
          {report.categories.map((c) => (
            <option key={c.id} value={c.id}>{c.title}</option>
          ))}
        </select>
        <div style={{ position: "relative" }}>
          <Icon name="search" size={14} style={{ position: "absolute", left: 10, top: 9, color: "var(--muted)" }} />
          <input className="input" style={{ height: 32, width: 220, paddingLeft: 30 }} placeholder="Search findings or files…"
            value={query} onChange={(e) => setQuery(e.target.value)} />
        </div>
      </div>

      {visible.length === 0 ? (
        <div className="card"><EmptyState icon="search" title="No findings match these filters" /></div>
      ) : (
        report.categories.map((cat) => {
          const items = visible
            .filter((f) => f.category_id === cat.id)
            .sort((a, b) => (numbers.get(a.id) ?? "").localeCompare(numbers.get(b.id) ?? "", undefined, { numeric: true }));
          if (!items.length) return null;
          return (
            <section key={cat.id} className="stack" style={{ gap: 8 }}>
              <div className="row" style={{ gap: 8, marginTop: 4 }}>
                <h2>{cat.title}</h2>
                <Badge>{items.length}</Badge>
              </div>
              {items.map((f) => (
                <FindingCard key={f.id} finding={f} number={numbers.get(f.id) ?? f.id} defaultOpen={f.id === focus} />
              ))}
            </section>
          );
        })
      )}
    </div>
  );
}

function FindingCard({ finding, number, defaultOpen }: { finding: Finding; number: string; defaultOpen: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const v = finding.verification;
  return (
    <article className="card" style={{ borderLeft: `3px solid ${SEVERITY_COLOR[finding.severity]}` }}
      ref={(el) => { if (el && defaultOpen) el.scrollIntoView({ block: "center" }); }}>
      <button onClick={() => setOpen(!open)} aria-expanded={open}
        style={{ all: "unset", cursor: "pointer", display: "grid", gridTemplateColumns: "auto 1fr auto", gap: 12, alignItems: "center", padding: "14px 18px", width: "100%", boxSizing: "border-box" }}>
        <SeverityBadge severity={finding.severity} />
        <span className="stack" style={{ gap: 3, minWidth: 0 }}>
          <span className="strong" style={{ fontSize: 14 }}><span className="muted mono" style={{ marginRight: 8 }}>{number}</span>{finding.title}</span>
          <span className="muted small truncate mono">{finding.evidence.map((e) => loc(e)).join("  ·  ")}</span>
        </span>
        <span className="row" style={{ gap: 8 }}>
          {v?.verdict === "confirmed" && <Badge color="var(--ok)"><Icon name="check" size={12} />Verified</Badge>}
          {v?.verdict === "adjusted" && <Badge color="var(--warn)">Re-rated from {v.original_severity}</Badge>}
          {finding.kpi_ids.map((k) => <Badge key={k}><Icon name="shield" size={12} />{k}</Badge>)}
          <Icon name="chevron" size={16} style={{ color: "var(--muted)", transform: open ? "rotate(90deg)" : undefined, transition: "transform .15s" }} />
        </span>
      </button>
      {open && (
        <div style={{ padding: "0 18px 18px 18px", display: "grid", gap: 14, borderTop: "1px solid var(--border-soft)", paddingTop: 14 }}>
          <Markdown>{finding.description}</Markdown>
          <div className="stack" style={{ gap: 4 }}>
            <span className="stat-label">Impact</span>
            <p className="muted-2">{finding.impact}</p>
          </div>
          {finding.remediation && (
            <div className="stack" style={{ gap: 4 }}>
              <span className="stat-label">Remediation</span>
              <p className="muted-2">{finding.remediation}</p>
            </div>
          )}
          <div className="stack" style={{ gap: 6 }}>
            <span className="stat-label">Evidence</span>
            <div className="stack" style={{ gap: 4 }}>
              {finding.evidence.map((e, i) => (
                <div key={i} className="row small" style={{ gap: 8, background: "var(--surface-2)", border: "1px solid var(--border-soft)", borderRadius: 6, padding: "6px 10px" }}>
                  <Icon name="file" size={13} style={{ color: "var(--muted)" }} />
                  <code style={{ color: "var(--text-strong)" }}>{loc(e)}</code>
                  {e.note && <span className="muted">— {e.note}</span>}
                </div>
              ))}
            </div>
          </div>
          {v && (
            <div className="alert alert-info small">
              <strong style={{ color: "var(--text-strong)" }}>Independent verification ({v.verdict}):</strong> {v.note}
            </div>
          )}
          <div className="row muted small" style={{ gap: 14 }}>
            <span>Confidence: {finding.confidence}</span>
            {finding.static_finding_ids.length > 0 && <span>Confirms {finding.static_finding_ids.length} static-analysis finding(s)</span>}
            <span className="mono">{finding.id}</span>
          </div>
        </div>
      )}
    </article>
  );
}

const loc = (e: { file: string; line_start: number; line_end: number | null }) =>
  e.line_end && e.line_end !== e.line_start ? `${e.file}:${e.line_start}-${e.line_end}` : `${e.file}:${e.line_start}`;

// ---- Security KPIs ---------------------------------------------------------------

function Kpis({ report, onOpenFinding }: { report: DeepReviewReport; onOpenFinding: (id: string) => void }) {
  const numbers = useSectionNumbers(report);
  if (!report.kpi_assessments.length) {
    return <div className="card"><EmptyState icon="shield" title="No KPI checklist in this review" /></div>;
  }
  const tally = report.kpi_assessments.reduce<Record<string, number>>((acc, k) => ({ ...acc, [k.status]: (acc[k.status] ?? 0) + 1 }), {});
  return (
    <div className="stack" style={{ gap: 14 }}>
      <div className="row" style={{ gap: 8 }}>
        {(Object.keys(KPI_STATUS) as (keyof typeof KPI_STATUS)[]).filter((s) => tally[s]).map((s) => (
          <span key={s} className="row small" style={{ gap: 6 }}><KpiBadge status={s} /><span className="strong">{tally[s]}</span></span>
        ))}
      </div>
      <div className="grid-2">
        {report.kpi_assessments.map((k) => (
          <div key={k.kpi_id} className="card card-pad stack" style={{ gap: 10, borderTop: `3px solid ${KPI_STATUS[k.status].color}` }}>
            <div className="row" style={{ gap: 8, flexWrap: "nowrap", alignItems: "flex-start" }}>
              <span className="stack" style={{ gap: 2, minWidth: 0 }}>
                <span className="muted small mono">{k.kpi_id}</span>
                <span className="strong">{k.title}</span>
              </span>
              <span className="spacer" />
              <KpiBadge status={k.status} />
            </div>
            <p className="muted-2 small">{k.summary}</p>
            {k.evidence.length > 0 && (
              <div className="row" style={{ gap: 6 }}>
                {k.evidence.slice(0, 4).map((e, i) => <code key={i} className="small muted-2">{loc(e)}</code>)}
              </div>
            )}
            <FindingLinks ids={k.finding_ids} numbers={numbers} onOpen={onOpenFinding} />
          </div>
        ))}
      </div>
    </div>
  );
}

// ---- Static analysis -----------------------------------------------------------

const TRIAGE_SEGMENTS: { key: keyof StaticToolSummary; label: string; color: string }[] = [
  { key: "true_positive", label: "Real issue", color: "var(--sev-high)" },
  { key: "false_positive", label: "False positive", color: "var(--muted-2)" },
  { key: "low_value", label: "Low value", color: "#555" },
  { key: "untriaged", label: "Not triaged", color: "var(--surface-3)" },
];

function StaticAnalysis({ report }: { report: DeepReviewReport }) {
  const tools = [...report.static_summary].sort((a, b) => b.total - a.total);
  const dismissed = useMemo(() => {
    const groups = new Map<string, { tool: string; reason: string; count: number }>();
    for (const t of report.static_triage) {
      if (t.verdict !== "false_positive") continue;
      const key = `${t.tool}|${t.reason}`;
      const g = groups.get(key) ?? { tool: t.tool, reason: t.reason, count: 0 };
      g.count += 1;
      groups.set(key, g);
    }
    return [...groups.values()].sort((a, b) => b.count - a.count);
  }, [report]);

  return (
    <div className="stack" style={{ gap: 16 }}>
      <div className="alert alert-info">
        Every tool finding was judged by an AI reviewer against the actual code. Real issues that matter are folded into
        the findings; false positives and noise are filtered out here.
      </div>
      <div className="card">
        <div className="card-header">
          <h2>Triage by tool</h2>
          <span className="row small" style={{ gap: 12 }}>
            {TRIAGE_SEGMENTS.map((s) => (
              <span key={s.key} className="row" style={{ gap: 6 }}><span className="dot" style={{ color: s.color }} /><span className="muted-2">{s.label}</span></span>
            ))}
          </span>
        </div>
        <table className="table">
          <thead>
            <tr><th>Tool</th><th>Status</th><th style={{ width: "45%" }}>Triage</th><th className="num">Findings</th><th className="num">Real</th><th className="num">False +</th></tr>
          </thead>
          <tbody>
            {tools.map((t) => (
              <tr key={t.tool}>
                <td className="strong mono">{t.tool}</td>
                <td>{t.status === "success" ? <Badge color="var(--ok)">ran</Badge> : <Badge color="var(--warn)">{t.status}</Badge>}</td>
                <td>
                  {t.total ? (
                    <div style={{ display: "flex", gap: 2, height: 8 }}>
                      {TRIAGE_SEGMENTS.map((s) => {
                        const n = t[s.key] as number;
                        return n ? <div key={s.key} title={`${s.label}: ${n}`} style={{ flex: n, background: s.color, borderRadius: 2 }} /> : null;
                      })}
                    </div>
                  ) : <span className="muted small">no findings</span>}
                </td>
                <td className="num">{t.total}</td>
                <td className="num">{t.true_positive}</td>
                <td className="num">{t.false_positive}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {dismissed.length > 0 && (
        <div className="card">
          <div className="card-header"><h2>Dismissed as false positives</h2><span className="hint">with the reviewer's reason</span></div>
          <div className="card-body stack" style={{ gap: 10 }}>
            {dismissed.slice(0, 25).map((d, i) => (
              <div key={i} className="row small" style={{ gap: 10, flexWrap: "nowrap", alignItems: "flex-start" }}>
                <Badge>{d.tool} ×{d.count}</Badge>
                <span className="muted-2">{d.reason}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ---- Full report -----------------------------------------------------------------

function FullReport({ review }: { review: ReviewDetail }) {
  const download = () => {
    const blob = new Blob([review.report_markdown ?? ""], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${review.report_data?.repository_name ?? "review"}-${(review.commit_sha ?? "").slice(0, 8)}-review.md`;
    a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <div className="card">
      <div className="card-header">
        <h2>Engineering review (markdown)</h2>
        <button className="btn btn-sm" onClick={download}><Icon name="download" size={14} />Download .md</button>
      </div>
      <div className="card-body" style={{ padding: "20px 28px" }}>
        {review.report_markdown ? <Markdown>{review.report_markdown}</Markdown> : <span className="muted">No report.</span>}
      </div>
    </div>
  );
}
