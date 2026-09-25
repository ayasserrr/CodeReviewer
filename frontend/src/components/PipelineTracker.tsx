import { useEffect, useState } from "react";

import type { AgentProgress, ReviewRead } from "../api/types";
import { categoryName, formatDuration, parseAgent, PIPELINE_STAGES, secondsBetween } from "../lib/format";
import { Icon, Spinner } from "./ui";

type StepState = "done" | "running" | "failed" | "waiting";

function stepState(review: ReviewRead, stageId: string, index: number): StepState {
  const entry = review.progress?.stages?.[stageId];
  if (entry?.status === "completed") return "done";
  if (entry?.status === "failed") return "failed";
  if (entry?.status === "running") return "running";
  if (review.status === "completed") return "done";
  // Rows created before stage tracking existed: infer from the coarse status.
  const current = PIPELINE_STAGES.findIndex((s) => s.id === review.stage);
  return current > index ? "done" : "waiting";
}

function useNow(active: boolean): number {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!active) return;
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, [active]);
  return now;
}

const STEP_COLOR: Record<StepState, string> = {
  done: "var(--ok)",
  running: "var(--accent)",
  failed: "var(--sev-critical)",
  waiting: "var(--border)",
};

export function PipelineTracker({ review }: { review: ReviewRead }) {
  const active = review.status === "pending" || review.status === "running";
  useNow(active); // re-render every second so running timers tick
  const elapsed = secondsBetween(review.created_at, review.completed_at);

  return (
    <div className="card">
      <div className="card-header">
        <h2>Pipeline</h2>
        <span className="hint row" style={{ gap: 6 }}>
          <Icon name="clock" size={14} />
          {active ? "Elapsed" : "Took"} {formatDuration(elapsed)}
        </span>
      </div>
      <div className="card-body">
        <ol className="stepper">
          {PIPELINE_STAGES.map((stage, i) => {
            const state = stepState(review, stage.id, i);
            const entry = review.progress?.stages?.[stage.id];
            const seconds = entry ? secondsBetween(entry.started_at, entry.finished_at) : null;
            return (
              <li key={stage.id} style={{ display: "grid", gap: 8 }}>
                <div style={{ height: 4, borderRadius: 4, background: STEP_COLOR[state], opacity: state === "waiting" ? 1 : 0.95 }}
                  className={state === "running" ? "pulse" : undefined} />
                <div className="row" style={{ gap: 8, flexWrap: "nowrap" }}>
                  <span style={{ width: 22, height: 22, borderRadius: "50%", display: "grid", placeItems: "center", flexShrink: 0,
                    border: `1.5px solid ${STEP_COLOR[state]}`, color: state === "waiting" ? "var(--muted)" : STEP_COLOR[state] }}>
                    {state === "done" ? <Icon name="check" size={13} /> : state === "failed" ? <Icon name="x" size={13} />
                      : state === "running" ? <span className="dot pulse" /> : <span className="small">{i + 1}</span>}
                  </span>
                  <span className={state === "waiting" ? "muted" : "strong"} style={{ fontSize: 13 }}>{stage.label}</span>
                </div>
                <span className="muted small" style={{ lineHeight: 1.35 }}>
                  {state === "running" ? `Running · ${formatDuration(seconds)}` : state === "done" && seconds != null ? `Done in ${formatDuration(seconds)}`
                    : state === "failed" ? "Failed" : stage.hint}
                </span>
              </li>
            );
          })}
        </ol>
        {review.status === "failed" && review.error && (
          <div className="alert alert-error" style={{ marginTop: 16 }}>{review.error}</div>
        )}
      </div>
      <AgentBoard agents={review.progress?.agents} />
    </div>
  );
}

const AGENT_STATUS_COLOR: Record<AgentProgress["status"], string> = {
  running: "var(--accent)",
  completed: "var(--ok)",
  incomplete: "var(--warn)",
  timed_out: "var(--warn)",
  failed: "var(--sev-critical)",
  skipped: "var(--muted)",
};

/** Deep-review agents grouped per category: specialist (+ KPI assessor) then verifier. */
function AgentBoard({ agents }: { agents: Record<string, AgentProgress> | undefined }) {
  if (!agents || !Object.keys(agents).length) return null;
  const groups = new Map<string, { name: string; label: string; info: AgentProgress }[]>();
  for (const [name, info] of Object.entries(agents)) {
    const { role, category, part } = parseAgent(name);
    const key = role === "synthesizer" ? "synthesis" : category;
    const label = role === "synthesizer" ? "Synthesizer" : role === "verifier" ? "Verifier" : part === "kpis" ? "KPI checklist" : "Reviewer";
    groups.set(key, [...(groups.get(key) ?? []), { name, label, info }]);
  }
  const done = Object.values(agents).filter((a) => a.status !== "running").length;
  const running = Object.values(agents).filter((a) => a.status === "running").length;

  return (
    <>
      <hr className="divider" />
      <div className="card-body stack">
        <div className="row">
          <h3>Review agents</h3>
          <span className="muted small">{done} finished{running ? ` · ${running} working now` : ""}</span>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(210px, 1fr))", gap: 8 }}>
          {[...groups.entries()].map(([group, items]) => (
            <div key={group} style={{ background: "var(--surface-2)", border: "1px solid var(--border-soft)", borderRadius: 8, padding: "10px 12px", display: "grid", gap: 6 }}>
              <span className="strong" style={{ fontSize: 13 }}>{categoryName(group)}</span>
              {items.map(({ name, label, info }) => (
                <div key={name} className="row small" style={{ gap: 8, flexWrap: "nowrap" }} title={`${name}: ${info.status}`}>
                  {info.status === "running" ? <Spinner /> : <span className="dot" style={{ color: AGENT_STATUS_COLOR[info.status] }} />}
                  <span className="muted-2">{label}</span>
                  <span className="spacer" />
                  <span className="muted">
                    {info.status === "running" ? "working…" : info.status === "completed"
                      ? `${formatDuration(info.duration_seconds)} · ${info.model_calls ?? 0} calls` : info.status.replace("_", " ")}
                  </span>
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>
    </>
  );
}
