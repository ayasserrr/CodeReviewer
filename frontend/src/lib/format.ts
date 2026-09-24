import type { KpiStatus, ReviewStatus, Severity } from "../api/types";

export const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low"];

export const SEVERITY_COLOR: Record<Severity, string> = {
  Critical: "var(--sev-critical)",
  High: "var(--sev-high)",
  Medium: "var(--sev-medium)",
  Low: "var(--sev-low)",
};

export const PIPELINE_STAGES: { id: string; label: string; hint: string }[] = [
  { id: "ingest", label: "Clone", hint: "Fetch the repository snapshot" },
  { id: "discovery", label: "Discovery", hint: "Map files, languages, frameworks, endpoints" },
  { id: "static_analysis", label: "Static analysis", hint: "10 linters, type checkers and security scanners" },
  { id: "dependency_graph", label: "Dependency graph", hint: "Functions, classes, calls and imports" },
  { id: "deep_review", label: "Deep review", hint: "Parallel AI reviewers, verification and synthesis" },
];

export const KPI_STATUS: Record<KpiStatus, { label: string; color: string; icon: string }> = {
  open: { label: "Open", color: "var(--sev-critical)", icon: "✕" },
  partially_open: { label: "Partially open", color: "var(--warn)", icon: "!" },
  closed: { label: "Closed", color: "var(--ok)", icon: "✓" },
  not_applicable: { label: "Not applicable", color: "var(--muted)", icon: "–" },
  not_verified: { label: "Not verified", color: "var(--info)", icon: "?" },
};

export const STATUS_META: Record<ReviewStatus, { label: string; color: string }> = {
  pending: { label: "Queued", color: "var(--info)" },
  running: { label: "Running", color: "var(--warn)" },
  completed: { label: "Completed", color: "var(--ok)" },
  failed: { label: "Failed", color: "var(--sev-critical)" },
};

export function timeAgo(iso: string | null | undefined): string {
  if (!iso) return "—";
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return "just now";
  const units: [number, string][] = [
    [60, "minute"],
    [3600, "hour"],
    [86400, "day"],
    [604800, "week"],
    [2629800, "month"],
  ];
  let unit = units[0];
  for (const u of units) if (seconds >= u[0]) unit = u;
  const n = Math.floor(seconds / unit[0]);
  return `${n} ${unit[1]}${n === 1 ? "" : "s"} ago`;
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null || !Number.isFinite(seconds)) return "—";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return m < 60 ? `${m}m ${s.toString().padStart(2, "0")}s` : `${Math.floor(m / 60)}h ${m % 60}m`;
}

export function secondsBetween(start?: string | null, end?: string | null): number | null {
  if (!start) return null;
  return ((end ? new Date(end) : new Date()).getTime() - new Date(start).getTime()) / 1000;
}

export function shortSha(sha: string | null | undefined): string {
  return sha ? sha.slice(0, 8) : "—";
}

export function formatNumber(n: number): string {
  return new Intl.NumberFormat("en", { notation: n >= 100_000 ? "compact" : "standard" }).format(n);
}

/** "specialist:security-kpis" -> { role: "specialist", category: "security", part: "kpis" } */
export function parseAgent(name: string): { role: string; category: string; part: string | null } {
  const [role, rest = ""] = name.split(":");
  const [category, part] = rest.split(/-(kpis)$/);
  return { role, category: category || rest, part: part ?? null };
}

const CATEGORY_NAMES: Record<string, string> = {
  integration: "Integration",
  security: "Security",
  auth: "Auth & sessions",
  observability: "Observability",
  testing: "Testing & CI",
  secrets: "Secrets",
  performance: "Performance",
  llm: "AI / LLM usage",
  inputs: "Input controls",
  correctness: "Correctness",
  maintainability: "Maintainability",
  dependencies: "Dependencies",
  synthesis: "Synthesis",
};

/** Short display name for a review category id (falls back to a humanized id). */
export function categoryName(id: string): string {
  return CATEGORY_NAMES[id] ?? id.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}
