import type { CSSProperties, ReactNode } from "react";

import type { KpiStatus, ReviewStatus, Severity } from "../api/types";
import { KPI_STATUS, SEVERITIES, SEVERITY_COLOR, STATUS_META } from "../lib/format";

// ---- icons (inline SVG, stroke = currentColor) ------------------------------

const PATHS: Record<string, string> = {
  dashboard: "M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z",
  repo: "M4 4h11a3 3 0 0 1 3 3v13H7a3 3 0 0 1-3-3zM4 17a3 3 0 0 1 3-3h11",
  review: "M9 11l3 3 8-8M20 12v6a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h9",
  plus: "M12 5v14M5 12h14",
  logout: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9",
  check: "M5 12l5 5L20 7",
  x: "M18 6L6 18M6 6l12 12",
  clock: "M12 7v5l3 2M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z",
  file: "M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8zM14 3v5h5",
  download: "M12 4v12M6 11l6 6 6-6M4 20h16",
  shield: "M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z",
  search: "M11 18a7 7 0 1 1 0-14 7 7 0 0 1 0 14zM21 21l-4.3-4.3",
  chevron: "M9 6l6 6-6 6",
  trash: "M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3",
  refresh: "M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7",
  branch: "M6 3v12M18 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM6 21a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM18 9a9 9 0 0 1-9 9",
  bolt: "M13 2L4 14h7l-1 8 9-12h-7z",
  layers: "M12 3l9 5-9 5-9-5zM3 13l9 5 9-5",
};

export function Icon({ name, size = 16, style }: { name: keyof typeof PATHS | string; size?: number; style?: CSSProperties }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ flexShrink: 0, ...style }}>
      <path d={PATHS[name] ?? ""} />
    </svg>
  );
}

export function Logo({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth={2.6}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M8 6l-6 6 6 6M16 6l6 6-6 6" />
    </svg>
  );
}

// ---- badges -----------------------------------------------------------------

export function Badge({ color, children, title }: { color?: string; children: ReactNode; title?: string }) {
  return (
    <span className="badge" title={title} style={color ? { color, borderColor: `color-mix(in srgb, ${color} 40%, transparent)` } : undefined}>
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge color={SEVERITY_COLOR[severity]}>
      <span className="dot" />
      {severity}
    </Badge>
  );
}

export function StatusBadge({ status }: { status: ReviewStatus }) {
  const meta = STATUS_META[status];
  return (
    <Badge color={meta.color}>
      {status === "running" || status === "pending" ? <span className="dot pulse" /> : <span className="dot" />}
      {meta.label}
    </Badge>
  );
}

export function KpiBadge({ status }: { status: KpiStatus }) {
  const meta = KPI_STATUS[status];
  return (
    <Badge color={meta.color}>
      <span aria-hidden="true" style={{ fontWeight: 800 }}>{meta.icon}</span>
      {meta.label}
    </Badge>
  );
}

// ---- layout pieces ----------------------------------------------------------

export function Spinner({ large }: { large?: boolean }) {
  return <span className={`spinner${large ? " spinner-lg" : ""}`} role="status" aria-label="Loading" />;
}

export function PageLoading() {
  return (
    <div className="empty">
      <Spinner large />
    </div>
  );
}

export function EmptyState({ icon = "review", title, children }: { icon?: string; title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <Icon name={icon} size={28} style={{ color: "var(--muted)" }} />
      <h3>{title}</h3>
      {children}
    </div>
  );
}

export function StatTile({ label, value, sub, accent }: { label: string; value: ReactNode; sub?: ReactNode; accent?: boolean }) {
  return (
    <div className={`card stat${accent ? " stat-accent" : ""}`}>
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
      {sub != null && <span className="stat-sub">{sub}</span>}
    </div>
  );
}

// ---- severity distribution ---------------------------------------------------

/** One stacked bar (2px surface gaps between segments) + a labelled legend; each segment has a hover title. */
export function SeverityBar({ counts, height = 10 }: { counts: Partial<Record<Severity, number>>; height?: number }) {
  const total = SEVERITIES.reduce((sum, s) => sum + (counts[s] ?? 0), 0);
  if (!total) return <div className="muted small">No findings</div>;
  return (
    <div className="stack" style={{ gap: 10 }}>
      <div role="img" aria-label={SEVERITIES.map((s) => `${counts[s] ?? 0} ${s}`).join(", ")}
        style={{ display: "flex", gap: 2, height, borderRadius: 4, overflow: "hidden", background: "var(--surface-2)" }}>
        {SEVERITIES.filter((s) => counts[s]).map((s) => (
          <div key={s} title={`${s}: ${counts[s]} (${Math.round(((counts[s] ?? 0) / total) * 100)}%)`}
            style={{ flex: counts[s], background: SEVERITY_COLOR[s], minWidth: 4 }} />
        ))}
      </div>
      <div className="row" style={{ gap: 14 }}>
        {SEVERITIES.map((s) => (
          <span key={s} className="row small" style={{ gap: 6 }}>
            <span className="dot" style={{ color: SEVERITY_COLOR[s] }} />
            <span className="muted-2">{s}</span>
            <span className="strong">{counts[s] ?? 0}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

/** Compact inline counts for tables: "2 C · 7 H · 12 M · 6 L" with colored dots. */
export function SeverityCounts({ counts }: { counts: Partial<Record<Severity, number>> | undefined }) {
  if (!counts || !SEVERITIES.some((s) => counts[s])) return <span className="muted small">No findings</span>;
  return (
    <span className="row small" style={{ gap: 10 }}>
      {SEVERITIES.filter((s) => counts[s]).map((s) => (
        <span key={s} className="row" style={{ gap: 5 }} title={`${counts[s]} ${s}`}>
          <span className="dot" style={{ color: SEVERITY_COLOR[s] }} />
          <span className="strong">{counts[s]}</span>
          <span className="muted">{s[0]}</span>
        </span>
      ))}
    </span>
  );
}
