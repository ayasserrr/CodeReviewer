import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { api } from "../api/client";
import type { RepositorySummary } from "../api/types";
import { EmptyState, Icon, PageLoading, SeverityCounts, StatusBadge } from "../components/ui";
import { shortSha, timeAgo } from "../lib/format";
import { usePolling } from "../lib/usePolling";

export function RepositoriesPage() {
  const navigate = useNavigate();
  const [repos, setRepos] = useState<RepositorySummary[] | null>(null);
  const active = repos?.some((r) => r.latest_review && ["pending", "running"].includes(r.latest_review.status)) ?? false;
  usePolling(async () => setRepos(await api.repositories()), active ? 5000 : 60000, true);

  if (!repos) return <div className="page"><PageLoading /></div>;
  return (
    <div className="page">
      <div className="page-header">
        <div><h1>Repositories</h1><p className="subtitle">{repos.length} repositor{repos.length === 1 ? "y" : "ies"}</p></div>
        <Link to="/new" className="btn btn-primary"><Icon name="plus" size={15} />New review</Link>
      </div>
      {repos.length === 0 ? (
        <div className="card"><EmptyState icon="repo" title="No repositories yet"><Link to="/new" className="btn btn-primary">Review one</Link></EmptyState></div>
      ) : (
        <div className="grid-3">
          {repos.map((r) => (
            <div key={r.id} className="card card-pad stack clickable" style={{ gap: 12, cursor: "pointer" }} onClick={() => navigate(`/repositories/${r.id}`)}>
              <div className="row" style={{ gap: 10, flexWrap: "nowrap" }}>
                <span style={{ width: 34, height: 34, borderRadius: 8, background: "var(--surface-2)", border: "1px solid var(--border)", display: "grid", placeItems: "center", color: "var(--accent)" }}>
                  <Icon name="repo" size={16} />
                </span>
                <span className="stack" style={{ gap: 0, minWidth: 0 }}>
                  <span className="strong truncate">{r.name}</span>
                  <span className="muted small truncate">{r.clone_url.replace(/^https?:\/\//, "").replace(/\.git$/, "")}</span>
                </span>
              </div>
              <div className="row small muted" style={{ gap: 12 }}>
                <span className="row mono" style={{ gap: 5 }}><Icon name="branch" size={13} />{r.default_branch ?? "—"} · {shortSha(r.head_sha)}</span>
                <span>{r.review_count} review{r.review_count === 1 ? "" : "s"}</span>
              </div>
              <hr className="divider" />
              {r.latest_review ? (
                <div className="row" style={{ gap: 10 }}>
                  <StatusBadge status={r.latest_review.status} />
                  {r.latest_review.status === "completed" && <SeverityCounts counts={r.latest_review.issues_summary?.by_severity} />}
                  <span className="spacer" />
                  <span className="muted small">{timeAgo(r.latest_review.created_at)}</span>
                </div>
              ) : <span className="muted small">Not reviewed yet</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
