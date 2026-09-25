import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { api } from "../api/client";
import type { RepositorySummary, ReviewListItem, Severity } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { PixelBot } from "../components/PixelBot";
import { EmptyState, Icon, PageLoading, SeverityBar, SeverityCounts, StatTile, StatusBadge } from "../components/ui";
import { shortSha, timeAgo } from "../lib/format";
import { usePolling } from "../lib/usePolling";

export function DashboardPage() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [repos, setRepos] = useState<RepositorySummary[] | null>(null);
  const [reviews, setReviews] = useState<ReviewListItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    try {
      const [r, v] = await Promise.all([api.repositories(), api.reviews(20)]);
      setRepos(r);
      setReviews(v);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    }
  };
  const anyActive = reviews?.some((r) => r.status === "pending" || r.status === "running") ?? false;
  usePolling(load, anyActive ? 5000 : 60000, true);

  if (!repos || !reviews) return <div className="page">{error ? <div className="alert alert-error">{error}</div> : <PageLoading />}</div>;

  // Headline numbers come from each repository's latest completed review.
  const latest = repos.map((r) => r.latest_review).filter((r) => r?.status === "completed");
  const totals: Partial<Record<Severity, number>> = {};
  for (const r of latest) for (const [sev, n] of Object.entries(r?.issues_summary?.by_severity ?? {})) totals[sev as Severity] = (totals[sev as Severity] ?? 0) + (n ?? 0);
  const openFindings = Object.values(totals).reduce((a, b) => a + (b ?? 0), 0);
  const running = reviews.filter((r) => r.status === "pending" || r.status === "running").length;

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <span className="eyebrow"><Icon name="sparkle" size={13} />{greeting()}{user ? `, ${user.email.split("@")[0]}` : ""}</span>
          <h1>Dashboard</h1>
          <p className="subtitle">Code health across your repositories</p>
        </div>
      </div>

      {repos.length === 0 ? (
        <div className="card has-bot">
          <PixelBot />
          <EmptyState icon="review" title="Run your first review">
            <p>Point CodeReviewer at a GitLab repository. It clones it, runs 10 static-analysis tools and a team of
              AI reviewers, and produces a full engineering report.</p>
            <Link to="/new" className="btn btn-primary" style={{ marginTop: 8 }}>Start a review</Link>
          </EmptyState>
        </div>
      ) : (
        <>
          <div className="grid-4">
            <StatTile accent icon="repo" label="Repositories" value={repos.length} sub={`${reviews.length} recent reviews`} />
            <StatTile icon="bug" label="Open findings" value={openFindings} sub="from each repo's latest review" />
            <StatTile icon="alert" label="Critical + High" value={<span style={{ color: (totals.Critical ?? 0) + (totals.High ?? 0) ? "var(--sev-critical)" : undefined }}>{(totals.Critical ?? 0) + (totals.High ?? 0)}</span>} sub="release blockers" />
            <StatTile icon="activity" label="In progress" value={running} sub={running ? "reviews running now" : "nothing running"} />
          </div>

          <div className="card">
            <div className="card-header"><h2>Severity across repositories</h2><span className="hint">latest completed review per repository</span></div>
            <div className="card-body"><SeverityBar counts={totals} height={12} /></div>
          </div>

          <div className="card has-bot">
            <PixelBot speed={running ? "busy" : "normal"} />
            <div className="card-header">
              <h2>Recent reviews</h2>
              <Link to="/reviews" className="btn btn-ghost btn-sm">View all</Link>
            </div>
            <div className="table-wrap"><table className="table">
              <thead><tr><th>Repository</th><th>Status</th><th className="hide-sm">Commit</th><th>Findings</th><th className="num">Started</th></tr></thead>
              <tbody>
                {reviews.slice(0, 8).map((r) => (
                  <tr key={r.id} className="clickable" onClick={() => navigate(`/reviews/${r.id}`)}>
                    <td><span className="repo-cell"><span className="icon-tile neutral" style={{ width: 30, height: 30 }}><Icon name="repo" size={14} /></span><span className="strong truncate">{r.repository_name}</span></span></td>
                    <td><StatusBadge status={r.status} /></td>
                    <td className="mono muted-2 hide-sm">{shortSha(r.commit_sha)}{r.branch && <span className="muted"> · {r.branch}</span>}</td>
                    <td>{r.status === "completed" ? <SeverityCounts counts={r.issues_summary?.by_severity} /> : <span className="muted small">{r.status === "failed" ? "—" : "in progress…"}</span>}</td>
                    <td className="num muted">{timeAgo(r.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          </div>
        </>
      )}
    </div>
  );
}

function greeting(): string {
  const hour = new Date().getHours();
  return hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening";
}
