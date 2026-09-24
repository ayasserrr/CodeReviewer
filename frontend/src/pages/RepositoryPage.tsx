import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { api, ApiError } from "../api/client";
import type { RepositorySummary, ReviewRead } from "../api/types";
import { EmptyState, Icon, PageLoading, SeverityCounts, StatusBadge } from "../components/ui";
import { formatDuration, secondsBetween, shortSha, timeAgo } from "../lib/format";
import { usePolling } from "../lib/usePolling";

export function RepositoryPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const [repo, setRepo] = useState<RepositorySummary | null>(null);
  const [reviews, setReviews] = useState<ReviewRead[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  const active = reviews?.some((r) => r.status === "pending" || r.status === "running") ?? false;
  usePolling(async () => {
    try {
      const [r, v] = await Promise.all([api.repository(id), api.repositoryReviews(id)]);
      setRepo(r);
      setReviews(v);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load");
    }
  }, active ? 5000 : 60000, !error);

  const remove = async () => {
    if (!repo || !window.confirm(`Delete ${repo.name} and all ${repo.review_count} of its reviews? This cannot be undone.`)) return;
    setDeleting(true);
    try {
      await api.deleteRepository(repo.id);
      navigate("/repositories");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Delete failed");
      setDeleting(false);
    }
  };

  if (error && !repo) return <div className="page"><div className="card"><EmptyState icon="repo" title="Repository not found"><p>{error}</p></EmptyState></div></div>;
  if (!repo || !reviews) return <div className="page"><PageLoading /></div>;

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="breadcrumb"><Link to="/repositories">Repositories</Link></div>
          <h1>{repo.name}</h1>
          <p className="subtitle row" style={{ gap: 14 }}>
            <span className="mono">{repo.clone_url}</span>
            <span className="row mono" style={{ gap: 5 }}><Icon name="branch" size={13} />{repo.default_branch ?? "—"} · {shortSha(repo.head_sha)}</span>
          </p>
        </div>
        <div className="row">
          <button className="btn btn-danger" onClick={remove} disabled={deleting || active} title={active ? "A review is still running" : undefined}>
            <Icon name="trash" size={14} />Delete
          </button>
          <Link to={`/new?repo=${repo.id}`} className="btn btn-primary"><Icon name="refresh" size={14} />Review again</Link>
        </div>
      </div>
      {error && <div className="alert alert-error">{error}</div>}
      <div className="card">
        <div className="card-header"><h2>Review history</h2><span className="hint">{reviews.length} review{reviews.length === 1 ? "" : "s"}</span></div>
        {reviews.length === 0 ? <EmptyState title="No reviews yet" /> : (
          <table className="table">
            <thead><tr><th>Status</th><th>Commit</th><th>Findings</th><th className="num">Duration</th><th className="num">Started</th></tr></thead>
            <tbody>
              {reviews.map((r) => (
                <tr key={r.id} className="clickable" onClick={() => navigate(`/reviews/${r.id}`)}>
                  <td><StatusBadge status={r.status} /></td>
                  <td className="mono muted-2">{shortSha(r.commit_sha)}{r.branch && <span className="muted"> · {r.branch}</span>}</td>
                  <td>{r.status === "completed" ? <SeverityCounts counts={r.issues_summary?.by_severity} /> : <span className="muted small">{r.status === "failed" ? "failed" : "in progress…"}</span>}</td>
                  <td className="num muted">{r.completed_at ? formatDuration(secondsBetween(r.created_at, r.completed_at)) : "—"}</td>
                  <td className="num muted">{timeAgo(r.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
