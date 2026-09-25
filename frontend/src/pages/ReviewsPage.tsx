import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { api } from "../api/client";
import type { ReviewListItem, ReviewStatus } from "../api/types";
import { PixelBot } from "../components/PixelBot";
import { EmptyState, Icon, PageLoading, SeverityCounts, StatusBadge } from "../components/ui";
import { formatDuration, secondsBetween, shortSha, STATUS_META, timeAgo } from "../lib/format";
import { usePolling } from "../lib/usePolling";

export function ReviewsPage() {
  const navigate = useNavigate();
  const [reviews, setReviews] = useState<ReviewListItem[] | null>(null);
  const [filter, setFilter] = useState<ReviewStatus | "all">("all");

  const active = reviews?.some((r) => r.status === "pending" || r.status === "running") ?? false;
  usePolling(async () => setReviews(await api.reviews(100)), active ? 5000 : 60000, true);

  if (!reviews) return <div className="page"><PageLoading /></div>;
  const shown = filter === "all" ? reviews : reviews.filter((r) => r.status === filter);

  return (
    <div className="page">
      <div className="page-header">
        <div><h1>Reviews</h1><p className="subtitle">Every review across your repositories</p></div>
        <PixelBot busy={active} />
        <Link to="/new" className="btn btn-primary"><Icon name="plus" size={15} />New review</Link>
      </div>
      <div className="row" style={{ gap: 8 }}>
        {(["all", "running", "completed", "failed"] as const).map((f) => (
          <button key={f} className={`chip${filter === f ? " on" : ""}`} onClick={() => setFilter(f)}>
            {f === "all" ? "All" : STATUS_META[f].label}
            <span className="muted">{f === "all" ? reviews.length : reviews.filter((r) => r.status === f || (f === "running" && r.status === "pending")).length}</span>
          </button>
        ))}
      </div>
      <div className="card">
        {shown.length === 0 ? <EmptyState title="No reviews here yet" /> : (
          <div className="table-wrap"><table className="table">
            <thead><tr><th>Repository</th><th>Status</th><th className="hide-sm">Commit</th><th>Findings</th><th className="num hide-sm">Duration</th><th className="num">Started</th></tr></thead>
            <tbody>
              {shown.map((r) => (
                <tr key={r.id} className="clickable" onClick={() => navigate(`/reviews/${r.id}`)}>
                  <td className="strong">{r.repository_name}</td>
                  <td><StatusBadge status={r.status} /></td>
                  <td className="mono muted-2 hide-sm">{shortSha(r.commit_sha)}</td>
                  <td>{r.status === "completed" ? <SeverityCounts counts={r.issues_summary?.by_severity} /> : <span className="muted small">{r.status === "failed" ? (r.error ?? "failed").slice(0, 60) : "in progress…"}</span>}</td>
                  <td className="num muted hide-sm">{r.completed_at ? formatDuration(secondsBetween(r.created_at, r.completed_at)) : "—"}</td>
                  <td className="num muted">{timeAgo(r.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </div>
    </div>
  );
}
