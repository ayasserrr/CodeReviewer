import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { api, ApiError } from "../api/client";
import type { ReviewDetail, ReviewRead } from "../api/types";
import { PipelineTracker } from "../components/PipelineTracker";
import { ReportView } from "../components/ReportView";
import { Badge, EmptyState, Icon, PageLoading, StatusBadge } from "../components/ui";
import { shortSha, timeAgo } from "../lib/format";
import { usePolling } from "../lib/usePolling";

/** Polls the lightweight /status endpoint while the run is in flight, then loads the full report once. */
export function ReviewPage() {
  const { id = "" } = useParams();
  const [status, setStatus] = useState<ReviewRead | null>(null);
  const [detail, setDetail] = useState<ReviewDetail | null>(null);
  const [error, setError] = useState<{ code: number; message: string } | null>(null);
  const [repoName, setRepoName] = useState<string | null>(null);

  const active = !status || status.status === "pending" || status.status === "running";

  const poll = useCallback(async () => {
    try {
      const s = await api.reviewStatus(id);
      setStatus(s);
      if (s.status === "completed" || s.status === "failed") setDetail(await api.review(id));
    } catch (e) {
      setError(e instanceof ApiError ? { code: e.status, message: e.message } : { code: 0, message: "Failed to load" });
    }
  }, [id]);
  usePolling(poll, 3000, active && !error);

  const repositoryId = status?.repository_id;
  useEffect(() => {
    if (repositoryId) api.repository(repositoryId).then((r) => setRepoName(r.name)).catch(() => {});
  }, [repositoryId]);

  if (error) {
    return (
      <div className="page">
        <div className="card">
          <EmptyState icon="review" title={error.code === 404 ? "Review not found" : "Could not load this review"}>
            <p>{error.message}</p>
            <Link to="/reviews" className="btn" style={{ marginTop: 8 }}>Back to reviews</Link>
          </EmptyState>
        </div>
      </div>
    );
  }
  if (!status) return <div className="page"><PageLoading /></div>;

  const name = detail?.report_data?.repository_name ?? repoName;
  return (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="breadcrumb">
            <Link to="/reviews">Reviews</Link><Icon name="chevron" size={12} />
            <Link to={`/repositories/${status.repository_id}`}>{name ?? "Repository"}</Link>
          </div>
          <div className="row" style={{ gap: 12 }}>
            <h1>{name ? `${name} — engineering review` : "Engineering review"}</h1>
            <StatusBadge status={status.status} />
          </div>
          <p className="subtitle row" style={{ gap: 14, marginTop: 6 }}>
            {status.commit_sha && <span className="row mono" style={{ gap: 6 }}><Icon name="branch" size={13} />{status.branch} · {shortSha(status.commit_sha)}</span>}
            <span>Started {timeAgo(status.created_at)}</span>
            {status.model && <Badge>{status.model}</Badge>}
          </p>
        </div>
        {status.status === "completed" && (
          <Link to={`/new?repo=${status.repository_id}`} className="btn"><Icon name="refresh" size={14} />Review again</Link>
        )}
      </div>

      {(active || status.status === "failed") && <PipelineTracker review={status} />}
      {active && (
        <div className="alert alert-info">
          The review runs in the background — you can leave this page and come back. This view updates live.
        </div>
      )}
      {status.status === "completed" && !detail && <PageLoading />}
      {status.status === "completed" && detail && (
        <>
          <ReportView review={detail} />
          <details className="card">
            <summary className="card-header" style={{ cursor: "pointer", listStyle: "none" }}>
              <h2>Pipeline run</h2><span className="hint">stages and agents</span>
            </summary>
            <PipelineTracker review={status} />
          </details>
        </>
      )}
    </div>
  );
}
