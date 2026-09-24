import { useEffect, useState, type FormEvent } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import { api, ApiError } from "../api/client";
import type { RepositorySummary } from "../api/types";
import { Icon, Spinner } from "../components/ui";
import { PIPELINE_STAGES } from "../lib/format";

export function NewReviewPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [gitlabUrl, setGitlabUrl] = useState("");
  const [token, setToken] = useState("");
  const [repoId, setRepoId] = useState(params.get("repo") ?? "");
  const [repos, setRepos] = useState<RepositorySummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.repositories().then((r) => {
      setRepos(r);
      const preset = r.find((x) => x.id === params.get("repo"));
      if (preset) setGitlabUrl(preset.clone_url.replace(/\.git$/, ""));
    }).catch(() => {});
  }, [params]);

  const pickRepo = (id: string) => {
    setRepoId(id);
    const repo = repos.find((r) => r.id === id);
    if (repo) setGitlabUrl(repo.clone_url.replace(/\.git$/, ""));
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const res = await api.startReview(gitlabUrl.trim(), token, repoId || undefined);
      navigate(`/reviews/${res.review_report_id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not start the review.");
      setBusy(false);
    }
  };

  return (
    <div className="page" style={{ maxWidth: 980 }}>
      <div className="page-header">
        <div>
          <h1>New review</h1>
          <p className="subtitle">Review a GitLab repository's default branch end to end</p>
        </div>
      </div>
      <div className="grid-form">
        <form className="card card-pad stack" style={{ gap: 16 }} onSubmit={submit}>
          {error && <div className="alert alert-error">{error}</div>}
          {repos.length > 0 && (
            <div className="field">
              <label htmlFor="repo">Repository</label>
              <select id="repo" className="select" value={repoId} onChange={(e) => pickRepo(e.target.value)}>
                <option value="">A new repository</option>
                {repos.map((r) => <option key={r.id} value={r.id}>Re-review {r.name}</option>)}
              </select>
              <span className="help">Re-reviewing keeps the history together; an unchanged commit reuses cached results.</span>
            </div>
          )}
          <div className="field">
            <label htmlFor="url">GitLab repository URL</label>
            <input id="url" className="input" required placeholder="https://gitlab.com/group/project" value={gitlabUrl} onChange={(e) => setGitlabUrl(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="token">Access token</label>
            <input id="token" className="input" type="password" required autoComplete="off" placeholder="glpat-…" value={token} onChange={(e) => setToken(e.target.value)} />
            <span className="help">A GitLab token with <code>read_repository</code> and <code>read_api</code>. Used only for this clone — never stored or logged.</span>
          </div>
          <button className="btn btn-primary" type="submit" disabled={busy}>
            {busy ? <Spinner /> : <Icon name="bolt" size={15} />}Start review
          </button>
        </form>

        <div className="card card-pad stack" style={{ gap: 12 }}>
          <h2>What happens next</h2>
          <ol style={{ margin: 0, padding: 0, listStyle: "none", display: "grid", gap: 12 }}>
            {PIPELINE_STAGES.map((s, i) => (
              <li key={s.id} className="row" style={{ gap: 10, flexWrap: "nowrap", alignItems: "flex-start" }}>
                <span style={{ width: 22, height: 22, borderRadius: "50%", border: "1px solid var(--border)", display: "grid", placeItems: "center", fontSize: 11.5, color: "var(--muted-2)", flexShrink: 0 }}>{i + 1}</span>
                <span className="stack" style={{ gap: 1 }}>
                  <span className="strong small">{s.label}</span>
                  <span className="muted small">{s.hint}</span>
                </span>
              </li>
            ))}
          </ol>
          <p className="muted small">Typically 5–10 minutes. You can leave the page — the review keeps running.</p>
        </div>
      </div>
    </div>
  );
}
