import { useState, type FormEvent } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";

import { ApiError } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { PixelBot } from "../components/PixelBot";
import { Icon, Logo, Spinner } from "../components/ui";

const FEATURES = [
  { icon: "layers", title: "10 static analyzers, one report", text: "Ruff, Pyright, Semgrep, Bandit, gitleaks, pip-audit and more — triaged, not dumped." },
  { icon: "shield", title: "Specialist AI reviewers", text: "Security, auth, performance, LLM usage, correctness — each lane with its own leads." },
  { icon: "check", title: "Independently verified", text: "Every finding is re-checked against the code before it reaches the report." },
];

export function AuthPage({ mode }: { mode: "login" | "register" }) {
  const { user, login, register } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const from = (location.state as { from?: string } | null)?.from ?? "/";

  if (user) return <Navigate to={from} replace />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (mode === "login") await login(email, password);
      else await register(email, password);
      navigate(from, { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong. Is the API running?");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth-wrap">
      <aside className="auth-aside">
        <div className="brand"><span className="brand-mark"><Logo /></span>CodeReviewer</div>
        <div>
          <h2>Engineering reviews that read like <em>your senior team</em> wrote them.</h2>
          <p className="lead">Point it at a GitLab repository. It maps the code, runs the analyzers and a team of
            AI specialists, and hands back a prioritised, evidence-cited report.</p>
        </div>
        <PixelBot />
        <ul className="auth-features">
          {FEATURES.map((f) => (
            <li key={f.title}>
              <span className="icon-tile"><Icon name={f.icon} size={17} /></span>
              <span><strong>{f.title}</strong><span>{f.text}</span></span>
            </li>
          ))}
        </ul>
      </aside>
      <div className="auth-main">
        <form className="card auth-card" onSubmit={submit}>
          <div className="brand auth-mobile-brand"><span className="brand-mark"><Logo /></span>CodeReviewer</div>
          <div style={{ display: "grid", gap: 6 }}>
            <h1>{mode === "login" ? "Welcome back" : "Create your account"}</h1>
            <p className="muted">{mode === "login" ? "Sign in to see your repositories and reviews." : "Start reviewing your repositories in minutes."}</p>
          </div>
          {error && <div className="alert alert-error"><Icon name="alert" size={15} />{error}</div>}
          <div className="field">
            <label htmlFor="email">Email</label>
            <input id="email" className="input" type="email" autoComplete="email" required placeholder="you@company.com"
              value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="password">Password</label>
            <input id="password" className="input" type="password" required minLength={8} maxLength={64} placeholder="••••••••"
              autoComplete={mode === "login" ? "current-password" : "new-password"} value={password} onChange={(e) => setPassword(e.target.value)} />
            {mode === "register" && <span className="help">8–64 characters, with upper- and lowercase letters, a number and a symbol.</span>}
          </div>
          <button className="btn btn-primary btn-lg" disabled={busy} type="submit">
            {busy && <Spinner />}{mode === "login" ? "Sign in" : "Create account"}
            {!busy && <Icon name="arrowRight" size={16} />}
          </button>
          <p className="muted small" style={{ textAlign: "center" }}>
            {mode === "login" ? <>No account? <Link to="/register" className="strong">Create one</Link></>
              : <>Already registered? <Link to="/login" className="strong">Sign in</Link></>}
          </p>
        </form>
      </div>
    </div>
  );
}
