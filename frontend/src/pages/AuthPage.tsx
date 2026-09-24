import { useState, type FormEvent } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";

import { ApiError } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { Logo, Spinner } from "../components/ui";

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
      <form className="card auth-card" onSubmit={submit}>
        <div className="brand"><span className="brand-mark"><Logo /></span>CodeReviewer</div>
        <div style={{ textAlign: "center", display: "grid", gap: 4 }}>
          <h1>{mode === "login" ? "Welcome back" : "Create your account"}</h1>
          <p className="muted">AI-powered engineering reviews for your repositories</p>
        </div>
        {error && <div className="alert alert-error">{error}</div>}
        <div className="field">
          <label htmlFor="email">Email</label>
          <input id="email" className="input" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <input id="password" className="input" type="password" required minLength={8} maxLength={64}
            autoComplete={mode === "login" ? "current-password" : "new-password"} value={password} onChange={(e) => setPassword(e.target.value)} />
          {mode === "register" && <span className="help">8–64 characters, with upper- and lowercase letters, a number and a symbol.</span>}
        </div>
        <button className="btn btn-primary" disabled={busy} type="submit">
          {busy && <Spinner />}{mode === "login" ? "Sign in" : "Create account"}
        </button>
        <p className="muted small" style={{ textAlign: "center" }}>
          {mode === "login" ? <>No account? <Link to="/register" className="strong">Create one</Link></>
            : <>Already registered? <Link to="/login" className="strong">Sign in</Link></>}
        </p>
      </form>
    </div>
  );
}
