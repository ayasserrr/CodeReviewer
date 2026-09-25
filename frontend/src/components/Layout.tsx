import { useEffect, useRef, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";

import { useAuth } from "../auth/AuthContext";
import { useTheme } from "../lib/useTheme";
import { Icon, Logo } from "./ui";

const NAV = [
  { to: "/", label: "Dashboard", icon: "dashboard", end: true },
  { to: "/repositories", label: "Repositories", icon: "repo", end: false },
  { to: "/reviews", label: "Reviews", icon: "review", end: false },
] as const;

/** Avatar button with a small menu: identity, theme toggle, sign out. */
function UserMenu() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [theme, toggleTheme] = useTheme();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onDown); document.removeEventListener("keydown", onKey); };
  }, [open]);

  if (!user) return null;
  const initials = user.email.slice(0, 2).toUpperCase();
  return (
    <div className="user-menu" ref={ref}>
      <button className={`user-trigger${open ? " open" : ""}`} onClick={() => setOpen((o) => !o)}
        aria-haspopup="menu" aria-expanded={open} title={user.email}>
        <span className="avatar">{initials}</span>
        <span className="user-email hide-md">{user.email}</span>
        <Icon name="chevronDown" size={14} style={{ color: "var(--muted)" }} />
      </button>
      {open && (
        <div className="menu" role="menu">
          <div className="menu-head">
            <span className="avatar avatar-lg">{initials}</span>
            <span className="stack" style={{ gap: 0, minWidth: 0 }}>
              <span className="muted small">Signed in as</span>
              <span className="strong truncate">{user.email}</span>
            </span>
          </div>
          <button className="menu-item" role="menuitem" onClick={toggleTheme}>
            <Icon name={theme === "dark" ? "sun" : "moon"} size={15} />
            {theme === "dark" ? "Light mode" : "Dark mode"}
          </button>
          <button className="menu-item menu-item-danger" role="menuitem"
            onClick={() => { setOpen(false); logout(); navigate("/login"); }}>
            <Icon name="logout" size={15} />Sign out
          </button>
        </div>
      )}
    </div>
  );
}

export function Layout() {
  const [theme, toggleTheme] = useTheme();
  const { pathname } = useLocation();
  useEffect(() => { window.scrollTo(0, 0); }, [pathname]);

  return (
    <div className="shell">
      <header className="navbar">
        <div className="navbar-inner">
          <Link to="/" className="brand" aria-label="CodeReviewer home">
            <span className="brand-mark"><Logo /></span>
            <span className="brand-name">CodeReviewer</span>
          </Link>
          <nav className="nav" aria-label="Main">
            {NAV.map((item) => (
              <NavLink key={item.to} to={item.to} end={item.end} className="nav-link" title={item.label}>
                <Icon name={item.icon} size={16} /><span>{item.label}</span>
              </NavLink>
            ))}
          </nav>
          <div className="navbar-end">
            <NavLink to="/new" className="btn btn-primary btn-sm nav-cta" title="New review">
              <Icon name="plus" size={15} /><span className="hide-sm">New review</span>
            </NavLink>
            <button className="icon-btn hide-sm" onClick={toggleTheme}
              title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
              aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}>
              <Icon name={theme === "dark" ? "sun" : "moon"} size={17} />
            </button>
            <UserMenu />
          </div>
        </div>
      </header>
      <main className="main">
        <Outlet />
      </main>
      <footer className="footer">
        <span className="row" style={{ gap: 8 }}><Logo size={14} />CodeReviewer</span>
        <span>Static analysis + AI specialist reviews, independently verified</span>
      </footer>
    </div>
  );
}
