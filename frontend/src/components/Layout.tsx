import { NavLink, Outlet, useNavigate } from "react-router-dom";

import { useAuth } from "../auth/AuthContext";
import { useTheme } from "../lib/useTheme";
import { Icon, Logo } from "./ui";

export function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [theme, toggleTheme] = useTheme();
  return (
    <div className="shell">
      <header className="navbar">
        <div className="brand">
          <span className="brand-mark"><Logo /></span>
          <span className="brand-name">CodeReviewer</span>
        </div>
        <nav className="nav">
          <NavLink to="/" end title="Dashboard"><Icon name="dashboard" /><span>Dashboard</span></NavLink>
          <NavLink to="/repositories" title="Repositories"><Icon name="repo" /><span>Repositories</span></NavLink>
          <NavLink to="/reviews" title="Reviews"><Icon name="review" /><span>Reviews</span></NavLink>
          <NavLink to="/new" title="New review"><Icon name="plus" /><span>New review</span></NavLink>
        </nav>
        <div className="navbar-end">
          <button className="btn btn-ghost btn-sm" onClick={toggleTheme}
            title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
            aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}>
            <Icon name={theme === "dark" ? "sun" : "moon"} size={16} />
          </button>
          {user && (
            <div className="user-chip">
              <span className="avatar">{user.email.slice(0, 2).toUpperCase()}</span>
              <span className="truncate small muted-2 hide-sm" title={user.email}>{user.email}</span>
            </div>
          )}
          <button className="btn btn-ghost btn-sm" onClick={() => { logout(); navigate("/login"); }}>
            <Icon name="logout" size={15} /><span className="hide-sm">Sign out</span>
          </button>
        </div>
      </header>
      <main className="main">
        <Outlet />
      </main>
    </div>
  );
}
