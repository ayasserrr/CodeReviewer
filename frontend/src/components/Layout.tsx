import { NavLink, Outlet, useNavigate } from "react-router-dom";

import { useAuth } from "../auth/AuthContext";
import { Icon, Logo } from "./ui";

export function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark"><Logo /></span>
          CodeReviewer
        </div>
        <nav className="nav">
          <NavLink to="/" end><Icon name="dashboard" />Dashboard</NavLink>
          <NavLink to="/repositories"><Icon name="repo" />Repositories</NavLink>
          <NavLink to="/reviews"><Icon name="review" />Reviews</NavLink>
          <NavLink to="/new"><Icon name="plus" />New review</NavLink>
        </nav>
        <div className="sidebar-footer">
          {user && (
            <div className="user-chip">
              <span className="avatar">{user.email.slice(0, 2).toUpperCase()}</span>
              <span className="truncate small muted-2" title={user.email}>{user.email}</span>
            </div>
          )}
          <button className="btn btn-ghost btn-sm" style={{ justifyContent: "flex-start" }}
            onClick={() => { logout(); navigate("/login"); }}>
            <Icon name="logout" size={15} />Sign out
          </button>
        </div>
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </div>
  );
}
