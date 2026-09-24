import type { ReactNode } from "react";
import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";

import { AuthProvider, useAuth } from "./auth/AuthContext";
import { Layout } from "./components/Layout";
import { PageLoading } from "./components/ui";
import { AuthPage } from "./pages/AuthPage";
import { DashboardPage } from "./pages/DashboardPage";
import { NewReviewPage } from "./pages/NewReviewPage";
import { RepositoriesPage } from "./pages/RepositoriesPage";
import { RepositoryPage } from "./pages/RepositoryPage";
import { ReviewPage } from "./pages/ReviewPage";
import { ReviewsPage } from "./pages/ReviewsPage";

function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return <PageLoading />;
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <>{children}</>;
}

export function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<AuthPage mode="login" />} />
          <Route path="/register" element={<AuthPage mode="register" />} />
          <Route element={<RequireAuth><Layout /></RequireAuth>}>
            <Route index element={<DashboardPage />} />
            <Route path="new" element={<NewReviewPage />} />
            <Route path="reviews" element={<ReviewsPage />} />
            <Route path="reviews/:id" element={<ReviewPage />} />
            <Route path="repositories" element={<RepositoriesPage />} />
            <Route path="repositories/:id" element={<RepositoryPage />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
