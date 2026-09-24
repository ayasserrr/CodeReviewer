import type {
  AuthResponse,
  IngestionAccepted,
  RepositorySummary,
  ReviewDetail,
  ReviewListItem,
  ReviewRead,
  TokenPair,
  User,
} from "./types";

const API = "/api/v1";
const TOKENS_KEY = "codereviewer.tokens";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

// ---- token storage --------------------------------------------------------

export function loadTokens(): TokenPair | null {
  try {
    const raw = localStorage.getItem(TOKENS_KEY);
    return raw ? (JSON.parse(raw) as TokenPair) : null;
  } catch {
    return null;
  }
}

export function saveTokens(tokens: TokenPair | null): void {
  if (tokens) localStorage.setItem(TOKENS_KEY, JSON.stringify(tokens));
  else localStorage.removeItem(TOKENS_KEY);
}

let onUnauthorized: () => void = () => {};
export function setUnauthorizedHandler(handler: () => void): void {
  onUnauthorized = handler;
}

// One in-flight refresh shared by every request that hit a 401 at once.
let refreshing: Promise<boolean> | null = null;

async function refreshTokens(): Promise<boolean> {
  const tokens = loadTokens();
  if (!tokens) return false;
  refreshing ??= (async () => {
    try {
      const res = await fetch(`${API}/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: tokens.refresh_token }),
      });
      if (!res.ok) return false;
      saveTokens((await res.json()) as TokenPair);
      return true;
    } catch {
      return false;
    } finally {
      setTimeout(() => (refreshing = null), 0);
    }
  })();
  return refreshing;
}

function errorMessage(body: unknown, status: number): string {
  if (body && typeof body === "object" && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail) && detail.length) {
      return detail
        .map((d: { msg?: string }) => (d.msg ?? "Invalid value").replace(/^Value error, /, ""))
        .join("; ");
    }
  }
  if (status === 429) return "Too many requests — please wait a moment and try again.";
  return `Request failed (${status})`;
}

async function request<T>(path: string, init: RequestInit = {}, retry = true): Promise<T> {
  const tokens = loadTokens();
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (tokens) headers.set("Authorization", `Bearer ${tokens.access_token}`);

  const res = await fetch(`${API}${path}`, { ...init, headers });
  if (res.status === 401 && retry && tokens) {
    if (await refreshTokens()) return request<T>(path, init, false);
    saveTokens(null);
    onUnauthorized();
  }
  if (!res.ok) {
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, errorMessage(body, res.status));
  }
  if (res.status === 204) return undefined as T;
  const type = res.headers.get("content-type") ?? "";
  return (type.includes("application/json") ? res.json() : res.text()) as Promise<T>;
}

// ---- endpoints ------------------------------------------------------------

export const api = {
  register: (email: string, password: string) =>
    request<User>("/auth/register", { method: "POST", body: JSON.stringify({ email, password }) }, false),
  login: (email: string, password: string) =>
    request<AuthResponse>("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }, false),
  me: () => request<User>("/auth/me"),

  startReview: (gitlabUrl: string, accessToken: string, repoId?: string) =>
    request<IngestionAccepted>("/ingestion/repositories", {
      method: "POST",
      body: JSON.stringify({ gitlab_url: gitlabUrl, access_token: accessToken, repo_id: repoId || null }),
    }),

  repositories: () => request<RepositorySummary[]>("/repositories?page_size=100"),
  repository: (id: string) => request<RepositorySummary>(`/repositories/${id}`),
  deleteRepository: (id: string) => request<void>(`/repositories/${id}`, { method: "DELETE" }),
  repositoryReviews: (id: string) => request<ReviewRead[]>(`/reviews/repository/${id}?page_size=100`),

  reviews: (pageSize = 50) => request<ReviewListItem[]>(`/reviews?page_size=${pageSize}`),
  reviewStatus: (id: string) => request<ReviewRead>(`/reviews/${id}/status`),
  review: (id: string) => request<ReviewDetail>(`/reviews/${id}`),
  reviewMarkdownUrl: (id: string) => `${API}/reviews/${id}/markdown`,
  reviewMarkdown: (id: string) => request<string>(`/reviews/${id}/markdown`),
};
