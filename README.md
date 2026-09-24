# CodeReviewer

An automated code-review service. Point it at a GitLab repository and it clones the repo,
builds a structural understanding of the codebase (dependency graph, static analysis, security
scans), then runs a multi-agent LLM review that reads the real code, verifies its own findings,
and produces a findings-based engineering review — evidence-cited, severity-rated, false
positives triaged out.

## Pipeline

One [LangGraph](https://github.com/langchain-ai/langgraph) graph, five stages, each a thin node
delegating to its own controller (`src/nodes/` → `src/controllers/`):

1. **Ingest** (`ingest`) — clones the GitLab repository into an isolated workspace, verifies
   integrity, publishes it atomically to `cloned_repos/<repository_id>/`.
2. **Discovery** (`discovery`) — deterministic, no LLM: classifies every file, parses Python ASTs,
   detects frameworks/entrypoints/HTTP endpoints, parses dependency manifests. Produces the
   versioned, cached `RepositoryManifest` every later stage reads instead of re-scanning.
3. **Static analysis** (`static_analysis`) — ten tools across two tracks: structural
   (`ruff`, `pyright`, `radon`, `vulture`, `jscpd`, `lizard`) run sequentially, security
   (`pip-audit`, `semgrep`, `bandit`, `gitleaks`) run concurrently. Every finding is normalized
   and content-hashed.
4. **Dependency graph** (`dependency_graph`) — [tree-sitter](https://tree-sitter.github.io/) for
   function/class/call extraction (flattened: every call in a function's body, however deeply
   nested, not just direct statements) plus [grimp](https://github.com/seddonym/grimp) for the
   module import graph, isolated in a subprocess since building it means importing the target
   repo's own code.
5. **Deep review** (`deep_review`) — a [deepagents](https://github.com/langchain-ai/deepagents)
   multi-agent review built on everything above. See below.

Every stage after Ingest is cached by content hash (commit SHA + engine/schema version, plus the
review config's hash for Deep Review) — an unchanged repository at the same commit skips
straight to the cached result instead of re-running.

### The deep-review agents

One specialist agent per enabled category in `src/assets/review_config.toml` (security,
correctness, performance, dependencies, ...), run concurrently, each with read-only filesystem
access to the clone, the dependency-graph and static-analysis query tools, and a
`general-purpose` code-explorer subagent it can fan broad sweeps out to. A specialist's
high-severity findings are then re-checked by an independent verifier agent — pipelined per
category, so verification overlaps with the slower categories rather than adding a whole extra
phase. A synthesizer agent de-duplicates across categories and writes the executive summary
(scope, verdict, priority order, root causes). No single agent's failure or timeout fails the
whole review — whatever it had already recorded is kept, and its section gets a coverage warning.

Runs on Gemini (`gemini-2.5-flash` by default for the read-heavy roles; a stronger judge model,
`gemini-3.1-pro-preview` by default, for the verifier and synthesizer — live testing showed the
base model alone as verifier lets praise and false "unused" findings through, while the stronger
judge model rejects them correctly).

## Setup

Requires Python 3.13, [uv](https://docs.astral.sh/uv/), and a PostgreSQL instance.

```bash
uv sync --group dev --group analysis-tools
```

`analysis-tools` installs everything pip-installable for the static-analysis tools (`ruff`,
`pyright`, `radon`, `vulture`, `lizard`, `bandit`, `pip-audit`). Two tools need a separate install:

- **semgrep** — deliberately *not* in `analysis-tools`: it pins `wcmatch<9`, which conflicts with
  deepagents' `wcmatch>=11`. Install it in its own isolated tool environment instead:

  ```bash
  uv tool install "semgrep>=1.177.0"
  ```

  It runs fully offline against the project's own bundled ruleset
  (`src/assets/semgrep/python-security.yml`: SQL injection via built queries, command injection,
  eval/exec, unsafe deserialization, disabled autoescaping/TLS/JWT verification, weak hashes,
  debug mode, hard-coded secrets, …). Set `SEMGREP_CONFIG=auto` to use the online registry instead.

- **jscpd** (copy-paste duplication) — not a Python package; install via npm:

  ```bash
  npm install -g jscpd
  ```

**gitleaks** needs no separate install — a bundled binary ships at `src/assets/gitleaks.exe`
(Windows) and is resolved automatically; on other platforms it falls back to a `gitleaks` on
`PATH` (`helpers.tool_bootstrap.resolve_gitleaks_bin`).

Every required tool is checked up front (`helpers.tool_bootstrap.verify_tools_available`) before
the Static Analysis node touches a repository — a clear error listing everything missing, not a
partial run.

### Environment configuration

Copy `.env.example` to `.env.development` (or `.env.production`) and fill in real values — see
that file for every setting with inline documentation. The ones specific to this project's LLM
layer:

| Setting | Default | Notes |
| --- | --- | --- |
| `GEMINI_API_KEY` | — | Required for the deep-review node to run at all. |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Base model for specialists and the code-explorer subagent. |
| `DEEP_REVIEW_JUDGE_MODEL` | `gemini-3.1-pro-preview` | Stronger model for verifier + synthesizer only. Set to an empty string to use `GEMINI_MODEL` for every role. |
| `DEEP_REVIEW_ENABLED` | `true` | Set `false` to run only ingest → discovery → static analysis → dependency graph. |
| `DEEP_REVIEW_CONFIG_PATH` | bundled `review_config.toml` | Point at a different file to override what the review looks for without touching code. |
| `DEEP_REVIEW_MAX_CONCURRENCY` | `6` | Parallel review agents; lower it on rate-limited API tiers. |

`APP_ENV` (set as a real environment variable, e.g. `set APP_ENV=production`) selects which
`.env.<APP_ENV>` file gets merged on top of the base `.env` — defaults to `development`.
`.env.testing` is the exception: it's committed with dummy, non-secret values on purpose (see
[Testing](#testing) below) — never put a real credential in it.

### Migrations

```bash
uv run alembic upgrade head
```

Add a migration after changing an ORM model in `src/data/models/`:

```bash
uv run alembic revision --autogenerate -m "describe the change"
uv run alembic upgrade head
```

### Running the API

```bash
uv run main.py
# or: uv run uvicorn main:app --reload
```

Docs at `http://localhost:8000/api/v1/docs`.

## Frontend (`frontend/`)

A React + TypeScript single-page app (Vite) — dashboard, repositories, a live pipeline view and an
interactive report (findings explorer, security KPI checklist, static-analysis triage, full
markdown report). Requires Node 20+.

```bash
cd frontend
npm install
npm run dev      # http://localhost:5173 — proxies /api to the FastAPI app on :8000
```

For production, build it once and FastAPI serves it itself (same origin, no CORS, no second
server) — every non-API path returns the SPA:

```bash
cd frontend && npm run build   # writes frontend/dist/
uv run main.py                 # UI at http://localhost:8000/, API at /api/v1
```

`npm run typecheck` runs the TypeScript compiler without emitting.

## API flow

1. **`POST /api/v1/ingestion/repositories`** — submit a GitLab URL + access token. Validates the
   input, queues a `PENDING` review row, and returns **202** immediately with a
   `review_report_id`:

   ```json
   {"repository_id": "...", "review_report_id": "...", "status": "pending"}
   ```

   The full pipeline (all five stages above — several minutes) then runs as a background task,
   detached from the request. The access token is never persisted or logged; it lives only in
   the in-memory state handed to that background task.
2. **`GET /api/v1/reviews/{review_report_id}/status`** — poll this while the run is in flight. A
   small payload: `status`, the current `stage` (`queued` → `ingest` → `discovery` →
   `static_analysis` → `dependency_graph` → `deep_review` → `done` / `failed`) and live
   `progress` (per-stage start/finish times and every deep-review agent's status). A pipeline
   failure at *any* stage marks the row `failed` with the error — nothing is lost silently.
3. **`GET /api/v1/reviews/{review_report_id}`** — once `completed`: the full structured report
   (`report_data`: findings, KPI assessments, static triage, statistics) plus `report_markdown`.
4. **`GET /api/v1/reviews/{review_report_id}/markdown`** — the rendered report as `text/markdown`.

Other endpoints: `GET /api/v1/repositories` (each with its latest review and review count),
`GET|DELETE /api/v1/repositories/{id}` (delete is refused with 409 while a review is running),
`GET /api/v1/reviews` (newest first, across all your repositories) and
`GET /api/v1/reviews/repository/{id}`. Everything is scoped to the signed-in user; other users'
ids return 404.

## Tuning the review (`src/assets/review_config.toml`)

The single source of truth for *what* the review looks for — editing it changes the review
without touching code (its content hash is part of the review cache key, so an edit invalidates
previously cached reports for the same commit):

- **`[[categories]]`** — one specialist subagent per enabled category, run in parallel; the order
  here is the section order in the final report. Each has an `id`, `title`, a short `code` used
  as its finding-id prefix (e.g. `SEC-3`), and a `focus` checklist injected into its prompt.
  Setting `enabled = false` skips a category entirely. Exactly one category should set
  `owns_security_kpis = true` — that specialist gets a second, dedicated KPI-assessor agent
  running alongside it.
- **`[[security_kpis]]`** — the mandatory security checklist the KPI-owning specialist assesses
  one by one (report §0.1: open / partially_open / closed / not_applicable / not_verified, each
  with evidence).
- **`[static_analysis.owners]`** — `tool -> category id`. The owner triages every finding from
  that tool (true_positive / false_positive / low_value); every other specialist can still read
  all static findings as context.
- **`[review]`** — global knobs: `max_findings_per_category` (caps one noisy specialist),
  `min_confidence` (drops low-confidence findings before reporting), `verify_severities` (which
  severities get an independent verification pass), `include_remediation`.

## Testing

```bash
uv run --group dev pytest -q
```

No secrets required — `tests/conftest.py` defaults `APP_ENV` to `testing`, which pulls in the
committed `.env.testing` (dummy values only). The suite mocks the database layer throughout
(repositories are patched with `MagicMock`/`AsyncMock`) and never opens a real Postgres
connection or calls a real LLM provider, so this works on a bare checkout with nothing configured.
To run against a real local Postgres instead: `APP_ENV=development uv run pytest`.

Lint with the same config CI uses:

```bash
uv run ruff check --config src/assets/ruff.toml src/ tests/
```

> **Known flaky test**: `tests/controllers/test_deep_review_controller.py::test_full_review_with_scripted_agents`
> intermittently fails when run alongside the other test in that file (passes in isolation). Root
> cause: when a specialist agent records multiple findings in one turn, deepagents/LangGraph
> executes those `record_finding` tool calls concurrently, so which finding gets the lower numeric
> id (`SEC-1` vs `SEC-2`) is a genuine race — not data corruption (each finding stays internally
> consistent), just non-deterministic id-to-content ordering. The test hardcodes an assumption the
> code doesn't actually guarantee. Pre-existing, not yet fixed.
