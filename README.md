# CodeReviewer

An automated, evidence-based code-review service for Python backends. Point it at a GitLab
repository and it clones the code, builds a deterministic understanding of it (files, routes,
auth, data flow, dependency graph, static analysis, security scans), then runs a team of LLM
review agents that read the real code, form and test their own hypotheses, verify each other's
work and produce a findings-based engineering review: every finding cited to `file:line`,
severity-calibrated, independently verified, with false positives and wrong "this is safe"
conclusions filtered out.

It is built to review **any** Python backend, not one codebase: nothing in the engine is tuned to
a specific project. Version 1 reviews Python services (FastAPI, Flask, Quart, Sanic, Django,
Django REST framework, aiohttp, Starlette, workers and scripts); the browser frontend is out of
scope by default (see [Scope](#scope-backend-first)).

---

## Contents

- [Architecture](#architecture)
- [Pipeline stages](#pipeline-stages)
- [The deep-review engine](#the-deep-review-engine)
  - [1. Deterministic context](#1-deterministic-context-no-llm)
  - [2. Review lanes](#2-review-lanes)
  - [3. Agent roles and workflow](#3-agent-roles-and-workflow)
  - [4. Guardrails enforced in code](#4-guardrails-enforced-in-code)
  - [5. The report](#5-the-report)
- [Why it works on any project](#why-it-works-on-any-project)
- [Scope: backend first](#scope-backend-first)
- [Project structure](#project-structure)
- [Setup](#setup) · [Configuration](#environment-configuration) · [Running](#running-the-api) · [Web UI](#web-ui-frontend)
- [API flow](#api-flow)
- [Describing your system (`AGENTS.md`)](#describing-your-system-agentsmd)
- [Tuning the review](#tuning-the-review-srcassetsreview_configtoml)
- [Testing](#testing)

---

## Architecture

```mermaid
flowchart LR
    A[POST /ingestion] --> B[Ingest<br/>clone + verify]
    B --> C[Discovery<br/>files, ASTs, frameworks,<br/>endpoints, manifests]
    C --> D[Static analysis<br/>10 tools, 2 tracks]
    D --> E[Dependency graph<br/>tree-sitter + grimp]
    E --> F[Deep review]
    F --> G[(Report<br/>JSON + Markdown)]

    subgraph F[Deep review]
      direction TB
      M[Review maps + runtime signals<br/>deterministic, no LLM] --> S[12 specialist lanes<br/>+ KPI assessor<br/>+ code-explorer subagents]
      S --> V[Verifiers<br/>per lane, severity-split]
      V --> N[Negative audit<br/>re-checks every 'safe' conclusion]
      N --> V2[Verification of<br/>overturned items]
      V2 --> Y[Synthesizer<br/>dedup + executive summary]
    end
```

One [LangGraph](https://github.com/langchain-ai/langgraph) graph, five stages, each a thin node
delegating to its own controller (`src/nodes/` → `src/controllers/`). Every stage after Ingest is
cached by content hash (commit SHA + engine/schema version, plus the review config's hash for the
deep review), so an unchanged repository at the same commit returns the cached result.

## Pipeline stages

1. **Ingest** — clones the GitLab repository into an isolated workspace, verifies integrity and
   publishes it atomically to `cloned_repos/<repository_id>/`. The access token is never persisted
   or logged.
2. **Discovery** — deterministic: classifies every file, parses Python ASTs, detects
   frameworks, entry points and HTTP endpoints, parses dependency manifests. Produces the versioned
   `RepositoryManifest` every later stage reads.
3. **Static analysis** — ten tools on two tracks, every finding normalized and content-hashed:
   - structural (sequential): `ruff`, `pyright`, `radon`, `vulture`, `jscpd`, `lizard`;
   - security (concurrent): `pip-audit`, `semgrep` (bundled offline rules), `bandit`, `gitleaks`.
4. **Dependency graph** — [tree-sitter](https://tree-sitter.github.io/) function/class/call
   extraction plus [grimp](https://github.com/seddonym/grimp) module imports (isolated in a
   subprocess because it imports the target's code).
5. **Deep review** — the multi-agent review below, built on
   [deepagents](https://github.com/langchain-ai/deepagents).

## The deep-review engine

### 1. Deterministic context (no LLM)

Before any agent starts, `helpers/review_maps.py`, `helpers/route_frameworks.py` and
`helpers/review_signals.py` build exhaustive tables from the whole codebase in about a second.
They are mounted read-only at `/_review/context/` and every agent walks them row by row instead of
rediscovering the system with greps:

| File | What it holds |
| --- | --- |
| `system_overview.md` | Components, declared runtimes (requires-python, base images), entry points, API surface by area and auth, data stores, external services, background work, tests/CI. |
| `route_map.md` | Every HTTP route of every supported framework with its full path (router/blueprint/include prefixes resolved), the auth that really applies (dependencies, `Annotated` aliases, decorators, mixins, DRF permission classes, app-level hooks), identity values read from the request, and flags: `CLIENT-ASSERTED IDENTITY`, `NO AUTH DEPENDENCY`, `AUTH ENTRY POINT`, `FILE UPLOAD`. |
| `env_map.md` | Every environment read with its inline default, keys whose defaults diverge between modules, and a value-free inspection of every `.env*` file (duplicates, weak/short/localhost/browser-exposed flags). Values never leave the process. |
| `reachability.md` | Python modules no entry point reaches. Entry points include app constructors, launch commands (`uvicorn main:app`, `python -m`), app factories, worker tasks, schedulers, consumers, Django management commands and any module loaded **by name** (Celery `include`, Django `include`/`INSTALLED_APPS`, `importlib`). |
| `architecture.md` | Process-local state, background jobs (in-process tasks, Celery/RQ/Dramatiq tasks, schedulers, consumers), queries that ignore the caller's identity. |
| `runtime_signals.md` | How the running system behaves beyond the linters (list below). |
| `scopes.md` | The files each lane must open — every live backend file is in at least one lane's scope. |
| `client_calls.md` | Client API calls vs backend routes (used for the API contract). |
| `agents_md.md` | The developers' `AGENTS.md`, when present. |

**Runtime signals** (`review_signals.py`): each one is a deterministic detector that becomes a
mandatory lead for the lane that owns it.

| Area | Signals |
| --- | --- |
| Risk hotspots | Functions combining several kinds of side effect (DB write, network, files, subprocess, model calls, locks, messaging, background work), followed two calls deep and weighted by route-handler status, size and broad excepts. |
| Data & lifecycle | Request-scoped DB sessions passed to background work, fire-and-forget tasks, session dependencies that leak on error, ORM tables no migration creates, text cleaners that rewrite identifier characters (emails, URLs, ids, dates), whole-file rewrites, naive datetimes, unbounded reads. |
| Security | Session fixation (identity written into an un-renewed session), response models returning password hashes/keys, security controls defined but applied nowhere, credentials in query strings, packaged secrets and personal data, privileged containers, third-party data processors. |
| Runtime | Blocking/sync work reached from async code, model clients built at import, agent loops re-sending history, unbounded tool output, token usage never read, subprocesses without timeouts, startup fragility, executor nesting, process-local state. |
| Operations | `print()` in live modules, health checks that check nothing, tests and which drive the API, CI pipelines and missing scan steps, pipeline hygiene, deploy-manifest env conflicts, missing lockfiles, unpinned images. |
| Structure | Parallel implementations of one operation, layer import cycles, duplicate libraries, unused dependencies. |

**Bundled semgrep rules** (`src/assets/semgrep/`, offline, project-owned): 57 rules, each routed
to the lane that judges it.

- `python-security.yml`: injection (SQL, `text()`, shell, `eval`), SSTI, unsafe deserialization, XXE, weak hashes and RNG, TLS/JWT verification off, CORS wildcard with credentials, debug mode, upload filenames reaching paths, exception text returned to clients, insecure secret defaults, static mounts, blocking calls in async code, HTTP calls without timeout, and more.
- `python-web-app.yml`: mass assignment, open redirects, `assert` used as a guard, cookies without HttpOnly/Secure, `jwt.decode` without an algorithm list, secrets compared with `==`, archive extraction without path checks, secrets written to logs, swallowed exceptions, mutable default arguments, process-wide DB sessions, money as float.
- `web-security.yml`: browser rules, used only when the frontend lane is enabled.

### 2. Review lanes

One specialist per enabled category in `src/assets/review_config.toml`, run concurrently (heavier
lanes start first and get proportionally more time):

| Lane | Code | Looks at |
| --- | --- | --- |
| Security & Authorization | `SEC` | Authorization per route and object (IDOR), client-asserted identity, injection, SSRF, business-logic abuse, multi-tenant isolation, webhooks, response over-exposure, data exposure and privacy. Also runs the KPI assessor. |
| Authentication, Sessions & Tokens | `AUTH` | Token/session lifecycle, credential flows, rate limiting and lockout, enumeration, weak RNG, session rotation and fixation. |
| Upload Governance & Input Controls | `INP` | Every input path: content-type checks, size limits, parser abuse, quotas, cancellation, stuck jobs, request validation. |
| Correctness & Data Integrity | `BUG` | Core flows end to end, logic errors, lossy normalization, check-then-act races, idempotency, transactions, async/ORM pitfalls, locks that survive a crash, results that lie. Runs on the stronger model. |
| Integration & Configuration | `INT` | Settings and their defaults, external URLs, the backend API contract, outbound calls, operational scripts (migrations, entrypoints, shell, SQL). |
| Performance & Scalability | `PERF` | Event-loop blocking, horizontal scaling, growth with data, N+1, transactions held across slow work, pool sizing, memory growth. |
| Logging, Observability & Governance | `OBS` | Tracing, logging, health, metrics, durability of failures, backups. |
| Testing & CI | `TST` | What the tests really exercise, tests that cannot fail, CI gates, migrations tested the way production runs them. |
| Environment & Secrets | `ENV` | Hard-coded and default secrets, startup validation, configuration and artifact governance. |
| Dependencies & Supply Chain | `DEP` | Known CVEs (pip-audit), reproducibility, lockfiles, end-of-life runtimes, unused or duplicate packages. |
| Dead Code, Duplication & Architecture | `MNT` | Proven dead code, diverged duplicates, layering and cycles. |
| AI/LLM Usage | `LLM` | Only when the code calls models: what one request sends, token growth, cost measurement/attribution/enforcement, robustness, oversight of automated decisions. |
| Frontend & Client Security | `WEB` | **Disabled by default**. See [Scope](#scope-backend-first). |

Each lane's checklist is a set of expert questions, not a pattern list. The security lane also
owns a mandatory 12-item KPI checklist (rate limiting on auth, docs and debug endpoints in
production, formula injection in exports, stored XSS, file-serving authorization, path and
internal-host disclosure, header injection, security headers, upload content checks).

### 3. Agent roles and workflow

| Role | Model | Job |
| --- | --- | --- |
| **Specialist** (one per lane) | `GEMINI_MODEL` (correctness: judge model) | Reviews its lane end to end. |
| **KPI assessor** | base | Assesses each security KPI with evidence, in parallel with the security specialist. |
| **Code explorer** (subagent) | base | Read-only sweeps the specialists fan out in parallel ("read these 10 files and report every defect relevant to X"). |
| **Verifier** (per lane) | judge for Critical/High, base for Medium/Low | Tries to disprove every finding; confirms, adjusts severity/title/impact/exposure, or rejects with the code that disproves it. Batches of 8, then one retry pass. |
| **Negative auditor** (per lane) | judge | Re-checks every ruled-out hypothesis and dismissed lead: upholds it with code, or overturns it into a finding that then goes through verification. |
| **Synthesizer** | judge | Folds duplicates across lanes and writes the executive summary: scope, verdict, priority order, root causes. |

A specialist works in four phases, and its completion check will not let it stop early:

1. **Understand** — read the system overview, `AGENTS.md`, entry points and core modules; write
   down the system's **invariants** for its lane (each record has one owner, a job runs once, a
   caller only sees their own data, a lock is always released).
2. **Hypothesize** — record at least six repository-specific suspicions, each naming the code it
   suspects: for every invariant, the concrete path that could break it (an error path, a second
   caller, a concurrent request, a restart, an unusual input).
3. **Investigate** — prove or disprove each hypothesis in the code, sweep the whole file scope
   (with parallel explorers), and follow anything else it notices.
4. **Close the leads** — every deterministic lead ends as a finding that cites it, is attached
   to an existing finding, or is dismissed with the code that shows it is safe.

This is what lets it find issues no rule names. The leads are a safety net; the findings that
matter most come from the agents' own model of the system. The report counts how many findings
came from the agents' own investigation.

### 4. Guardrails enforced in code

The agents' tools refuse bad work instead of relying on instructions alone
(`helpers/review_workspace.py`):

- **Evidence**: every finding needs valid repository `file:line` citations; findings in
  unreachable code are relabelled latent, and severity is capped by exposure (latent at most High,
  dead or theoretical at most Medium).
- **Backend scope**: a finding whose only evidence is browser-client code is refused while the
  frontend lane is off (client `.env` templates excepted: a backend key handed to the browser is a
  backend issue).
- **Claims are checked, not believed**: "does not parse / cannot import" is refused when the file
  compiles, or when the project declares a newer Python than the checker has. "Unused" needs
  `find_references` proof.
- **Hypotheses**: each must name the code it suspects; hedged lists ("might… potentially… X or Y")
  and near-duplicates are refused. A confirmation must cite a finding about the same defect.
  Ruling one out needs code that addresses it.
- **Dismissals**: "out of time", "partially checked" and similar are refused. A reason that relies
  on `finally`/`except` cleanup for a persisted lock, flag or job is refused unless it names a real
  recovery mechanism (expiry, startup reset, heartbeat, owner check), because cleanup code does not
  run when the process is killed.
- **Verification**: a rejection must cite the code that disproves the claim, may not rest on "the
  checklist does not list it", and must be about the finding it names (crossed verdicts are
  refused).
- **Static analysis**: severe tool hits triaged as true positives must reach a finding; severe hits
  cannot hide inside the "mostly triaged" allowance.
- **Coverage**: a lane cannot finish with unopened scope files, open hypotheses or open leads. The
  completion check hands it pre-written parallel sweep calls instead.
- **Time safety**: every model call is bounded by the lane's clock; agents stop gracefully and keep
  everything recorded. A timed-out or failed agent never fails the review; its section gets a
  coverage warning.

### 5. The report

Markdown and structured JSON (`DeepReviewReport`), stored in the database and served by the API:

0. Priority order and the security KPI checklist
1. One section per lane: findings with severity, exposure, evidence, impact and verification status
2. Static-analysis triage per tool
3. Cross-cutting root causes
4. **Review coverage** (computed, not model-generated): files opened per lane, agent outcomes,
   open leads, own-investigation count

Appendices:

- **A.** Inventory
- **B.** Claims rejected by verification
- **C.** Leads dismissed and why
- **D.** Every hypothesis and its outcome

## Why it works on any project

Nothing in the engine knows about a particular codebase. It adapts to each repository through:

- **Framework-neutral maps**: routes, auth and identity inputs for FastAPI, Flask, Quart, Sanic,
  Django, DRF, aiohttp and Starlette; worker tasks, schedulers and consumers as entry points;
  modules loaded by name treated as reachable.
- **Version-tolerant parsing**: syntax newer than the reviewer's interpreter (e.g. Python 3.14's
  `except A, B:`) does not drop a module from the analysis; the declared runtime is used when
  judging syntax claims.
- **Structure-based detectors**: hotspots, lifecycle bugs, session fixation, unwired controls and
  lossy cleaning are found from the shape of the code, not from names in a list.
- **Hypothesis-driven agents**: every lane builds its own model and invariants of *this* system
  and must test repository-specific suspicions before it may finish.
- **Two independent checks**: findings go to verifiers, and "safe" conclusions to the negative
  auditor.

Validated live on repositories it was never tuned on: a production FastAPI + LLM system, the
FastAPI full-stack template, DVRA (FastAPI, planted vulnerabilities) and dvpwa (aiohttp, planted
vulnerabilities). On dvpwa, runs found all five documented vulnerabilities (SQL injection, MD5
passwords, stored XSS, session fixation, disabled CSRF), plus unauthenticated data routes.

Known limits:

- LLM runs vary somewhat from one run to the next. Recurring misses are turned into
  deterministic signals.
- Flask, Django and Celery support is covered by fixtures; it has not been through a live run.
- Non-Python backends are out of scope for version 1.

## Scope: backend first

The review covers the backend: the Python service, its API, data layer, background work,
integrations, scripts, configuration, deployment, tests and dependencies.

Browser-client code in the same repository is **context only**: which routes it calls and what the
backend hands it. Client folders (a `package.json` with no Python under it), TS/JS sources and
bundler config are in no lane's scope, and findings that cite only client code are refused.
Backend defects that reach the browser stay in scope: server-rendered HTML, CORS, cookies, security
headers, and secrets the backend hands out.

To review the browser client too, set `enabled = true` under the `frontend` category in
`src/assets/review_config.toml`.

## Project structure

```text
CodeReviewer/
├── main.py                     # FastAPI entry point (uv run main.py / uvicorn main:app)
├── pyproject.toml              # Python deps (uv) — dev / analysis-tools groups
├── alembic.ini                 # Migration runner config (src/data/alembic)
├── .env.example                # Every setting, documented
├── .env.testing                # Committed dummy values so tests need no secrets
├── src/
│   ├── api/v1/                 # Routers: auth, ingestion, repositories, reviews
│   ├── config/settings.py      # One pydantic-settings object (incl. DEEP_REVIEW_ENGINE_VERSION)
│   ├── graph/                  # LangGraph pipeline: state, workflow, background runner
│   ├── nodes/                  # One thin node per stage
│   ├── controllers/            # Per-stage logic; deep_review_controller.py orchestrates the agents
│   ├── services/               # Cross-cutting orchestration (static_analysis.py)
│   ├── helpers/
│   │   ├── review_maps.py         # Route/env/reachability/architecture maps, inventory
│   │   ├── route_frameworks.py    # Flask/Quart/Sanic/Django/DRF/aiohttp/Starlette routes
│   │   ├── review_signals.py      # Runtime signals and backend detectors
│   │   ├── review_workspace.py    # Agent tools, leads, scopes, guardrails, verification state
│   │   ├── review_prompts.py      # Shared rules + role prompts (specialist, verifier, auditor, synthesizer)
│   │   ├── review_agents.py       # Agent factory, time/budget bounds, completion-check resumes
│   │   ├── review_report_renderer.py  # Markdown report
│   │   └── ast_analyzer.py, tool_runner.py, finding_normalizers.py, git_operations.py, ...
│   ├── data/                   # ORM models, repositories (only layer touching the DB), schemas, migrations
│   ├── security/               # Password hashing, JWT
│   ├── utils/                  # Shared domain models (DeepReviewReport, ReviewFinding, ...)
│   └── assets/                 # Bundled per-scan config: review_config.toml, semgrep/*.yml,
│                               #   ruff.toml, pyrightconfig.json, gitleaks binary
├── frontend/                   # CodeReviewer's own web UI (React 19 + TypeScript, Vite)
└── tests/                      # Mirrors src/ 1:1
```

Rule of thumb: **nodes** are thin, **controllers** hold per-stage logic, **helpers** are
stateless building blocks, and only **data/** touches the database.

## Setup

Requires Python 3.13, [uv](https://docs.astral.sh/uv/) and PostgreSQL.

```bash
uv sync --group dev --group analysis-tools
```

`analysis-tools` installs `ruff`, `pyright`, `radon`, `vulture`, `lizard`, `bandit` and
`pip-audit`. Two tools are installed separately:

- **semgrep** — in its own tool environment (it pins `wcmatch<9`, which conflicts with
  deepagents). It runs offline against the bundled rules; `SEMGREP_CONFIG=auto` switches to the
  online registry.

  ```bash
  uv tool install "semgrep>=1.177.0"
  ```

- **jscpd** — via npm:

  ```bash
  npm install -g jscpd
  ```

**gitleaks** ships as a bundled binary (`src/assets/gitleaks.exe`, Windows) or is taken from `PATH`.
Every required tool is checked before static analysis starts, with one clear error listing anything
missing.

### Environment configuration

Copy `.env.example` to `.env.development` (or `.env.production`) and fill it in. `APP_ENV` selects
which `.env.<APP_ENV>` is merged on top of `.env`. The deep-review settings:

| Setting | Default | Notes |
| --- | --- | --- |
| `GEMINI_API_KEY` | — | Required for the deep review. |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Base model: specialists, explorers, KPI assessor, Medium/Low verifiers. |
| `DEEP_REVIEW_JUDGE_MODEL` | `gemini-3.1-pro-preview` | Critical/High verifiers, negative auditors, synthesizer, correctness lane. Empty means `GEMINI_MODEL` for every role. |
| `DEEP_REVIEW_ENABLED` | `true` | `false` stops after the dependency graph. |
| `DEEP_REVIEW_CONFIG_PATH` | bundled `review_config.toml` | Change what the review looks for without touching code. |
| `DEEP_REVIEW_MAX_CONCURRENCY` | `6` | Parallel agents; lower it on rate-limited tiers. |
| `DEEP_REVIEW_AGENT_TIMEOUT_SECONDS` | `900` | Base wall-clock per agent, scaled by lane effort. |
| `DEEP_REVIEW_SPECIALIST_MODEL_CALLS` | `60` | Per-agent budget; there are matching settings for verifier (`30`), explorer (`20`) and synthesizer (`25`). |
| `DEEP_REVIEW_INSPECT_ENV_FILES` | `true` | Value-free `.env` inspection; `false` skips committed real `.env` files. |
| `DEEP_REVIEW_ENGINE_VERSION` | set in code | Part of the cache key; bumped whenever review behaviour changes. |

`.env.testing` is committed with dummy values on purpose. Never put a real credential in it.

### Migrations

```bash
uv run alembic upgrade head
uv run alembic revision --autogenerate -m "describe the change"   # after changing a model
```

### Running the API

```bash
uv run main.py          # or: uv run uvicorn main:app --reload
```

The API docs are served at `http://localhost:8000/api/v1/docs`.

## Web UI (`frontend/`)

CodeReviewer's own React + TypeScript app: dashboard, repositories, a live pipeline view and an
interactive report (findings explorer, KPI checklist, static triage, full markdown). It needs
Node 20+.

```bash
cd frontend && npm install && npm run dev     # http://localhost:5173, proxies /api to :8000
cd frontend && npm run build                  # production: FastAPI serves frontend/dist itself
```

This is the tool's UI. It is unrelated to the `frontend` review lane, which reviews *your*
repository's browser code.

## API flow

1. **`POST /api/v1/ingestion/repositories`** — GitLab URL + access token. It queues a `PENDING`
   review and returns **202** with a `review_report_id`; the pipeline then runs in the background.
2. **`GET /api/v1/reviews/{id}/status`** — poll while it runs:
   - `status`;
   - `stage`: `queued` → `ingest` → `discovery` → `static_analysis` → `dependency_graph` → `deep_review` → `done` / `failed`;
   - live per-agent progress.
3. **`GET /api/v1/reviews/{id}`** — the structured report plus `report_markdown`.
4. **`GET /api/v1/reviews/{id}/markdown`** — the report as `text/markdown`.

Also:

- `GET /api/v1/repositories`;
- `GET|DELETE /api/v1/repositories/{id}` (delete is refused with 409 while a review runs);
- `GET /api/v1/reviews`;
- `GET /api/v1/reviews/repository/{id}`.

Everything is scoped to the signed-in user.

## Describing your system (`AGENTS.md`)

Add an `AGENTS.md` to the reviewed repository (root, or one per service) describing how the system
is meant to work: main flows, business rules, invariants, who may do what. Every agent reviews the
code against it, and a divergence becomes a finding (`violates_documented_rule`). It is read as
data, never as instructions.

## Tuning the review (`src/assets/review_config.toml`)

The single source of truth for *what* the review looks for. Its hash is part of the cache key, so an
edit invalidates cached reports.

- **`[[categories]]`** — one specialist per enabled lane:
  - `id`, `title`;
  - `code` (finding-id prefix);
  - `effort` (relative run time);
  - `focus` (the checklist);
  - `enabled`;
  - `strong_model`;
  - `owns_security_kpis`.
- **`[[security_kpis]]`** — the mandatory checklist, each item assessed with evidence.
- **`[static_analysis.owners]`** — which lane triages which tool.
- **`[review]`** — `max_findings_per_category`, `min_confidence`, `verify_severities`,
  `include_remediation`.

To add a check, write it as an expert question in the right lane's `focus`. For a new
deterministic pattern, add a semgrep rule under `src/assets/semgrep/` and route it to a lane in
`review_workspace.py` (`_SECURITY_LEAD_RULES` / `_LANE_RULE_LEADS`).

## Testing

```bash
uv run --group dev pytest -q
uv run ruff check --config src/assets/ruff.toml src/ tests/
```

No secrets are needed: `tests/conftest.py` selects the committed `.env.testing`, the database layer
is mocked, and no real LLM is called. The bundled semgrep rules are exercised by the real binary
over fixtures (`tests/controllers/test_bundled_semgrep_*.py`), each rule both firing on its defect
and staying quiet on the safe variant. The framework route collectors, runtime signals and every
guardrail have their own tests.
