# EcoMind-AI — Development Environment Record

**Document status:** authoritative for "what actually runs where"
**Last verified:** 2026-09-24, against the sandbox described below
**Rule:** this file records *observed* facts with the command that produced
evidence. No capability is claimed here without a reproduction step.

---

## 1. Verified sandbox capabilities

| Capability | Status | Evidence |
|---|---|---|
| OS | Debian 12 (bookworm), kernel 6.1, x86_64 | `cat /etc/os-release`, `uname -a` |
| CPU / RAM | 2 vCPU / 3.8 GB RAM | `nproc`, `free -h` |
| Disk | 20 GB free on `/` | `df -h /home/user` |
| Python | 3.11.2, `venv` available | `python3 --version` |
| Node.js / npm | v22.22.3 / 10.9.8 | `node --version`, `npm --version` |
| PyPI reachable | yes (HTTP 200) | `curl -o /dev/null -w '%{http_code}' https://pypi.org/simple/` |
| npm registry reachable | yes (HTTP 200) | `curl https://registry.npmjs.org/` |
| Debian apt mirrors | **blocked** | `apt-get update` → `Connection failed` |
| Docker / Docker Compose | **absent** | `docker --version` → `command not found` |
| PostgreSQL (packages) | **absent** | `psql --version` → `command not found` |
| Redis (packages) | **absent** | `redis-server --version` → `command not found` |
| GPU | none | `nvidia-smi` unavailable |
| sudo | available, but apt unusable | `sudo -n true` → OK |

### 1.1 The three environment findings that changed the design

**Finding 1 — Real PostgreSQL *is* available via bundled binaries.**
`pgserver` (PyPI, a package that vendors official PostgreSQL 16.2 binaries)
installs in ~1.5 s and runs a genuine server. Verified:

```
SELECT version();
→ PostgreSQL 16.2 on x86_64-pc-linux-gnu, compiled by gcc (GCC) 10.2.1 ...
SHOW server_version_num;
→ 160002
```

Constraints are enforced by the real engine, not emulated:

```
CREATE TABLE b(fill numeric(5,2) CHECK (fill>=0 AND fill<=100), ...);
INSERT INTO b(fill) VALUES (150);
→ ERROR: new row for relation "b" violates check constraint "b_fill_check"
SELECT gen_random_uuid();  → works (PG13+ built-in)
SELECT (123.456::numeric(12,4))::text;  → 123.4560  (exact decimal, no float)
```

The cluster also **survives across processes**: a second process pointed at the
same data directory re-attaches to the running server, and `ps aux` shows the
`postgres` process still alive. This is what makes a long-lived dev/test
database possible without Docker.

**Consequence:** the project targets **PostgreSQL-only** semantics. There is no
SQLite test path, so tests cannot accidentally pass on a database that ignores
constraints. `docs/database/erd.md` and every migration use PostgreSQL-native
types (`NUMERIC`, `UUID`, `TIMESTAMPTZ`, partial indexes, `CHECK` constraints).

> **PostGIS is NOT available.** The bundled cluster reports zero rows in
> `pg_available_extensions` — the contrib and PostGIS extension files are not
> shipped. Therefore the platform must not require PostGIS to function.
> **Decision (ADR-0005):** a dialect-aware geo layer. Coordinates are stored as
> validated `NUMERIC(9,6)`/`NUMERIC(10,7)` columns (never strings), geospatial
> queries use a haversine SQL expression with bounding-box pre-filtering on a
> `btree` index, and the schema reserves an optional PostGIS `geometry` column
> that is created when `GEO_ENABLE_POSTGIS=true`. Behaviour is identical in both
> modes; only the index strategy improves. This is a portability decision, not a
> downgrade — and it is strictly better than storing lat/lng as text.

**Finding 2 — No Redis daemon.**
Production and Docker Compose use Redis 7. For development and tests the
platform ships a `CacheBackend`/`BrokerBackend` abstraction with a `fakeredis`
implementation. The adapter is **explicitly labelled** at startup and in
`/health` output (`"cache": {"backend": "fakeredis", "is_simulated": true}`), so
a reader can never mistake it for a real Redis deployment.

**Finding 3 — PyTorch is not justified here.**
`torch` 2.14 CPU wheel is 528.9 MB on a 2-vCPU, no-GPU, no-dataset host.
Per sections 49/62/64 of the master prompt, a model may not be claimed as
accurate without evaluation data. **Decision (ADR-0008):** the waste
classification subsystem ships
1. a pluggable `ClassificationBackend` interface,
2. a **classical computer-vision backend** (colour histograms, texture/LBP,
   edge density, HOG-style descriptors → scikit-learn classifier) that is
   *actually trained and actually evaluated* on a deterministic synthetic
   corpus whose construction is documented and whose measured metrics are
   reported verbatim, and
3. a `torchvision` backend behind `requirements/vision.txt`, selectable with
   `CLASSIFICATION_BACKEND=torchvision`.
The deep-learning model is registered as `CANDIDATE`, never `ACTIVE`, until a
real labelled corpus exists. No accuracy number is ever hardcoded.

---

## 2. What runs where

| Component | Sandbox (this environment) | Docker Compose (documented prod-like) |
|---|---|---|
| API | `uvicorn` on `0.0.0.0:8000`, native process | `backend` container |
| Frontend | Vite dev server on `0.0.0.0:5173` | `frontend` container behind nginx |
| Database | **real PostgreSQL 16.2** via `pgserver`, socket in `.runtime/pgdata` | `postgres:16` service |
| Cache | `fakeredis` adapter (labelled) | `redis:7` service |
| Jobs | `JOB_RUNNER=inline` (in-process, synchronous) | Celery worker + beat |
| Object storage | `STORAGE_PROVIDER=local` (`.runtime/storage`) | MinIO / S3 |
| Routing provider | `local_haversine` deterministic adapter | OSRM/Google adapter |
| LLM provider | `local` deterministic assistant | `openai_compatible` adapter |

### 2.1 Live-preview constraints (platform requirement)

Servers are bound to `0.0.0.0` (never `127.0.0.1`) so the platform's preview
proxy can reach them. The Vite dev server proxies `/api` to the backend
**server-side**, so browser code only ever calls relative URLs and never
`localhost` — the user's browser is not the sandbox. CORS origins are
configured from `CORS_ALLOWED_ORIGINS` and the preview host/origin is accepted
in development; `allowedHosts` is disabled in the Vite config for that reason.

---

## 3. Reproducing this environment

```bash
./scripts/bootstrap.sh          # venv + deps + .env + PostgreSQL + migrations + seed
make api                        # http://localhost:8000/docs
make web                        # http://localhost:5173
make test                       # full backend test suite against real PostgreSQL
```

If the sandbox is rebuilt between sessions, `.venv/` and `.runtime/` are not
preserved (they are deliberately outside version control). `bootstrap.sh` is
idempotent and restores everything; the repository itself never depends on
them.

### 3.1 Verification commands (copy-paste audit)

```bash
# Database really is PostgreSQL, not a substitute
.venv/bin/python scripts/pg_server.py psql -c "SELECT version();"

# Test suite really ran against PostgreSQL
.venv/bin/python -m pytest backend/tests -q

# Migrations are reversible and current
cd backend && ../.venv/bin/python -m alembic current && ../.venv/bin/python -m alembic check
```

---

## 4. Known environment limitations (disclosed, not hidden)

1. **No Docker in the sandbox.** Compose files and Dockerfiles are authored to
   the specification's deployment section but their *image builds are not
   executed here*. They are validated by `docker compose config`-equivalent
   static review and by parity with the native process commands. This is stated
   plainly rather than implied to be tested.
2. **No PostGIS.** Geo queries use the documented fallback; the PostGIS code
   path is present but cannot be executed in this sandbox.
3. **2 vCPU / 3.8 GB.** Route optimization is therefore bounded by a solver time
   limit (`OPTIMIZER_MAX_SOLVE_SECONDS`, default 10 s) and always reports
   whether it reached optimality or hit the limit. Large-scale telemetry
   benchmarking is not possible here; retention and aggregation strategies are
   designed for scale and documented as untested at that scale.
4. **No real IoT hardware, vehicle fleet, weather API, or LLM endpoint.**
   Adapters plus deterministic simulators are provided and labelled as such in
   the UI and in API responses (`data_source: "simulated"`).
