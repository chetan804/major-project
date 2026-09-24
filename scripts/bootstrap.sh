#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# EcoMind-AI — local bootstrap
#
# Creates the Python virtual environment, installs dependencies, materialises
# `.env` from `.env.example`, and starts a real PostgreSQL cluster using the
# bundled `pgserver` binaries. Idempotent: safe to re-run.
#
# Usage:
#   ./scripts/bootstrap.sh              # full bootstrap
#   ./scripts/bootstrap.sh --deps-only  # only (re)install python dependencies
#
# Rationale for pgserver: this project's development and test environments must
# exercise real PostgreSQL semantics (CHECK constraints, NUMERIC precision, RLS,
# window functions). See docs/environment.md and ADR-0002.
# ---------------------------------------------------------------------------
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VENV_DIR="${VENV_DIR:-$REPO_ROOT/.venv}"
PGDATA_DIR="${PGDATA_DIR:-$REPO_ROOT/.runtime/pgdata}"
RUN_DIR="$REPO_ROOT/.runtime"

log() { printf '\033[1;36m[bootstrap]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[bootstrap]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[bootstrap]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. Python environment
# ---------------------------------------------------------------------------
if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  log "creating virtual environment at $VENV_DIR"
  python3 -m venv "$VENV_DIR"
fi

log "installing python dependencies (base + ml + worker + dev)"
"$VENV_DIR/bin/python" -m pip install --quiet --upgrade pip
"$VENV_DIR/bin/python" -m pip install --quiet -r backend/requirements/dev.txt
log "python dependencies ready ($("$VENV_DIR/bin/python" --version))"

if [[ "${1:-}" == "--deps-only" ]]; then
  log "deps-only requested; skipping database and env setup"
  exit 0
fi

# ---------------------------------------------------------------------------
# 2. Local configuration
# ---------------------------------------------------------------------------
if [[ ! -f .env ]]; then
  log "creating .env from .env.example (development values)"
  cp .env.example .env
  # Generate a real secret rather than shipping a placeholder.
  SECRET="$("$VENV_DIR/bin/python" -c 'import secrets; print(secrets.token_urlsafe(64))')"
  "$VENV_DIR/bin/python" - "$SECRET" <<'PY'
import pathlib, sys
p = pathlib.Path(".env")
text = p.read_text()
text = text.replace(
    'JWT_SECRET_KEY="CHANGE_ME_generate_a_64_byte_random_secret"',
    f'JWT_SECRET_KEY="{sys.argv[1]}"',
)
text = text.replace(
    'TELEMETRY_INGEST_API_KEY="CHANGE_ME_device_gateway_key"',
    f'TELEMETRY_INGEST_API_KEY="{sys.argv[1][:43]}"',
)
p.write_text(text)
PY
  log "generated JWT_SECRET_KEY and TELEMETRY_INGEST_API_KEY"
else
  log ".env already exists; leaving it untouched"
fi

# ---------------------------------------------------------------------------
# 3. PostgreSQL (real server, bundled binaries)
# ---------------------------------------------------------------------------
mkdir -p "$RUN_DIR" "$PGDATA_DIR"
log "starting PostgreSQL cluster at $PGDATA_DIR"
# The server is started detached and persists; a second invocation re-attaches.
"$VENV_DIR/bin/python" scripts/pg_server.py start

"$VENV_DIR/bin/python" scripts/pg_server.py url > "$RUN_DIR/database_url"
DB_URL="$(cat "$RUN_DIR/database_url")"
log "database ready: $DB_URL"

# ---------------------------------------------------------------------------
# 4. Migrations + seed data
# ---------------------------------------------------------------------------
if [[ "${SKIP_MIGRATIONS:-0}" != "1" ]]; then
  log "applying database migrations"
  ( cd backend && "$VENV_DIR/bin/python" -m alembic upgrade head )
  log "seeding development data"
  ( cd backend && "$VENV_DIR/bin/python" -m app.scripts.seed --profile dev )
fi

log "bootstrap complete"
cat <<'EOF'

Next steps:
  make api        # start the FastAPI server        (http://localhost:8000/docs)
  make web        # start the Vite dev server       (http://localhost:5173)
  make worker     # start background job processing
  make test       # run the test suite
  make simulate   # emit simulated IoT telemetry

EOF
